"""
Discoverykastle — Central Server
FastAPI application entry point.
"""

from __future__ import annotations

import logging

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from server.logging_config import setup_logging
from server.database import init_db
from server.modules.loader import load_all
from server.modules.registry import registry
from server.api.agents import router as agents_router
from server.api.alerts import router as alerts_router
from server.api.auth_api import router as auth_router
from server.api.version import router as version_router
from server.api.inventory import router as inventory_router
from server.api.topology import router as topology_router
from server.api.netbox import router as netbox_router
from server.api.modules import router as modules_router
from server.api.setup import router as setup_router
from server.api.webpush import router as webpush_router
from server.api.data import router as data_router
from server.api.ws import router as ws_router
from server.api.tasks import router as tasks_router
from server.api.vulns import router as vulns_router
from server.api.users import router as users_router
from server.api.audit_log import router as audit_log_router
from server.api.vault import router as vault_router
from server.middleware.setup_guard import SetupGuardMiddleware

# Must be called before any other module creates a logger.
# Configures console + rotating JSON file + Graylog (if configured).
setup_logging()
logger = logging.getLogger("dkastle.server")


async def _bootstrap_admin() -> None:
    """Create the admin User row from settings if no users exist yet."""
    from sqlalchemy import select

    from server.config import settings
    from server.database import AsyncSessionLocal
    from server.models.user import User
    from server.services.auth import hash_password

    if not settings.admin_password:
        return

    async with AsyncSessionLocal() as db:
        count_result = await db.execute(select(User))
        if count_result.first() is not None:
            return  # users already bootstrapped

        pw = settings.admin_password
        # Hash if stored as plain text (dev convenience)
        try:
            is_hashed = pw.startswith("$2b$") or pw.startswith("$pbkdf2")
        except Exception:
            is_hashed = False

        pw_hash = pw if is_hashed else hash_password(pw)
        admin = User(
            username=settings.admin_username,
            password_hash=pw_hash,
            role="admin",
            is_active=True,
        )
        db.add(admin)
        await db.commit()
        logger.info(
            "Bootstrapped admin user '%s' into the users table.",
            settings.admin_username,
            extra={"event": "admin_bootstrapped"},
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    import time
    t0 = time.monotonic()
    logger.info("Discoverykastle server starting up...", extra={"event": "startup"})

    await init_db()
    logger.info("Database initialized.", extra={"event": "db_init"})

    await _bootstrap_admin()
    logger.info("Admin user bootstrapped.", extra={"event": "admin_bootstrap"})

    from server.services.ca import ca
    from server.config import settings
    ca.init(settings.ca_dir)
    logger.info("Certificate Authority initialized.", extra={"event": "ca_init"})

    load_all()
    await registry.setup_all()
    module_names = [m["name"] for m in registry.list_modules()]
    logger.info(
        "Modules loaded: %s",
        module_names,
        extra={
            "event": "modules_loaded",
            "module_count": len(module_names),
            "modules": module_names,
            "duration_ms": round((time.monotonic() - t0) * 1000),
        },
    )

    # Start background task timeout monitor
    import asyncio
    from server.services.task import run_timeout_monitor
    monitor_task = asyncio.create_task(run_timeout_monitor())
    logger.info("Task timeout monitor started.", extra={"event": "monitor_started"})

    yield

    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass

    logger.info("Discoverykastle server shutting down...", extra={"event": "shutdown"})
    await registry.teardown_all()


app = FastAPI(
    title="Discoverykastle",
    description=(
        "Autonomous network discovery, security assessment, and documentation platform. "
        "Extensible via the module system."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production via Nginx
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SetupGuard must be added AFTER CORS so CORS headers are still sent on 302/503.
# Starlette middlewares execute in reverse registration order, so this runs first.
app.add_middleware(SetupGuardMiddleware)

# Static assets (webpush.js, icons, …)
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Routers — setup first so /setup is always reachable
app.include_router(setup_router)
app.include_router(auth_router)
app.include_router(agents_router)
app.include_router(version_router)
app.include_router(webpush_router)
app.include_router(alerts_router)
app.include_router(inventory_router)
app.include_router(topology_router)
app.include_router(netbox_router)
app.include_router(modules_router)
app.include_router(data_router)
app.include_router(ws_router)
app.include_router(tasks_router)
app.include_router(vulns_router)
app.include_router(users_router)
app.include_router(audit_log_router)
app.include_router(vault_router)

# Serve the React SPA — static assets first, then index.html catch-all
_ui_dir = Path(__file__).parent / "static" / "ui"
if _ui_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(_ui_dir / "assets")), name="ui-assets")


@app.get("/{path:path}", include_in_schema=False)
async def spa_fallback(path: str) -> FileResponse:
    """Serve the React SPA for all non-API routes."""
    index = _ui_dir / "index.html"
    if not index.exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="UI not built")
    return FileResponse(str(index))


@app.get("/sw.js", include_in_schema=False)
async def service_worker() -> FileResponse:
    """
    Serve the service worker from the root path.
    Required so the SW scope covers the entire app (not just /static/).
    """
    return FileResponse(
        str(_static_dir / "sw.js"),
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/"},
    )


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "modules": len(registry.list_modules()),
    }
