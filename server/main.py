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
from server.api.inventory import router as inventory_router
from server.api.topology import router as topology_router
from server.api.netbox import router as netbox_router
from server.api.modules import router as modules_router
from server.api.setup import router as setup_router
from server.api.webpush import router as webpush_router
from server.api.data import router as data_router
from server.middleware.setup_guard import SetupGuardMiddleware

# Must be called before any other module creates a logger.
# Configures console + rotating JSON file + Graylog (if configured).
setup_logging()
logger = logging.getLogger("dkastle.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    import time
    t0 = time.monotonic()
    logger.info("Discoverykastle server starting up...", extra={"event": "startup"})

    await init_db()
    logger.info("Database initialized.", extra={"event": "db_init"})

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

    yield

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
app.include_router(webpush_router)
app.include_router(alerts_router)
app.include_router(inventory_router)
app.include_router(topology_router)
app.include_router(netbox_router)
app.include_router(modules_router)
app.include_router(data_router)


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
