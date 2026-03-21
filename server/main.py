"""
Discoverykastle — Central Server
FastAPI application entry point.
"""

from __future__ import annotations

import logging

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.database import init_db
from server.modules.loader import load_all
from server.modules.registry import registry
from server.api.alerts import router as alerts_router
from server.api.inventory import router as inventory_router
from server.api.topology import router as topology_router
from server.api.netbox import router as netbox_router
from server.api.modules import router as modules_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dkastle.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Discoverykastle server starting up...")

    # Initialize DB tables
    await init_db()
    logger.info("Database initialized.")

    # Load all modules (built-in + entry points + ./modules/ directory)
    load_all()
    await registry.setup_all()
    logger.info("Modules loaded: %s", [m["name"] for m in registry.list_modules()])

    yield

    logger.info("Discoverykastle server shutting down...")
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

# Routers
app.include_router(alerts_router)
app.include_router(inventory_router)
app.include_router(topology_router)
app.include_router(netbox_router)
app.include_router(modules_router)


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "modules": len(registry.list_modules()),
    }
