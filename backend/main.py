"""
main.py — ForensiWipe FastAPI application entry point.

Mounts all API routers and configures:
  - CORS (frontend origin from settings)
  - Structured JSON logging
  - WebSocket progress endpoint
  - OpenAPI metadata
  - Lifespan startup/shutdown hooks

The backend is the security boundary. Route handlers never execute shell
commands directly — all logic lives in module services.
"""

from __future__ import annotations

import logging
import logging.config
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.core.config import get_settings
from backend.core.events import lifespan


# ── Logging setup ─────────────────────────────────────────────────────────────
def _configure_logging(debug: bool) -> None:
    level = "DEBUG" if debug else "INFO"
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "structured": {
                "format": "%(asctime)s %(levelname)-8s %(name)-40s %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "structured",
            }
        },
        "root": {"level": level, "handlers": ["console"]},
        # Silence noisy third-party loggers
        "loggers": {
            "uvicorn.access": {"level": "WARNING"},
            "aiosqlite": {"level": "WARNING"},
        },
    })


settings = get_settings()
_configure_logging(settings.debug)
logger = logging.getLogger("forensiwipe.main")


# ── Application factory ────────────────────────────────────────────────────────
app = FastAPI(
    title="ForensiWipe",
    description=(
        "Integrated Secure Data Erasure and Advanced File Recovery Tool\n\n"
        "**DEMONSTRATION SAFE MODE** — Only loopback disk images are writable.\n\n"
        "SIH 2026 — PS 26149 | Organisation: NTRO | Theme: Cybersecurity"
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "system",    "description": "Application status and safety state"},
        {"name": "devices",   "description": "Storage device discovery"},
        {"name": "erase",     "description": "Secure drive erasure (Module 1)"},
        {"name": "carve",     "description": "Forensic file carving and recovery (Module 3)"},
        {"name": "fileerase", "description": "Secure file and folder erasure (Module 2)"},
        {"name": "operations","description": "Operation lifecycle and progress"},
        {"name": "audit",     "description": "Tamper-evident hash-chain audit log"},
    ],
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
from backend.api import devices, erase, operations, audit as audit_router, system, ws, carve as carve_router, fileerase as fileerase_router, reports as reports_router

app.include_router(system.router,           prefix="/api",                tags=["system"])
app.include_router(devices.router,          prefix="/api/devices",        tags=["devices"])
app.include_router(erase.router,            prefix="/api/erase",          tags=["erase"])
app.include_router(operations.router,       prefix="/api/operations",     tags=["operations"])
app.include_router(audit_router.router,     prefix="/api/audit",          tags=["audit"])
app.include_router(carve_router.router,     prefix="/api/carve",          tags=["carve"])
app.include_router(fileerase_router.router, prefix="/api/fileerase",      tags=["fileerase"])
app.include_router(reports_router.router,   prefix="/api/reports",        tags=["reports"])
app.include_router(ws.router,               prefix="/ws",                 tags=["websocket"])

logger.info(
    "forensiwipe_app_ready safe_mode=%s version=%s",
    settings.safe_mode,
    settings.app_version,
)
