"""
core/events.py — Application startup / shutdown event handlers.

Registered with FastAPI's lifespan context manager in main.py.
Responsible for initialising shared resources (DB, directories, etc.)
in the correct order at startup.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

logger = logging.getLogger("forensiwipe.events")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context — replaces deprecated on_event handlers."""
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("forensiwipe_startup begin")

    # Import here to avoid circular imports at module load time.
    from backend.core.config import get_settings
    from backend.audit.database import init_db

    settings = get_settings()
    settings.ensure_directories()

    logger.info(
        "config loaded safe_mode=%s physical_erase=%s",
        settings.safe_mode,
        settings.physical_erase_enabled,
    )

    await init_db()
    logger.info("audit_db_initialised path=%s", settings.audit_db_path)

    if settings.safe_mode:
        logger.info(
            "SAFE_MODE=true — only loopback targets inside %s are permitted",
            settings.safe_demo_dir,
        )
    else:
        logger.warning(
            "SAFE_MODE=false — physical targets may be accessible; "
            "physical_erase_enabled=%s",
            settings.physical_erase_enabled,
        )

    logger.info("forensiwipe_startup complete")

    yield  # ← application runs here

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("forensiwipe_shutdown")
