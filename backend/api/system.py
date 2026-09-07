"""
api/system.py — System status and safety state endpoints.

GET /api/status   — Current safety state, mode, version
GET /api/health   — Simple liveness check
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from backend.core.config import get_settings

router = APIRouter()


class SafetyStatus(BaseModel):
    safe_mode: bool
    physical_erase_enabled: bool
    demo_banner: str
    safe_demo_dir: str


class SystemStatus(BaseModel):
    app_name: str
    version: str
    timestamp: datetime
    safety: SafetyStatus
    operator_id: str


@router.get("/status", response_model=SystemStatus, summary="Application safety state")
async def get_status() -> SystemStatus:
    """
    Return the current application safety configuration.

    The frontend uses this on every load to show the SAFE MODE banner.
    """
    s = get_settings()
    return SystemStatus(
        app_name=s.app_name,
        version=s.app_version,
        timestamp=datetime.now(timezone.utc),
        operator_id=s.operator_id,
        safety=SafetyStatus(
            safe_mode=s.safe_mode,
            physical_erase_enabled=s.physical_erase_enabled,
            demo_banner=(
                "DEMONSTRATION SAFE MODE — Only loopback disk images are writable."
                if s.safe_mode
                else "⚠ SAFE MODE DISABLED — Physical targets may be accessible."
            ),
            safe_demo_dir=str(s.safe_demo_dir_resolved),
        ),
    )


@router.get("/health", summary="Liveness probe")
async def health_check() -> dict:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
