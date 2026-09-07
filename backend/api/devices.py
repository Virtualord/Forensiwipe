"""
api/devices.py — Storage device discovery endpoints.

GET /api/devices          — List all detected devices with safety annotations
GET /api/devices/{path}   — Get info for a specific device (path is URL-encoded)
"""

from __future__ import annotations

import logging
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException

from backend.erase.device_detector import discover_devices, get_device_info
from backend.erase.models import DeviceInfo

router = APIRouter()
logger = logging.getLogger("forensiwipe.api.devices")


@router.get("", response_model=list[DeviceInfo], summary="List all storage devices")
async def list_devices() -> list[DeviceInfo]:
    """
    Enumerate all storage devices on the current platform.

    Each device includes:
    - Path, model, serial, size
    - Media type (HDD / SSD / NVMe / USB / LOOP)
    - Mount status
    - System-disk flag
    - Safety status (SAFE / BLOCKED / CAUTION / UNKNOWN)

    On Windows, device listing is not yet implemented.
    """
    try:
        devices = discover_devices()
        logger.info("devices_listed count=%d", len(devices))
        return devices
    except Exception as exc:
        logger.exception("device_list_error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Device discovery failed: {exc}")


@router.get("/{device_path:path}", response_model=DeviceInfo, summary="Get specific device info")
async def get_device(device_path: str) -> DeviceInfo:
    """
    Return device info for a specific path (e.g. `/dev/loop10`).

    The path parameter is URL-encoded — `/dev/loop10` → `%2Fdev%2Floop10`.
    """
    path = unquote(device_path)
    if not path.startswith("/"):
        path = "/" + path

    device = get_device_info(path)
    if device is None:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{path}' not found or not accessible.",
        )
    return device
