"""
erase/device_detector.py — Platform-agnostic device discovery entry point.

Delegates to the appropriate platform module and applies safety status
annotations after discovery so callers get a unified DeviceInfo list
regardless of OS.
"""

from __future__ import annotations

import logging
import platform
import sys
from typing import Optional

from backend.erase.models import DeviceInfo

logger = logging.getLogger("forensiwipe.erase.device_detector")


def _get_platform_module():
    """Return the correct platform implementation module."""
    system = platform.system().lower()
    if system == "linux":
        from backend.erase.platform import linux
        return linux
    elif system == "windows":
        from backend.erase.platform import windows
        return windows
    else:
        # macOS / other — no implementation yet
        logger.warning(
            "unsupported_platform system=%s — device discovery unavailable", system
        )
        return None


def discover_devices() -> list[DeviceInfo]:
    """
    Enumerate storage devices on the current platform.

    Returns annotated DeviceInfo list with safety_status filled in.
    """
    mod = _get_platform_module()
    if mod is None:
        return []

    devices = mod.discover_devices()

    # Annotate safety status using the target validator.
    # Import here to avoid circular imports at module load time.
    from backend.erase.target_validator import classify_device_safety
    for device in devices:
        safety = classify_device_safety(device)
        device.safety_status = safety["status"]
        device.safety_reason = safety["reason"]

    return devices


def get_device_info(path: str) -> Optional[DeviceInfo]:
    """Return DeviceInfo for a specific device path."""
    mod = _get_platform_module()
    if mod is None:
        return None

    device = mod.get_device_info(path)
    if device is None:
        return None

    from backend.erase.target_validator import classify_device_safety
    safety = classify_device_safety(device)
    device.safety_status = safety["status"]
    device.safety_reason = safety["reason"]
    return device
