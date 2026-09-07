"""
erase/platform/windows.py — Windows device discovery stub.

Full Windows implementation is deferred.  This stub allows the application
to start on Windows without import errors and provides a clear capability
boundary consistent with SCOPE.md.

Windows-specific capabilities when this is fully implemented:
- PowerShell / CIM queries for disk enumeration
- WMI-based disk/partition identification
- Get-Disk / Get-Partition / Get-Volume
- Windows drive letter → physical disk mapping
"""

from __future__ import annotations

import logging
from typing import Optional

from backend.erase.models import DeviceInfo

logger = logging.getLogger("forensiwipe.erase.platform.windows")

_WINDOWS_STUB_NOTE = (
    "Windows device discovery is not fully implemented in this prototype. "
    "Device listing is unavailable on Windows. "
    "Carving, audit, file-erase, and reporting modules function on Windows."
)


def discover_devices() -> list[DeviceInfo]:
    """
    Windows device enumeration — not yet implemented.

    Returns an empty list and logs a capability notice.
    This is intentional: the application must not crash on Windows startup.
    """
    logger.info("windows_device_discovery: %s", _WINDOWS_STUB_NOTE)
    return []


def get_device_info(path: str) -> Optional[DeviceInfo]:
    """Not implemented on Windows."""
    logger.info("windows_get_device_info: not implemented for path=%s", path)
    return None
