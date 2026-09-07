"""
erase/platform/linux.py — Linux-specific device discovery and metadata collection.

Uses:
- lsblk (JSON output)  — primary source
- /sys/block           — removable, rotational flags
- /proc/mounts         — mount status
- psutil               — additional disk info

Never issues destructive commands.  Read-only discovery only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from backend.core.models import MediaType
from backend.erase.models import DeviceInfo

logger = logging.getLogger("forensiwipe.erase.platform.linux")


def _run(cmd: list[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logger.debug("command_failed cmd=%s stderr=%s", cmd, result.stderr.strip())
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("command_error cmd=%s exc=%s", cmd, exc)
        return None


def _human_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} PB"


def _get_mounts() -> dict[str, list[str]]:
    """Return mapping: device_path → [mount_point, ...]"""
    mounts: dict[str, list[str]] = {}
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    dev = parts[0]
                    mount = parts[1]
                    mounts.setdefault(dev, []).append(mount)
    except OSError:
        pass
    return mounts


def _get_root_device() -> Optional[str]:
    """Return the device that backs the root filesystem '/'."""
    mounts = _get_mounts()
    for dev, points in mounts.items():
        if "/" in points:
            # Strip partition number to get the base device.
            return re.sub(r"\d+$", "", dev)
    return None


def _is_removable(name: str) -> bool:
    """Check /sys/block/<name>/removable."""
    try:
        p = Path(f"/sys/block/{name}/removable")
        return p.read_text().strip() == "1"
    except OSError:
        return False


def _is_rotational(name: str) -> bool:
    """Check /sys/block/<name>/queue/rotational."""
    try:
        p = Path(f"/sys/block/{name}/queue/rotational")
        return p.read_text().strip() == "1"
    except OSError:
        return True  # Assume rotational (safer default for HDD)


def _get_loopback_backing(path: str) -> Optional[str]:
    """For a loopback device, return the backing file path."""
    output = _run(["losetup", "--json"])
    if not output:
        return None
    try:
        data = json.loads(output)
        for entry in data.get("loopdevices", []):
            if entry.get("name") == path:
                return entry.get("back-file")
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _detect_media_type(name: str, path: str) -> MediaType:
    """Detect media type from sysfs and device path."""
    if path.startswith("/dev/loop"):
        return MediaType.LOOP
    if "nvme" in name:
        return MediaType.NVME
    if name.startswith("sd") and _is_removable(name):
        return MediaType.USB
    if name.startswith("sd"):
        return MediaType.HDD if _is_rotational(name) else MediaType.SSD
    if name.startswith("hd"):
        return MediaType.HDD
    if name.startswith("mmcblk"):
        return MediaType.USB  # SD card / eMMC treated as removable
    return MediaType.UNKNOWN


def _parse_lsblk_device(entry: dict, mounts: dict[str, list[str]], root_device: Optional[str]) -> DeviceInfo:
    """Build a DeviceInfo from one lsblk JSON entry."""
    path = entry.get("path", "") or entry.get("name", "")
    if not path.startswith("/dev/"):
        path = f"/dev/{path}"

    name = entry.get("name", Path(path).name)
    size_bytes = int(entry.get("size", 0) or 0)

    # Mount points from lsblk entry or /proc/mounts
    lsblk_mountpoint = entry.get("mountpoint") or entry.get("mountpoints", [])
    if isinstance(lsblk_mountpoint, str) and lsblk_mountpoint:
        mount_points = [lsblk_mountpoint]
    elif isinstance(lsblk_mountpoint, list):
        mount_points = [m for m in lsblk_mountpoint if m]
    else:
        mount_points = mounts.get(path, [])

    is_mounted = bool(mount_points)
    is_loopback = path.startswith("/dev/loop")
    backing_file: Optional[str] = None

    if is_loopback:
        backing_file = _get_loopback_backing(path)

    media_type = _detect_media_type(name, path)

    # System disk: device is the same as the root device (or a partition of it)
    is_system = False
    if root_device:
        base = re.sub(r"\d+$", "", path)
        is_system = path == root_device or base == root_device or "/" in mount_points

    return DeviceInfo(
        path=path,
        name=name,
        model=entry.get("model"),
        serial=entry.get("serial"),
        size_bytes=size_bytes,
        size_human=_human_size(size_bytes),
        media_type=media_type,
        is_removable=entry.get("rm", False) or _is_removable(name),
        is_system_disk=is_system,
        is_loopback=is_loopback,
        is_mounted=is_mounted,
        mount_points=mount_points,
        filesystem=entry.get("fstype"),
        backing_file=backing_file,
        safety_status="UNKNOWN",
        safety_reason="",
    )


def discover_devices() -> list[DeviceInfo]:
    """
    Enumerate all block devices on Linux using lsblk.

    Returns a list of DeviceInfo for top-level devices only
    (partitions are included in mount data but not listed separately
    at this stage — the drive-erase module targets whole devices).
    """
    output = _run(["lsblk", "-J", "-b", "-o",
                   "NAME,PATH,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINT,RM,ROTA,TYPE"])
    if not output:
        logger.warning("lsblk_failed — returning empty device list")
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        logger.error("lsblk_json_parse_error: %s", exc)
        return []

    mounts = _get_mounts()
    root_device = _get_root_device()

    devices: list[DeviceInfo] = []
    for entry in data.get("blockdevices", []):
        # Only process disk-level devices (type == "disk" or "loop").
        dev_type = entry.get("type", "")
        if dev_type not in ("disk", "loop"):
            continue
        try:
            info = _parse_lsblk_device(entry, mounts, root_device)
            devices.append(info)
        except Exception as exc:
            logger.warning("device_parse_error name=%s exc=%s", entry.get("name"), exc)

    logger.info("discovered %d devices", len(devices))
    return devices


def get_device_info(path: str) -> Optional[DeviceInfo]:
    """Return DeviceInfo for a specific device path, or None if not found."""
    for device in discover_devices():
        if device.path == path:
            return device
    return None
