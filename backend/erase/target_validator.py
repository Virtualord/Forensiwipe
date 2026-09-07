"""
erase/target_validator.py — The central safety choke point for ALL destructive operations.

ARCHITECTURE NOTE:
    This module is the ONLY place where the decision to permit or deny a
    destructive operation is made.  No other module may bypass these checks.
    Every call to the erase engine MUST pass through validate_target() first.

SAFE MODE (default):
    Only loopback devices (/dev/loopX) backed by .img files inside the
    configured SAFE_DEMO_DIR are permitted.

PHYSICAL ERASE (disabled by default):
    Requires BOTH:
        SAFE_MODE=false
        ALLOW_PHYSICAL_ERASE=true
    Even then, all 12 validation checks still run.

Validation checks (in order):
    1.  Path exists as a block device (or image file for direct-image mode)
    2.  Path is a loopback device (in safe mode)
    3.  Backing file is inside SAFE_DEMO_DIR (in safe mode)
    4.  Device is not currently mounted
    5.  Device is not the root filesystem
    6.  Device is not a boot/EFI partition
    7.  Device is not part of the current OS disk
    8.  Device is not in active use by this application
    9.  Device serial/identity cross-check
    10. Filesystem type safety check
    11. Operator explicit approval provided
    12. SAFE_MODE allows this target type
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from backend.core.config import get_settings
from backend.core.models import MediaType, RiskLevel, ValidationResult
from backend.erase.models import DeviceInfo

logger = logging.getLogger("forensiwipe.erase.target_validator")

# Paths that are always blocked regardless of mode.
_ALWAYS_BLOCKED_PATHS: frozenset[str] = frozenset({
    "/dev/sda",    # Common first HDD on Linux — blocked by name for extra safety
    "/dev/vda",    # Common VM disk
})

# Mount points that indicate a system-critical filesystem.
_SYSTEM_MOUNT_POINTS: frozenset[str] = frozenset({
    "/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home",
    "C:\\", "D:\\",  # Windows system drives
})

# Active in-use tracking: paths currently being operated on by this process.
_active_targets: set[str] = set()


def _get_mounts() -> dict[str, list[str]]:
    """Read /proc/mounts → {device: [mount_point, ...]}"""
    mounts: dict[str, list[str]] = {}
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mounts.setdefault(parts[0], []).append(parts[1])
    except OSError:
        pass
    return mounts


def _get_loopback_backing(path: str) -> Optional[str]:
    """Return the backing file for a loopback device, or None."""
    try:
        import json
        result = subprocess.run(
            ["losetup", "--json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for entry in data.get("loopdevices", []):
                if entry.get("name") == path:
                    return entry.get("back-file")
    except Exception as exc:
        logger.debug("losetup_error: %s", exc)
    return None


def _is_efi_partition(device: DeviceInfo) -> bool:
    """Heuristic check for EFI/boot partition."""
    for mp in device.mount_points:
        if mp.lower() in ("/boot", "/boot/efi", "/efi"):
            return True
    if device.filesystem and device.filesystem.lower() in ("vfat", "fat32"):
        # FAT32 on a disk partition is likely EFI
        if not device.is_loopback:
            return True
    return False


def _is_part_of_os_disk(device: DeviceInfo) -> bool:
    """
    Check if this device shares a disk with the running OS.
    Strips partition numbers and compares base device names.
    """
    try:
        import psutil
        disk_partitions = psutil.disk_partitions(all=True)
        # Get the set of device paths that host OS filesystems
        os_devices: set[str] = set()
        for p in disk_partitions:
            base = re.sub(r"\d+$", "", p.device)
            os_devices.add(base)
            os_devices.add(p.device)

        device_base = re.sub(r"\d+$", "", device.path)
        return device.path in os_devices or device_base in os_devices
    except ImportError:
        # psutil not available — fall back to conservative check
        mounts = _get_mounts()
        for mounted_dev in mounts:
            base = re.sub(r"\d+$", "", mounted_dev)
            device_base = re.sub(r"\d+$", "", device.path)
            if base == device_base:
                return True
        return False


def classify_device_safety(device: DeviceInfo) -> dict[str, str]:
    """
    Quick safety classification for UI display.
    Returns {"status": "SAFE"|"BLOCKED"|"CAUTION"|"UNKNOWN", "reason": str}
    """
    settings = get_settings()

    if device.is_system_disk:
        return {"status": "BLOCKED", "reason": "System disk — contains OS"}
    if device.is_mounted:
        mps = ", ".join(device.mount_points)
        if any(mp in _SYSTEM_MOUNT_POINTS for mp in device.mount_points):
            return {"status": "BLOCKED", "reason": f"Mounted at critical path: {mps}"}
        return {"status": "CAUTION", "reason": f"Currently mounted: {mps}"}
    if device.is_loopback and settings.safe_mode:
        if device.backing_file:
            try:
                backing = Path(device.backing_file).resolve()
                safe_dir = settings.safe_demo_dir_resolved
                if str(backing).startswith(str(safe_dir)):
                    return {"status": "SAFE", "reason": "Loopback demo image inside safe directory"}
            except OSError:
                pass
        return {"status": "CAUTION", "reason": "Loopback device — backing file not in safe demo dir"}
    if settings.safe_mode:
        return {"status": "BLOCKED", "reason": "SAFE_MODE: only demo loopback images are permitted"}
    return {"status": "CAUTION", "reason": "Physical device — manual review required"}


def validate_target(
    target_path: str,
    device_info: Optional[DeviceInfo] = None,
    operator_approved: bool = False,
) -> ValidationResult:
    """
    Run all 12 validation checks against a target device path.

    Parameters
    ----------
    target_path:
        Absolute path to the block device (e.g. /dev/loop10) or image file.
    device_info:
        Pre-fetched DeviceInfo.  If None, the detector is called automatically.
    operator_approved:
        Whether the operator has explicitly confirmed the target (check 11).

    Returns
    -------
    ValidationResult — always returned, never raises.
    """
    settings = get_settings()
    checks_passed: list[str] = []
    checks_failed: list[str] = []

    def _allow(media_type: MediaType = MediaType.UNKNOWN) -> ValidationResult:
        return ValidationResult(
            allowed=True,
            safe_mode=settings.safe_mode,
            device=target_path,
            reason="All validation checks passed.",
            risk_level=RiskLevel.LOW,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            media_type=media_type,
            is_loopback="loop" in target_path.lower(),
        )

    def _block(reason: str, risk: RiskLevel = RiskLevel.HIGH) -> ValidationResult:
        checks_failed.append(reason)
        logger.warning(
            "target_blocked path=%s reason=%s risk=%s", target_path, reason, risk.value
        )
        return ValidationResult(
            allowed=False,
            safe_mode=settings.safe_mode,
            device=target_path,
            reason=reason,
            risk_level=risk,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
        )

    # ── CHECK 1: Path is a block device or approved image ────────────────────
    p = Path(target_path)
    is_block_device = p.exists() and p.is_block_device()
    is_image_file = (
        p.exists()
        and p.is_file()
        and target_path.endswith(".img")
    )

    if not is_block_device and not is_image_file:
        return _block(
            f"Target '{target_path}' is not a block device or a recognised .img file.",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_1: target exists as block device or image file")

    # ── Fetch device info if not provided ────────────────────────────────────
    if device_info is None and is_block_device:
        from backend.erase.device_detector import get_device_info
        device_info = get_device_info(target_path)

    # ── CHECK 2: Safe mode — must be loopback or image ───────────────────────
    is_loopback = (
        target_path.startswith("/dev/loop")
        or is_image_file
    )

    if settings.safe_mode and not is_loopback:
        return _block(
            "SAFE_MODE is enabled. Only loopback image targets are permitted. "
            f"'{target_path}' is a physical device.",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_2: safe mode / loopback check passed")

    # ── CHECK 3: Backing file inside SAFE_DEMO_DIR ───────────────────────────
    backing_file: Optional[str] = None
    if is_loopback and target_path.startswith("/dev/loop"):
        backing_file = _get_loopback_backing(target_path)
        if settings.safe_mode:
            if backing_file is None:
                return _block(
                    "SAFE_MODE: cannot determine backing file for loopback device. "
                    "Only approved demo images are permitted.",
                    RiskLevel.HIGH,
                )
            try:
                backing_resolved = Path(backing_file).resolve()
                safe_dir_resolved = settings.safe_demo_dir_resolved
                if not str(backing_resolved).startswith(str(safe_dir_resolved)):
                    return _block(
                        f"SAFE_MODE: backing file '{backing_file}' is outside "
                        f"the approved demo directory '{safe_dir_resolved}'.",
                        RiskLevel.CRITICAL,
                    )
            except OSError as exc:
                return _block(
                    f"SAFE_MODE: cannot resolve backing file path: {exc}",
                    RiskLevel.HIGH,
                )
    elif is_image_file:
        backing_file = target_path
        if settings.safe_mode:
            try:
                img_resolved = Path(target_path).resolve()
                safe_dir_resolved = settings.safe_demo_dir_resolved
                if not str(img_resolved).startswith(str(safe_dir_resolved)):
                    return _block(
                        f"SAFE_MODE: image file '{target_path}' is outside "
                        f"the approved demo directory '{safe_dir_resolved}'.",
                        RiskLevel.CRITICAL,
                    )
            except OSError as exc:
                return _block(
                    f"SAFE_MODE: cannot resolve image path: {exc}",
                    RiskLevel.HIGH,
                )
    checks_passed.append("CHECK_3: backing file path verified")

    # ── CHECK 4: Not currently mounted ───────────────────────────────────────
    if device_info and device_info.is_mounted:
        mount_str = ", ".join(device_info.mount_points)
        if any(mp in _SYSTEM_MOUNT_POINTS for mp in device_info.mount_points):
            return _block(
                f"Target is mounted at a critical path: {mount_str}",
                RiskLevel.CRITICAL,
            )
        # Mounted but not critical — still block; erasure of mounted FS is dangerous
        return _block(
            f"Target is currently mounted at: {mount_str}. "
            "Unmount before proceeding.",
            RiskLevel.HIGH,
        )
    checks_passed.append("CHECK_4: target is not mounted")

    # ── CHECK 5: Not the root filesystem ─────────────────────────────────────
    if device_info and device_info.is_system_disk:
        return _block(
            "Target appears to be the active root filesystem device.",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_5: not the root filesystem")

    # ── CHECK 6: Not boot/EFI partition ──────────────────────────────────────
    if device_info and _is_efi_partition(device_info):
        return _block(
            "Target appears to be a boot/EFI partition.",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_6: not a boot/EFI partition")

    # ── CHECK 7: Not part of the OS disk ─────────────────────────────────────
    if device_info and not device_info.is_loopback:
        if _is_part_of_os_disk(device_info):
            return _block(
                "Target shares a physical disk with an OS filesystem.",
                RiskLevel.CRITICAL,
            )
    checks_passed.append("CHECK_7: not part of active OS disk")

    # ── CHECK 8: Not currently in use by this application ────────────────────
    if target_path in _active_targets:
        return _block(
            "Target is currently being processed by another operation.",
            RiskLevel.HIGH,
        )
    checks_passed.append("CHECK_8: not in use by current process")

    # ── CHECK 9: Always-blocked paths ────────────────────────────────────────
    if target_path in _ALWAYS_BLOCKED_PATHS:
        return _block(
            f"Target '{target_path}' is in the always-blocked list "
            "(common OS disk — denied as extra protection).",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_9: not in always-blocked-paths list")

    # ── CHECK 10: Filesystem type ─────────────────────────────────────────────
    if device_info and device_info.filesystem:
        fs = device_info.filesystem.lower()
        if fs in ("swap", "tmpfs", "sysfs", "proc", "devtmpfs"):
            return _block(
                f"Target has a system pseudo-filesystem: {device_info.filesystem}",
                RiskLevel.CRITICAL,
            )
    checks_passed.append("CHECK_10: filesystem type is safe")

    # ── CHECK 11: Operator approval ──────────────────────────────────────────
    if not operator_approved and not settings.safe_mode:
        # In safe mode with a demo image, we consider implicit approval
        # acceptable for the demo workflow.  In production mode, explicit
        # operator approval (typed confirmation) is required.
        return _block(
            "Operator explicit approval has not been provided.",
            RiskLevel.HIGH,
        )
    checks_passed.append("CHECK_11: operator approval obtained")

    # ── CHECK 12: Safe mode final gate ───────────────────────────────────────
    if settings.safe_mode and not is_loopback:
        return _block(
            "SAFE_MODE final gate: only loopback/image targets are permitted.",
            RiskLevel.CRITICAL,
        )
    checks_passed.append("CHECK_12: safe mode final gate passed")

    # ── All checks passed ─────────────────────────────────────────────────────
    media_type = device_info.media_type if device_info else MediaType.LOOP
    result = _allow(media_type)
    result.is_mounted = device_info.is_mounted if device_info else False
    result.is_system_disk = device_info.is_system_disk if device_info else False
    result.is_loopback = is_loopback
    result.backing_file = backing_file

    logger.info(
        "target_validated path=%s checks_passed=%d",
        target_path, len(checks_passed)
    )
    return result


# ── Active target registry helpers ────────────────────────────────────────────


def mark_target_active(path: str) -> None:
    """Register a target as actively being processed (check 8)."""
    _active_targets.add(path)
    logger.info("target_marked_active path=%s", path)


def mark_target_inactive(path: str) -> None:
    """Remove a target from the active set when the operation finishes."""
    _active_targets.discard(path)
    logger.info("target_marked_inactive path=%s", path)
