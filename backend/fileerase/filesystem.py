"""
fileerase/filesystem.py — Filesystem detection and capability badge matrix.

Honest capability reporting:
  ext4   🟢 FULL    — primary target, overwrite + unlink tested
  NTFS   🟡 PARTIAL — detection/interface; advanced sanitisation limited
  APFS   🟡 STUB    — detection/interface stub only
  FAT32  ⚪ DETECT  — detection only
  exFAT  ⚪ DETECT  — detection only
  Other  ⚪ DETECT  — detection only

Filesystem journal note: We do NOT falsely claim complete journal sanitisation.
Journal entries are filesystem- and privilege-dependent. This module reports
what is detectable and flags the limitation clearly.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional

from backend.fileerase.models import FilesystemBadge, FilesystemSupport

logger = logging.getLogger("forensiwipe.fileerase.filesystem")

# ── Badge registry ────────────────────────────────────────────────────────────

FILESYSTEM_BADGES: dict[str, FilesystemBadge] = {
    "ext4": FilesystemBadge(
        name="ext4", support=FilesystemSupport.FULL, icon="🟢",
        description="Fully tested prototype support. Overwrite + unlink on ext4.",
        limitations=[
            "Filesystem journal may retain metadata about deleted files.",
            "Journal sanitisation is filesystem- and privilege-dependent.",
            "This prototype performs detection/reporting but does not claim "
            "complete journal sanitisation.",
        ],
    ),
    "ext3": FilesystemBadge(
        name="ext3", support=FilesystemSupport.FULL, icon="🟢",
        description="Treated equivalently to ext4 for overwrite operations.",
        limitations=["Same journal caveats as ext4."],
    ),
    "ext2": FilesystemBadge(
        name="ext2", support=FilesystemSupport.FULL, icon="🟢",
        description="No journaling. Overwrite + unlink supported.",
        limitations=[],
    ),
    "ntfs": FilesystemBadge(
        name="NTFS", support=FilesystemSupport.PARTIAL, icon="🟡",
        description="Detection and interface support. Advanced sanitisation limited.",
        limitations=[
            "NTFS maintains $MFT records that may persist after deletion.",
            "Alternate Data Streams (ADS) may not be fully enumerated.",
            "VSS (Volume Shadow Copies) may retain copies outside our control.",
            "Full NTFS sanitisation requires Windows-specific APIs.",
        ],
    ),
    "apfs": FilesystemBadge(
        name="APFS", support=FilesystemSupport.STUB, icon="🟡",
        description="Detection and interface stub. Not actively supported.",
        limitations=[
            "APFS uses copy-on-write semantics — overwrite may not hit original blocks.",
            "Snapshots may retain data outside the active file system.",
            "macOS-specific APIs required for full sanitisation.",
        ],
    ),
    "vfat": FilesystemBadge(
        name="FAT32/vfat", support=FilesystemSupport.DETECT, icon="⚪",
        description="Detection only. Basic overwrite attempted.",
        limitations=["No journaling, but no metadata sanitisation support."],
    ),
    "exfat": FilesystemBadge(
        name="exFAT", support=FilesystemSupport.DETECT, icon="⚪",
        description="Detection only.",
        limitations=[],
    ),
    "tmpfs": FilesystemBadge(
        name="tmpfs", support=FilesystemSupport.DETECT, icon="⚪",
        description="RAM-backed; erasure is memory-only.",
        limitations=["Data is not on persistent storage."],
    ),
    "unknown": FilesystemBadge(
        name="Unknown", support=FilesystemSupport.DETECT, icon="⚪",
        description="Filesystem type could not be determined.",
        limitations=["Proceed with caution."],
    ),
}


def get_badge(fs_type: str) -> FilesystemBadge:
    key = fs_type.lower().strip()
    return FILESYSTEM_BADGES.get(key, FILESYSTEM_BADGES["unknown"])


def all_badges() -> list[FilesystemBadge]:
    return list(FILESYSTEM_BADGES.values())


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_filesystem(path: str) -> str:
    """
    Detect the filesystem type of the partition containing `path`.

    Linux:   reads /proc/mounts and matches the mount point.
    Windows: uses os.path and a stub.
    Returns a lowercase filesystem type string e.g. "ext4", "ntfs", "unknown".
    """
    p = Path(path).resolve()

    if platform.system().lower() == "linux":
        return _detect_linux(str(p))
    elif platform.system().lower() == "windows":
        return _detect_windows(str(p))
    return "unknown"


def _detect_linux(path: str) -> str:
    """
    Walk /proc/mounts to find the deepest mount point that is a parent
    of `path`, then return its filesystem type.
    """
    best_mount = "/"
    best_fstype = "unknown"
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount_point = parts[1]
                fstype      = parts[2].lower()
                if path.startswith(mount_point) and len(mount_point) > len(best_mount):
                    best_mount  = mount_point
                    best_fstype = fstype
    except OSError as exc:
        logger.debug("proc_mounts_read_error: %s", exc)
    return best_fstype


def _detect_windows(path: str) -> str:
    """Windows filesystem detection stub."""
    drive = os.path.splitdrive(path)[0].upper()
    if drive:
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetVolumeInformationW(
                drive + "\\", None, 0, None, None, None, buf, 256
            )
            return buf.value.lower()
        except Exception:
            pass
    return "unknown"


def journal_warning(fs_type: str) -> Optional[str]:
    """
    Return a journal sanitisation warning if the filesystem has a journal.
    Returns None for non-journaled filesystems.
    """
    journaled = {"ext3", "ext4", "ntfs", "apfs", "xfs", "btrfs", "jfs"}
    if fs_type.lower() in journaled:
        return (
            f"Filesystem journal sanitisation ({fs_type}): "
            "Filesystem journals are complex and may contain historical records "
            "that normal user-space applications cannot reliably erase. "
            "This prototype performs detection and reporting where feasible "
            "but does not falsely claim complete journal sanitisation."
        )
    return None
