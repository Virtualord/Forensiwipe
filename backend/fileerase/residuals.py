"""
fileerase/residuals.py — Residual trace scanner.

After a file is deleted, references to it may persist in:

Linux:
  - GTK/GNOME recent files: ~/.local/share/recently-used.xbel
  - KDE recent files:       ~/.local/share/RecentDocuments/
  - Thumbnail caches:       ~/.cache/thumbnails/  (normal/ large/ fail/)
  - Application-specific:   ~/.local/share/<app>/

Windows (stubs — detection interface, not fully implemented):
  - Recent Items:           %APPDATA%\Microsoft\Windows\Recent\
  - Jump Lists:             %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
  - Thumbnail cache:        %LOCALAPPDATA%\Microsoft\Windows\Explorer\

IMPORTANT:
  We distinguish clearly between:
    FOUND           — reference exists in the store
    REMOVED         — reference was successfully removed
    NOT_ACCESSIBLE  — store exists but we cannot read/write it
    NOT_IMPLEMENTED — platform store not yet implemented
    NOT_APPLICABLE  — not relevant for this platform/file type
    CLEAN           — store checked and no reference found

We do NOT falsely claim complete journal destruction or registry sanitisation.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from backend.fileerase.models import ResidualFinding, ResidualStatus

logger = logging.getLogger("forensiwipe.fileerase.residuals")

_IS_LINUX   = platform.system().lower() == "linux"
_IS_WINDOWS = platform.system().lower() == "windows"


# ── Public entry point ────────────────────────────────────────────────────────

def scan_residuals(file_path: str) -> list[ResidualFinding]:
    """
    Scan all known residual stores for references to `file_path`.

    Returns a list of ResidualFinding, one per store checked.
    Never raises — individual scanner failures produce NOT_ACCESSIBLE entries.
    """
    target = Path(file_path).resolve()
    findings: list[ResidualFinding] = []

    if _IS_LINUX:
        findings.extend(_scan_gtk_recent(target))
        findings.extend(_scan_thumbnails(target))
        findings.extend(_scan_kde_recent(target))
    elif _IS_WINDOWS:
        findings.extend(_scan_windows_recent(target))
        findings.extend(_scan_windows_thumbcache(target))
    else:
        findings.append(ResidualFinding(
            location="platform-residuals",
            status=ResidualStatus.NOT_IMPLEMENTED,
            detail=f"Residual scanning not implemented for platform: {platform.system()}",
        ))

    return findings


# ── Linux scanners ────────────────────────────────────────────────────────────

def _scan_gtk_recent(target: Path) -> list[ResidualFinding]:
    """
    Scan ~/.local/share/recently-used.xbel for the target file URI.
    Attempt to remove matching entries if found.
    """
    xbel_path = Path.home() / ".local" / "share" / "recently-used.xbel"
    location  = str(xbel_path)

    if not xbel_path.exists():
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.NOT_APPLICABLE,
            detail="GTK recent-files database not present.",
        )]

    target_uri = target.as_uri()   # file:///home/...

    try:
        content = xbel_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.NOT_ACCESSIBLE,
            detail="Permission denied reading recently-used.xbel",
        )]

    if target_uri not in content and str(target) not in content:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.CLEAN,
            detail="No reference found in GTK recent-files database.",
        )]

    # Found — attempt removal
    try:
        tree = ET.parse(str(xbel_path))
        root = tree.getroot()
        ns   = {"xbel": "http://www.freedesktop.org/standards/xbel"}

        # Remove bookmarks that reference the target
        removed = 0
        for bm in root.findall("bookmark"):
            href = bm.get("href", "")
            if target_uri in href or str(target) in href:
                root.remove(bm)
                removed += 1

        if removed > 0:
            tree.write(str(xbel_path), encoding="unicode", xml_declaration=True)
            return [ResidualFinding(
                location=location,
                status=ResidualStatus.REMOVED,
                detail=f"Removed {removed} bookmark(s) from GTK recent-files database.",
            )]
        else:
            return [ResidualFinding(
                location=location,
                status=ResidualStatus.FOUND,
                detail="URI found in recently-used.xbel but could not locate bookmark element.",
            )]
    except Exception as exc:
        logger.warning("gtk_recent_remove_error: %s", exc)
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.FOUND,
            detail=f"Reference found but removal failed: {exc}",
        )]


def _scan_thumbnails(target: Path) -> list[ResidualFinding]:
    """
    Check thumbnail cache directories for files whose embedded URI
    references the target. Thumbnail filenames are MD5 hashes of the URI.
    Remove matching thumbnail files.
    """
    import hashlib

    target_uri = target.as_uri()
    thumb_hash = hashlib.md5(target_uri.encode()).hexdigest()

    thumb_dirs = [
        Path.home() / ".cache" / "thumbnails" / "normal",
        Path.home() / ".cache" / "thumbnails" / "large",
        Path.home() / ".cache" / "thumbnails" / "fail",
        Path.home() / ".thumbnails" / "normal",   # older Freedesktop location
        Path.home() / ".thumbnails" / "large",
    ]

    findings: list[ResidualFinding] = []

    for thumb_dir in thumb_dirs:
        if not thumb_dir.exists():
            continue

        thumb_file = thumb_dir / f"{thumb_hash}.png"
        location   = str(thumb_file)

        if thumb_file.exists():
            try:
                thumb_file.unlink()
                findings.append(ResidualFinding(
                    location=location,
                    status=ResidualStatus.REMOVED,
                    detail=f"Thumbnail cache file removed: {thumb_file.name}",
                ))
            except PermissionError:
                findings.append(ResidualFinding(
                    location=location,
                    status=ResidualStatus.NOT_ACCESSIBLE,
                    detail="Thumbnail found but permission denied during removal.",
                ))
        else:
            findings.append(ResidualFinding(
                location=str(thumb_dir),
                status=ResidualStatus.CLEAN,
                detail=f"No thumbnail found in {thumb_dir.name}/",
            ))

    if not findings:
        findings.append(ResidualFinding(
            location="~/.cache/thumbnails",
            status=ResidualStatus.NOT_APPLICABLE,
            detail="Thumbnail cache directories do not exist.",
        ))

    return findings


def _scan_kde_recent(target: Path) -> list[ResidualFinding]:
    """
    Scan KDE recent documents (.desktop files in ~/.local/share/RecentDocuments/).
    Remove matching .desktop files.
    """
    kde_dir  = Path.home() / ".local" / "share" / "RecentDocuments"
    location = str(kde_dir)

    if not kde_dir.exists():
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.NOT_APPLICABLE,
            detail="KDE RecentDocuments directory not present.",
        )]

    target_str = str(target)
    removed    = 0
    found      = 0

    try:
        for desktop in kde_dir.glob("*.desktop"):
            try:
                text = desktop.read_text(encoding="utf-8", errors="replace")
                if target_str in text or target.name in text:
                    found += 1
                    desktop.unlink()
                    removed += 1
            except Exception:
                pass
    except PermissionError:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.NOT_ACCESSIBLE,
            detail="Permission denied scanning KDE RecentDocuments.",
        )]

    if removed > 0:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.REMOVED,
            detail=f"Removed {removed} KDE recent-document entry/entries.",
        )]
    elif found > 0:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.FOUND,
            detail=f"Found {found} references but removal failed.",
        )]
    else:
        return [ResidualFinding(
            location=location,
            status=ResidualStatus.CLEAN,
            detail="No references found in KDE RecentDocuments.",
        )]


# ── Windows stubs ─────────────────────────────────────────────────────────────

def _scan_windows_recent(target: Path) -> list[ResidualFinding]:
    recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    return [ResidualFinding(
        location=str(recent_dir),
        status=ResidualStatus.NOT_IMPLEMENTED,
        detail="Windows Recent Items scanning is not fully implemented in this prototype.",
    )]


def _scan_windows_thumbcache(target: Path) -> list[ResidualFinding]:
    thumb_dir = (Path(os.environ.get("LOCALAPPDATA", ""))
                 / "Microsoft" / "Windows" / "Explorer")
    return [ResidualFinding(
        location=str(thumb_dir),
        status=ResidualStatus.NOT_IMPLEMENTED,
        detail="Windows thumbnail cache scanning is not fully implemented in this prototype.",
    )]
