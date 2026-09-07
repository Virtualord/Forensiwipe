"""
fileerase/patterns.py — Overwrite patterns for file-level erasure.

Same honest labelling as the drive-erase module:
  - Zero fill:  single-pass 0x00
  - Random:     single-pass PRNG
  - DoD 3-pass: 0x00 → 0xFF → random (historical, not current NIST recommendation)

Write block size is smaller than the drive engine because we are operating
on individual files, not block devices.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

WRITE_BLOCK = 64 * 1024   # 64 KB per write for file-level operations


def _zero_chunks(size: int) -> Generator[bytes, None, None]:
    block = bytes(WRITE_BLOCK)
    remaining = size
    while remaining > 0:
        n = min(WRITE_BLOCK, remaining)
        yield block[:n]
        remaining -= n


def _random_chunks(size: int) -> Generator[bytes, None, None]:
    remaining = size
    while remaining > 0:
        n = min(WRITE_BLOCK, remaining)
        yield os.urandom(n)
        remaining -= n


def _ff_chunks(size: int) -> Generator[bytes, None, None]:
    block = b"\xFF" * WRITE_BLOCK
    remaining = size
    while remaining > 0:
        n = min(WRITE_BLOCK, remaining)
        yield block[:n]
        remaining -= n


def overwrite_file(path: str, standard: str) -> tuple[int, int]:
    """
    Overwrite the file at `path` according to `standard`.

    Parameters
    ----------
    path:     Absolute path to the file to overwrite (must already exist).
    standard: "ZERO_FILL" | "RANDOM_FILL" | "DOD_3PASS"

    Returns
    -------
    (bytes_written, passes_completed)

    Raises OSError on write failure — caller must handle and mark FAILED.

    The file descriptor is opened with O_SYNC (Linux) to reduce OS caching.
    After all passes, fsync() is called.
    """
    size = os.path.getsize(path)
    if size == 0:
        return 0, 0

    passes_spec: list[Generator[bytes, None, None]]
    if standard == "ZERO_FILL":
        passes_spec = [_zero_chunks(size)]
    elif standard == "RANDOM_FILL":
        passes_spec = [_random_chunks(size)]
    elif standard == "DOD_3PASS":
        passes_spec = [
            _zero_chunks(size),
            _ff_chunks(size),
            _random_chunks(size),
        ]
    else:
        passes_spec = [_zero_chunks(size)]

    total_written = 0
    flags = os.O_WRONLY
    if hasattr(os, "O_SYNC"):
        flags |= os.O_SYNC

    fd = os.open(path, flags)
    try:
        for gen in passes_spec:
            os.lseek(fd, 0, os.SEEK_SET)
            for chunk in gen:
                os.write(fd, chunk)
                total_written += len(chunk)
        os.fsync(fd)
    finally:
        os.close(fd)

    return total_written, len(passes_spec)


def collect_files(paths: list[str], recursive: bool, glob_pattern: str | None) -> list[str]:
    """
    Expand a list of paths (files and/or directories) into a flat list
    of individual file paths.

    Processing order: files first, then directories (deepest first).
    This ensures directory contents are erased before the directory itself
    is unlinkable.
    """
    files: list[str] = []
    dirs:  list[str] = []

    import glob as glob_mod
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        # Do not follow a selected symlink.  Overwriting a symlink would modify
        # its referent, which may be outside the operator's reviewed selection.
        if path.is_symlink():
            continue
        if path.is_file():
            files.append(str(path.resolve()))
        elif path.is_dir() and recursive:
            dirs.append(str(path.resolve()))

    # Expand directories
    for d in dirs:
        dp = Path(d)
        pattern = glob_pattern or "**/*"
        for match in sorted(dp.glob(pattern)):
            if match.is_file() and not match.is_symlink():
                files.append(str(match.resolve()))

    # De-duplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            result.append(f)

    return result


def selected_directories(paths: list[str], recursive: bool) -> list[Path]:
    """Return selected directories, deepest first, without following symlinks."""
    if not recursive:
        return []
    directories: list[Path] = []
    for raw in paths:
        root = Path(raw)
        if not root.is_dir() or root.is_symlink():
            continue
        directories.append(root.resolve())
        # Include child directories so that a recursive selection is removed
        # from the leaves upward. rglob does not follow directory symlinks.
        directories.extend(
            child.resolve()
            for child in root.rglob("*")
            if child.is_dir() and not child.is_symlink()
        )
    return sorted(set(directories), key=lambda item: len(item.parts), reverse=True)
