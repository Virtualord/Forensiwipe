"""
carve/hashing.py — SHA-256 hashing for evidence integrity and recovered files.

Two distinct hashing concerns:

1. EVIDENCE INTEGRITY
   The source disk image is hashed before and after the scan.
   If the hashes differ → CRITICAL: evidence image was modified.
   The source image must always be opened read-only.

2. RECOVERED FILE HASHING
   Every file written to the recovered/ directory receives a SHA-256.
   This hash is included in the scan result and the forensic report.
   It provides a chain of custody from recovered byte range to output file.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("forensiwipe.carve.hashing")

# Maximum file size for which we compute hash synchronously without chunking
_CHUNK_SIZE = 1024 * 1024   # 1 MB read chunks


def sha256_file(path: str) -> Optional[str]:
    """
    Compute SHA-256 of the file at `path`.

    Returns hex digest string, or None if the file is unreadable.
    Reads in chunks — safe for large evidence images.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(_CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.warning("sha256_file_error path=%s exc=%s", path, exc)
        return None


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 of an in-memory bytes object."""
    return hashlib.sha256(data).hexdigest()


def verify_evidence_integrity(
    path: str,
    expected_hash: str,
) -> tuple[bool, str]:
    """
    Re-hash the evidence file and compare against the expected hash.

    Returns (intact: bool, actual_hash: str).
    """
    actual = sha256_file(path)
    if actual is None:
        return False, ""
    intact = actual == expected_hash
    if not intact:
        logger.critical(
            "EVIDENCE_INTEGRITY_FAILURE path=%s expected=%s actual=%s",
            path, expected_hash[:16], actual[:16],
        )
    return intact, actual


def write_carved_file(
    data: bytes,
    output_dir: Path,
    index: int,
    file_type: str,
    offset: int,
    extension: str,
) -> tuple[str, str]:
    """
    Write recovered bytes to a file and compute its SHA-256.

    Filename format: {index:04d}_{type}_{offset}{ext}
    e.g.:  0001_JPEG_1048576.jpg

    Returns (output_path: str, sha256: str).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{index:04d}_{file_type}_{offset}{extension}"
    out_path  = output_dir / filename

    out_path.write_bytes(data)
    digest = sha256_bytes(data)

    logger.debug(
        "carved_file_written path=%s size=%d sha256=%s",
        out_path, len(data), digest[:16],
    )
    return str(out_path), digest
