"""
carve/signatures.py — File type signatures (magic bytes) for header/footer matching.

Each FileSignature describes:
  - header:   bytes that appear at the start of a valid file
  - footers:  list of bytes patterns that mark the end (may be empty)
  - max_size: hard cap on how far to scan forward from header for footer
  - extension / mime for output naming

IMPORTANT: Header/footer matching alone is not sufficient for recovery.
Every candidate must pass through the structural validator (validators.py)
to earn a meaningful confidence score.

We do NOT call every PK\x03\x04 structure an Office file without checking
its internal ZIP directory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.carve.models import CarvedFileType


@dataclass(frozen=True)
class FileSignature:
    file_type:  CarvedFileType
    header:     bytes
    footers:    tuple[bytes, ...]        # may be empty for open-ended types
    max_size:   int                      # bytes — hard scan limit from header
    extension:  str
    mime:       str
    # Minimum plausible size in bytes (candidates smaller than this are rejected)
    min_size:   int = 64
    # Whether to attempt decoder validation (requires Pillow, pikepdf, etc.)
    decoder_available: bool = False


# ── Signature registry ────────────────────────────────────────────────────────

SIGNATURES: list[FileSignature] = [

    FileSignature(
        file_type  = CarvedFileType.JPEG,
        header     = b"\xFF\xD8\xFF",
        footers    = (b"\xFF\xD9",),
        max_size   = 30 * 1024 * 1024,   # 30 MB — generous for high-res JPEG
        extension  = ".jpg",
        mime       = "image/jpeg",
        min_size   = 64,                  # allow minimal valid JPEGs
        decoder_available = True,
    ),

    FileSignature(
        file_type  = CarvedFileType.PNG,
        header     = b"\x89PNG\r\n\x1a\n",
        footers    = (b"\x00\x00\x00\x00IEND\xaeB`\x82",),
        max_size   = 30 * 1024 * 1024,
        extension  = ".png",
        mime       = "image/png",
        min_size   = 67,
        decoder_available = True,
    ),

    FileSignature(
        file_type  = CarvedFileType.PDF,
        header     = b"%PDF-",
        footers    = (b"%%EOF",),
        max_size   = 100 * 1024 * 1024,  # 100 MB — PDFs can be large
        extension  = ".pdf",
        mime       = "application/pdf",
        min_size   = 64,
        decoder_available = False,
    ),

    # ZIP-based formats — all share the local file header signature.
    # We detect ZIP first; the validator promotes to DOCX/XLSX/PPTX if
    # the internal structure matches. We never blindly call a PK file an
    # Office document.
    FileSignature(
        file_type  = CarvedFileType.ZIP,
        header     = b"PK\x03\x04",
        footers    = (b"PK\x05\x06",),  # End of central directory record
        max_size   = 50 * 1024 * 1024,
        extension  = ".zip",
        mime       = "application/zip",
        min_size   = 22,
        decoder_available = False,
    ),
]


# ── Lookup helpers ────────────────────────────────────────────────────────────

def get_signature(file_type: CarvedFileType) -> Optional[FileSignature]:
    """Return the FileSignature for a given type, or None."""
    for sig in SIGNATURES:
        if sig.file_type == file_type:
            return sig
    return None


def match_header(data: bytes, offset: int) -> Optional[FileSignature]:
    """
    Test whether any known signature header starts at `offset` in `data`.

    Returns the matching FileSignature or None.
    Only checks that the header bytes are present — no structural validation.
    """
    for sig in SIGNATURES:
        end = offset + len(sig.header)
        if end <= len(data) and data[offset:end] == sig.header:
            return sig
    return None


def find_footer(data: bytes, sig: FileSignature, start: int, limit: int) -> int:
    """
    Search for the best (latest) footer of `sig` starting from `start`,
    scanning at most `limit` bytes.

    Returns the offset of the END of the footer (exclusive), or -1 if not found.

    For JPEG we want the last FF D9 (some JPEGs have multiple EOI markers from
    progressive encoding or embedded thumbnails). We therefore scan forward and
    return the last match within limit.
    """
    search_end = min(start + limit, len(data))
    last_pos = -1

    for footer in sig.footers:
        flen = len(footer)
        pos = start
        while pos < search_end - flen + 1:
            idx = data.find(footer, pos, search_end)
            if idx == -1:
                break
            # For JPEG, keep scanning for the last EOI
            if sig.file_type == CarvedFileType.JPEG:
                last_pos = idx + flen
                pos = idx + 1
            else:
                # For all others, first match is canonical end
                return idx + flen

    return last_pos


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
