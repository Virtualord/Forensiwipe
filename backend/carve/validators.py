"""
carve/validators.py — Structural validation for carved file candidates.

Header/footer matching is the minimum bar. This module adds real structural
checks that filter out false positives and assign a more meaningful confidence.

Per-type validation:

JPEG  — Parse JPEG markers. Check SOI, sane segment lengths, look for EOI.
        Optionally attempt Pillow decode (full image round-trip).

PNG   — Validate 8-byte signature, check IHDR chunk presence and dimensions,
        verify IEND presence. Optionally attempt Pillow decode.

PDF   — Check %PDF- header, scan for obj/endobj, xref/startxref, %%EOF.
        Validate object count is nonzero and boundaries are sane.

ZIP   — Parse local file headers, central directory. Attempt to identify
        DOCX/XLSX/PPTX from [Content_Types].xml presence.

We do NOT build full parsers — these are forensic heuristics.
Each validator returns a (ValidationStatus, list[str]) tuple:
    status   — PASSED / PARTIAL / FAILED / SKIPPED
    notes    — list of human-readable observations (shown in UI)
"""

from __future__ import annotations

import io
import logging
import struct
import zipfile
from typing import Optional

from backend.carve.models import CarvedFileType, ValidationStatus

logger = logging.getLogger("forensiwipe.carve.validators")


# ── JPEG ──────────────────────────────────────────────────────────────────────

# Two-byte JPEG marker codes that carry a length field
_JPEG_MARKERS_WITH_LENGTH: frozenset[int] = frozenset({
    0xC0, 0xC1, 0xC2, 0xC3,            # SOF
    0xC4,                               # DHT
    0xC8, 0xC9, 0xCA, 0xCB,
    0xCC, 0xCD, 0xCE, 0xCF,
    0xDB,                               # DQT
    0xDC,                               # DNL
    0xDD,                               # DRI
    0xDE,                               # DHP
    0xDF,                               # EXP
    0xE0, 0xE1, 0xE2, 0xE3,            # APP0-APPn
    0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB,
    0xEC, 0xED, 0xEE, 0xEF,
    0xFE,                               # COM
})

_JPEG_SOI = b"\xFF\xD8"
_JPEG_EOI = b"\xFF\xD9"
_JPEG_SOS = 0xDA


def validate_jpeg(data: bytes) -> tuple[ValidationStatus, list[str]]:
    """
    Parse JPEG marker structure.

    Returns (ValidationStatus, notes).
    Attempts Pillow decode if structural parse passes.
    """
    notes: list[str] = []

    if not data.startswith(_JPEG_SOI):
        return ValidationStatus.FAILED, ["Missing JPEG SOI marker (FF D8)"]

    notes.append("SOI marker present")

    # Parse markers
    pos = 2
    found_eoi = False
    found_sos = False
    found_sof = False
    marker_count = 0
    max_markers = 256

    while pos < len(data) - 1 and marker_count < max_markers:
        if data[pos] != 0xFF:
            # Not a marker start — scan forward to find next 0xFF
            next_ff = data.find(b"\xFF", pos + 1)
            if next_ff == -1:
                break
            pos = next_ff
            continue

        # Skip fill bytes (0xFF 0xFF ... 0xXX)
        while pos < len(data) - 1 and data[pos + 1] == 0xFF:
            pos += 1

        if pos + 1 >= len(data):
            break

        marker_byte = data[pos + 1]
        marker_count += 1

        if marker_byte == 0xD9:   # EOI
            found_eoi = True
            notes.append("EOI marker found")
            break
        elif marker_byte == 0xD8:  # SOI (nested — skip)
            pos += 2
            continue
        elif marker_byte == 0xDA:  # SOS — scan to EOI
            found_sos = True
            notes.append("SOS marker found")
            eoi_pos = data.find(_JPEG_EOI, pos + 2)
            if eoi_pos != -1:
                found_eoi = True
                notes.append("EOI found after SOS")
            break
        elif marker_byte in _JPEG_MARKERS_WITH_LENGTH:
            if pos + 3 >= len(data):
                break
            length = struct.unpack(">H", data[pos + 2: pos + 4])[0]
            if length < 2 or pos + 2 + length > len(data) + 16:
                notes.append(f"Suspicious segment length {length} at offset {pos}")
                break
            if marker_byte in (0xC0, 0xC1, 0xC2):
                found_sof = True
                notes.append("SOF marker found")
            pos += 2 + length
        else:
            # Standalone marker (RST, etc.)
            pos += 2

    if not found_eoi:
        notes.append("EOI marker not found — file may be truncated")

    structural_ok = found_sos or found_sof

    # Attempt Pillow decode
    decoder_ok = False
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.verify()
        # verify() closes the image — re-open to get dimensions
        img2 = Image.open(io.BytesIO(data))
        w, h = img2.size
        if w > 0 and h > 0:
            decoder_ok = True
            notes.append(f"Pillow decode: OK ({w}×{h} px)")
        else:
            notes.append("Pillow decode: zero dimensions")
    except ImportError:
        notes.append("Pillow not available — decoder validation skipped")
    except Exception as exc:
        notes.append(f"Pillow decode: FAILED ({exc})")

    if decoder_ok:
        return ValidationStatus.PASSED, notes
    elif structural_ok and found_eoi:
        return ValidationStatus.PASSED, notes
    elif structural_ok or found_eoi:
        return ValidationStatus.PARTIAL, notes
    else:
        return ValidationStatus.FAILED, notes


# ── PNG ───────────────────────────────────────────────────────────────────────

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_IHDR = b"IHDR"
_PNG_IEND = b"IEND"


def validate_png(data: bytes) -> tuple[ValidationStatus, list[str]]:
    """Validate PNG signature, IHDR, and IEND chunks."""
    notes: list[str] = []

    if not data.startswith(_PNG_SIGNATURE):
        return ValidationStatus.FAILED, ["PNG signature mismatch"]

    notes.append("PNG signature valid")

    if len(data) < 33:
        return ValidationStatus.FAILED, ["File too small for valid PNG (< 33 bytes)"]

    # IHDR must be the first chunk
    ihdr_length = struct.unpack(">I", data[8:12])[0]
    ihdr_type   = data[12:16]

    if ihdr_type != _PNG_IHDR:
        return ValidationStatus.FAILED, [f"First chunk is not IHDR (got {ihdr_type})"]

    if ihdr_length != 13:
        notes.append(f"Unexpected IHDR length: {ihdr_length} (expected 13)")

    # Parse IHDR fields
    if len(data) >= 29:
        width  = struct.unpack(">I", data[16:20])[0]
        height = struct.unpack(">I", data[20:24])[0]
        bit_depth = data[24]
        color_type = data[25]
        notes.append(f"IHDR: {width}×{height} px, bit_depth={bit_depth}, color_type={color_type}")
        if width == 0 or height == 0:
            return ValidationStatus.FAILED, notes + ["Zero image dimensions"]

    found_iend = _PNG_IEND in data
    if found_iend:
        notes.append("IEND chunk present")
    else:
        notes.append("IEND chunk not found — file may be truncated")

    # Attempt Pillow decode
    decoder_ok = False
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.verify()
        decoder_ok = True
        notes.append("Pillow decode: OK")
    except ImportError:
        notes.append("Pillow not available — decoder validation skipped")
    except Exception as exc:
        notes.append(f"Pillow decode: FAILED ({exc})")

    if decoder_ok:
        return ValidationStatus.PASSED, notes
    elif found_iend:
        return ValidationStatus.PASSED, notes
    else:
        return ValidationStatus.PARTIAL, notes


# ── PDF ───────────────────────────────────────────────────────────────────────

def validate_pdf(data: bytes) -> tuple[ValidationStatus, list[str]]:
    """
    Basic PDF structural validation.
    Checks: %PDF- header, presence of obj/endobj, xref or cross-reference,
    %%EOF terminator, and approximate object count.
    """
    notes: list[str] = []

    if not data.startswith(b"%PDF-"):
        return ValidationStatus.FAILED, ["Missing %PDF- header"]

    # Extract version
    nl = data.find(b"\n", 0, 20)
    version_line = data[:nl if nl != -1 else 10].decode("latin-1", errors="replace")
    notes.append(f"Header: {version_line.strip()}")

    has_eof   = b"%%EOF" in data
    has_obj   = b" obj" in data or b"\nobj" in data
    has_endobj = b"endobj" in data
    has_xref  = b"xref" in data or b"startxref" in data

    if has_obj and has_endobj:
        # Count objects
        count = data.count(b" obj\n") + data.count(b" obj\r") + data.count(b"\nobj\n")
        notes.append(f"Object markers found (~{count} objects)")
    else:
        notes.append("No obj/endobj markers found")

    if has_xref:
        notes.append("xref/startxref present")
    else:
        notes.append("xref not found — may be a linearised or corrupt PDF")

    if has_eof:
        notes.append("%%EOF marker present")
    else:
        notes.append("%%EOF not found — file may be truncated")

    if has_obj and has_endobj and has_eof:
        return ValidationStatus.PASSED, notes
    elif has_obj and has_endobj:
        return ValidationStatus.PARTIAL, notes
    elif has_eof:
        return ValidationStatus.PARTIAL, notes
    else:
        return ValidationStatus.FAILED, notes


# ── ZIP / Office ──────────────────────────────────────────────────────────────

# Central directory signatures inside ZIP that identify Office formats
_OFFICE_CONTENT_TYPES = {
    b"word/document.xml":     CarvedFileType.DOCX,
    b"xl/workbook.xml":       CarvedFileType.XLSX,
    b"ppt/presentation.xml":  CarvedFileType.PPTX,
}


def validate_zip(data: bytes) -> tuple[ValidationStatus, list[str], CarvedFileType]:
    """
    Validate ZIP structure and attempt Office sub-type detection.

    Returns (ValidationStatus, notes, detected_type).
    detected_type defaults to ZIP; promoted to DOCX/XLSX/PPTX if internal
    structure confirms it.

    We do NOT call every PK file an Office document without checking.
    """
    notes: list[str] = []
    detected_type = CarvedFileType.ZIP

    if not data.startswith(b"PK\x03\x04"):
        return ValidationStatus.FAILED, ["Missing ZIP local file header (PK\\x03\\x04)"], detected_type

    notes.append("ZIP local file header valid")

    # Try parsing with zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        notes.append(f"ZIP entries: {len(names)}")

        # Check for Office content types
        for marker, office_type in _OFFICE_CONTENT_TYPES.items():
            marker_str = marker.decode()
            if marker_str in names or any(marker_str in n for n in names):
                detected_type = office_type
                notes.append(f"Office sub-type detected: {office_type.value}")
                break

        if "[Content_Types].xml" in names:
            notes.append("[Content_Types].xml present — OOXML format confirmed")

        zf.close()
        return ValidationStatus.PASSED, notes, detected_type

    except zipfile.BadZipFile as exc:
        notes.append(f"ZIP parse failed: {exc}")
        # Check for central directory at the end
        if b"PK\x01\x02" in data:
            notes.append("Central directory signature found — partial ZIP")
            return ValidationStatus.PARTIAL, notes, detected_type
        return ValidationStatus.FAILED, notes, detected_type
    except Exception as exc:
        notes.append(f"ZIP validation error: {exc}")
        return ValidationStatus.FAILED, notes, detected_type


# ── Dispatch ──────────────────────────────────────────────────────────────────

def validate(
    file_type: CarvedFileType,
    data: bytes,
) -> tuple[ValidationStatus, list[str], CarvedFileType]:
    """
    Route validation to the appropriate type-specific validator.

    Returns (status, notes, actual_type) — actual_type may differ from
    input file_type when ZIP is promoted to DOCX/XLSX/PPTX.
    """
    if file_type == CarvedFileType.JPEG:
        status, notes = validate_jpeg(data)
        return status, notes, file_type

    elif file_type == CarvedFileType.PNG:
        status, notes = validate_png(data)
        return status, notes, file_type

    elif file_type == CarvedFileType.PDF:
        status, notes = validate_pdf(data)
        return status, notes, file_type

    elif file_type == CarvedFileType.ZIP:
        return validate_zip(data)

    else:
        return ValidationStatus.SKIPPED, [f"No validator for {file_type}"], file_type
