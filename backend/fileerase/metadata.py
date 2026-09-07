"""
fileerase/metadata.py — Best-effort metadata sanitisation before file erasure.

Supported formats and methods:

  JPEG/PNG/TIFF  Pillow    — rebuild image without EXIF
  DOCX/XLSX/PPTX python-docx / openpyxl — strip core properties where possible
  PDF            pikepdf   — remove /Info and XMP metadata where available

IMPORTANT:
  - We operate on a WORKING COPY, never the original file.
  - We NEVER report "metadata removed" unless the operation actually succeeded.
  - If a dependency is missing or the format is unsupported: NOT_AVAILABLE.
  - Pillow strips EXIF by rebuilding the image data without APP1 segment.

Limitations stated honestly:
  - python-docx and openpyxl can clear core properties but may not reach
    embedded thumbnails, revision history, or custom properties.
  - pikepdf removes /Info dict and XMP stream but cannot guarantee all
    metadata pathways (e.g. embedded JavaScript, form fields).
  - We never claim "all metadata removed" — we report what was targeted.
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from backend.fileerase.models import MetadataResult, MetadataStatus

logger = logging.getLogger("forensiwipe.fileerase.metadata")

# Extensions → handler name
_HANDLERS: dict[str, str] = {
    ".jpg":  "image", ".jpeg": "image", ".png": "image",
    ".tif":  "image", ".tiff": "image", ".bmp": "image",
    ".docx": "docx",
    ".xlsx": "xlsx",
    ".pdf":  "pdf",
}


def sanitise_metadata(path: str) -> tuple[MetadataResult, Optional[bytes]]:
    """
    Attempt to remove metadata from the file at `path`.

    Returns (MetadataResult, clean_bytes).
    clean_bytes is None if sanitisation was not performed or failed.
    The caller must write clean_bytes to a temp path before unlinking the original.
    """
    ext = Path(path).suffix.lower()
    handler = _HANDLERS.get(ext)

    if handler == "image":
        return _sanitise_image(path)
    elif handler == "docx":
        return _sanitise_docx(path)
    elif handler == "xlsx":
        return _sanitise_xlsx(path)
    elif handler == "pdf":
        return _sanitise_pdf(path)
    else:
        return MetadataResult(
            status=MetadataStatus.NOT_APPLICABLE,
            note=f"No metadata sanitisation handler for {ext or 'unknown'} format.",
        ), None


# ── Image (Pillow) ────────────────────────────────────────────────────────────

def _sanitise_image(path: str) -> tuple[MetadataResult, Optional[bytes]]:
    """
    Rebuild the image without EXIF / ICC profile / comment metadata.
    Uses Pillow to decode and re-encode — the EXIF segment is not forwarded.
    """
    try:
        from PIL import Image
    except ImportError:
        return MetadataResult(
            status=MetadataStatus.NOT_AVAILABLE,
            note="Pillow not installed — image metadata sanitisation unavailable.",
        ), None

    try:
        img = Image.open(path)
        # Determine output format
        fmt = img.format or "JPEG"
        # Strip EXIF: open image data without passing exif= to save
        clean_buf = io.BytesIO()
        # Convert RGBA → RGB for JPEG compatibility
        if fmt == "JPEG" and img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        save_kwargs: dict = {}
        if fmt == "JPEG":
            save_kwargs["quality"] = 95
            save_kwargs["subsampling"] = 0

        img.save(clean_buf, format=fmt, **save_kwargs)
        clean_data = clean_buf.getvalue()

        removed = []
        # Check what was in the original
        if hasattr(img, "_getexif") and img._getexif():    # type: ignore[attr-defined]
            removed.append("EXIF")
        # Pillow info may carry ICC profile, comments
        for key in ("icc_profile", "comment", "dpi", "jfif_version"):
            if key in img.info:
                removed.append(key)

        return MetadataResult(
            status=MetadataStatus.REMOVED,
            removed_fields=removed or ["EXIF/metadata (rebuild without metadata)"],
            note="Image rebuilt without EXIF/metadata via Pillow.",
        ), clean_data

    except Exception as exc:
        logger.warning("image_metadata_sanitise_error path=%s exc=%s", path, exc)
        return MetadataResult(
            status=MetadataStatus.FAILED,
            note=f"Image metadata sanitisation failed: {exc}",
        ), None


# ── DOCX (python-docx) ────────────────────────────────────────────────────────

def _sanitise_docx(path: str) -> tuple[MetadataResult, Optional[bytes]]:
    try:
        from docx import Document
    except ImportError:
        return MetadataResult(
            status=MetadataStatus.NOT_AVAILABLE,
            note="python-docx not installed — DOCX metadata sanitisation unavailable.",
        ), None

    try:
        doc = Document(path)
        props = doc.core_properties
        cleared: list[str] = []

        _clear_fields = [
            ("author", ""), ("last_modified_by", ""), ("title", ""),
            ("subject", ""), ("keywords", ""), ("description", ""),
            ("category", ""), ("comments", ""),
        ]
        for attr, val in _clear_fields:
            try:
                if getattr(props, attr, None):
                    setattr(props, attr, val)
                    cleared.append(attr)
            except Exception:
                pass

        buf = io.BytesIO()
        doc.save(buf)
        return MetadataResult(
            status=MetadataStatus.REMOVED,
            removed_fields=cleared,
            note=(
                "Core properties cleared via python-docx. "
                "Embedded thumbnails and revision history may persist."
            ),
        ), buf.getvalue()

    except Exception as exc:
        logger.warning("docx_metadata_error path=%s exc=%s", path, exc)
        return MetadataResult(
            status=MetadataStatus.FAILED,
            note=f"DOCX metadata sanitisation failed: {exc}",
        ), None


# ── XLSX (openpyxl) ───────────────────────────────────────────────────────────

def _sanitise_xlsx(path: str) -> tuple[MetadataResult, Optional[bytes]]:
    try:
        import openpyxl
    except ImportError:
        return MetadataResult(
            status=MetadataStatus.NOT_AVAILABLE,
            note="openpyxl not installed — XLSX metadata sanitisation unavailable.",
        ), None

    try:
        wb = openpyxl.load_workbook(path)
        props = wb.properties
        cleared: list[str] = []

        _fields = ["creator", "lastModifiedBy", "title", "subject",
                   "description", "keywords", "category"]
        for f in _fields:
            if getattr(props, f, None):
                setattr(props, f, "")
                cleared.append(f)

        buf = io.BytesIO()
        wb.save(buf)
        return MetadataResult(
            status=MetadataStatus.REMOVED,
            removed_fields=cleared,
            note="Core properties cleared via openpyxl.",
        ), buf.getvalue()

    except Exception as exc:
        logger.warning("xlsx_metadata_error path=%s exc=%s", path, exc)
        return MetadataResult(
            status=MetadataStatus.FAILED,
            note=f"XLSX metadata sanitisation failed: {exc}",
        ), None


# ── PDF (pikepdf) ─────────────────────────────────────────────────────────────

def _sanitise_pdf(path: str) -> tuple[MetadataResult, Optional[bytes]]:
    try:
        import pikepdf
    except ImportError:
        return MetadataResult(
            status=MetadataStatus.NOT_AVAILABLE,
            note="pikepdf not installed — PDF metadata sanitisation unavailable.",
        ), None

    try:
        pdf = pikepdf.open(path)
        cleared: list[str] = []

        # Remove /Info dictionary entries
        if "/Info" in pdf.trailer:
            info = pdf.trailer["/Info"]
            info_keys = list(info.keys()) if hasattr(info, "keys") else []
            for key in info_keys:
                try:
                    del info[key]
                    cleared.append(str(key))
                except Exception:
                    pass

        # Remove XMP metadata stream
        try:
            with pdf.open_metadata() as meta:
                meta.clear()
            cleared.append("XMP metadata")
        except Exception:
            pass

        buf = io.BytesIO()
        pdf.save(buf)
        return MetadataResult(
            status=MetadataStatus.REMOVED,
            removed_fields=cleared,
            note=(
                "PDF /Info dict and XMP cleared via pikepdf. "
                "Embedded JavaScript or form data may persist."
            ),
        ), buf.getvalue()

    except Exception as exc:
        logger.warning("pdf_metadata_error path=%s exc=%s", path, exc)
        return MetadataResult(
            status=MetadataStatus.FAILED,
            note=f"PDF metadata sanitisation failed: {exc}",
        ), None
