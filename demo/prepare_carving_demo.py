#!/usr/bin/env python3
"""
demo/prepare_carving_demo.py — Prepare a raw disk image seeded with real
recoverable files for the Module 3 carving demonstration.

Unlike create_demo_image.py (which formats with ext4 and uses losetup),
this script writes files DIRECTLY into a raw binary image at known offsets,
then optionally zero-fills the regions between them to simulate a deleted
filesystem. This is the canonical carving test image because:

  - No filesystem metadata — pure signature-based recovery required
  - Files are at predictable offsets — easy to verify recovery
  - Works without root / losetup / mkfs
  - Can embed a JPEG fragmentation scenario

Output: demo/carving_demo.img  (default 8 MB)

Manifest saved to: demo/carving_demo_manifest.json
  Contains: {filename, offset, size, sha256} for each planted file.

Usage:
    cd /path/to/forensiwipe
    python demo/prepare_carving_demo.py [--size-mb 8] [--fragment]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent.resolve()
IMAGE_PATH   = SCRIPT_DIR / "carving_demo.img"
MANIFEST     = SCRIPT_DIR / "carving_demo_manifest.json"
DEFAULT_SIZE = 8   # MB


# ── Minimal file builders (same as create_demo_image.py) ─────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_jpeg(label: str = "ForensiWipe Demo") -> bytes:
    """Return a minimal but valid JPEG (1×1 red pixel) with comment marker."""
    base = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xFF, 0xDB, 0x00, 0x43, 0x00,
        0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
        0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14,
        0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13,
        0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A,
        0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22,
        0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C,
        0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39,
        0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01,
        0x01, 0x01, 0x11, 0x00,
        0xFF, 0xC4, 0x00, 0x14, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xC4, 0x00, 0x14, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        0x7F, 0xA4,
        0xFF, 0xD9,
    ])
    # Embed label in a JPEG COM (comment) marker
    label_bytes = label.encode("utf-8")
    com = (b"\xFF\xFE"
           + struct.pack(">H", len(label_bytes) + 2)
           + label_bytes)
    # Insert COM after the JFIF APP0
    return base[:20] + com + base[20:]


def make_png() -> bytes:
    """Minimal valid 1×1 green pixel PNG."""
    import zlib
    def chunk(name: bytes, data: bytes) -> bytes:
        import zlib as _z
        length = struct.pack(">I", len(data))
        crc    = struct.pack(">I", _z.crc32(name + data) & 0xFFFFFFFF)
        return length + name + data + crc

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\xFF\x00")   # filter=0, R=0, G=255, B=0
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def make_pdf() -> bytes:
    return b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 46>>
stream
BT /F1 12 Tf 72 720 Td (ForensiWipe Carving Demo) Tj ET
endstream
endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
xref
0 6
0000000000 65535 f\r
0000000009 00000 n\r
0000000058 00000 n\r
0000000115 00000 n\r
0000000266 00000 n\r
0000000362 00000 n\r
trailer<</Size 6/Root 1 0 R>>
startxref
441
%%EOF
"""


def make_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument'
            '.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>'
        ))
        zf.writestr("word/document.xml", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>ForensiWipe Carving Demo Document</w:t></w:r></w:p></w:body>'
            '</w:document>'
        ))
        zf.writestr("word/_rels/document.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
        ))
    return buf.getvalue()


def make_fragmented_jpeg() -> tuple[bytes, bytes]:
    """
    Return (part_a, part_b): a JPEG split at the SOS scan data boundary.
    The scanner should detect part_a as truncated and attempt reconstruction.
    """
    full = make_jpeg("Fragmented JPEG Demo")
    # Split just after the SOS header — before the scan data
    sos_pos = full.find(b"\xFF\xDA")
    if sos_pos == -1 or sos_pos + 10 >= len(full):
        # Fallback: split at midpoint
        mid = len(full) // 2
        return full[:mid], full[mid:]
    # Keep the SOS header in part_a; scan data continuation in part_b
    split_at = sos_pos + 10   # SOI + SOS marker + length + header
    return full[:split_at], full[split_at:]


# ── Image writer ──────────────────────────────────────────────────────────────

def build_image(size_mb: int, include_fragment: bool) -> dict:
    """
    Build the raw carving demo image and return a manifest dict.

    Layout (all offsets are sector-aligned at 512 bytes):
      0x00000  — 512 B boot/header filler (random-looking non-JPEG data)
      0x00200  — JPEG #1  (clean, fully recoverable)
      gap      — zero-filled
      0x02000  — PNG      (clean)
      gap      — zero-filled
      0x04000  — PDF      (clean)
      gap      — zero-filled
      0x06000  — DOCX/ZIP (clean)
      gap      — zero-filled
      0x08000  — JPEG #2  (clean second JPEG)
      if --fragment:
      0x0A000  — JPEG fragment part A  (truncated JPEG)
      0x0C000  — gap fill (non-JPEG data, interrupts stream)
      0x0E000  — JPEG fragment part B  (continuation bytes + EOI)
    """
    total_bytes = size_mb * 1024 * 1024
    image = bytearray(total_bytes)

    manifest = {"image_path": str(IMAGE_PATH), "size_mb": size_mb, "files": []}

    def plant(offset: int, data: bytes, label: str, file_type: str) -> None:
        if offset + len(data) > total_bytes:
            print(f"  WARNING: {label} at {offset:#x} would exceed image size — skipped")
            return
        image[offset: offset + len(data)] = data
        entry = {
            "label":     label,
            "file_type": file_type,
            "offset":    offset,
            "size":      len(data),
            "sha256":    _sha256(data),
        }
        manifest["files"].append(entry)
        print(f"  Planted {file_type:6s}  offset={offset:#010x}  "
              f"size={len(data):6d}B  sha256={_sha256(data)[:16]}…")

    # Non-JPEG header region (ensures scanner doesn't false-positive at byte 0)
    image[0:512] = bytes([0xAA, 0x55] * 256)

    plant(0x0200,  make_jpeg("Photo 001"),  "jpeg_001", "JPEG")
    plant(0x2000,  make_png(),              "png_001",  "PNG")
    plant(0x4000,  make_pdf(),              "pdf_001",  "PDF")
    plant(0x6000,  make_docx(),             "docx_001", "DOCX")
    plant(0x8000,  make_jpeg("Photo 002"),  "jpeg_002", "JPEG")

    if include_fragment:
        part_a, part_b = make_fragmented_jpeg()
        plant(0xA000, part_a,             "jpeg_frag_a", "JPEG_FRAGMENT_A")
        # Gap: 0xC000–0xE000 filled with non-JPEG noise
        noise = bytes(range(256)) * ((0x2000) // 256)
        image[0xC000: 0xC000 + len(noise)] = noise
        plant(0xE000, part_b,             "jpeg_frag_b", "JPEG_FRAGMENT_B")
        manifest["fragment_scenario"] = {
            "part_a_offset": 0xA000,
            "part_b_offset": 0xE000,
            "gap_start":     0xC000,
            "gap_size":      0x2000,
            "description":   "JPEG split across a gap. Scanner should detect truncation and attempt reconstruction.",
        }

    return manifest, bytes(image)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare ForensiWipe carving demo image.")
    parser.add_argument("--size-mb",  type=int, default=DEFAULT_SIZE)
    parser.add_argument("--fragment", action="store_true",
                        help="Include a JPEG fragmentation scenario")
    args = parser.parse_args()

    print("=" * 65)
    print("  ForensiWipe Carving Demo Image Preparer")
    print("  SAFETY: writes only to demo/carving_demo.img")
    print("  No root, no losetup, no physical disk access required.")
    print("=" * 65)

    print(f"\nBuilding {args.size_mb} MB raw image at {IMAGE_PATH}…")
    manifest, image_bytes = build_image(args.size_mb, args.fragment)
    manifest["image_sha256"] = _sha256(image_bytes)

    IMAGE_PATH.write_bytes(image_bytes)
    MANIFEST.write_text(json.dumps(manifest, indent=2))

    print(f"\n  Image written: {IMAGE_PATH}  ({len(image_bytes) // (1024*1024)} MB)")
    print(f"  Manifest:      {MANIFEST}")
    print(f"  SHA-256:       {manifest['image_sha256'][:32]}…")
    print(f"  Files planted: {len(manifest['files'])}")

    print("\n  To run a carving scan:")
    print(f"    POST /api/carve/scan")
    print(f"    {{\"evidence_path\": \"{IMAGE_PATH}\"}}")
    print("\n  Expected recoveries:")
    for f in manifest["files"]:
        if "FRAGMENT" not in f["file_type"]:
            print(f"    offset={f['offset']:#010x}  {f['file_type']:6s}  sha256={f['sha256'][:16]}…")
    if args.fragment:
        print("\n  Fragment scenario embedded — scanner should attempt JPEG reconstruction.")
    print("=" * 65)


if __name__ == "__main__":
    main()
