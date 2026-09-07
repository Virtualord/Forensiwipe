#!/usr/bin/env python3
"""
demo/create_demo_image.py — Create a controlled demo disk image for ForensiWipe.

This script:
  1. Creates demo/sample_disk.img (64 MB sparse file)
  2. Formats it with ext4
  3. Mounts it as a loopback device
  4. Seeds sample files (JPEG, PNG, PDF, DOCX placeholders, text files)
  5. Records SHA-256 hashes of all planted files
  6. Deletes the files (leaving data recoverable by Module 3)
  7. Unmounts
  8. Prints the loopback device path for use in the erase demo

SAFETY NOTES:
  - Only operates on files inside ./demo/
  - Creates the loopback device from a local .img file only
  - Never touches /dev/sda or any physical disk
  - Requires: sudo (for mount/losetup), mkfs.ext4, losetup

Usage:
    cd /path/to/forensiwipe
    sudo python demo/create_demo_image.py [--size-mb 64] [--teardown]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
IMAGE_PATH = SCRIPT_DIR / "sample_disk.img"
MOUNT_DIR  = SCRIPT_DIR / "mnt"
MANIFEST   = SCRIPT_DIR / "demo_manifest.json"
IMAGE_SIZE_DEFAULT_MB = 64


def _run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command, print it, and raise on failure if check=True."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        print(f"  ERROR: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ── Sample file creators ──────────────────────────────────────────────────────

def _create_minimal_jpeg(path: Path) -> None:
    """Create a minimal valid JPEG (1×1 red pixel)."""
    # Minimal JFIF JPEG — 1×1 red pixel
    jpeg_bytes = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
        0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
        0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
        0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
        0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
        0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
        0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
        0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD7, 0xFF, 0xD9,
    ])
    path.write_bytes(jpeg_bytes)


def _create_minimal_png(path: Path) -> None:
    """Create a minimal valid PNG (1×1 red pixel)."""
    import zlib
    def png_chunk(name: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        return length + name + data + crc

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
    idat_raw = b"\x00\xFF\x00\x00"  # filter byte + RGB
    idat_compressed = zlib.compress(idat_raw)

    png_data = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", idat_compressed)
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(png_data)


def _create_minimal_pdf(path: Path) -> None:
    """Create a minimal valid PDF."""
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj

4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (ForensiWipe Demo PDF) Tj ET
endstream
endobj

5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj

xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000266 00000 n
0000000360 00000 n

trailer
<< /Size 6 /Root 1 0 R >>
startxref
441
%%EOF
"""
    path.write_bytes(pdf_content)


def _create_text_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _create_docx_placeholder(path: Path) -> None:
    """Create a minimal ZIP-based DOCX placeholder."""
    import zipfile, io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>')
        zf.writestr("_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>')
        zf.writestr("word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>ForensiWipe Demo Document</w:t></w:r></w:p></w:body></w:document>')
    path.write_bytes(buf.getvalue())


# ── Main workflow ─────────────────────────────────────────────────────────────

def check_prerequisites() -> None:
    print("\n[1/8] Checking prerequisites...")
    missing = []
    for tool in ["dd", "mkfs.ext4", "losetup", "mount", "umount"]:
        r = subprocess.run(["which", tool], capture_output=True)
        if r.returncode != 0:
            missing.append(tool)
    if missing:
        print(f"  ERROR: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("  Install with: sudo apt install e2fsprogs util-linux", file=sys.stderr)
        sys.exit(1)
    if os.geteuid() != 0:
        print("  ERROR: This script requires root privileges (sudo) for mount/losetup.", file=sys.stderr)
        sys.exit(1)
    print("  OK — all prerequisites satisfied, running as root.")


def create_image(size_mb: int) -> None:
    print(f"\n[2/8] Creating {size_mb} MB sparse image at {IMAGE_PATH}...")
    SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    if IMAGE_PATH.exists():
        print(f"  Existing image found — removing and recreating.")
        IMAGE_PATH.unlink()
    _run(["dd", "if=/dev/zero", f"of={IMAGE_PATH}", "bs=1M", f"count={size_mb}", "status=none"])
    print(f"  Image created: {IMAGE_PATH} ({size_mb} MB)")


def format_image() -> None:
    print(f"\n[3/8] Formatting image as ext4...")
    _run(["mkfs.ext4", "-F", "-L", "forensiwipe_demo", str(IMAGE_PATH)])
    print("  Formatted as ext4 with label 'forensiwipe_demo'")


def attach_loopback() -> str:
    print(f"\n[4/8] Attaching loopback device...")
    result = _run(["losetup", "--find", "--show", str(IMAGE_PATH)], capture=True)
    loop_dev = result.stdout.strip()
    print(f"  Attached: {loop_dev} → {IMAGE_PATH}")
    return loop_dev


def mount_image(loop_dev: str) -> None:
    print(f"\n[5/8] Mounting {loop_dev} at {MOUNT_DIR}...")
    MOUNT_DIR.mkdir(parents=True, exist_ok=True)
    _run(["mount", loop_dev, str(MOUNT_DIR)])
    print(f"  Mounted at {MOUNT_DIR}")


def seed_files() -> dict[str, str]:
    """Plant sample files on the mounted image. Returns {filename: sha256}."""
    print(f"\n[6/8] Seeding sample files...")
    files: dict[str, str] = {}

    samples = [
        ("sample_photo_001.jpg",  _create_minimal_jpeg),
        ("sample_photo_002.jpg",  _create_minimal_jpeg),
        ("sample_diagram.png",    _create_minimal_png),
        ("sample_report.pdf",     _create_minimal_pdf),
        ("sample_document.docx",  _create_docx_placeholder),
    ]

    for filename, creator in samples:
        target_path = MOUNT_DIR / filename
        creator(target_path)
        h = _sha256(target_path)
        files[filename] = h
        size = target_path.stat().st_size
        print(f"  Created {filename:40s} SHA-256: {h[:16]}...  ({size} bytes)")

    # Also plant a text file with notes
    notes_path = MOUNT_DIR / "README_demo.txt"
    _create_text_file(
        notes_path,
        "ForensiWipe Demo Image\n"
        "This image was created by create_demo_image.py\n"
        "Files were planted and then deleted to demonstrate Module 3 carving.\n"
    )
    files["README_demo.txt"] = _sha256(notes_path)

    # Sync to ensure data is written to image
    _run(["sync"])
    print(f"  Synced {len(files)} files to image.")
    return files


def delete_files(manifest: dict[str, str]) -> None:
    print(f"\n[7/8] Deleting planted files (simulating data loss)...")
    for filename in manifest:
        target_path = MOUNT_DIR / filename
        if target_path.exists():
            target_path.unlink()
            print(f"  Deleted: {filename}")
    _run(["sync"])
    print("  All planted files deleted.")


def unmount_and_detach(loop_dev: str) -> None:
    print(f"\n[8/8] Unmounting and detaching...")
    _run(["umount", str(MOUNT_DIR)])
    _run(["losetup", "-d", loop_dev])
    try:
        MOUNT_DIR.rmdir()
    except OSError:
        pass
    print(f"  Unmounted and detached {loop_dev}.")


def teardown_demo() -> None:
    """Remove demo image and clean up."""
    print("\n[TEARDOWN] Removing demo image...")

    # Detach any loopback devices backed by our image
    result = subprocess.run(
        ["losetup", "-j", str(IMAGE_PATH)], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        dev = line.split(":")[0].strip()
        if dev:
            print(f"  Detaching {dev}")
            subprocess.run(["losetup", "-d", dev])

    # Unmount if mounted
    if MOUNT_DIR.exists():
        subprocess.run(["umount", str(MOUNT_DIR)], capture_output=True)
        try:
            MOUNT_DIR.rmdir()
        except OSError:
            pass

    if IMAGE_PATH.exists():
        IMAGE_PATH.unlink()
        print(f"  Removed {IMAGE_PATH}")

    if MANIFEST.exists():
        MANIFEST.unlink()

    print("  Teardown complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a ForensiWipe demo disk image."
    )
    parser.add_argument("--size-mb", type=int, default=IMAGE_SIZE_DEFAULT_MB,
                        help=f"Image size in MB (default: {IMAGE_SIZE_DEFAULT_MB})")
    parser.add_argument("--teardown", action="store_true",
                        help="Remove the demo image and detach loopback device")
    args = parser.parse_args()

    if args.teardown:
        teardown_demo()
        return

    print("=" * 65)
    print("  ForensiWipe Demo Image Creator")
    print("  SAFETY: Only operates on files inside ./demo/")
    print("  Never touches physical disks.")
    print("=" * 65)

    check_prerequisites()
    create_image(args.size_mb)
    format_image()
    loop_dev = attach_loopback()
    mount_image(loop_dev)
    manifest = seed_files()
    delete_files(manifest)

    # Write manifest BEFORE unmounting so we have it
    manifest_data = {
        "image_path": str(IMAGE_PATH),
        "loop_device": loop_dev,
        "image_size_mb": args.size_mb,
        "planted_files": manifest,
        "note": (
            "Files were planted on the image and then deleted. "
            "Their signatures remain recoverable via Module 3 carving."
        ),
    }

    unmount_and_detach(loop_dev)

    # Save manifest (loop_dev is now detached — note this for re-attachment)
    manifest_data["loop_device_detached"] = True
    MANIFEST.write_text(json.dumps(manifest_data, indent=2))

    print("\n" + "=" * 65)
    print("  Demo image ready!")
    print(f"  Image:    {IMAGE_PATH}")
    print(f"  Manifest: {MANIFEST}")
    print()
    print("  To attach for the erase demo:")
    print(f"    sudo losetup --find --show {IMAGE_PATH}")
    print()
    print("  Expected output: /dev/loopX")
    print()
    print("  Then in ForensiWipe:")
    print("  → Target: /dev/loopX (shown in device list)")
    print("  → Standard: DoD 3-pass (DEMO)")
    print("  → Execute → Verify → Report")
    print("=" * 65)


if __name__ == "__main__":
    main()
