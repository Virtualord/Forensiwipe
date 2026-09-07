"""
tests/test_fileerase.py — Tests for Module 2: Secure File & Folder Eraser.

Coverage per requirement:
  Individual file deletion
  Recursive folder selection
  Glob selection
  Metadata processing (Pillow image)
  Residual scan runs without crash
  Unsupported filesystem correctly labelled
  Demo mode: no actual writes/unlinks
  Audit records created
  API: preview, start, status, results, filesystems
  Failed file handled gracefully (not found)
  Zero-size file handled
  DOD 3-pass writes 3x the file size
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import os
import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.main import app


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_jpeg(tmp_path: Path, name: str = "test.jpg") -> Path:
    """Minimal valid JPEG for metadata tests."""
    data = bytes([
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
        0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,
        0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,0x00,0x01,0x01,0x01,0x11,0x00,
        0xFF,0xC4,0x00,0x14,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0xC4,0x00,0x14,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,0x7F,0xA4,0xFF,0xD9,
    ])
    f = tmp_path / name
    f.write_bytes(data)
    return f


def _make_text_file(tmp_path: Path, name: str = "test.txt", size: int = 1024) -> Path:
    f = tmp_path / name
    f.write_bytes(b"ForensiWipe test data " * (size // 22 + 1))
    return f


def _make_dir_with_files(tmp_path: Path) -> tuple[Path, list[Path]]:
    """Create a directory tree with mixed file types."""
    d = tmp_path / "testdir"
    d.mkdir()
    sub = d / "subdir"
    sub.mkdir()
    files = [
        _make_text_file(d, "a.txt", 512),
        _make_text_file(d, "b.txt", 256),
        _make_text_file(sub, "c.txt", 128),
    ]
    return d, files


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Pattern / collection tests ────────────────────────────────────────────────

class TestPatterns:

    def test_zero_fill_overwrites_content(self, tmp_path):
        from backend.fileerase.patterns import overwrite_file
        f = tmp_path / "data.bin"
        f.write_bytes(b"\xFF" * 1024)
        overwrite_file(str(f), "ZERO_FILL")
        assert f.read_bytes() == b"\x00" * 1024

    def test_random_fill_changes_content(self, tmp_path):
        from backend.fileerase.patterns import overwrite_file
        f = tmp_path / "data.bin"
        original = b"\xAB" * 1024
        f.write_bytes(original)
        overwrite_file(str(f), "RANDOM_FILL")
        assert f.read_bytes() != original

    def test_dod_3pass_bytes_written(self, tmp_path):
        from backend.fileerase.patterns import overwrite_file
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x55" * 512)
        written, passes = overwrite_file(str(f), "DOD_3PASS")
        assert passes == 3
        assert written == 512 * 3

    def test_zero_size_file_returns_zero(self, tmp_path):
        from backend.fileerase.patterns import overwrite_file
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        written, passes = overwrite_file(str(f), "ZERO_FILL")
        assert written == 0
        assert passes == 0

    def test_collect_files_single_file(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        f = _make_text_file(tmp_path)
        result = collect_files([str(f)], recursive=False, glob_pattern=None)
        assert str(f.resolve()) in result

    def test_collect_files_recursive_dir(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        d, files = _make_dir_with_files(tmp_path)
        result = collect_files([str(d)], recursive=True, glob_pattern=None)
        assert len(result) == 3
        for f in files:
            assert str(f.resolve()) in result

    def test_collect_files_nonexistent_skipped(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        result = collect_files(["/nonexistent/path/file.txt"], recursive=False, glob_pattern=None)
        assert result == []

    def test_collect_files_glob_pattern(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        d, files = _make_dir_with_files(tmp_path)
        result = collect_files([str(d)], recursive=True, glob_pattern="**/*.txt")
        assert len(result) == 3

    def test_collect_files_glob_filter(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        d, _ = _make_dir_with_files(tmp_path)
        # Add a non-.txt file
        (d / "image.jpg").write_bytes(b"\xFF\xD8\xFF\xD9")
        result = collect_files([str(d)], recursive=True, glob_pattern="**/*.txt")
        assert all(r.endswith(".txt") for r in result)
        assert len(result) == 3   # only .txt files


# ── Filesystem detection tests ────────────────────────────────────────────────

class TestFilesystem:

    def test_detect_filesystem_returns_string(self, tmp_path):
        from backend.fileerase.filesystem import detect_filesystem
        fs = detect_filesystem(str(tmp_path))
        assert isinstance(fs, str)
        assert len(fs) > 0

    def test_get_badge_ext4(self):
        from backend.fileerase.filesystem import get_badge
        from backend.fileerase.models import FilesystemSupport
        badge = get_badge("ext4")
        assert badge.support == FilesystemSupport.FULL
        assert badge.icon == "🟢"

    def test_get_badge_ntfs_partial(self):
        from backend.fileerase.filesystem import get_badge
        from backend.fileerase.models import FilesystemSupport
        badge = get_badge("ntfs")
        assert badge.support == FilesystemSupport.PARTIAL
        assert badge.icon == "🟡"
        assert len(badge.limitations) > 0

    def test_get_badge_apfs_stub(self):
        from backend.fileerase.filesystem import get_badge
        from backend.fileerase.models import FilesystemSupport
        badge = get_badge("apfs")
        assert badge.support == FilesystemSupport.STUB

    def test_get_badge_unknown(self):
        from backend.fileerase.filesystem import get_badge
        badge = get_badge("some_exotic_fs_xyz")
        assert badge.name == "Unknown"

    def test_journal_warning_ext4(self):
        from backend.fileerase.filesystem import journal_warning
        warn = journal_warning("ext4")
        assert warn is not None
        assert "journal" in warn.lower()

    def test_journal_warning_fat32_none(self):
        from backend.fileerase.filesystem import journal_warning
        assert journal_warning("vfat") is None

    def test_all_badges_returns_list(self):
        from backend.fileerase.filesystem import all_badges
        badges = all_badges()
        assert len(badges) >= 5


# ── Metadata sanitisation tests ───────────────────────────────────────────────

class TestMetadata:

    def test_jpeg_metadata_sanitised(self, tmp_path):
        from backend.fileerase.metadata import sanitise_metadata
        from backend.fileerase.models import MetadataStatus
        f = _make_jpeg(tmp_path)
        result, clean = sanitise_metadata(str(f))
        # If Pillow is available, should be REMOVED; otherwise NOT_AVAILABLE
        # The hand-crafted fixture may be rejected by newer Pillow decoders;
        # the sanitiser must report that honestly instead of claiming removal.
        assert result.status in (
            MetadataStatus.REMOVED, MetadataStatus.NOT_AVAILABLE, MetadataStatus.FAILED
        )
        if result.status == MetadataStatus.REMOVED:
            assert clean is not None
            assert len(clean) > 0

    def test_unsupported_format_not_applicable(self, tmp_path):
        from backend.fileerase.metadata import sanitise_metadata
        from backend.fileerase.models import MetadataStatus
        f = tmp_path / "test.xyz"
        f.write_bytes(b"\x00" * 64)
        result, clean = sanitise_metadata(str(f))
        assert result.status == MetadataStatus.NOT_APPLICABLE
        assert clean is None

    def test_text_file_not_applicable(self, tmp_path):
        from backend.fileerase.metadata import sanitise_metadata
        from backend.fileerase.models import MetadataStatus
        f = _make_text_file(tmp_path)
        result, clean = sanitise_metadata(str(f))
        assert result.status == MetadataStatus.NOT_APPLICABLE

    def test_docx_metadata_available_or_missing_dep(self, tmp_path):
        """DOCX sanitisation either works or reports NOT_AVAILABLE (no crash)."""
        from backend.fileerase.metadata import sanitise_metadata
        from backend.fileerase.models import MetadataStatus
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml",
                        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                        '<Override PartName="/word/document.xml" '
                        'ContentType="application/vnd.openxmlformats-officedocument'
                        '.wordprocessingml.document.main+xml"/></Types>')
            zf.writestr("word/document.xml",
                        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                        '<w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body></w:document>')
        f = tmp_path / "test.docx"
        f.write_bytes(buf.getvalue())
        result, _ = sanitise_metadata(str(f))
        assert result.status in (
            MetadataStatus.REMOVED, MetadataStatus.NOT_AVAILABLE, MetadataStatus.FAILED
        )


# ── Residual scanner tests ────────────────────────────────────────────────────

class TestResiduals:

    def test_scan_returns_list(self, tmp_path):
        from backend.fileerase.residuals import scan_residuals
        f = _make_text_file(tmp_path)
        findings = scan_residuals(str(f))
        assert isinstance(findings, list)

    def test_scan_never_raises(self, tmp_path):
        """Residual scanner must not crash even for edge-case paths."""
        from backend.fileerase.residuals import scan_residuals
        # Non-existent file
        findings = scan_residuals("/nonexistent/path/file.txt")
        assert isinstance(findings, list)

    def test_findings_have_required_fields(self, tmp_path):
        from backend.fileerase.residuals import scan_residuals
        f = _make_text_file(tmp_path)
        findings = scan_residuals(str(f))
        for finding in findings:
            assert hasattr(finding, "location")
            assert hasattr(finding, "status")
            assert finding.status is not None

    def test_valid_statuses_only(self, tmp_path):
        from backend.fileerase.residuals import scan_residuals
        from backend.fileerase.models import ResidualStatus
        f = _make_text_file(tmp_path)
        findings = scan_residuals(str(f))
        valid = set(s.value for s in ResidualStatus)
        for finding in findings:
            assert finding.status.value in valid


# ── Engine integration tests ──────────────────────────────────────────────────

class TestFileEraseEngine:

    @pytest.mark.asyncio
    async def test_single_file_erased(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest, FileEraseStatus
        f = _make_text_file(tmp_path, size=512)
        req = FileEraseRequest(paths=[str(f)], standard="ZERO_FILL",
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-001")
        assert result.succeeded == 1
        assert result.failed == 0
        assert not f.exists(), "File should be unlinked after erase"

    @pytest.mark.asyncio
    async def test_recursive_folder_erased(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        d, files = _make_dir_with_files(tmp_path)
        req = FileEraseRequest(paths=[str(d)], recursive=True,
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-002")
        assert result.total_files == 3
        assert result.succeeded == 3
        for f in files:
            assert not f.exists()
        assert not d.exists(), "An emptied selected directory should be removed last"

    def test_collect_files_skips_symlink(self, tmp_path):
        from backend.fileerase.patterns import collect_files
        target = _make_text_file(tmp_path, "target.txt")
        link = tmp_path / "selected-link.txt"
        link.symlink_to(target)
        assert collect_files([str(link)], recursive=False, glob_pattern=None) == []
        assert target.exists()

    @pytest.mark.asyncio
    async def test_glob_selection(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        d, files = _make_dir_with_files(tmp_path)
        # Add a non-.txt file that should NOT be erased
        keeper = d / "keep.log"
        keeper.write_bytes(b"keep me")
        req = FileEraseRequest(paths=[str(d)], recursive=True,
                               glob_pattern="**/*.txt",
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-003")
        assert result.total_files == 3
        assert keeper.exists(), "Non-.txt file should not be erased"

    @pytest.mark.asyncio
    async def test_demo_mode_no_writes(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        f = _make_text_file(tmp_path, size=512)
        original = f.read_bytes()
        req = FileEraseRequest(paths=[str(f)], demo_mode=True,
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-004")
        assert f.exists(), "Demo mode must not unlink file"
        assert f.read_bytes() == original, "Demo mode must not overwrite file"
        assert result.simulated is True

    @pytest.mark.asyncio
    async def test_dod_3pass_erase(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        f = _make_text_file(tmp_path, size=512)
        req = FileEraseRequest(paths=[str(f)], standard="DOD_3PASS",
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-005")
        assert result.succeeded == 1
        assert result.file_results[0].passes_written == 3
        assert not f.exists()

    @pytest.mark.asyncio
    async def test_missing_file_is_skipped(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest, FileEraseStatus
        req = FileEraseRequest(paths=["/nonexistent/path/file.txt"],
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-006")
        # No files found → zero total_files, not a crash
        assert result.total_files == 0

    @pytest.mark.asyncio
    async def test_jpeg_metadata_processed(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest, MetadataStatus
        f = _make_jpeg(tmp_path)
        req = FileEraseRequest(paths=[str(f)], sanitise_metadata=True,
                               scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-007")
        assert result.succeeded == 1
        meta = result.file_results[0].metadata
        assert meta.status in (
            MetadataStatus.REMOVED, MetadataStatus.NOT_AVAILABLE, MetadataStatus.FAILED
        )

    @pytest.mark.asyncio
    async def test_audit_records_created(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        from backend.audit import database as audit_db
        f = _make_text_file(tmp_path, size=256)
        req = FileEraseRequest(paths=[str(f)], sanitise_metadata=False,
                               scan_residuals=False)
        result = await run_file_erase(req, "FE-AUDIT-001")
        records = await audit_db.get_records_for_operation("FE-AUDIT-001")
        assert len(records) >= 2
        actions = [r["action"] for r in records]
        assert "FILE_ERASE_STARTED" in actions
        assert "FILE_ERASE_COMPLETED" in actions

    @pytest.mark.asyncio
    async def test_residual_scan_runs(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        f = _make_text_file(tmp_path, size=256)
        req = FileEraseRequest(paths=[str(f)], sanitise_metadata=False,
                               scan_residuals=True)
        result = await run_file_erase(req, "FE-TEST-008")
        # Residuals should have been scanned (list may be empty on clean system)
        assert isinstance(result.file_results[0].residuals, list)

    @pytest.mark.asyncio
    async def test_sha256_before_recorded(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        f = _make_text_file(tmp_path, size=256)
        expected_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        req = FileEraseRequest(paths=[str(f)], sanitise_metadata=False,
                               scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-009")
        assert result.file_results[0].sha256_before == expected_hash

    @pytest.mark.asyncio
    async def test_multiple_files_all_erased(self, tmp_path):
        from backend.fileerase.engine import run_file_erase
        from backend.fileerase.models import FileEraseRequest
        files = [_make_text_file(tmp_path, f"f{i}.txt", 256) for i in range(5)]
        req = FileEraseRequest(paths=[str(f) for f in files],
                               sanitise_metadata=False, scan_residuals=False)
        result = await run_file_erase(req, "FE-TEST-010")
        assert result.succeeded == 5
        assert result.failed == 0
        for f in files:
            assert not f.exists()


# ── API tests ─────────────────────────────────────────────────────────────────

class TestFileEraseAPI:

    @pytest.mark.asyncio
    async def test_filesystems_endpoint(self, client):
        resp = await client.get("/api/fileerase/filesystems")
        assert resp.status_code == 200
        badges = resp.json()
        assert len(badges) >= 5
        names = [b["name"] for b in badges]
        assert any("ext4" in n.lower() for n in names)
        assert any("ntfs" in n.lower() or "NTFS" in n for n in names)

    @pytest.mark.asyncio
    async def test_preview_single_file(self, client, tmp_path):
        f = _make_text_file(tmp_path, size=1024)
        resp = await client.post("/api/fileerase/preview",
                                 json={"paths": [str(f)]})
        assert resp.status_code == 200
        d = resp.json()
        assert d["total_files"] == 1
        assert d["total_size_bytes"] == f.stat().st_size
        assert d["filesystem"] != ""

    @pytest.mark.asyncio
    async def test_preview_empty_paths(self, client):
        resp = await client.post("/api/fileerase/preview",
                                 json={"paths": ["/nonexistent/path"]})
        assert resp.status_code == 200
        d = resp.json()
        assert d["total_files"] == 0

    @pytest.mark.asyncio
    async def test_start_erase_returns_operation_id(self, client, tmp_path):
        f = _make_text_file(tmp_path, size=256)
        resp = await client.post("/api/fileerase/start",
                                 json={"paths": [str(f)], "demo_mode": True})
        assert resp.status_code == 200
        d = resp.json()
        assert d["operation_id"].startswith("OP-")
        assert d["status"] == "QUEUED"

    @pytest.mark.asyncio
    async def test_start_erase_nonexistent_returns_404(self, client):
        resp = await client.post("/api/fileerase/start",
                                 json={"paths": ["/nonexistent/file.txt"]})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_status_endpoint(self, client, tmp_path):
        import asyncio
        f = _make_text_file(tmp_path, size=256)
        resp = await client.post("/api/fileerase/start",
                                 json={"paths": [str(f)], "demo_mode": True})
        op_id = resp.json()["operation_id"]
        await asyncio.sleep(0.5)
        resp2 = await client.get(f"/api/fileerase/{op_id}/status")
        assert resp2.status_code == 200
        assert "status" in resp2.json()

    @pytest.mark.asyncio
    async def test_status_unknown_op_404(self, client):
        resp = await client.get("/api/fileerase/NO-SUCH-OP/status")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_full_erase_via_api(self, client, tmp_path):
        """Real erase (not demo mode) via API — file must be gone after."""
        import asyncio
        f = _make_text_file(tmp_path, size=256)
        resp = await client.post("/api/fileerase/start",
                                 json={"paths": [str(f)], "demo_mode": False,
                                       "sanitise_metadata": False,
                                       "scan_residuals": False})
        op_id = resp.json()["operation_id"]
        await asyncio.sleep(1.0)
        resp2 = await client.get(f"/api/fileerase/{op_id}/status")
        d = resp2.json()
        assert d["status"] == "COMPLETED"
        assert d["succeeded"] >= 1
        assert not f.exists()

    @pytest.mark.asyncio
    async def test_audit_chain_valid_after_fileerase(self, client, tmp_path):
        import asyncio
        f = _make_text_file(tmp_path, size=256)
        await client.post("/api/fileerase/start",
                          json={"paths": [str(f)], "demo_mode": True})
        await asyncio.sleep(0.5)
        resp = await client.post("/api/audit/verify")
        assert resp.json()["valid"] is True
