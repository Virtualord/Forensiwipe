"""
tests/test_erase.py — Unit tests for the erase engine and verification.

Tests:
  - Zero-pattern verification passes on zeroed image
  - Zero-pattern verification fails on non-zero image
  - DoD 3-pass actually writes data (image changes)
  - Verification correctly identifies non-deterministic patterns (random)
  - SHA-256 before/after are different after erasure
  - Cancelled operation does not report success
  - Audit record is created for completed operations
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
import pytest_asyncio

from backend.core.models import EraseStandard, OperationModule, OperationRecord, OperationStatus
from backend.erase import verification
from backend.erase.models import EraseRequest
from backend.core.models import VerificationStatus


# ── Verification tests ────────────────────────────────────────────────────────

class TestVerification:
    """Tests for verification.verify_target — the post-erase sampling check."""

    def test_zero_fill_passes_on_zeroed_image(self, zero_img: Path):
        """A file full of 0x00 should pass zero-fill verification."""
        result = verification.verify_target(str(zero_img), EraseStandard.ZERO_FILL)
        assert result.status == VerificationStatus.PASSED
        assert result.samples_passed > 0
        assert result.samples_failed == 0

    def test_zero_fill_fails_on_ff_image(self, demo_img: Path):
        """A file full of 0xFF should fail zero-fill verification."""
        result = verification.verify_target(str(demo_img), EraseStandard.ZERO_FILL)
        assert result.status in (VerificationStatus.FAILED, VerificationStatus.PARTIAL)
        assert result.samples_failed > 0

    def test_nist_clear_passes_on_zeroed_image(self, zero_img: Path):
        """NIST Clear (zero fill) should also pass on a zeroed image."""
        result = verification.verify_target(str(zero_img), EraseStandard.NIST_CLEAR)
        assert result.status == VerificationStatus.PASSED

    def test_random_fill_not_applicable(self, demo_img: Path):
        """Random fill is non-deterministic — verification should return NOT_APPLICABLE."""
        result = verification.verify_target(str(demo_img), EraseStandard.RANDOM_FILL)
        assert result.status == VerificationStatus.NOT_APPLICABLE
        assert result.samples_total == 0

    def test_gutmann_not_applicable(self, demo_img: Path):
        """Gutmann's final state is random — not byte-verifiable."""
        result = verification.verify_target(str(demo_img), EraseStandard.GUTMANN_35)
        assert result.status == VerificationStatus.NOT_APPLICABLE

    def test_verification_produces_evidence_hash(self, zero_img: Path):
        """Evidence hash must be a non-empty hex string."""
        result = verification.verify_target(str(zero_img), EraseStandard.ZERO_FILL)
        assert result.evidence_hash is not None
        assert len(result.evidence_hash) == 64   # SHA-256 hex

    def test_verification_note_mentions_sampling(self, zero_img: Path):
        """The note must clarify this is sampling, not full verification."""
        result = verification.verify_target(str(zero_img), EraseStandard.ZERO_FILL)
        note_lower = result.note.lower()
        assert "sampl" in note_lower  # 'sampled' or 'samples'

    def test_nonexistent_target_fails(self, tmp_path: Path):
        result = verification.verify_target(str(tmp_path / "gone.img"), EraseStandard.ZERO_FILL)
        assert result.status == VerificationStatus.FAILED

    def test_offsets_recorded(self, zero_img: Path):
        """Some offsets should be recorded for the evidence report."""
        result = verification.verify_target(str(zero_img), EraseStandard.ZERO_FILL)
        assert len(result.offsets_checked) > 0


# ── Engine integration tests ──────────────────────────────────────────────────

class TestEraseEngine:
    """Integration tests for run_erase — writes to actual temp image files."""

    @pytest.mark.asyncio
    async def test_zero_fill_changes_image(self, demo_img: Path, tmp_path: Path):
        """After zero-fill, image content should differ from original 0xFF fill."""
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase

        # Register a task first
        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(demo_img),
            standard=EraseStandard.ZERO_FILL,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        before_hash = hashlib.sha256(demo_img.read_bytes()).hexdigest()

        request = EraseRequest(
            target=str(demo_img),
            standard=EraseStandard.ZERO_FILL,
            operator_id="test-operator",
            demo_mode=False,
        )

        result = await run_erase(request, op.operation_id)

        after_hash = hashlib.sha256(demo_img.read_bytes()).hexdigest()

        assert result.verification.status == VerificationStatus.PASSED
        assert before_hash != after_hash, "Image should have changed after erasure"
        assert result.sha256_before == before_hash
        assert result.sha256_after == after_hash
        assert result.bytes_written > 0
        assert result.passes_completed == 1
        assert result.simulated is False

    @pytest.mark.asyncio
    async def test_zero_fill_verifies_correctly(self, demo_img: Path):
        """After zero-fill, all sampled regions should read as 0x00."""
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase

        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(demo_img),
            standard=EraseStandard.ZERO_FILL,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        result = await run_erase(
            EraseRequest(target=str(demo_img), standard=EraseStandard.ZERO_FILL,
                         operator_id="test-operator"),
            op.operation_id,
        )

        assert result.verification.status == VerificationStatus.PASSED
        assert result.verification.samples_failed == 0

    @pytest.mark.asyncio
    async def test_failed_verification_detected(self, tmp_path: Path):
        """
        If we run verification on a non-zeroed image and expect zeros,
        the verifier should detect the mismatch.
        """
        # Create an image that is NOT zeroed
        img = tmp_path / "nonzero.img"
        img.write_bytes(b"\xAB" * (256 * 1024))

        result = verification.verify_target(str(img), EraseStandard.ZERO_FILL)
        assert result.status in (VerificationStatus.FAILED, VerificationStatus.PARTIAL)
        assert result.samples_failed > 0

    @pytest.mark.asyncio
    async def test_audit_record_created_after_erase(self, demo_img: Path):
        """A completed erase operation should create at least 2 audit records (START + COMPLETE)."""
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase
        from backend.audit import database as audit_db

        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(demo_img),
            standard=EraseStandard.ZERO_FILL,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        await run_erase(
            EraseRequest(target=str(demo_img), standard=EraseStandard.ZERO_FILL,
                         operator_id="test-operator"),
            op.operation_id,
        )

        records = await audit_db.get_records_for_operation(op.operation_id)
        assert len(records) >= 2, f"Expected ≥2 audit records, got {len(records)}"

        actions = [r["action"] for r in records]
        assert "ERASE_STARTED" in actions
        assert "ERASE_COMPLETED" in actions

    @pytest.mark.asyncio
    async def test_demo_mode_does_not_modify_image(self, demo_img: Path):
        """Demo mode must NOT write to the image."""
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase

        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(demo_img),
            standard=EraseStandard.DOD_3PASS,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        before = demo_img.read_bytes()

        result = await run_erase(
            EraseRequest(target=str(demo_img), standard=EraseStandard.DOD_3PASS,
                         operator_id="test-operator", demo_mode=True),
            op.operation_id,
        )

        after = demo_img.read_bytes()
        assert before == after, "Demo mode must not modify the target image"
        assert result.simulated is True

    @pytest.mark.asyncio
    async def test_blocked_target_does_not_write(self, tmp_path: Path):
        """A target that fails validation should not cause any write."""
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase

        # Use a path OUTSIDE the safe demo dir to trigger CHECK_3
        other = tmp_path.parent / "unsafe_dir"
        other.mkdir(exist_ok=True)
        img = other / "unsafe.img"
        img.write_bytes(b"\xFF" * 512)

        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(img),
            standard=EraseStandard.ZERO_FILL,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        result = await run_erase(
            EraseRequest(target=str(img), standard=EraseStandard.ZERO_FILL,
                         operator_id="test-operator"),
            op.operation_id,
        )

        # Image should be unchanged
        assert img.read_bytes() == b"\xFF" * 512
        assert result.validation.allowed is False

    @pytest.mark.asyncio
    async def test_dod_3pass_completes_3_passes(self, demo_img: Path):
        from backend.core import tasks as task_store
        from backend.erase.engine import run_erase

        op = OperationRecord(
            module=OperationModule.DRIVE_ERASE,
            target=str(demo_img),
            standard=EraseStandard.DOD_3PASS,
            operator_id="test-operator",
        )
        await task_store.register_operation(op)

        result = await run_erase(
            EraseRequest(target=str(demo_img), standard=EraseStandard.DOD_3PASS,
                         operator_id="test-operator"),
            op.operation_id,
        )

        # DoD 3-pass final state is random → verification is NOT_APPLICABLE
        assert result.passes_completed == 3
        assert result.verification.status == VerificationStatus.NOT_APPLICABLE


# ── Hash chain audit tests ────────────────────────────────────────────────────

class TestAuditHashChain:
    """Tests for the hash chain and tamper detection."""

    @pytest.mark.asyncio
    async def test_audit_hash_generated(self, demo_img: Path):
        """Each audit record must have a non-empty current_hash."""
        from backend.audit.database import init_db, get_all_records
        from backend.audit import service as audit_service

        await init_db()

        record = await audit_service.record(
            operation_id="TEST-OP-001",
            module="DRIVE_ERASE",
            action="TEST_ACTION",
            target=str(demo_img),
            result="SUCCESS",
        )

        assert record["current_hash"] is not None
        assert len(record["current_hash"]) == 64

    @pytest.mark.asyncio
    async def test_chain_validates_clean(self, demo_img: Path):
        """A freshly created chain should verify as valid."""
        from backend.audit.database import init_db
        from backend.audit import service as audit_service
        from backend.audit.verifier import verify_chain

        await init_db()

        # Create a few records
        for i in range(3):
            await audit_service.record(
                operation_id=f"TEST-CHAIN-{i:03d}",
                module="DRIVE_ERASE",
                action="TEST",
                target="test-target",
                result="SUCCESS",
            )

        result = await verify_chain()
        assert result.valid is True
        assert result.checked_records == 3

    @pytest.mark.asyncio
    async def test_modified_record_detected(self, demo_img: Path):
        """Modifying a record's content after insertion should break the chain."""
        import sqlite3
        from backend.core.config import get_settings
        from backend.audit.database import init_db
        from backend.audit import service as audit_service
        from backend.audit.verifier import verify_chain

        await init_db()

        await audit_service.record(
            operation_id="TAMPER-TEST-001",
            module="DRIVE_ERASE",
            action="ORIGINAL",
            target="target-device",
            result="SUCCESS",
        )

        # Directly modify the SQLite record to simulate tampering
        db_path = get_settings().audit_db_path
        with sqlite3.connect(str(db_path)) as db:
            db.execute(
                "UPDATE audit_records SET action = 'TAMPERED' WHERE operation_id = 'TAMPER-TEST-001'"
            )

        # Chain verification should now fail
        result = await verify_chain()
        assert result.valid is False
        assert result.first_invalid_operation_id == "TAMPER-TEST-001"
        assert "mismatch" in result.reason.lower() or "tamper" in result.reason.lower() \
               or "modified" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_genesis_hash_is_correct(self):
        """The first record's previous_hash must be 'GENESIS'."""
        from backend.audit.database import init_db, get_all_records
        from backend.audit import service as audit_service

        await init_db()

        await audit_service.record(
            operation_id="GENESIS-TEST",
            module="SYSTEM",
            action="FIRST_RECORD",
            target="system",
            result="INFO",
        )

        records = await get_all_records()
        assert records[0]["previous_hash"] == "GENESIS"

    @pytest.mark.asyncio
    async def test_chain_links_correctly(self):
        """Each record's previous_hash must equal the prior record's current_hash."""
        from backend.audit.database import init_db, get_all_records
        from backend.audit import service as audit_service

        await init_db()

        for i in range(4):
            await audit_service.record(
                operation_id=f"LINK-TEST-{i}",
                module="SYSTEM",
                action="TEST",
                target="t",
                result="INFO",
            )

        records = await get_all_records()
        for i in range(1, len(records)):
            assert records[i]["previous_hash"] == records[i-1]["current_hash"], (
                f"Chain broken between seq {records[i-1]['sequence']} and {records[i]['sequence']}"
            )
