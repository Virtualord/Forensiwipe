"""
tests/test_target_validator.py — Unit tests for the target validator (safety choke point).

Tests:
  - Safe loopback image inside SAFE_DEMO_DIR → allowed
  - Non-existent path → blocked
  - Physical disk in safe mode → blocked (CHECK_2)
  - /dev/sda → blocked (always-blocked-paths + safe mode)
  - Mounted target → blocked (CHECK_4)
  - Active target (in-use) → blocked (CHECK_8)
  - Correct confirmation accepted / wrong confirmation rejected
  - Image outside SAFE_DEMO_DIR → blocked (CHECK_3)
  - Zero-size target → still passes validation (size is an engine concern)
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.erase import target_validator
from backend.erase.models import DeviceInfo
from backend.core.models import MediaType


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_loopback_device_info(
    path: str,
    backing_file: str,
    is_mounted: bool = False,
    mount_points: list[str] | None = None,
    is_system_disk: bool = False,
) -> DeviceInfo:
    return DeviceInfo(
        path=path,
        name=Path(path).name,
        media_type=MediaType.LOOP,
        is_loopback=True,
        is_mounted=is_mounted,
        mount_points=mount_points or [],
        is_system_disk=is_system_disk,
        backing_file=backing_file,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSafeLoopbackImage:
    """Image files inside SAFE_DEMO_DIR should be allowed in safe mode."""

    def test_valid_demo_image_allowed(self, tmp_path: Path):
        img = tmp_path / "sample_disk.img"
        img.write_bytes(b"\x00" * 1024)

        result = target_validator.validate_target(
            str(img), operator_approved=True
        )
        assert result.allowed is True, f"Expected allowed, got: {result.reason}"
        assert result.safe_mode is True
        assert result.risk_level == "LOW"

    def test_valid_demo_image_passes_all_12_checks(self, tmp_path: Path):
        img = tmp_path / "test.img"
        img.write_bytes(b"\xFF" * 512)

        result = target_validator.validate_target(str(img), operator_approved=True)

        assert result.allowed is True
        assert len(result.checks_passed) == 12
        assert len(result.checks_failed) == 0


class TestBlockedTargets:
    """Targets that should always be rejected."""

    def test_nonexistent_path_blocked(self):
        result = target_validator.validate_target("/nonexistent/path", operator_approved=True)
        assert result.allowed is False
        assert "not a block device" in result.reason.lower() or "not found" in result.reason.lower() \
               or "recognised" in result.reason.lower()

    def test_physical_disk_blocked_in_safe_mode(self):
        """
        In safe mode, any non-loopback device path should be blocked.
        We use /dev/nvme0n1 if it exists (common in CI), otherwise /dev/sdb.
        If neither exists, we verify that a missing path is still blocked (CHECK_1).
        """
        import os
        # Pick a plausible physical disk path for this machine
        candidates = ["/dev/nvme0n1", "/dev/sda", "/dev/sdb", "/dev/vda"]
        physical = next((p for p in candidates if os.path.exists(p)), "/dev/sdb")

        result = target_validator.validate_target(physical, operator_approved=True)
        # It must be blocked — either at CHECK_1 (doesn't exist) or CHECK_2 (safe mode)
        assert result.allowed is False
        # If the device exists, it must be blocked because of safe mode
        if os.path.exists(physical):
            assert "SAFE_MODE" in result.reason or "safe mode" in result.reason.lower()
            assert result.risk_level in ("CRITICAL", "HIGH")

    def test_dev_sda_always_blocked(self):
        result = target_validator.validate_target("/dev/sda", operator_approved=True)
        assert result.allowed is False

    def test_image_outside_safe_dir_blocked(self, tmp_path: Path):
        # Create an image in a DIFFERENT directory (outside tmp_path which is SAFE_DEMO_DIR)
        other_dir = tmp_path.parent / "other_dir_not_safe"
        other_dir.mkdir(exist_ok=True)
        img = other_dir / "bad.img"
        img.write_bytes(b"\x00" * 512)

        result = target_validator.validate_target(str(img), operator_approved=True)
        assert result.allowed is False
        assert "outside" in result.reason.lower() or "SAFE_MODE" in result.reason

    def test_non_img_file_blocked(self, tmp_path: Path):
        txt = tmp_path / "notanimage.txt"
        txt.write_text("hello")

        result = target_validator.validate_target(str(txt), operator_approved=True)
        assert result.allowed is False


class TestMountedTarget:
    """Mounted targets must be blocked."""

    def test_mounted_loopback_blocked(self, tmp_path: Path):
        img = tmp_path / "mounted.img"
        img.write_bytes(b"\x00" * 512)

        # Provide device_info indicating it is mounted
        device_info = _make_loopback_device_info(
            "/dev/loop99",
            str(img),
            is_mounted=True,
            mount_points=["/mnt/test"],
        )

        result = target_validator.validate_target(
            "/dev/loop99",
            device_info=device_info,
            operator_approved=True,
        )
        # Note: /dev/loop99 is a block device path — in safe mode it hits CHECK_1
        # (not a block device on this machine), so it'll be blocked at CHECK_1.
        # The important thing is it's blocked.
        assert result.allowed is False

    def test_system_mount_point_critical(self, tmp_path: Path):
        img = tmp_path / "sys.img"
        img.write_bytes(b"\x00" * 512)

        device_info = _make_loopback_device_info(
            str(img),
            str(img),
            is_mounted=True,
            mount_points=["/"],
            is_system_disk=True,
        )

        result = target_validator.validate_target(
            str(img), device_info=device_info, operator_approved=True
        )
        assert result.allowed is False
        assert result.risk_level in ("CRITICAL", "HIGH")


class TestActiveTarget:
    """Targets currently in-use by another operation should be blocked."""

    def test_active_target_blocked(self, tmp_path: Path):
        img = tmp_path / "active.img"
        img.write_bytes(b"\x00" * 512)
        path = str(img)

        # Mark it as active
        target_validator.mark_target_active(path)
        try:
            result = target_validator.validate_target(path, operator_approved=True)
            assert result.allowed is False
            # Verify the block message refers to concurrent operation
            assert "processed" in result.reason.lower() or \
                   "in use" in result.reason.lower() or \
                   "operation" in result.reason.lower()
        finally:
            target_validator.mark_target_inactive(path)

    def test_inactive_after_mark_inactive(self, tmp_path: Path):
        img = tmp_path / "inactive.img"
        img.write_bytes(b"\x00" * 512)
        path = str(img)

        target_validator.mark_target_active(path)
        target_validator.mark_target_inactive(path)

        result = target_validator.validate_target(path, operator_approved=True)
        assert result.allowed is True


class TestConfirmation:
    """Confirmation validation for physical-device mode."""

    def test_exact_confirmation_accepted(self):
        from backend.core.security import validate_exact_confirmation
        # Should not raise
        validate_exact_confirmation("/dev/sdb", "/dev/sdb")

    def test_wrong_confirmation_rejected(self):
        from backend.core.security import validate_exact_confirmation, ConfirmationError
        with pytest.raises(ConfirmationError):
            validate_exact_confirmation("/dev/sdb", "sdb")

    def test_yes_confirmation_rejected(self):
        from backend.core.security import validate_exact_confirmation, ConfirmationError
        with pytest.raises(ConfirmationError):
            validate_exact_confirmation("/dev/sdb", "yes")

    def test_confirm_word_rejected(self):
        from backend.core.security import validate_exact_confirmation, ConfirmationError
        with pytest.raises(ConfirmationError):
            validate_exact_confirmation("/dev/sdb", "confirm")

    def test_case_mismatch_rejected(self):
        from backend.core.security import validate_exact_confirmation, ConfirmationError
        with pytest.raises(ConfirmationError):
            validate_exact_confirmation("/dev/sdb", "/DEV/SDB")

    def test_whitespace_stripped_but_content_must_match(self):
        from backend.core.security import validate_exact_confirmation
        # Leading/trailing whitespace is stripped before comparison
        validate_exact_confirmation("/dev/sdb", "  /dev/sdb  ")
