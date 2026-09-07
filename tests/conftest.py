"""
tests/conftest.py — Shared pytest fixtures for ForensiWipe test suite.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio


# ── Temp directory fixture ────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """A temporary directory that is cleaned up after each test."""
    return tmp_path


# ── Demo-image fixture ────────────────────────────────────────────────────────

@pytest.fixture
def demo_img(tmp_path: Path) -> Path:
    """
    Create a small (1 MB) ext4-like binary image in a temp directory.

    We do NOT actually format it with mkfs — that requires root.
    For unit tests, we create a file filled with known data that
    the erase engine and verifier can operate on directly.
    """
    img = tmp_path / "test_disk.img"
    # 1 MB of 0xFF bytes (pre-existing "data")
    with open(img, "wb") as f:
        f.write(b"\xFF" * (1 * 1024 * 1024))
    return img


@pytest.fixture
def zero_img(tmp_path: Path) -> Path:
    """A 256 KB image already filled with zeros."""
    img = tmp_path / "zero_disk.img"
    with open(img, "wb") as f:
        f.write(b"\x00" * (256 * 1024))
    return img


# ── Environment override fixture ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def safe_env(tmp_path: Path, monkeypatch):
    """
    Override environment variables for every test:
    - SAFE_MODE=true (always)
    - SAFE_DEMO_DIR=tmp_path (so test images qualify as approved)
    - AUDIT_DB_PATH=tmp_path/test_audit.db
    - RECOVERED_DIR=tmp_path/recovered
    - REPORTS_DIR=tmp_path/reports
    """
    monkeypatch.setenv("SAFE_MODE", "true")
    monkeypatch.setenv("ALLOW_PHYSICAL_ERASE", "false")
    monkeypatch.setenv("SAFE_DEMO_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "test_audit.db"))
    monkeypatch.setenv("RECOVERED_DIR", str(tmp_path / "recovered"))
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))

    # Clear the lru_cache so Settings is re-read with patched env
    from backend.core.config import get_settings
    get_settings.cache_clear()

    yield

    # Re-clear after test too
    get_settings.cache_clear()



# ── Auto-initialise audit DB for every test ───────────────────────────────────

@pytest_asyncio.fixture(autouse=True)
async def auto_init_db(safe_env):
    """
    Ensure the audit database schema exists before every test.
    Depends on safe_env so the patched AUDIT_DB_PATH is active first.
    """
    from backend.audit.database import init_db
    await init_db()
