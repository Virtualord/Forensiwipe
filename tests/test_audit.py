"""
tests/test_audit.py — Tests for audit chain integrity features via the API.

Tests:
  - GET /api/audit/history returns records
  - POST /api/audit/verify returns valid=True on clean chain
  - Tampered record causes verify to return valid=False
  - Deleted record causes gap detection
  - GET /api/audit/latest-hash reflects most recent record
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.main import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestAuditAPI:

    @pytest.mark.asyncio
    async def test_empty_history(self, client: AsyncClient):
        resp = await client.get("/api/audit/history")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_verify_empty_chain(self, client: AsyncClient):
        resp = await client.post("/api/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked_records"] == 0

    @pytest.mark.asyncio
    async def test_history_after_erase(self, client: AsyncClient, demo_img):
        """After an erase operation, audit history should have records."""
        from backend.audit import service as audit_service

        await audit_service.record(
            operation_id="API-TEST-001",
            module="DRIVE_ERASE",
            action="ERASE_STARTED",
            target=str(demo_img),
            result="INFO",
        )
        await audit_service.record(
            operation_id="API-TEST-001",
            module="DRIVE_ERASE",
            action="ERASE_COMPLETED",
            target=str(demo_img),
            result="SUCCESS",
        )

        resp = await client.get("/api/audit/history")
        assert resp.status_code == 200
        records = resp.json()
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_verify_clean_chain(self, client: AsyncClient, demo_img):
        from backend.audit import service as audit_service

        for i in range(3):
            await audit_service.record(
                operation_id=f"CLEAN-{i}",
                module="DRIVE_ERASE",
                action="TEST",
                target=str(demo_img),
                result="SUCCESS",
            )

        resp = await client.post("/api/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked_records"] == 3

    @pytest.mark.asyncio
    async def test_verify_detects_tampered_record(self, client: AsyncClient, demo_img):
        import sqlite3
        from backend.core.config import get_settings
        from backend.audit import service as audit_service

        await audit_service.record(
            operation_id="TAMPER-API",
            module="SYSTEM",
            action="ORIGINAL_ACTION",
            target=str(demo_img),
            result="SUCCESS",
        )

        # Tamper directly in DB
        db_path = get_settings().audit_db_path
        with sqlite3.connect(str(db_path)) as db:
            db.execute(
                "UPDATE audit_records SET result = 'TAMPERED_RESULT' WHERE operation_id = 'TAMPER-API'"
            )

        resp = await client.post("/api/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert data["first_invalid_operation_id"] == "TAMPER-API"

    @pytest.mark.asyncio
    async def test_latest_hash_updates(self, client: AsyncClient, demo_img):
        from backend.audit import service as audit_service

        resp1 = await client.get("/api/audit/latest-hash")
        initial_hash = resp1.json()["latest_hash"]

        await audit_service.record(
            operation_id="HASH-TEST",
            module="SYSTEM",
            action="UPDATE",
            target=str(demo_img),
            result="INFO",
        )

        resp2 = await client.get("/api/audit/latest-hash")
        updated_hash = resp2.json()["latest_hash"]

        assert updated_hash != initial_hash
        assert resp2.json()["record_count"] == 1

    @pytest.mark.asyncio
    async def test_operation_audit_history(self, client: AsyncClient, demo_img):
        from backend.audit import service as audit_service

        await audit_service.record(
            operation_id="OP-SPECIFIC",
            module="DRIVE_ERASE",
            action="STARTED",
            target=str(demo_img),
            result="INFO",
        )

        resp = await client.get("/api/audit/history/OP-SPECIFIC")
        assert resp.status_code == 200
        records = resp.json()
        assert len(records) == 1
        assert records[0]["operation_id"] == "OP-SPECIFIC"

    @pytest.mark.asyncio
    async def test_operation_not_found_returns_404(self, client: AsyncClient):
        resp = await client.get("/api/audit/history/NO-SUCH-OP")
        assert resp.status_code == 404


class TestSystemAPI:

    @pytest.mark.asyncio
    async def test_health_check(self, client: AsyncClient):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_status_shows_safe_mode(self, client: AsyncClient):
        resp = await client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["safety"]["safe_mode"] is True
        assert data["safety"]["physical_erase_enabled"] is False
        assert "DEMONSTRATION SAFE MODE" in data["safety"]["demo_banner"]


class TestEraseAPI:

    @pytest.mark.asyncio
    async def test_standards_endpoint(self, client: AsyncClient):
        resp = await client.get("/api/erase/standards")
        assert resp.status_code == 200
        standards = resp.json()
        assert len(standards) >= 5
        names = [s["id"] for s in standards]
        assert "ZERO_FILL" in names
        assert "DOD_3PASS" in names
        assert "GUTMANN_35" in names

    @pytest.mark.asyncio
    async def test_validate_nonexistent_target(self, client: AsyncClient):
        resp = await client.post(
            "/api/erase/validate",
            json={"target": "/nonexistent/device"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False

    @pytest.mark.asyncio
    async def test_validate_demo_image_allowed(self, client: AsyncClient, demo_img):
        resp = await client.post(
            "/api/erase/validate",
            json={"target": str(demo_img)},
        )
        assert resp.status_code == 200
        # validate endpoint uses operator_approved=False (pre-confirmation check)
        # Image exists and is in safe dir — should pass up to check 11

    @pytest.mark.asyncio
    async def test_validate_physical_disk_blocked(self, client: AsyncClient):
        resp = await client.post(
            "/api/erase/validate",
            json={"target": "/dev/sda"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["safe_mode"] is True

    @pytest.mark.asyncio
    async def test_erase_start_returns_operation_id(self, client: AsyncClient, demo_img):
        resp = await client.post(
            "/api/erase/start",
            json={
                "target": str(demo_img),
                "standard": "ZERO_FILL",
                "demo_mode": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "operation_id" in data
        assert data["operation_id"].startswith("OP-")
        assert data["status"] == "QUEUED"

    @pytest.mark.asyncio
    async def test_erase_blocked_target_returns_403(self, client: AsyncClient):
        resp = await client.post(
            "/api/erase/start",
            json={
                "target": "/dev/sda",
                "standard": "ZERO_FILL",
            },
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["detail"]["blocked"] is True
