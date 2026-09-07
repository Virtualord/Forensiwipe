"""End-to-end API contracts for the final demo workflow."""
import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app


@pytest.mark.asyncio
async def test_report_api_generates_downloadable_evidence_report():
    from backend.audit.service import record

    operation_id = "INTEGRATION-REPORT-001"
    await record(operation_id, "SYSTEM", "INTEGRATION_TEST", "demo/carving_demo.img", "SUCCESS")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        generated = await client.post(f"/api/reports/{operation_id}/generate")
        assert generated.status_code == 200
        report = await client.get(f"/api/reports/{operation_id}?format=pdf")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/pdf")
    assert report.content.startswith(b"%PDF")


@pytest.mark.asyncio
async def test_status_reports_the_backend_safety_boundary():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/status")
    assert response.status_code == 200
    assert response.json()["safety"]["safe_mode"] is True
