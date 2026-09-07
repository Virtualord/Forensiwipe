"""Phase 4 report generation tests."""
from pathlib import Path
import pytest

@pytest.mark.asyncio
async def test_operation_report_contains_audit_evidence():
    from backend.audit.service import record
    from backend.reports.service import generate
    from backend.core.config import get_settings

    operation_id = "REPORT-TEST-001"
    await record(operation_id, "SYSTEM", "REPORT_TEST", "demo/evidence.img", "SUCCESS")
    paths = await generate(operation_id)

    json_report = Path(paths["json"])
    pdf_report = Path(paths["pdf"])
    assert json_report.is_file()
    assert pdf_report.is_file()
    contents = json_report.read_text(encoding="utf-8")
    assert operation_id in contents
    assert '"audit_verification"' in contents
    assert pdf_report.read_bytes().startswith(b"%PDF")
