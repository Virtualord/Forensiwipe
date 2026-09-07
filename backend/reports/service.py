"""Report assembly service; routes do not generate documents directly."""
from __future__ import annotations
from backend.audit import database, verifier
from backend.core.config import get_settings
from backend.core import tasks
from backend.reports.json import base_report, write_json_report
from backend.reports.pdf import write_pdf_report

async def generate(operation_id: str) -> dict[str, str]:
    op = await tasks.get_operation(operation_id)
    records = await database.get_records_for_operation(operation_id)
    if op is None and not records: raise LookupError(operation_id)
    verification = await verifier.verify_chain()
    payload = base_report(op.model_dump(mode="json") if op else None, records, verification.model_dump(mode="json"))
    output_dir = get_settings().reports_dir / operation_id
    return {"json": str(write_json_report(output_dir / "report.json", payload)), "pdf": str(write_pdf_report(output_dir / "report.pdf", payload))}
