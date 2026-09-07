"""Operation report generation and retrieval endpoints."""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from backend.reports import service
router = APIRouter()

class ReportResponse(BaseModel):
    operation_id: str
    json_url: str
    pdf_url: str

@router.post("/{operation_id}/generate", response_model=ReportResponse)
async def generate_report(operation_id: str) -> ReportResponse:
    try: await service.generate(operation_id)
    except LookupError: raise HTTPException(status_code=404, detail=f"No operation or audit records for '{operation_id}'.")
    return ReportResponse(operation_id=operation_id, json_url=f"/api/reports/{operation_id}?format=json", pdf_url=f"/api/reports/{operation_id}?format=pdf")

@router.get("/{operation_id}")
async def get_report(operation_id: str, format: str = "pdf") -> FileResponse:
    if format not in {"pdf", "json"}: raise HTTPException(status_code=422, detail="format must be 'pdf' or 'json'.")
    try: paths = await service.generate(operation_id)
    except LookupError: raise HTTPException(status_code=404, detail=f"No operation or audit records for '{operation_id}'.")
    return FileResponse(Path(paths[format]), media_type="application/pdf" if format == "pdf" else "application/json", filename=f"forensiwipe-{operation_id}-report.{format}")
