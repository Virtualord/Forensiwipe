"""Concise evidential PDF report generation using ReportLab."""
from __future__ import annotations
from pathlib import Path
from typing import Any

def write_pdf_report(path: Path, payload: dict[str, Any]) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    operation = payload.get("operation") or {}
    story = [Paragraph("ForensiWipe", styles["Title"]), Paragraph("Digital Forensics &amp; Secure Sanitization", styles["Heading2"]), Spacer(1, 5 * mm)]
    rows = [["Operation ID", str(operation.get("operation_id", "Unavailable"))], ["Module", str(operation.get("module", "Unavailable"))], ["Target", str(operation.get("target", "Unavailable"))], ["Status", str(operation.get("status", "Unavailable"))], ["Generated", str(payload.get("generated_at", ""))]]
    table = Table(rows, colWidths=[42 * mm, 130 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EDF3")), ("GRID", (0, 0), (-1, -1), .25, colors.HexColor("#BBC5D1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 6)]))
    story += [table, Spacer(1, 6 * mm)]
    audit = payload.get("audit_verification", {})
    story += [Paragraph(f"Audit Chain: {'VERIFIED' if audit.get('valid') else 'TAMPERING DETECTED'}", styles["Heading2"]), Paragraph(str(audit.get("reason", "No verification result available.")), styles["BodyText"]), Spacer(1, 4 * mm), Paragraph("Audit records", styles["Heading2"])]
    records = payload.get("audit_records", [])
    if records:
        chain_rows = [["#", "Action", "Result", "Previous hash", "Current hash"]] + [[str(r.get("sequence", "")), str(r.get("action", "")), str(r.get("result", "")), str(r.get("previous_hash", ""))[:16], str(r.get("current_hash", ""))[:16]] for r in records]
        chain = Table(chain_rows, repeatRows=1, colWidths=[10*mm, 38*mm, 20*mm, 55*mm, 55*mm])
        chain.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .25, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EDF3")), ("FONTSIZE", (0, 0), (-1, -1), 7), ("PADDING", (0, 0), (-1, -1), 3)]))
        story.append(chain)
    else: story.append(Paragraph("No audit records were available for this operation.", styles["BodyText"]))
    SimpleDocTemplate(str(path), pagesize=A4, title="ForensiWipe Operation Report").build(story)
    return path
