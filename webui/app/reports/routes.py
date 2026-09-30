"""routes.py - Report download endpoints (Agent 5).

Endpoints
---------
    GET /api/campaigns/{campaign_id}/report?format=html|pdf&name=<title>
        Generate and download the aggregated report for a whole campaign.

    GET /api/runs/{run_id}/report?format=html|pdf&name=<title>
        Generate and download the report for a single run.

Response contract
-----------------
    format=html (default)
        200, Content-Type: text/html; charset=utf-8
        Content-Disposition: attachment; filename="<name>.html"
        Header X-Report-Format: html

    format=pdf, backend available (weasyprint or wkhtmltopdf)
        200, Content-Type: application/pdf
        Content-Disposition: attachment; filename="<name>.pdf"
        Headers X-Report-Format: pdf, X-Report-PDF-Available: true

    format=pdf, no backend available  -> graceful degradation
        200, Content-Type: text/html; charset=utf-8   (the HTML report)
        Content-Disposition: attachment; filename="<name>.html"
        Headers:
            X-Report-Format: html
            X-Report-PDF-Available: false
            X-Report-Note: <install hint>
        The body is the fully usable HTML report; only the PDF wrapper is
        missing. No dependency is ever required at import time.

    Unknown campaign / run id -> 404.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from .export import (
    ReportResult,
    build_campaign_report_result,
    build_run_report_result,
)

router = APIRouter(prefix="/api", tags=["reports"])

_MEDIA_TYPES = {"html": "text/html; charset=utf-8", "pdf": "application/pdf"}


def _download_name(result: ReportResult) -> str:
    """Filename offered to the browser (matches the produced format)."""
    return result.path.name


def _to_response(result: ReportResult) -> FileResponse:
    """Turn a ReportResult into a FileResponse with the documented headers."""
    headers = {
        "Content-Disposition": f'attachment; filename="{_download_name(result)}"',
        "X-Report-Format": result.fmt,
    }
    if result.requested_fmt == "pdf":
        headers["X-Report-PDF-Available"] = "true" if result.pdf_available else "false"
        if not result.pdf_available and result.message:
            # Header values must stay single-line.
            headers["X-Report-Note"] = " ".join(result.message.split())
    return FileResponse(
        path=str(result.path),
        media_type=_MEDIA_TYPES.get(result.fmt, "application/octet-stream"),
        headers=headers,
    )


@router.get("/campaigns/{campaign_id}/report")
def campaign_report(
    campaign_id: int,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
    name: Optional[str] = Query(default=None),
) -> FileResponse:
    """Generate and download a campaign report (HTML, or PDF best-effort)."""
    try:
        result = build_campaign_report_result(campaign_id, name=name, fmt=format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_response(result)


@router.get("/runs/{run_id}/report")
def run_report(
    run_id: int,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
    name: Optional[str] = Query(default=None),
) -> FileResponse:
    """Generate and download a single-run report (HTML, or PDF best-effort)."""
    try:
        result = build_run_report_result(run_id, name=name, fmt=format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_response(result)
