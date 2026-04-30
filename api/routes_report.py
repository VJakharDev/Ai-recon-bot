"""
api/routes_report.py — Report download endpoints.
GET /api/report/{id}        — Download Markdown report
GET /api/report/{id}/json   — Download JSON report
"""

import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from core.memory import get_scan
from core.reporter import get_report_path, save_report

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/report/{scan_id}", summary="Download Markdown report")
async def download_markdown_report(scan_id: str):
    """Download the Markdown bug bounty report for a completed scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("complete", "stopped"):
        raise HTTPException(
            status_code=400,
            detail=f"Report not available — scan status: {scan.status}"
        )

    path = get_report_path(scan_id, "markdown")
    if not path:
        # Regenerate if missing
        logger.info(f"[report] Regenerating markdown report for {scan_id}")
        save_report(scan)
        path = get_report_path(scan_id, "markdown")

    if not path:
        raise HTTPException(status_code=500, detail="Failed to generate report")

    return FileResponse(
        path=str(path),
        media_type="text/markdown",
        filename=f"recon-report-{scan.domain}-{scan_id[:8]}.md",
        headers={"Content-Disposition": f'attachment; filename="recon-{scan.domain}.md"'},
    )


@router.get("/report/{scan_id}/json", summary="Download JSON report")
async def download_json_report(scan_id: str):
    """Download the full JSON scan data."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("complete", "stopped"):
        raise HTTPException(
            status_code=400,
            detail=f"Report not available — scan status: {scan.status}"
        )

    path = get_report_path(scan_id, "json")
    if not path:
        save_report(scan)
        path = get_report_path(scan_id, "json")

    if not path:
        raise HTTPException(status_code=500, detail="Failed to generate report")

    return FileResponse(
        path=str(path),
        media_type="application/json",
        filename=f"recon-{scan.domain}-{scan_id[:8]}.json",
    )


@router.get("/report/{scan_id}/view", summary="View Markdown report in browser")
async def view_markdown_report(scan_id: str):
    """Return Markdown report as plain text for browser viewing."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    path = get_report_path(scan_id, "markdown")
    if not path and scan.status in ("complete", "stopped"):
        save_report(scan)
        path = get_report_path(scan_id, "markdown")

    if not path:
        raise HTTPException(status_code=404, detail="Report not yet available")

    content = path.read_text(encoding="utf-8")
    return PlainTextResponse(content, media_type="text/plain")
