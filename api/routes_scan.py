"""
api/routes_scan.py — Scan management endpoints.
POST /api/scan          — Start a new scan
GET  /api/scan/{id}     — Get scan result
GET  /api/scans         — List all scans
DELETE /api/scan/{id}   — Delete a scan
WS   /ws/scan/{id}      — Live progress stream
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks

import config
from models.schema import ScanRequest, ScanResult, ScanStatusResponse, LiveHost
from core import tools, intel, scorer, reporter
from core.memory import save_scan, get_scan, list_scans, delete_scan, update_scan_status
from core.llm import llm_engine

logger = logging.getLogger(__name__)
router = APIRouter()

# ─── In-memory state ─────────────────────────────────────────────────────────
# Maps scan_id -> {"progress": int, "task": str, "message": str}
_scan_progress: Dict[str, Dict[str, Any]] = {}

# WebSocket connections per scan
_ws_connections: Dict[str, list] = {}

# Cancellation flags: scan_id -> asyncio.Event (set = stop requested)
_cancel_flags: Dict[str, asyncio.Event] = {}


def _update_progress(scan_id: str, progress: int, task: str, message: str = ""):
    """Update progress and broadcast to WebSocket clients."""
    _scan_progress[scan_id] = {
        "progress": progress,
        "task": task,
        "message": message,
    }


async def _broadcast(scan_id: str, data: dict):
    """Send data to all WebSocket clients watching this scan."""
    dead = []
    for ws in _ws_connections.get(scan_id, []):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_connections.get(scan_id, []).remove(ws)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _is_cancelled(scan_id: str) -> bool:
    """Return True if a stop has been requested for this scan."""
    flag = _cancel_flags.get(scan_id)
    return flag is not None and flag.is_set()


async def _finalize_partial(scan: ScanResult, scan_id: str, progress_fn) -> ScanResult:
    """
    Run intel / scoring / attack-paths / AI / report on whatever data
    has been collected so far. Called on early stop.
    """
    await progress_fn(0, "Finalizing partial results", "Running intel analysis on collected data...")
    try:
        scan.intel_tags = intel.analyze_intel(scan)
        scan = scorer.score_all_hosts(scan)
        scan.attack_paths = scorer.build_attack_paths(scan)
        save_scan(scan)

        await progress_fn(0, "AI analysis", "Requesting AI analysis of partial data...")
        try:
            scan.ai_analysis = await llm_engine.analyze_scan(scan)
        except Exception as e:
            scan.ai_analysis = f"AI analysis skipped: {e}"

        reporter.save_report(scan)
    except Exception as e:
        logger.error(f"[scan] Error during partial finalization: {e}")
    return scan


# ─── Background Scan Worker ───────────────────────────────────────────────────

async def run_scan_pipeline(scan_id: str, domain: str, options: dict):
    """
    Full async recon pipeline. Checks cancellation flag between every phase.
    On stop: finalizes partial data and marks status 'stopped'.
    """
    scan = get_scan(scan_id)
    if not scan:
        logger.error(f"Scan {scan_id} not found at pipeline start")
        return

    available_tools, missing_tools = tools.check_tools()
    scan.tools_skipped = missing_tools
    scan.tools_used = []

    async def progress(pct: int, task: str, msg: str = ""):
        _update_progress(scan_id, pct, task, msg)
        scan.progress = pct
        scan.current_task = task
        await _broadcast(scan_id, {
            "type": "progress",
            "progress": pct,
            "task": task,
            "message": msg,
        })

    async def check_stop() -> bool:
        """Returns True if scan was stopped; handles finalization + broadcast."""
        if not _is_cancelled(scan_id):
            return False
        logger.info(f"[scan] Stop requested for {scan_id} — finalizing partial results")
        await progress(scan.progress, "Stopping...", "Finalizing collected data...")
        scan_ref = await _finalize_partial(scan, scan_id, progress)
        scan_ref.status = "stopped"
        scan_ref.current_task = "Stopped by user"
        save_scan(scan_ref)
        await _broadcast(scan_id, {
            "type": "stopped",
            "scan_id": scan_id,
            "progress": scan_ref.progress,
            "summary": {
                "subdomains": len(scan_ref.subdomains),
                "live_hosts": len(scan_ref.live_hosts),
                "vulnerabilities": len(scan_ref.vulnerabilities),
            }
        })
        return True

    try:
        scan.status = "running"
        save_scan(scan)
        await progress(2, "Initializing scan", f"Starting recon for {domain}")

        # ── Phase 1: Subdomain Enumeration ──────────────────────────────────
        await progress(5, "Subdomain enumeration", "Running subfinder...")
        subdomains = set()

        if "subfinder" in available_tools:
            sf_results = await tools.run_subfinder(domain)
            subdomains.update(sf_results)
            scan.tools_used.append("subfinder")
            await progress(15, "Subdomain enumeration",
                           f"subfinder found {len(sf_results)} subdomains")

        if await check_stop(): return

        amass_enabled = options.get("amass_enabled", config.AMASS_ENABLED)
        if "amass" in available_tools and amass_enabled:
            await progress(16, "Subdomain enumeration", "Running amass (passive)...")
            amass_results = await tools.run_amass(domain)
            subdomains.update(amass_results)
            scan.tools_used.append("amass")
            await progress(30, "Subdomain enumeration",
                           f"amass found {len(amass_results)} subdomains")

        if await check_stop(): return

        subdomains.add(domain)
        scan.subdomains = sorted(subdomains)
        save_scan(scan)

        # ── Phase 2: HTTP Probing ────────────────────────────────────────────
        await progress(32, "HTTP probing", f"Probing {len(scan.subdomains)} hosts with httpx...")
        if "httpx" in available_tools and scan.subdomains:
            probe_targets = []
            for sub in scan.subdomains:
                probe_targets.append(f"http://{sub}")
                probe_targets.append(f"https://{sub}")
            live_hosts = await tools.run_httpx(probe_targets)
            scan.live_hosts = live_hosts
            scan.tools_used.append("httpx")
            await progress(50, "HTTP probing", f"Found {len(live_hosts)} live hosts")
        else:
            scan.live_hosts = [LiveHost(url=f"https://{domain}", status_code=200)]

        save_scan(scan)
        if await check_stop(): return

        # ── Phase 3: URL Harvesting ──────────────────────────────────────────
        await progress(52, "URL harvesting", "Fetching historical URLs from gau/waybackurls...")
        if "gau" in available_tools or "waybackurls" in available_tools:
            urls = await tools.run_gau(domain)
            scan.urls = urls
            scan.tools_used.append("gau" if "gau" in available_tools else "waybackurls")
            await progress(62, "URL harvesting", f"Collected {len(urls)} URLs")

        save_scan(scan)
        if await check_stop(): return

        # ── Phase 4: Port Scanning ───────────────────────────────────────────
        await progress(63, "Port scanning", "Running naabu on live hosts...")
        if "naabu" in available_tools and scan.live_hosts:
            live_urls = [h.url for h in scan.live_hosts]
            open_ports = await tools.run_naabu(live_urls)
            scan.open_ports = open_ports
            scan.tools_used.append("naabu")
            await progress(75, "Port scanning", f"Found {len(open_ports)} open ports")

        save_scan(scan)
        if await check_stop(): return

        # ── Phase 5: Vulnerability Scanning ─────────────────────────────────
        await progress(76, "Vulnerability scanning",
                       "Running nuclei on live hosts (this takes a while)...")
        if "nuclei" in available_tools and scan.live_hosts:
            live_urls = [h.url for h in scan.live_hosts]
            vulns = await tools.run_nuclei(live_urls)
            scan.vulnerabilities = vulns
            scan.tools_used.append("nuclei")
            await progress(88, "Vulnerability scanning", f"Found {len(vulns)} vulnerabilities")

        save_scan(scan)
        if await check_stop(): return

        # ── Phase 6: Intelligence Analysis ──────────────────────────────────
        await progress(89, "Intel analysis", "Running pattern detection engine...")
        scan.intel_tags = intel.analyze_intel(scan)

        # ── Phase 7: Scoring ─────────────────────────────────────────────────
        await progress(91, "Scoring targets", "Scoring all targets...")
        scan = scorer.score_all_hosts(scan)

        # ── Phase 8: Attack Paths ────────────────────────────────────────────
        await progress(93, "Building attack paths", "Generating attack path simulation...")
        scan.attack_paths = scorer.build_attack_paths(scan)

        save_scan(scan)
        if await check_stop(): return

        # ── Phase 9: AI Analysis ─────────────────────────────────────────────
        await progress(94, "AI analysis", "Sending data to LLM for intelligent analysis...")
        try:
            scan.ai_analysis = await llm_engine.analyze_scan(scan)
            await progress(98, "AI analysis", "AI analysis complete")
        except Exception as e:
            logger.error(f"[scan] AI analysis failed: {e}")
            scan.ai_analysis = f"AI analysis failed: {str(e)}"

        save_scan(scan)

        # ── Phase 10: Report Generation ──────────────────────────────────────
        await progress(99, "Generating report", "Writing bug bounty report...")
        reporter.save_report(scan)

        scan.status = "complete"
        scan.progress = 100
        scan.current_task = "Scan complete"
        save_scan(scan)

        await _broadcast(scan_id, {
            "type": "complete",
            "progress": 100,
            "scan_id": scan_id,
            "summary": {
                "subdomains": len(scan.subdomains),
                "live_hosts": len(scan.live_hosts),
                "vulnerabilities": len(scan.vulnerabilities),
                "high_priority": len(scan.score_summary.get("high", [])),
            }
        })
        logger.info(f"[scan] Scan {scan_id} completed for {domain}")

    except Exception as e:
        logger.exception(f"[scan] Fatal error in scan {scan_id}: {e}")
        scan.status = "failed"
        scan.error = str(e)
        save_scan(scan)
        await _broadcast(scan_id, {"type": "error", "message": str(e)})
    finally:
        # Clean up cancel flag
        _cancel_flags.pop(scan_id, None)


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Start a new recon scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Kick off a full recon scan against a domain. Returns scan_id immediately."""
    domain = request.domain.strip().lower()
    # Strip protocol if provided
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain or len(domain) < 3 or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain name")

    scan = ScanResult(domain=domain)
    save_scan(scan)

    _scan_progress[scan.scan_id] = {"progress": 0, "task": "Queued", "message": ""}
    _ws_connections[scan.scan_id] = []
    _cancel_flags[scan.scan_id] = asyncio.Event()  # not set = keep running

    background_tasks.add_task(
        run_scan_pipeline, scan.scan_id, domain, request.options or {}
    )

    return {
        "scan_id": scan.scan_id,
        "domain": domain,
        "status": "pending",
        "message": f"Scan started for {domain}",
    }


@router.get("/scan/{scan_id}", summary="Get scan results")
async def get_scan_result(scan_id: str):
    """Get the full results of a scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scan/{scan_id}/status", summary="Get scan status")
async def get_scan_status(scan_id: str):
    """Get lightweight scan status and progress."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    live_progress = _scan_progress.get(scan_id, {})
    return {
        "scan_id": scan_id,
        "domain": scan.domain,
        "status": scan.status,
        "progress": live_progress.get("progress", scan.progress),
        "current_task": live_progress.get("task", scan.current_task),
    }


@router.get("/scans", summary="List all scans")
async def list_all_scans():
    """List all past scans."""
    return {"scans": list_scans(limit=50)}


@router.post("/scan/{scan_id}/stop", summary="Stop a running scan")
async def stop_scan(scan_id: str):
    """
    Request an immediate stop of a running scan.
    The pipeline finishes its current tool, then runs intel/scoring/AI
    on whatever data it has collected, and saves a partial report.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("running", "pending"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not running (status: {scan.status})"
        )

    flag = _cancel_flags.get(scan_id)
    if flag:
        flag.set()
        logger.info(f"[scan] Stop signal sent for {scan_id}")
    else:
        # Pipeline may not have started yet — mark directly
        scan.status = "stopped"
        scan.current_task = "Stopped by user"
        save_scan(scan)

    return {
        "scan_id": scan_id,
        "message": "Stop signal sent. Finalizing partial results...",
    }


@router.delete("/scan/{scan_id}", summary="Delete a scan")
async def remove_scan(scan_id: str):
    """Delete a scan and its report files."""
    if not get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    success = delete_scan(scan_id)
    return {"success": success, "scan_id": scan_id}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """Real-time progress stream for an active scan."""
    await websocket.accept()

    if scan_id not in _ws_connections:
        _ws_connections[scan_id] = []
    _ws_connections[scan_id].append(websocket)

    # Send current state immediately
    scan = get_scan(scan_id)
    if scan:
        progress = _scan_progress.get(scan_id, {})
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id,
            "status": scan.status,
            "progress": progress.get("progress", scan.progress),
            "task": progress.get("task", scan.current_task),
        })

    try:
        while True:
            # Keep connection alive; data is pushed via _broadcast
            await asyncio.sleep(1)
            # Check if scan is done
            current_scan = get_scan(scan_id)
            if current_scan and current_scan.status in ("complete", "failed", "stopped"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        if scan_id in _ws_connections:
            try:
                _ws_connections[scan_id].remove(websocket)
            except ValueError:
                pass
