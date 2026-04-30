"""
core/tools.py — Async wrappers for all recon tools.
Uses absolute paths for Go binaries to avoid conflicts with system tools (e.g. Python httpx).
"""

import asyncio
import json
import os
import re
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Optional

import config
from models.schema import LiveHost, PortResult, Vulnerability

logger = logging.getLogger(__name__)

# ─── Resolve Go binary paths ─────────────────────────────────────────────────
# Prefer ~/go/bin/<tool> to avoid conflicts with system binaries (e.g. Python httpx)
_GO_BIN = Path.home() / "go" / "bin"

def _find_binary(name: str) -> Optional[str]:
    """Return absolute path of a binary, preferring ~/go/bin over system paths."""
    go_path = _GO_BIN / name
    if go_path.exists():
        return str(go_path)
    found = shutil.which(name)
    if found:
        # Skip Python httpx in venv — it's not the ProjectDiscovery tool
        if name == "httpx" and ("site-packages" in found or ".venv" in found):
            return None
        return found
    return None

# Pre-resolve all binary paths at import time
_BINS: Dict[str, Optional[str]] = {
    t: _find_binary(t)
    for t in ["subfinder", "amass", "httpx", "gau", "waybackurls", "naabu", "nuclei"]
}
logger.info(f"[tools] Resolved binaries: { {k: v for k, v in _BINS.items()} }")


# ─── Tool Availability Check ─────────────────────────────────────────────────

RECON_TOOLS = ["subfinder", "amass", "httpx", "gau", "naabu", "nuclei", "waybackurls"]

def check_tools() -> Tuple[List[str], List[str]]:
    """Return (available_tools, missing_tools)."""
    available = [t for t in RECON_TOOLS if _BINS.get(t)]
    missing   = [t for t in RECON_TOOLS if not _BINS.get(t)]
    return available, missing


# ─── Subprocess Helper ───────────────────────────────────────────────────────

async def run_tool(
    cmd: List[str],
    timeout: int = config.TOOL_TIMEOUT,
    input_data: Optional[str] = None,
) -> Tuple[str, str, int]:
    """Run a subprocess command async. Returns (stdout, stderr, returncode)."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            env={**os.environ},
        )
        stdin_bytes = input_data.encode() if input_data else None
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=stdin_bytes), timeout=timeout
            )
            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                process.returncode or 0,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            logger.warning(f"Tool timed out after {timeout}s: {cmd[0]}")
            return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        logger.warning(f"Tool not found: {cmd[0]}")
        return "", f"Tool not found: {cmd[0]}", -2
    except Exception as e:
        logger.error(f"Error running {cmd[0]}: {e}")
        return "", str(e), -3


# ─── Subfinder ───────────────────────────────────────────────────────────────

async def run_subfinder(domain: str) -> List[str]:
    bin_path = _BINS.get("subfinder")
    if not bin_path:
        return []
    logger.info(f"[subfinder] Starting for {domain}")
    stdout, stderr, code = await run_tool([
        bin_path, "-d", domain, "-silent", "-all",
    ])
    if code < 0:
        logger.warning(f"[subfinder] Failed: {stderr[:200]}")
        return []
    subdomains = [
        line.strip().lower()
        for line in stdout.splitlines()
        if line.strip() and is_valid_subdomain(line.strip(), domain)
    ]
    result = list(set(subdomains))
    logger.info(f"[subfinder] Found {len(result)} subdomains")
    return result


# ─── Amass ───────────────────────────────────────────────────────────────────

async def run_amass(domain: str) -> List[str]:
    if not config.AMASS_ENABLED:
        return []
    bin_path = _BINS.get("amass")
    if not bin_path:
        return []
    logger.info(f"[amass] Starting passive enum for {domain}")
    stdout, stderr, code = await run_tool([
        bin_path, "enum", "-passive", "-d", domain, "-timeout", "4", "-nocolor",
    ], timeout=300)
    if code < 0:
        logger.warning(f"[amass] Failed: {stderr[:200]}")
        return []
    subdomains = [
        line.strip().lower()
        for line in stdout.splitlines()
        if line.strip() and is_valid_subdomain(line.strip(), domain)
    ]
    result = list(set(subdomains))
    logger.info(f"[amass] Found {len(result)} subdomains")
    return result


# ─── Httpx ───────────────────────────────────────────────────────────────────

async def run_httpx(targets: List[str]) -> List[LiveHost]:
    """Probe HTTP/HTTPS targets using ProjectDiscovery httpx (Go binary).
    JSON fields: status_code, title, tech, webserver, content_length, url."""
    bin_path = _BINS.get("httpx")
    if not bin_path or not targets:
        return []
    logger.info(f"[httpx] Probing {len(targets)} targets using {bin_path}")

    input_data = "\n".join(targets)
    stdout, stderr, code = await run_tool([
        bin_path,
        "-silent", "-json",
        "-title", "-status-code",
        "-tech-detect", "-web-server",
        "-content-length",
        "-follow-redirects",
        "-timeout", "10",
        "-threads", "50",
        "-retries", "1",
    ], input_data=input_data, timeout=300)

    if code < 0:
        logger.warning(f"[httpx] Failed: {stderr[:300]}")
        return []

    hosts = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            url    = d.get("url") or d.get("input", "")
            status = d.get("status_code", 0)
            title  = d.get("title", "")
            tech   = d.get("tech", []) or []
            websvr = d.get("webserver", "")
            clen   = d.get("content_length", 0)
            if not url:
                continue
            hosts.append(LiveHost(
                url=url,
                status_code=int(status) if status else 0,
                title=title[:200] if title else "",
                technologies=tech if isinstance(tech, list) else [],
                content_length=int(clen) if clen else 0,
                webserver=websvr,
            ))
        except (json.JSONDecodeError, ValueError):
            continue

    logger.info(f"[httpx] Found {len(hosts)} live hosts")
    return hosts


# ─── GAU ─────────────────────────────────────────────────────────────────────

async def run_gau(domain: str) -> List[str]:
    bin_path = _BINS.get("gau")
    wb_path  = _BINS.get("waybackurls")
    logger.info(f"[gau] Fetching URLs for {domain}")

    stdout, stderr, code = ("", "", -99)

    if bin_path:
        stdout, stderr, code = await run_tool([
            bin_path, "--threads", "5", "--timeout", "30",
            "--blacklist", "png,jpg,gif,css,woff,woff2,ttf,eot,svg,ico,mp4,mp3",
            domain,
        ], timeout=180)

    if (code < 0 or not stdout.strip()) and wb_path:
        logger.info("[gau] Falling back to waybackurls")
        stdout, stderr, code = await run_tool([wb_path, domain], timeout=120)

    if not stdout.strip():
        logger.warning("[gau] No URLs returned")
        return []

    urls = list(set([
        line.strip() for line in stdout.splitlines()
        if line.strip() and line.startswith("http")
    ]))
    logger.info(f"[gau] Found {len(urls)} URLs")
    return urls[:5000]


# ─── Naabu ───────────────────────────────────────────────────────────────────

async def run_naabu(hosts: List[str]) -> List[PortResult]:
    bin_path = _BINS.get("naabu")
    if not bin_path or not hosts:
        return []

    # Strip protocol and path — naabu needs bare hostnames
    clean_hosts = list(set([
        h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        for h in hosts
    ]))
    logger.info(f"[naabu] Scanning {len(clean_hosts)} hosts")

    input_data = "\n".join(clean_hosts)
    stdout, stderr, code = await run_tool([
        bin_path, "-silent", "-json",
        "-top-ports", "1000",
        "-timeout", "5",
        "-rate", "1000",
        "-retries", "1",
    ], input_data=input_data, timeout=300)

    if code < 0:
        logger.warning(f"[naabu] Failed: {stderr[:200]}")
        return []

    ports = []
    seen = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            host  = d.get("host") or d.get("ip", "")
            port  = d.get("port", 0)
            proto = d.get("protocol", "tcp")
            key   = f"{host}:{port}"
            if port and key not in seen:
                seen.add(key)
                svc_info = d.get("service", {})
                service  = svc_info.get("name", "unknown") if isinstance(svc_info, dict) else "unknown"
                ports.append(PortResult(host=host, port=int(port), service=service, protocol=proto))
        except (json.JSONDecodeError, ValueError):
            continue

    logger.info(f"[naabu] Found {len(ports)} open ports")
    return ports


# ─── Nuclei ──────────────────────────────────────────────────────────────────

async def run_nuclei(hosts: List[str]) -> List[Vulnerability]:
    bin_path = _BINS.get("nuclei")
    if not bin_path or not hosts:
        return []
    logger.info(f"[nuclei] Scanning {len(hosts)} hosts")

    if config.NUCLEI_UPDATE_TEMPLATES:
        logger.info("[nuclei] Updating templates...")
        await run_tool([bin_path, "-ut", "-silent"], timeout=120)
        config.NUCLEI_UPDATE_TEMPLATES = False

    input_data = "\n".join(hosts[:100])
    stdout, stderr, code = await run_tool([
        bin_path, "-silent", "-j",   # -j = JSONL output (nuclei v3)
        "-ot",                        # omit encoded template (cleaner output)
        "-severity", "critical,high,medium",
        "-tags", "cve,misconfig,exposure,xss,sqli,ssrf,redirect",
        "-rate-limit", "50",
        "-timeout", "10",
        "-retries", "1",
    ], input_data=input_data, timeout=config.TOOL_TIMEOUT)

    if code < 0:
        logger.warning(f"[nuclei] Failed: {stderr[:200]}")
        return []

    vulns = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            info = d.get("info", {})
            vulns.append(Vulnerability(
                host=d.get("host", d.get("matched-at", "")),
                template_id=d.get("template-id", ""),
                name=info.get("name", ""),
                severity=info.get("severity", "info"),
                description=info.get("description", ""),
                matched_at=d.get("matched-at", ""),
                tags=info.get("tags", []) if isinstance(info.get("tags"), list) else [],
            ))
        except (json.JSONDecodeError, ValueError):
            continue

    logger.info(f"[nuclei] Found {len(vulns)} vulnerabilities")
    return vulns


# ─── Helpers ─────────────────────────────────────────────────────────────────

def is_valid_subdomain(value: str, domain: str) -> bool:
    if not value or len(value) > 253:
        return False
    if not value.endswith(domain):
        return False
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$'
    return bool(re.match(pattern, value))
