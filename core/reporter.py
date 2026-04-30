"""
core/reporter.py — Export scan results as Markdown or JSON reports.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

import config
from models.schema import ScanResult

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SCORE_EMOJI = {
    "high": "🎯",
    "medium": "🔶",
    "low": "🔹",
}


def generate_markdown_report(scan: ScanResult) -> str:
    """Generate a comprehensive Markdown bug bounty report."""
    ts = datetime.fromisoformat(scan.timestamp).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# Bug Bounty Recon Report: {scan.domain}")
    lines.append(f"\n**Scan ID:** `{scan.scan_id}`  ")
    lines.append(f"**Target:** `{scan.domain}`  ")
    lines.append(f"**Timestamp:** {ts}  ")
    lines.append(f"**Status:** {scan.status}  ")
    lines.append(f"**Tools Used:** {', '.join(scan.tools_used) if scan.tools_used else 'N/A'}  ")
    if scan.tools_skipped:
        lines.append(f"**Tools Skipped (not installed):** {', '.join(scan.tools_skipped)}  ")

    # ── Executive Summary ──
    lines.append("\n---\n## Executive Summary\n")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Subdomains | {len(scan.subdomains)} |")
    lines.append(f"| Live Hosts | {len(scan.live_hosts)} |")
    lines.append(f"| URLs Collected | {len(scan.urls)} |")
    lines.append(f"| Open Ports | {len(scan.open_ports)} |")
    lines.append(f"| Vulnerabilities | {len(scan.vulnerabilities)} |")
    lines.append(f"| High Priority Targets | {len(scan.score_summary.get('high', []))} |")
    lines.append(f"| Medium Priority Targets | {len(scan.score_summary.get('medium', []))} |")

    # ── AI Analysis ──
    if scan.ai_analysis:
        lines.append("\n---\n## AI Security Analysis\n")
        lines.append(scan.ai_analysis)

    # ── High Priority Targets ──
    lines.append("\n---\n## Priority Targets\n")
    if scan.score_summary.get("high"):
        lines.append("### 🎯 HIGH Priority\n")
        for t in scan.score_summary["high"][:20]:
            lines.append(f"- {t}")
    if scan.score_summary.get("medium"):
        lines.append("\n### 🔶 MEDIUM Priority\n")
        for t in scan.score_summary["medium"][:20]:
            lines.append(f"- {t}")

    # ── Attack Paths ──
    if scan.attack_paths:
        lines.append("\n---\n## Attack Path Simulation\n")
        for i, path in enumerate(scan.attack_paths[:10], 1):
            sev = path.get("severity", "medium")
            lines.append(f"### {i}. {path.get('vulnerability_type', 'Unknown')} "
                         f"[{SEVERITY_EMOJI.get(sev, '⚪')} {sev.upper()}]")
            lines.append(f"\n**Target:** `{path.get('target', '')}`  ")
            lines.append(f"**Confidence:** {path.get('confidence', 'medium').upper()}  ")
            lines.append(f"\n**Reasoning:**  \n{path.get('reasoning', '')}\n")
            lines.append("**Steps:**")
            for step in path.get("steps", []):
                lines.append(f"{step}")
            lines.append("")

    # ── Intelligence Findings ──
    intel = scan.intel_tags
    lines.append("\n---\n## Intelligence Findings\n")

    if intel.high_value_endpoints:
        lines.append(f"### High-Value Endpoints ({len(intel.high_value_endpoints)})\n")
        for ep in intel.high_value_endpoints[:30]:
            lines.append(f"- `{ep}`")

    if intel.idor_candidates:
        lines.append(f"\n### IDOR Candidates ({len(intel.idor_candidates)})\n")
        for u in intel.idor_candidates[:20]:
            lines.append(f"- `{u}`")

    if intel.ssrf_candidates:
        lines.append(f"\n### SSRF Candidates ({len(intel.ssrf_candidates)})\n")
        for u in intel.ssrf_candidates[:20]:
            lines.append(f"- `{u}`")

    if intel.open_redirect_candidates:
        lines.append(f"\n### Open Redirect Candidates ({len(intel.open_redirect_candidates)})\n")
        for u in intel.open_redirect_candidates[:20]:
            lines.append(f"- `{u}`")

    if intel.xss_candidates:
        lines.append(f"\n### XSS Candidates ({len(intel.xss_candidates)})\n")
        for u in intel.xss_candidates[:20]:
            lines.append(f"- `{u}`")

    if intel.auth_exposure_candidates:
        lines.append(f"\n### Auth/Token Exposure Candidates ({len(intel.auth_exposure_candidates)})\n")
        for u in intel.auth_exposure_candidates[:20]:
            lines.append(f"- `{u}`")

    if intel.interesting_ports:
        lines.append(f"\n### Interesting Ports\n")
        for p in intel.interesting_ports:
            lines.append(f"- `{p}`")

    # ── Vulnerabilities ──
    if scan.vulnerabilities:
        lines.append("\n---\n## Nuclei Vulnerability Findings\n")
        for vuln in sorted(scan.vulnerabilities, key=lambda v: _sev_order(v.severity)):
            emoji = SEVERITY_EMOJI.get(vuln.severity.lower(), "⚪")
            lines.append(f"### {emoji} {vuln.name} [{vuln.severity.upper()}]")
            lines.append(f"\n- **Template:** `{vuln.template_id}`")
            lines.append(f"- **Host:** `{vuln.host}`")
            lines.append(f"- **Matched At:** `{vuln.matched_at}`")
            if vuln.description:
                lines.append(f"- **Description:** {vuln.description}")
            if vuln.tags:
                lines.append(f"- **Tags:** {', '.join(vuln.tags)}")
            lines.append("")

    # ── Subdomains ──
    lines.append("\n---\n## Discovered Subdomains\n")
    lines.append(f"Total: **{len(scan.subdomains)}**\n")
    if scan.subdomains:
        lines.append("```")
        lines.extend(sorted(scan.subdomains)[:200])
        lines.append("```")

    # ── Live Hosts ──
    if scan.live_hosts:
        lines.append("\n---\n## Live Hosts\n")
        lines.append("| URL | Status | Title | Tech | Score |")
        lines.append("|-----|--------|-------|------|-------|")
        for h in scan.live_hosts[:100]:
            tech = ", ".join(h.technologies[:3]) if h.technologies else "-"
            lines.append(
                f"| `{h.url}` | {h.status_code} | "
                f"{h.title[:40] if h.title else '-'} | {tech} | "
                f"{SCORE_EMOJI.get(h.score, '')} {h.score} |"
            )

    # ── Open Ports ──
    if scan.open_ports:
        lines.append("\n---\n## Open Ports\n")
        lines.append("| Host | Port | Service | Protocol |")
        lines.append("|------|------|---------|----------|")
        for p in scan.open_ports[:100]:
            lines.append(f"| `{p.host}` | {p.port} | {p.service} | {p.protocol} |")

    # ── Footer ──
    lines.append("\n---")
    lines.append(f"\n*Report generated by AI Bug Bounty Recon Assistant*  ")
    lines.append(f"*{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

    return "\n".join(lines)


def save_report(scan: ScanResult) -> dict:
    """Save both markdown and JSON reports. Returns paths dict."""
    scan_id = scan.scan_id
    md_path = config.REPORTS_DIR / f"{scan_id}.md"
    json_path = config.REPORTS_DIR / f"{scan_id}.json"

    # Markdown
    md_content = generate_markdown_report(scan)
    md_path.write_text(md_content, encoding="utf-8")

    # JSON
    json_path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")

    logger.info(f"[reporter] Reports saved: {md_path}, {json_path}")
    return {"markdown": str(md_path), "json": str(json_path)}


def get_report_path(scan_id: str, fmt: str = "markdown") -> Optional[Path]:
    """Return the path to an existing report file."""
    ext = "md" if fmt == "markdown" else "json"
    path = config.REPORTS_DIR / f"{scan_id}.{ext}"
    return path if path.exists() else None


def _sev_order(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        severity.lower(), 5
    )
