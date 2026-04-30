"""
core/scorer.py — Target scoring engine.
Assigns HIGH / MEDIUM / LOW scores to each live host based on
vulnerability signals, intel tags, and port findings.
"""

import logging
from typing import List
from models.schema import ScanResult, LiveHost
import config

logger = logging.getLogger(__name__)


def score_all_hosts(scan: ScanResult) -> ScanResult:
    """
    Score all live hosts and populate scan.score_summary.
    Modifies the scan object in-place and returns it.
    """
    intel = scan.intel_tags
    vuln_map = _build_vuln_map(scan)
    port_map = _build_port_map(scan)

    # Sets for fast lookup
    high_value_set = set(intel.high_value_endpoints)
    idor_set = set(intel.idor_candidates)
    ssrf_set = set(intel.ssrf_candidates)
    redirect_set = set(intel.open_redirect_candidates)
    xss_set = set(intel.xss_candidates)
    auth_set = set(intel.auth_exposure_candidates)

    high, medium, low = [], [], []

    for host in scan.live_hosts:
        score = 0
        url = host.url

        # Vulnerability-based scoring
        for vuln in vuln_map.get(url, []):
            sev = vuln.severity.lower()
            score += config.SCORE_WEIGHTS.get(f"vuln_{sev}", 0)

        # Intel-based scoring
        if any(url.startswith(ep) or ep.startswith(url) for ep in high_value_set):
            score += config.SCORE_WEIGHTS["high_value_endpoint"]
        if any(url in u for u in idor_set):
            score += config.SCORE_WEIGHTS["idor_param"]
        if any(url in u for u in ssrf_set):
            score += config.SCORE_WEIGHTS["ssrf_param"]
        if any(url in u for u in redirect_set):
            score += config.SCORE_WEIGHTS["open_redirect_param"]
        if any(url in u for u in xss_set):
            score += config.SCORE_WEIGHTS["xss_param"]
        if any(url in u for u in auth_set):
            score += config.SCORE_WEIGHTS["auth_param"]

        # Port-based scoring
        host_clean = url.replace("https://", "").replace("http://", "").split("/")[0]
        if host_clean in port_map:
            for port in port_map[host_clean]:
                if port not in (80, 443):
                    score += config.SCORE_WEIGHTS["non_standard_port"]

        # Base score for being alive
        score += config.SCORE_WEIGHTS["live_host"]

        # Assign bucket
        if score >= config.SCORE_HIGH_THRESHOLD:
            label = "high"
            high.append(url)
        elif score >= config.SCORE_MEDIUM_THRESHOLD:
            label = "medium"
            medium.append(url)
        else:
            label = "low"
            low.append(url)

        host.score = label
        host.score_value = score

    scan.score_summary = {"high": high, "medium": medium, "low": low}

    logger.info(
        f"[scorer] Scored {len(scan.live_hosts)} hosts: "
        f"{len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW"
    )
    return scan


def _build_vuln_map(scan: ScanResult) -> dict:
    """Map host URL to list of vulnerabilities for fast lookup."""
    vuln_map: dict = {}
    for vuln in scan.vulnerabilities:
        # Normalize key to match live_host URLs
        for host in scan.live_hosts:
            if vuln.host in host.url or host.url in vuln.host:
                if host.url not in vuln_map:
                    vuln_map[host.url] = []
                vuln_map[host.url].append(vuln)
    return vuln_map


def _build_port_map(scan: ScanResult) -> dict:
    """Map hostname to list of open ports for fast lookup."""
    port_map: dict = {}
    for pr in scan.open_ports:
        if pr.host not in port_map:
            port_map[pr.host] = []
        port_map[pr.host].append(pr.port)
    return port_map


def build_attack_paths(scan: ScanResult) -> list:
    """
    Generate structured attack path objects based on scored hosts and intel.
    Returns a list of attack path dicts for the report.
    """
    paths = []
    intel = scan.intel_tags

    # IDOR attack paths
    for url in intel.idor_candidates[:5]:
        paths.append({
            "target": url,
            "vulnerability_type": "IDOR (Insecure Direct Object Reference)",
            "severity": "high",
            "confidence": "medium",
            "reasoning": (
                f"URL contains parameter patterns (id=, user=, uid=, etc.) "
                f"that suggest direct object references. "
                f"Changing the parameter value may access other users' data."
            ),
            "steps": [
                f"1. Create two test accounts on {scan.domain}",
                f"2. With account A, access: {url}",
                f"3. Note the ID/reference value in the parameter",
                f"4. Switch to account B and use the same ID from account A",
                f"5. If you see account A's data — it's IDOR",
                "6. Test with IDs: 1, 2, 100, -1, 0, ../1, %2F1",
            ],
        })

    # SSRF attack paths
    for url in intel.ssrf_candidates[:5]:
        paths.append({
            "target": url,
            "vulnerability_type": "SSRF (Server-Side Request Forgery)",
            "severity": "critical",
            "confidence": "medium",
            "reasoning": (
                f"URL contains parameter patterns (url=, host=, proxy=, etc.) "
                f"that may cause the server to make outbound requests. "
                f"Can lead to internal network access, metadata exposure, or RCE."
            ),
            "steps": [
                f"1. Test with Burp Collaborator or interactsh: {url}&url=https://your-collaborator.com",
                "2. Try internal IP ranges: 127.0.0.1, 169.254.169.254, 10.0.0.1",
                "3. Test cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS)",
                "4. Try DNS rebinding bypass if direct IP is blocked",
                "5. Test with file:// protocol: file:///etc/passwd",
                "6. Use URL encoding bypasses: http://127.0.0.1%2F, http://0x7f000001",
            ],
        })

    # Open Redirect attack paths
    for url in intel.open_redirect_candidates[:3]:
        paths.append({
            "target": url,
            "vulnerability_type": "Open Redirect",
            "severity": "medium",
            "confidence": "high",
            "reasoning": (
                "URL contains redirect parameter (redirect=, url=, next=, etc.). "
                "If not validated, can be used for phishing and OAuth token theft."
            ),
            "steps": [
                f"1. Test: {url}?redirect=https://evil.com",
                "2. Try bypasses: //evil.com, /\\evil.com, https:///evil.com",
                "3. Check if it can be chained with OAuth to steal tokens",
                f"4. Test: {url}?redirect=javascript:alert(1) for XSS via redirect",
            ],
        })

    # XSS attack paths
    for url in intel.xss_candidates[:3]:
        paths.append({
            "target": url,
            "vulnerability_type": "XSS (Cross-Site Scripting)",
            "severity": "medium",
            "confidence": "medium",
            "reasoning": (
                "URL contains search/query parameters that may reflect user input. "
                "Reflected XSS can lead to session hijacking and credential theft."
            ),
            "steps": [
                f"1. Test basic reflection: {url}?q=<script>alert(1)</script>",
                "2. Try HTML injection first: <img src=x onerror=alert(1)>",
                "3. Test bypasses for WAF: <ScRiPt>alert`1`</ScRiPt>",
                "4. Check for DOM XSS in page source (document.location, innerHTML)",
                "5. Use dalfox or XSStrike for automated testing",
            ],
        })

    # Vulnerability-based paths
    critical_vulns = [v for v in scan.vulnerabilities if v.severity in ("critical", "high")]
    for vuln in critical_vulns[:5]:
        paths.append({
            "target": vuln.matched_at,
            "vulnerability_type": vuln.name,
            "severity": vuln.severity,
            "confidence": "high",
            "reasoning": (
                f"Nuclei detected {vuln.name} (template: {vuln.template_id}). "
                f"{vuln.description}"
            ),
            "steps": [
                f"1. Verify manually: curl -v '{vuln.matched_at}'",
                f"2. Review the nuclei template: nuclei -t {vuln.template_id} -u {vuln.host}",
                "3. Document the full request/response",
                "4. Assess business impact and write PoC",
            ],
        })

    return paths
