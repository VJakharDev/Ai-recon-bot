"""
core/intel.py — Intelligence layer: pattern detection & vulnerability tagging.
Runs before LLM analysis to enrich the scan data.
"""

import re
import logging
from typing import List, Dict
from urllib.parse import urlparse, parse_qs

import config
from models.schema import ScanResult, IntelReport, LiveHost

logger = logging.getLogger(__name__)

# Port → service significance mapping
SIGNIFICANT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker daemon (unencrypted!)",
    2376: "Docker daemon TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis (often unauthenticated!)",
    7001: "WebLogic",
    7199: "Cassandra",
    8080: "HTTP-Alt (often admin)",
    8443: "HTTPS-Alt",
    8888: "Jupyter Notebook",
    9000: "PHP-FPM / SonarQube",
    9090: "Prometheus",
    9200: "Elasticsearch (unauthenticated!)",
    9300: "Elasticsearch cluster",
    27017: "MongoDB (often unauthenticated!)",
    27018: "MongoDB",
}

HIGH_RISK_SERVICES = {6379, 9200, 27017, 2375, 23}


def analyze_intel(scan: ScanResult) -> IntelReport:
    """
    Run all intel analysis on a completed scan.
    Returns an enriched IntelReport.
    """
    logger.info(f"[intel] Analyzing scan for {scan.domain}")

    intel = IntelReport()

    # 1. High-value endpoint detection
    intel.high_value_endpoints = _find_high_value_endpoints(
        scan.urls + [h.url for h in scan.live_hosts]
    )

    # 2. URL parameter analysis
    all_urls = scan.urls + [h.url for h in scan.live_hosts]
    param_analysis = _analyze_url_params(all_urls)

    intel.idor_candidates = param_analysis["idor"]
    intel.open_redirect_candidates = param_analysis["redirect"]
    intel.ssrf_candidates = param_analysis["ssrf"]
    intel.xss_candidates = param_analysis["xss"]
    intel.auth_exposure_candidates = param_analysis["auth"]

    # 3. Interesting port analysis
    intel.interesting_ports = _analyze_ports(scan.open_ports)

    # 4. Tag each live host
    for host in scan.live_hosts:
        _tag_live_host(host, intel, scan.urls)

    logger.info(
        f"[intel] Tagged: {len(intel.high_value_endpoints)} high-value endpoints, "
        f"{len(intel.idor_candidates)} IDOR, {len(intel.ssrf_candidates)} SSRF, "
        f"{len(intel.open_redirect_candidates)} OpenRedirect"
    )
    return intel


def _find_high_value_endpoints(urls: List[str]) -> List[str]:
    """Find URLs matching high-value path patterns."""
    found = []
    seen = set()
    for url in urls:
        try:
            parsed = urlparse(url.lower())
            path = parsed.path.rstrip("/")
            for hv_path in config.HIGH_VALUE_PATHS:
                if path == hv_path or path.startswith(hv_path + "/"):
                    key = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if key not in seen:
                        seen.add(key)
                        # Store original URL
                        found.append(url)
                    break
        except Exception:
            continue
    return found[:200]  # Cap to avoid huge lists


def _analyze_url_params(urls: List[str]) -> Dict[str, List[str]]:
    """Scan URL parameters and classify them by vulnerability type."""
    results = {
        "idor": [], "redirect": [], "ssrf": [],
        "xss": [], "auth": []
    }
    seen: Dict[str, set] = {k: set() for k in results}

    param_map = {
        "idor": config.IDOR_PARAMS,
        "redirect": config.OPEN_REDIRECT_PARAMS,
        "ssrf": config.SSRF_PARAMS,
        "xss": config.XSS_PARAMS,
        "auth": config.AUTH_PARAMS,
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)
            param_names_lower = {k.lower(): k for k in params.keys()}

            for vuln_type, pattern_list in param_map.items():
                for pattern in pattern_list:
                    if pattern.lower() in param_names_lower:
                        # Normalize URL for deduplication
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{pattern}="
                        if base not in seen[vuln_type]:
                            seen[vuln_type].add(base)
                            results[vuln_type].append(url)
                        break
        except Exception:
            continue

    # Cap each category
    for k in results:
        results[k] = results[k][:100]

    return results


def _analyze_ports(open_ports) -> List[str]:
    """Identify and annotate interesting/high-risk open ports."""
    interesting = []
    for port_result in open_ports:
        port = port_result.port
        if port in SIGNIFICANT_PORTS:
            service_note = SIGNIFICANT_PORTS[port]
            risk = " ⚠️ HIGH RISK" if port in HIGH_RISK_SERVICES else ""
            interesting.append(
                f"{port_result.host}:{port} ({service_note}){risk}"
            )
        elif port not in (80, 443):
            # Non-standard port — flag it
            interesting.append(
                f"{port_result.host}:{port} (non-standard{risk_label(port)})"
            )
    return interesting


def risk_label(port: int) -> str:
    """Return risk label string for non-standard ports."""
    admin_ports = {8080, 8443, 8888, 9090, 9000, 9001, 4848, 7001}
    if port in admin_ports:
        return " — possible admin panel"
    return ""


def _tag_live_host(host: LiveHost, intel: IntelReport, all_urls: List[str]) -> None:
    """Add intel tags directly to a LiveHost object."""
    tags = []
    url = host.url

    # Check if this host appears in any intel category
    if any(url in ep for ep in intel.high_value_endpoints):
        tags.append("high-value-endpoint")

    if any(url in u for u in intel.idor_candidates):
        tags.append("idor-candidate")
    if any(url in u for u in intel.ssrf_candidates):
        tags.append("ssrf-candidate")
    if any(url in u for u in intel.open_redirect_candidates):
        tags.append("open-redirect-candidate")
    if any(url in u for u in intel.xss_candidates):
        tags.append("xss-candidate")
    if any(url in u for u in intel.auth_exposure_candidates):
        tags.append("auth-exposure")

    # Tech-based tags
    for tech in host.technologies:
        tl = tech.lower()
        if any(x in tl for x in ["php", "asp", "coldfusion"]):
            tags.append("legacy-tech")
        if any(x in tl for x in ["wordpress", "drupal", "joomla"]):
            tags.append("cms")
        if "apache" in tl or "nginx" in tl or "iis" in tl:
            tags.append("known-webserver")

    host.intel_tags = tags


def build_intel_summary_for_llm(scan: ScanResult) -> str:
    """
    Build a concise, structured text summary of intel findings
    to prepend to the LLM prompt. Prioritizes signal over noise.
    """
    intel = scan.intel_tags
    lines = []

    lines.append(f"## Intelligence Report for {scan.domain}")
    lines.append(f"- **Subdomains found:** {len(scan.subdomains)}")
    lines.append(f"- **Live hosts:** {len(scan.live_hosts)}")
    lines.append(f"- **URLs collected:** {len(scan.urls)}")
    lines.append(f"- **Open ports:** {len(scan.open_ports)}")
    lines.append(f"- **Vulnerabilities found:** {len(scan.vulnerabilities)}")

    if intel.high_value_endpoints:
        lines.append(f"\n### High-Value Endpoints ({len(intel.high_value_endpoints)})")
        for ep in intel.high_value_endpoints[:20]:
            lines.append(f"  - {ep}")

    if intel.idor_candidates:
        lines.append(f"\n### IDOR Candidates ({len(intel.idor_candidates)})")
        for u in intel.idor_candidates[:15]:
            lines.append(f"  - {u}")

    if intel.ssrf_candidates:
        lines.append(f"\n### SSRF Candidates ({len(intel.ssrf_candidates)})")
        for u in intel.ssrf_candidates[:15]:
            lines.append(f"  - {u}")

    if intel.open_redirect_candidates:
        lines.append(f"\n### Open Redirect Candidates ({len(intel.open_redirect_candidates)})")
        for u in intel.open_redirect_candidates[:15]:
            lines.append(f"  - {u}")

    if intel.xss_candidates:
        lines.append(f"\n### XSS Candidates ({len(intel.xss_candidates)})")
        for u in intel.xss_candidates[:15]:
            lines.append(f"  - {u}")

    if intel.auth_exposure_candidates:
        lines.append(f"\n### Auth/Token Exposure Candidates ({len(intel.auth_exposure_candidates)})")
        for u in intel.auth_exposure_candidates[:10]:
            lines.append(f"  - {u}")

    if intel.interesting_ports:
        lines.append(f"\n### Interesting Ports")
        for p in intel.interesting_ports[:30]:
            lines.append(f"  - {p}")

    if scan.vulnerabilities:
        lines.append(f"\n### Nuclei Findings ({len(scan.vulnerabilities)})")
        for vuln in sorted(scan.vulnerabilities,
                           key=lambda v: severity_order(v.severity))[:20]:
            lines.append(
                f"  - [{vuln.severity.upper()}] {vuln.name} @ {vuln.matched_at}"
            )

    if scan.live_hosts:
        high_hosts = [h for h in scan.live_hosts if h.score == "high"]
        if high_hosts:
            lines.append(f"\n### High-Priority Hosts ({len(high_hosts)})")
            for h in high_hosts[:15]:
                lines.append(
                    f"  - {h.url} (score={h.score_value}) "
                    f"tags={','.join(h.intel_tags)}"
                )

    return "\n".join(lines)


def severity_order(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity.lower(), 5)
