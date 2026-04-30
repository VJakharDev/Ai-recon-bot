"""
config.py — Centralized configuration for the Bug Bounty Recon Assistant.
Reads from environment variables / .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Ensure ~/go/bin is in PATH for subprocess calls (gau, naabu, waybackurls)
_go_bin = str(Path.home() / "go" / "bin")
if _go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _go_bin

# Load .env from project root
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# ─── NVIDIA / LLM Config ────────────────────────────────────────────────────
NVIDIA_API_KEY: str = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"

PRIMARY_MODEL: str = "meta/llama-3.3-70b-instruct"
FALLBACK_MODEL: str = "meta/llama-3.1-8b-instruct"

LLM_TEMPERATURE: float = 0.2
LLM_MAX_TOKENS: int = 4096

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = DATA_DIR / "results"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "scans.db"

# Ensure directories exist
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Recon Tool Config ───────────────────────────────────────────────────────
TOOL_TIMEOUT: int = int(os.getenv("TOOL_TIMEOUT", "300"))  # seconds per tool
AMASS_ENABLED: bool = os.getenv("AMASS_ENABLED", "true").lower() == "true"
NUCLEI_UPDATE_TEMPLATES   = os.getenv("NUCLEI_UPDATE_TEMPLATES", "false").lower() == "true"

# ─── High-Value Paths ────────────────────────────────────────────────────────
HIGH_VALUE_PATHS = [
    "/admin", "/administrator", "/login", "/signin", "/signup",
    "/register", "/dashboard", "/api", "/api/v1", "/api/v2",
    "/graphql", "/swagger", "/swagger-ui", "/openapi.json",
    "/config", "/configuration", "/backup", "/debug", "/console",
    "/actuator", "/health", "/metrics", "/env", "/info",
    "/phpinfo.php", "/.git", "/.env", "/robots.txt",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/panel", "/cpanel", "/webmail", "/mail",
    "/phpmyadmin", "/adminer", "/dbadmin",
    "/jenkins", "/jira", "/confluence",
    "/solr", "/elastic", "/kibana",
]

# ─── Vulnerability Parameter Patterns ────────────────────────────────────────
IDOR_PARAMS = ["id", "user", "uid", "user_id", "account", "account_id",
               "profile", "order", "order_id", "invoice", "file", "doc"]

OPEN_REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl",
                        "return_url", "redirect_uri", "redirect_url",
                        "forward", "goto", "destination", "redir"]

SSRF_PARAMS = ["url", "host", "server", "proxy", "target", "dest",
               "destination", "uri", "path", "load", "fetch", "webhook",
               "callback", "endpoint", "out", "reference"]

XSS_PARAMS = ["q", "s", "search", "query", "keyword", "term", "input",
              "name", "text", "message", "comment", "content", "data"]

AUTH_PARAMS = ["token", "key", "secret", "auth", "access_token", "api_key",
               "apikey", "jwt", "bearer", "session", "password", "pass"]

# ─── Scoring Weights ─────────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "vuln_critical": 100,
    "vuln_high": 70,
    "vuln_medium": 40,
    "vuln_low": 10,
    "high_value_endpoint": 30,
    "idor_param": 25,
    "ssrf_param": 25,
    "open_redirect_param": 20,
    "xss_param": 15,
    "auth_param": 20,
    "non_standard_port": 15,
    "live_host": 5,
}

SCORE_HIGH_THRESHOLD = 60
SCORE_MEDIUM_THRESHOLD = 20

# ─── Server Config ───────────────────────────────────────────────────────────
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))
DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
