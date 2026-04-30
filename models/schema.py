"""
models/schema.py — Pydantic data models for the Bug Bounty Recon Assistant.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


# ─── Recon Data Models ───────────────────────────────────────────────────────

class LiveHost(BaseModel):
    url: str
    status_code: int = 0
    title: str = ""
    technologies: List[str] = Field(default_factory=list)
    content_length: int = 0
    webserver: str = ""
    score: str = "low"  # high | medium | low
    score_value: int = 0
    intel_tags: List[str] = Field(default_factory=list)


class PortResult(BaseModel):
    host: str
    port: int
    service: str = "unknown"
    protocol: str = "tcp"


class Vulnerability(BaseModel):
    host: str
    template_id: str
    name: str
    severity: str  # critical | high | medium | low | info
    description: str = ""
    matched_at: str = ""
    tags: List[str] = Field(default_factory=list)


class IntelReport(BaseModel):
    high_value_endpoints: List[str] = Field(default_factory=list)
    idor_candidates: List[str] = Field(default_factory=list)
    xss_candidates: List[str] = Field(default_factory=list)
    ssrf_candidates: List[str] = Field(default_factory=list)
    open_redirect_candidates: List[str] = Field(default_factory=list)
    auth_exposure_candidates: List[str] = Field(default_factory=list)
    interesting_ports: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "pending"  # pending | running | complete | failed
    progress: int = 0  # 0-100
    current_task: str = ""
    subdomains: List[str] = Field(default_factory=list)
    live_hosts: List[LiveHost] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    open_ports: List[PortResult] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    intel_tags: IntelReport = Field(default_factory=IntelReport)
    ai_analysis: Optional[str] = None
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list)
    score_summary: Dict[str, List[str]] = Field(
        default_factory=lambda: {"high": [], "medium": [], "low": []}
    )
    error: Optional[str] = None
    tools_used: List[str] = Field(default_factory=list)
    tools_skipped: List[str] = Field(default_factory=list)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ─── API Request/Response Models ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str = Field(..., description="Target domain to scan", example="example.com")
    options: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional scan options: amass_enabled, timeout, tools"
    )


class ScanStatusResponse(BaseModel):
    scan_id: str
    domain: str
    status: str
    progress: int
    current_task: str
    timestamp: str


class ChatMessage(BaseModel):
    role: str  # user | assistant
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ChatRequest(BaseModel):
    scan_id: str
    message: str


class ChatResponse(BaseModel):
    scan_id: str
    message: str
    role: str = "assistant"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ReportFormat(BaseModel):
    scan_id: str
    format: str = "markdown"  # markdown | json


class HealthResponse(BaseModel):
    status: str
    model_selected: str
    tools_available: List[str]
    tools_missing: List[str]
    api_connected: bool


class AttackPath(BaseModel):
    target: str
    vulnerability_type: str
    severity: str
    reasoning: str
    steps: List[str]
    confidence: str  # high | medium | low
