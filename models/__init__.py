# models/__init__.py
from models.schema import (
    ScanResult, ScanRequest, LiveHost, PortResult, Vulnerability,
    IntelReport, ChatMessage, ChatRequest, ChatResponse,
    ScanStatusResponse, HealthResponse, AttackPath
)

__all__ = [
    "ScanResult", "ScanRequest", "LiveHost", "PortResult", "Vulnerability",
    "IntelReport", "ChatMessage", "ChatRequest", "ChatResponse",
    "ScanStatusResponse", "HealthResponse", "AttackPath"
]
