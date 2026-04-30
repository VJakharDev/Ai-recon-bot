"""
core/llm.py — LLM Engine using NVIDIA API.
Handles model selection with fallback, streaming, and chat history.
"""

import httpx
import json
import logging
import asyncio
from typing import List, Dict, Optional, AsyncGenerator

import config
from models.schema import ChatMessage, ScanResult
from core.intel import build_intel_summary_for_llm

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an elite bug bounty hunter and penetration tester with 10+ years of experience. 
You specialize in web application security, API security, and attack surface analysis.

When analyzing recon data, you:
1. Identify the highest-value targets based on technology stack, exposure, and vulnerability signals
2. Reason through attack paths step by step, like a real pentester would
3. Prioritize findings by realistic exploitability, not just theoretical severity
4. Suggest specific payloads and testing techniques for each attack vector
5. Explain WHY a target is interesting, not just WHAT to test
6. Think about business logic vulnerabilities, not just technical CVEs

Format your responses with clear sections, use markdown, and be specific and actionable.
Never be vague. Every suggestion must have a clear reason backed by the recon data provided."""


class LLMEngine:
    def __init__(self):
        self.api_key = config.NVIDIA_API_KEY
        self.base_url = config.NVIDIA_BASE_URL
        self.model: Optional[str] = None
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(120.0, connect=30.0),
        )

    async def initialize(self) -> str:
        """Check available models and select the best one. Returns selected model name."""
        self.model = await self._select_model()
        logger.info(f"[llm] Selected model: {self.model}")
        return self.model

    async def _select_model(self) -> str:
        """Query /v1/models and select primary or fallback model."""
        try:
            resp = await self.client.get("/models")
            if resp.status_code == 200:
                data = resp.json()
                available_ids = {
                    m.get("id", "") for m in data.get("data", [])
                }
                logger.info(f"[llm] Available models: {len(available_ids)}")

                if config.PRIMARY_MODEL in available_ids:
                    logger.info(f"[llm] Primary model available: {config.PRIMARY_MODEL}")
                    return config.PRIMARY_MODEL
                elif config.FALLBACK_MODEL in available_ids:
                    logger.warning(
                        f"[llm] Primary model unavailable, falling back to {config.FALLBACK_MODEL}"
                    )
                    return config.FALLBACK_MODEL
                else:
                    logger.warning("[llm] Neither primary nor fallback found, using primary anyway")
                    return config.PRIMARY_MODEL
        except Exception as e:
            logger.error(f"[llm] Failed to query models endpoint: {e}")

        return config.PRIMARY_MODEL

    async def is_api_connected(self) -> bool:
        """Check if NVIDIA API is reachable."""
        try:
            resp = await self.client.get("/models", timeout=10.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def analyze_scan(self, scan: ScanResult) -> str:
        """
        Generate a comprehensive AI analysis of scan results.
        Returns the full analysis as a string.
        """
        if not self.model:
            await self.initialize()

        intel_summary = build_intel_summary_for_llm(scan)

        prompt = f"""You have received the results of an automated reconnaissance scan against the domain: **{scan.domain}**

{intel_summary}

---

Based on this reconnaissance data, provide a comprehensive bug bounty analysis:

## 1. Executive Summary
Brief overview of the attack surface and most critical findings.

## 2. Priority Targets (Top 5-10)
For each target, explain:
- What makes it interesting
- Specific vulnerability type to test
- Concrete testing approach

## 3. Attack Path Simulation
Walk through 2-3 realistic attack paths from the recon data, step by step.

## 4. Vulnerability Deep-Dives
For each detected vulnerability pattern (IDOR, SSRF, XSS, Open Redirect, etc.):
- Explain the specific risk in context of THIS target
- Suggest specific payloads and bypass techniques
- Estimated CVSS / bug bounty value

## 5. Low-Hanging Fruit
Quick wins that any pentester should test first.

## 6. Recommended Next Steps
What additional manual testing should the hunter perform?

Be specific, technical, and actionable. Reference actual URLs and endpoints from the data above."""

        return await self._complete(prompt)

    async def chat(
        self,
        message: str,
        scan: ScanResult,
        history: List[ChatMessage],
    ) -> str:
        """
        Handle a chat message in context of a scan.
        Maintains conversation history for follow-up questions.
        """
        if not self.model:
            await self.initialize()

        # Build context from scan (condensed for chat)
        context = _build_chat_context(scan)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        # Add scan context as first assistant message
        messages.append({
            "role": "user",
            "content": f"I've scanned {scan.domain}. Here's the recon summary:\n\n{context}"
        })
        messages.append({
            "role": "assistant",
            "content": f"I've analyzed the recon data for {scan.domain}. I can see {len(scan.live_hosts)} live hosts, {len(scan.subdomains)} subdomains, {len(scan.vulnerabilities)} vulnerabilities, and various interesting endpoints. What would you like to explore?"
        })

        # Add conversation history (last 8 turns)
        for msg in history[-8:]:
            messages.append({"role": msg.role, "content": msg.content})

        # Add current message
        messages.append({"role": "user", "content": message})

        return await self._complete_messages(messages)

    async def stream_chat(
        self,
        message: str,
        scan: ScanResult,
        history: List[ChatMessage],
    ) -> AsyncGenerator[str, None]:
        """Stream a chat response token by token."""
        if not self.model:
            await self.initialize()

        context = _build_chat_context(scan)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.append({
            "role": "user",
            "content": f"Recon data for {scan.domain}:\n\n{context}"
        })
        messages.append({
            "role": "assistant",
            "content": f"Ready to analyze {scan.domain}. I have access to all recon findings."
        })
        for msg in history[-8:]:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": message})

        async for chunk in self._stream_messages(messages):
            yield chunk

    async def _complete(self, prompt: str) -> str:
        """Simple single-turn completion."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return await self._complete_messages(messages)

    async def _complete_messages(self, messages: List[Dict]) -> str:
        """Call the NVIDIA API chat completion endpoint (non-streaming)."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": config.LLM_TEMPERATURE,
            "max_tokens": config.LLM_MAX_TOKENS,
            "stream": False,
        }
        try:
            resp = await self.client.post("/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            logger.error(f"[llm] API error {e.response.status_code}: {e.response.text}")
            return f"⚠️ LLM API error: {e.response.status_code}. Check your API key and model availability."
        except Exception as e:
            logger.error(f"[llm] Completion failed: {e}")
            return f"⚠️ LLM error: {str(e)}"

    async def _stream_messages(self, messages: List[Dict]) -> AsyncGenerator[str, None]:
        """Stream tokens from the NVIDIA API."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": config.LLM_TEMPERATURE,
            "max_tokens": config.LLM_MAX_TOKENS,
            "stream": True,
        }
        try:
            async with self.client.stream(
                "POST", "/chat/completions", json=payload
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"[llm] Stream error: {e}")
            yield f"\n\n⚠️ Stream interrupted: {str(e)}"

    async def close(self):
        await self.client.aclose()


def _build_chat_context(scan: ScanResult) -> str:
    """Build a condensed context string for chat messages."""
    lines = [
        f"Domain: {scan.domain}",
        f"Scan ID: {scan.scan_id}",
        f"Status: {scan.status}",
        f"Subdomains: {len(scan.subdomains)}",
        f"Live Hosts: {len(scan.live_hosts)}",
        f"URLs: {len(scan.urls)}",
        f"Open Ports: {len(scan.open_ports)}",
        f"Vulnerabilities: {len(scan.vulnerabilities)}",
    ]

    if scan.live_hosts:
        lines.append("\nLive Hosts (top 20):")
        for h in scan.live_hosts[:20]:
            lines.append(f"  {h.url} [{h.status_code}] score={h.score} tags={h.intel_tags}")

    intel = scan.intel_tags
    if intel.high_value_endpoints:
        lines.append(f"\nHigh-value endpoints ({len(intel.high_value_endpoints)}):")
        for ep in intel.high_value_endpoints[:10]:
            lines.append(f"  {ep}")

    if intel.idor_candidates:
        lines.append(f"\nIDOR candidates ({len(intel.idor_candidates)}):")
        for u in intel.idor_candidates[:5]:
            lines.append(f"  {u}")

    if intel.ssrf_candidates:
        lines.append(f"\nSSRF candidates ({len(intel.ssrf_candidates)}):")
        for u in intel.ssrf_candidates[:5]:
            lines.append(f"  {u}")

    if scan.vulnerabilities:
        lines.append(f"\nNuclei findings ({len(scan.vulnerabilities)}):")
        for v in scan.vulnerabilities[:10]:
            lines.append(f"  [{v.severity}] {v.name} @ {v.matched_at}")

    if scan.score_summary["high"]:
        lines.append(f"\nHigh-priority targets:")
        for t in scan.score_summary["high"][:10]:
            lines.append(f"  {t}")

    if scan.ai_analysis:
        lines.append(f"\nPrevious AI analysis summary:")
        lines.append(scan.ai_analysis[:500] + "..." if len(scan.ai_analysis) > 500 else scan.ai_analysis)

    return "\n".join(lines)


# Singleton instance
llm_engine = LLMEngine()
