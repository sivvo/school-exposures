"""Google Safe Browsing v4 check.

Queries the Safe Browsing Lookup API for each target URL.
Flags URLs listed as malware, phishing (social engineering),
unwanted software, or potentially harmful applications.

## Requires Google Safe Browsing API key
"""
from __future__ import annotations

import asyncio
import aiohttp
from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_SEVERITY_MAP: dict[str, Severity] = {
    "MALWARE":                         Severity.CRITICAL,
    "SOCIAL_ENGINEERING":              Severity.CRITICAL,
    "UNWANTED_SOFTWARE":               Severity.HIGH,
    "POTENTIALLY_HARMFUL_APPLICATION": Severity.HIGH,
}

_LABEL_MAP: dict[str, str] = {
    "MALWARE":                         "malware",
    "SOCIAL_ENGINEERING":              "phishing / social engineering",
    "UNWANTED_SOFTWARE":               "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}

class SafeBrowsingCheck(BaseCheck):
    name     = "safe_browsing"
    category = CheckCategory.REPUTATION

    def __init__(self, api_key: str, semaphore: asyncio.Semaphore | None = None) -> None:
        self._api_key = api_key
        self._sem     = semaphore or asyncio.Semaphore(10)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        if not self._api_key:
            return [self.make_finding(
                target, runkey, "safe_browsing",
                Status.INFO, Severity.INFO,
                "Safe Browsing check skipped — GOOGLE_SAFE_BROWSING_API_KEY not configured",
            )]

        payload: dict[str, Any] = {
            "client": {
                "clientId":      "dfe-cyber-exposure-scanner",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes":      _THREAT_TYPES,
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": target.url}],
            },
        }

        try:
            async with self._sem:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        _API_URL,
                        params={"key": self._api_key},
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        resp.raise_for_status()
                        data = await resp.json()
        except Exception as exc:
            return [self.make_error(target, runkey, "safe_browsing", exc)]

        matches: list[dict] = data.get("matches", [])
        if not matches:
            return [self.make_finding(
                target, runkey, "safe_browsing",
                Status.PASS, Severity.INFO,
                "URL not listed in Google Safe Browsing",
            )]

        findings = []
        seen: set[str] = set()
        for match in matches:
            threat_type = match.get("threatType", "UNKNOWN")
            if threat_type in seen:
                continue
            seen.add(threat_type)
            sev   = _SEVERITY_MAP.get(threat_type, Severity.HIGH)
            label = _LABEL_MAP.get(threat_type, threat_type.lower().replace("_", " "))
            findings.append(self.make_finding(
                target, runkey, "safe_browsing",
                Status.FAIL, sev,
                f"URL flagged by Google Safe Browsing: {label}",
                evidence={
                    "threat_type":   threat_type,
                    "platform_type": match.get("platformType"),
                    "matched_url":   match.get("threatEntry", {}).get("url"),
                },
            ))
        return findings
