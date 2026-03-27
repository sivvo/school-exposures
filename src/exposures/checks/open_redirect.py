"""Open redirect detection check.

Tests common redirect parameters to identify unvalidated redirect vulnerabilities.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

import asyncio
import aiohttp

# Canary value — clearly invalid, used to detect if the app reflects it in Location
CANARY_DOMAIN = "openredirect-canary.invalid"
CANARY_URL = f"https://{CANARY_DOMAIN}/"

REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "return_to",
    "redir",
    "goto",
    "dest",
    "redirect_uri",
]

class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"
    category = CheckCategory.HTTP_HEADERS

    def __init__(self, config: Any, semaphore: asyncio.Semaphore | None = None) -> None:
        self._cfg = config
        self._semaphore = semaphore or asyncio.Semaphore(50)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        vulnerable_params: list[str] = []

        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            timeout = aiohttp.ClientTimeout(total=5, connect=3)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                tasks = [
                    self._test_param(session, target.url, param)
                    for param in REDIRECT_PARAMS
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for param, result in zip(REDIRECT_PARAMS, results):
                    if result is True:
                        vulnerable_params.append(param)
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "open_redirect", exc))
            return findings

        if vulnerable_params:
            findings.append(
                self.make_finding(
                    target, runkey, "open_redirect",
                    Status.FAIL, Severity.HIGH,
                    f"Open redirect detected via parameter(s): {', '.join(vulnerable_params)}",
                    evidence={
                        "vulnerable_params": vulnerable_params,
                        "canary_url": CANARY_URL,
                        "tested_params": REDIRECT_PARAMS,
                    },
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "open_redirect",
                    Status.PASS, Severity.INFO,
                    f"No open redirect detected across {len(REDIRECT_PARAMS)} tested parameters",
                    evidence={"tested_params": REDIRECT_PARAMS},
                )
            )

        return findings

    async def _test_param(
        self, session: aiohttp.ClientSession, url: str, param: str
    ) -> bool:
        """Return True if this parameter causes a redirect to the canary domain."""
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{param}={CANARY_URL}"
        try:
            async with self._semaphore:
                async with session.get(
                    test_url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if CANARY_DOMAIN in urlparse(location).netloc:
                            return True
        except Exception:
            pass
        return False
