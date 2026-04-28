"""Mixed content detection check.

Fetches the page HTML over HTTPS and scans for sub-resources (scripts, iframes,
forms, images, stylesheets) loaded over plain HTTP.

Active mixed content (scripts, iframes, forms) is blocked by modern browsers but
historically has been exploitable to compromise HTTPS sessions — FAIL / HIGH.
Passive mixed content (images, video, audio) is displayed with a warning — WARN / MEDIUM.

Body read is capped at 200 KB to avoid memory issues on large pages.
"""
from __future__ import annotations
from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck
import re
import asyncio
import aiohttp

_MAX_BODY_BYTES = 200_000
_TIMEOUT = aiohttp.ClientTimeout(total=20, connect=8)

# (attribute pattern, active_or_passive)
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Active: these can be used to hijack the session
    (re.compile(r'<script[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "active"),
    (re.compile(r'<iframe[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "active"),
    (re.compile(r'<form[^>]+\baction\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "active"),
    (re.compile(r'<link[^>]+\brel\s*=\s*["\']stylesheet["\'][^>]+\bhref\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "active"),
    (re.compile(r'<link[^>]+\bhref\s*=\s*["\']http://[^"\']+[^>]+\brel\s*=\s*["\']stylesheet["\']', re.IGNORECASE), "active"),
    # Passive: shown with browser warning, not blocked
    (re.compile(r'<img[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "passive"),
    (re.compile(r'<video[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "passive"),
    (re.compile(r'<audio[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "passive"),
    (re.compile(r'<source[^>]+\bsrc\s*=\s*["\']http://[^"\']+', re.IGNORECASE), "passive"),
]

_HTTP_URL_RE = re.compile(r'http://[^\s"\'<>]+')

def _extract_url(match_text: str) -> str:
    """Pull the http:// URL from a matched tag string."""
    m = _HTTP_URL_RE.search(match_text)
    return m.group(0)[:120] if m else match_text[:120]

class MixedContentCheck(BaseCheck):
    name = "mixed_content"
    category = CheckCategory.HTTP_HEADERS

    def __init__(self, semaphore: asyncio.Semaphore | None = None) -> None:
        self._semaphore = semaphore or asyncio.Semaphore(200)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        # Only meaningful for HTTPS URLs
        if not target.url.lower().startswith("https://"):
            return []

        try:
            html = await self._fetch_html(target.url)
        except Exception as exc:
            return [self.make_error(target, runkey, "mixed_content", exc)]

        if html is None:
            return []

        active_urls: list[str] = []
        passive_urls: list[str] = []

        for pattern, kind in _PATTERNS:
            for m in pattern.finditer(html):
                url = _extract_url(m.group(0))
                if kind == "active" and url not in active_urls:
                    active_urls.append(url)
                elif kind == "passive" and url not in passive_urls:
                    passive_urls.append(url)

        findings: list[Finding] = []

        if active_urls:
            findings.append(
                self.make_finding(
                    target, runkey, "mixed_content_active",
                    Status.FAIL, Severity.HIGH,
                    f"Active mixed content detected — {len(active_urls)} HTTP resource(s) "
                    f"(scripts/iframes/forms) loaded on an HTTPS page",
                    evidence={
                        "active_http_resources": active_urls[:10],
                        "count": len(active_urls),
                    },
                )
            )

        if passive_urls:
            findings.append(
                self.make_finding(
                    target, runkey, "mixed_content_passive",
                    Status.WARN, Severity.MEDIUM,
                    f"Passive mixed content detected — {len(passive_urls)} HTTP resource(s) "
                    f"(images/media) loaded on an HTTPS page",
                    evidence={
                        "passive_http_resources": passive_urls[:10],
                        "count": len(passive_urls),
                    },
                )
            )

        if not findings:
            findings.append(
                self.make_finding(
                    target, runkey, "mixed_content",
                    Status.PASS, Severity.INFO,
                    "No mixed content detected in page HTML",
                )
            )

        return findings

    async def _fetch_html(self, url: str) -> str | None:
        async with self._semaphore:
            try:
                connector = aiohttp.TCPConnector(ssl=False, limit=0)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=_TIMEOUT
                ) as session:
                    async with session.get(
                        url,
                        allow_redirects=True,
                        max_redirects=5,
                        headers={"User-Agent": "DfE-CyberExposureScanner/1.0"},
                    ) as resp:
                        if resp.status != 200:
                            return None
                        # Read body up to cap — avoid loading huge pages
                        raw = await resp.content.read(_MAX_BODY_BYTES)
                        return raw.decode("utf-8", errors="replace")
            except Exception:
                return None
