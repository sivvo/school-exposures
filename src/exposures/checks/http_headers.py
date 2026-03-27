"""HTTP security headers check.

Examines response headers for security best practices and produces one
Finding per sub-check.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse, urlunparse
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

import asyncio
import re
import aiohttp


class HttpHeadersCheck(BaseCheck):
    name = "http_headers"
    category = CheckCategory.HTTP_HEADERS

    def __init__(self, config: Any) -> None:
        self._cfg = config  # HttpHeadersCheckConfig

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Fetch HTTPS response (with redirects)
                https_headers, https_cookies, final_url = await self._fetch_https(session, target.url)
                # Check HTTPS enforcement (http:// → https://)
                findings += await self._check_https_enforced(session, target, runkey)
                if https_headers is not None:
                    findings += self._check_hsts(target, runkey, https_headers)
                    findings += self._check_csp(target, runkey, https_headers)
                    findings += self._check_x_frame_options(target, runkey, https_headers)
                    findings += self._check_x_content_type_options(target, runkey, https_headers)
                    findings += self._check_referrer_policy(target, runkey, https_headers)
                    findings += self._check_permissions_policy(target, runkey, https_headers)
                    findings += self._check_server_exposure(target, runkey, https_headers)
                    findings += self._check_x_powered_by(target, runkey, https_headers)
                    findings += self._check_cookie_security(target, runkey, https_cookies)
                else:
                    findings.append(
                        self.make_finding(
                            target, runkey, "https_fetch",
                            Status.ERROR, Severity.INFO,
                            f"Could not fetch HTTPS response from {target.url}",
                        )
                    )
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "http_headers", exc))
        return findings

    async def _fetch_https(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[dict | None, list[str], str]:
        """Fetch the URL following redirects; return (headers, raw_set_cookie_headers, final_url)."""
        try:
            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=self._cfg.max_redirects,
                headers={"User-Agent": self._cfg.user_agent},
            ) as resp:
                headers = dict(resp.headers)
                # Use getall to capture every Set-Cookie header
                raw_cookies = resp.headers.getall("Set-Cookie", [])
                return headers, raw_cookies, str(resp.url)
        except Exception:
            return None, [], url

    async def _check_https_enforced(
        self, session: aiohttp.ClientSession, target: ScanTarget, runkey: str
    ) -> list[Finding]:
        """Check whether plain HTTP redirects to HTTPS by manually following redirects."""
        parsed = urlparse(target.url)
        http_url = urlunparse(parsed._replace(scheme="http"))
        redirect_chain: list[str] = [http_url]
        final_is_https = False

        try:
            current_url = http_url
            for _ in range(self._cfg.max_redirects):
                async with session.get(
                    current_url,
                    allow_redirects=False,
                    headers={"User-Agent": self._cfg.user_agent},
                ) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if location:
                            # Resolve relative redirects
                            if location.startswith("/"):
                                p = urlparse(current_url)
                                location = urlunparse(p._replace(path=location, query="", fragment=""))
                            current_url = location
                            redirect_chain.append(current_url)
                            if current_url.lower().startswith("https://"):
                                final_is_https = True
                                break
                    else:
                        # Not a redirect — check if we ended up on https
                        final_is_https = current_url.lower().startswith("https://")
                        break
        except Exception:
            # Network error on http:// — we can't determine enforcement
            return [
                self.make_finding(
                    target, runkey, "https_enforced",
                    Status.ERROR, Severity.INFO,
                    "Could not check HTTP→HTTPS redirect (connection error on http://)",
                    evidence={"http_url": http_url},
                )
            ]

        if final_is_https:
            return [
                self.make_finding(
                    target, runkey, "https_enforced",
                    Status.PASS, Severity.INFO,
                    "HTTP redirects to HTTPS",
                    evidence={"redirect_chain": redirect_chain},
                )
            ]
        else:
            return [
                self.make_finding(
                    target, runkey, "https_enforced",
                    Status.FAIL, Severity.HIGH,
                    "HTTP does not redirect to HTTPS",
                    evidence={"redirect_chain": redirect_chain},
                )
            ]

    def _check_hsts(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        findings: list[Finding] = []
        hsts_value = _header(headers, "Strict-Transport-Security")

        if not hsts_value:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_present",
                    Status.FAIL, Severity.HIGH,
                    "Strict-Transport-Security header is missing",
                )
            )

            return findings

        findings.append(
            self.make_finding(
                target, runkey, "hsts_present",
                Status.PASS, Severity.INFO,
                "Strict-Transport-Security header is present",
                evidence={"value": hsts_value},
            )
        )

        # max-age
        max_age = _parse_hsts_max_age(hsts_value)
        if max_age is None:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_max_age",
                    Status.FAIL, Severity.HIGH,
                    "HSTS header missing max-age directive",
                    evidence={"value": hsts_value},
                )
            )
        elif max_age < 31_536_000:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_max_age",
                    Status.WARN, Severity.MEDIUM,
                    f"HSTS max-age ({max_age}s) is less than 1 year (31536000s)",
                    evidence={"max_age": max_age, "recommended": 31_536_000},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_max_age",
                    Status.PASS, Severity.INFO,
                    f"HSTS max-age is {max_age}s (>= 1 year)",
                    evidence={"max_age": max_age},
                )
            )

        # includeSubDomains
        has_include_subdomains = "includesubdomains" in hsts_value.lower()
        if has_include_subdomains:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_includesubdomains",
                    Status.PASS, Severity.INFO,
                    "HSTS includeSubDomains directive is present",
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "hsts_includesubdomains",
                    Status.WARN, Severity.LOW,
                    "HSTS includeSubDomains directive is missing",
                    evidence={"value": hsts_value},
                )
            )

        # preload
        has_preload = "preload" in hsts_value.lower()
        findings.append(
            self.make_finding(
                target, runkey, "hsts_preload",
                Status.INFO, Severity.INFO,
                "HSTS preload directive is present" if has_preload else "HSTS preload directive is absent",
                evidence={"preload": has_preload},
            )
        )

        return findings

    def _check_csp(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        findings: list[Finding] = []
        csp_value = _header(headers, "Content-Security-Policy")

        if not csp_value:
            findings.append(
                self.make_finding(
                    target, runkey, "csp_present",
                    Status.FAIL, Severity.HIGH,
                    "Content-Security-Policy header is missing",
                )
            )
            return findings

        findings.append(
            self.make_finding(
                target, runkey, "csp_present",
                Status.PASS, Severity.INFO,
                "Content-Security-Policy header is present",
                evidence={"value": csp_value[:500]},
            )
        )

        csp_lower = csp_value.lower()

        if "'unsafe-inline'" in csp_lower:
            findings.append(
                self.make_finding(
                    target, runkey, "csp_unsafe_inline",
                    Status.WARN, Severity.MEDIUM,
                    "CSP contains 'unsafe-inline' which allows inline scripts/styles",
                    evidence={"csp_snippet": csp_value[:300]},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "csp_unsafe_inline",
                    Status.PASS, Severity.INFO,
                    "CSP does not contain 'unsafe-inline'",
                )
            )

        if "'unsafe-eval'" in csp_lower:
            findings.append(
                self.make_finding(
                    target, runkey, "csp_unsafe_eval",
                    Status.WARN, Severity.MEDIUM,
                    "CSP contains 'unsafe-eval' which allows eval() and similar",
                    evidence={"csp_snippet": csp_value[:300]},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "csp_unsafe_eval",
                    Status.PASS, Severity.INFO,
                    "CSP does not contain 'unsafe-eval'",
                )
            )

        return findings


    def _check_x_frame_options(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        xfo = _header(headers, "X-Frame-Options")
        if not xfo:
            return [
                self.make_finding(
                    target, runkey, "x_frame_options",
                    Status.FAIL, Severity.MEDIUM,
                    "X-Frame-Options header is missing (clickjacking risk)",
                )
            ]
        xfo_upper = xfo.upper().strip()
        if xfo_upper in ("DENY", "SAMEORIGIN"):
            return [
                self.make_finding(
                    target, runkey, "x_frame_options",
                    Status.PASS, Severity.INFO,
                    f"X-Frame-Options is set to {xfo_upper}",
                    evidence={"value": xfo},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "x_frame_options",
                Status.WARN, Severity.MEDIUM,
                f"X-Frame-Options value '{xfo}' is non-standard",
                evidence={"value": xfo},
            )
        ]

    def _check_x_content_type_options(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        xcto = _header(headers, "X-Content-Type-Options")
        if xcto and xcto.strip().lower() == "nosniff":
            return [
                self.make_finding(
                    target, runkey, "x_content_type_options",
                    Status.PASS, Severity.INFO,
                    "X-Content-Type-Options: nosniff is set",
                )
            ]
        return [
            self.make_finding(
                target, runkey, "x_content_type_options",
                Status.FAIL, Severity.MEDIUM,
                "X-Content-Type-Options: nosniff is missing",
                evidence={"value": xcto or ""},
            )
        ]

    def _check_referrer_policy(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        rp = _header(headers, "Referrer-Policy")
        if rp:
            return [
                self.make_finding(
                    target, runkey, "referrer_policy",
                    Status.PASS, Severity.INFO,
                    f"Referrer-Policy is set to '{rp}'",
                    evidence={"value": rp},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "referrer_policy",
                Status.WARN, Severity.LOW,
                "Referrer-Policy header is missing",
            )
        ]

    def _check_permissions_policy(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        pp = _header(headers, "Permissions-Policy")
        if pp:
            return [
                self.make_finding(
                    target, runkey, "permissions_policy",
                    Status.PASS, Severity.INFO,
                    "Permissions-Policy header is present",
                    evidence={"value": pp[:300]},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "permissions_policy",
                Status.WARN, Severity.LOW,
                "Permissions-Policy header is missing",
            )
        ]

    def _check_server_exposure(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        server = _header(headers, "Server")
        if not server:
            return [
                self.make_finding(
                    target, runkey, "server_header_exposure",
                    Status.PASS, Severity.INFO,
                    "Server header is absent (good)",
                )
            ]
        # Check if it contains a version string: word/digits
        if re.search(r"/\d", server):
            return [
                self.make_finding(
                    target, runkey, "server_header_exposure",
                    Status.WARN, Severity.LOW,
                    f"Server header reveals version information: '{server}'",
                    evidence={"server": server},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "server_header_exposure",
                Status.PASS, Severity.INFO,
                f"Server header present but does not reveal version: '{server}'",
                evidence={"server": server},
            )
        ]

    def _check_x_powered_by(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        xpb = _header(headers, "X-Powered-By")
        if xpb:
            return [
                self.make_finding(
                    target, runkey, "x_powered_by_exposure",
                    Status.WARN, Severity.LOW,
                    f"X-Powered-By header present (tech stack leak): '{xpb}'",
                    evidence={"value": xpb},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "x_powered_by_exposure",
                Status.PASS, Severity.INFO,
                "X-Powered-By header is absent (good)",
            )
        ]

    def _check_cookie_security(
        self, target: ScanTarget, runkey: str, raw_set_cookie_headers: list[str]
    ) -> list[Finding]:
        if not raw_set_cookie_headers:
            return [
                self.make_finding(
                    target, runkey, "cookie_security",
                    Status.INFO, Severity.INFO,
                    "No Set-Cookie headers found",
                )
            ]

        findings: list[Finding] = []
        for raw in raw_set_cookie_headers:
            parsed = _parse_set_cookie(raw)
            name = parsed["name"]
            issues: list[str] = []

            if not parsed["secure"]:
                issues.append("Secure flag missing")
            if not parsed["httponly"]:
                issues.append("HttpOnly flag missing")
            if not parsed["samesite"]:
                issues.append("SameSite attribute missing")

            evidence = {
                "cookie_name": name,
                "secure": parsed["secure"],
                "httponly": parsed["httponly"],
                "samesite": parsed["samesite"],
            }

            if "Secure flag missing" in issues:
                findings.append(
                    self.make_finding(
                        target, runkey, "cookie_security",
                        Status.FAIL, Severity.HIGH,
                        f"Cookie '{name}' is missing the Secure flag: {', '.join(issues)}",
                        evidence=evidence,
                    )
                )
            elif issues:
                findings.append(
                    self.make_finding(
                        target, runkey, "cookie_security",
                        Status.WARN, Severity.MEDIUM,
                        f"Cookie '{name}' has security issues: {', '.join(issues)}",
                        evidence=evidence,
                    )
                )
            else:
                findings.append(
                    self.make_finding(
                        target, runkey, "cookie_security",
                        Status.PASS, Severity.INFO,
                        f"Cookie '{name}' has Secure, HttpOnly, and SameSite flags set",
                        evidence=evidence,
                    )
                )

        return findings


def _header(headers: dict, name: str) -> str | None:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _parse_set_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie header string into a dict of attributes."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0].strip() if parts else "unknown"
    attr_strs = [p.lower() for p in parts[1:]]
    samesite = ""
    for a in attr_strs:
        if a.startswith("samesite="):
            samesite = a.split("=", 1)[1].strip()
            break
    return {
        "name": name,
        "secure": "secure" in attr_strs,
        "httponly": "httponly" in attr_strs,
        "samesite": samesite,
    }


def _parse_hsts_max_age(hsts_value: str) -> int | None:
    """Extract max-age integer from HSTS header value."""
    match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None
