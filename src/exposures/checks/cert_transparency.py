"""Certificate Transparency check via crt.sh.

Queries crt.sh for all certificates issued for a domain and flags
unexpected issuers, recently issued certs, and wildcard certificates.
"""
from __future__ import annotations

import asyncio
import aiohttp
from datetime import datetime, timedelta, timezone
from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

CRT_SH_URL = "https://crt.sh/"

# Substrings to match against issuer_name  
# TODO : review and extend - but first validate that this logic makes sense

EXPECTED_ISSUER_SUBSTRINGS: list[str] = [
    "Let's Encrypt",
    "DigiCert",
    "Comodo",
    "Sectigo",
    "GlobalSign",
    "GoDaddy",
    "Entrust",
    "Thawte",
    "VeriSign",
    "Amazon",
    "Microsoft",
    "Google Trust Services",
    "Cloudflare",
    "ZeroSSL",
    "ISRG",  # Let's Encrypt root
]

class CertTransparencyCheck(BaseCheck):
    name = "cert_transparency"
    category = CheckCategory.TLS

    def __init__(self, config: Any, semaphore: asyncio.Semaphore | None = None) -> None:
        self._cfg = config
        self._semaphore = semaphore or asyncio.Semaphore(20)
        self._domain_cache: dict[str, list[dict]] = {}
        self._domain_locks: dict[str, asyncio.Lock] = {}

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            certs = await self._get_certs_cached(target.domain)
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "cert_transparency_query", exc))
            return findings

        if not certs:
            findings.append(
                self.make_finding(
                    target, runkey, "cert_transparency",
                    Status.INFO, Severity.INFO,
                    f"No certificates found in CT logs for '{target.domain}'",
                    evidence={"domain": target.domain},
                )
            )
            return findings

        now = datetime.now(timezone.utc)
        lookback_days: int = getattr(self._cfg, "lookback_days", 90)
        flag_unexpected: bool = getattr(self._cfg, "flag_unexpected_issuers", True)
        lookback_cutoff = now - timedelta(days=lookback_days)

        # Deduplicate by cert id
        seen_ids: set = set()
        unique_certs = []
        for cert in certs:
            cid = cert.get("id")
            if cid not in seen_ids:
                seen_ids.add(cid)
                unique_certs.append(cert)

        recent = [
            c for c in unique_certs
            if _parse_ct_date(c.get("logged_at", "")) >= lookback_cutoff
        ]

        findings.append(
            self.make_finding(
                target, runkey, "cert_transparency_count",
                Status.INFO, Severity.INFO,
                f"Found {len(unique_certs)} certificate(s) in CT logs for '{target.domain}' "
                f"({len(recent)} in last {lookback_days} days)",
                evidence={
                    "domain": target.domain,
                    "total_certs": len(unique_certs),
                    "recent_certs": len(recent),
                    "lookback_days": lookback_days,
                },
            )
        )

        # Avoid duplicate findings for the same issuer/CN combo
        reported: set[str] = set()

        for cert in recent:
            issuer = cert.get("issuer_name", "")
            common_name = cert.get("common_name", "")
            logged_at = cert.get("logged_at", "")
            logged_date = _parse_ct_date(logged_at)

            # Unexpected issuer
            if flag_unexpected and issuer:
                if not any(exp.lower() in issuer.lower() for exp in EXPECTED_ISSUER_SUBSTRINGS):
                    key = f"unexpected_issuer:{issuer}"
                    if key not in reported:
                        reported.add(key)
                        findings.append(
                            self.make_finding(
                                target, runkey, "cert_unexpected_issuer",
                                Status.WARN, Severity.MEDIUM,
                                f"Certificate for '{common_name}' issued by unexpected CA: {issuer}",
                                evidence={
                                    "common_name": common_name,
                                    "issuer": issuer,
                                    "logged_at": logged_at,
                                },
                            )
                        )

            # Very recently issued (last 7 days) — could be legitimate renewal or phishing infra
            if (now - logged_date).days <= 7:
                key = f"recent:{common_name}:{logged_at}"
                if key not in reported:
                    reported.add(key)
                    findings.append(
                        self.make_finding(
                            target, runkey, "cert_recently_issued",
                            Status.INFO, Severity.INFO,
                            f"Certificate for '{common_name}' was issued within the last 7 days",
                            evidence={
                                "common_name": common_name,
                                "issuer": issuer,
                                "logged_at": logged_at,
                            },
                        )
                    )

            # Wildcard certificate
            if common_name.startswith("*."):
                key = f"wildcard:{common_name}"
                if key not in reported:
                    reported.add(key)
                    findings.append(
                        self.make_finding(
                            target, runkey, "cert_wildcard",
                            Status.INFO, Severity.INFO,
                            f"Wildcard certificate in CT logs: '{common_name}' (issued by {issuer})",
                            evidence={
                                "common_name": common_name,
                                "issuer": issuer,
                                "logged_at": logged_at,
                            },
                        )
                    )

        return findings

    async def _get_certs_cached(self, domain: str) -> list[dict]:
        """Return crt.sh results for a domain, querying only once per domain per run."""
        if domain in self._domain_cache:
            return self._domain_cache[domain]
        if domain not in self._domain_locks:
            self._domain_locks[domain] = asyncio.Lock()
        async with self._domain_locks[domain]:
            # Re-check after acquiring lock — another coroutine may have populated it
            if domain not in self._domain_cache:
                self._domain_cache[domain] = await self._query_crt_sh(domain)
        return self._domain_cache[domain]

    async def _query_crt_sh(self, domain: str) -> list[dict]:
        """Query crt.sh for certificates including subdomains."""
        params = {"q": f"%.{domain}", "output": "json"}
        timeout = aiohttp.ClientTimeout(total=30)
        async with self._semaphore:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(CRT_SH_URL, params=params) as resp:
                    if resp.status == 200:
                        try:
                            return await resp.json(content_type=None)
                        except Exception:
                            return []
                    return []


def _parse_ct_date(date_str: str) -> datetime:
    """Parse crt.sh date strings to UTC datetime."""
    if not date_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.min.replace(tzinfo=timezone.utc)
