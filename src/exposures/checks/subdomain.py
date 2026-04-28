"""Subdomain enumeration check

Discovers additional attack surface beyond the primary URL by:
1. Querying crt.sh Certificate Transparency logs for SANs/CNs
2. DNS brute-force against a short wordlist of common subdomains
3. Flagging dangling CNAMEs (potential subdomain takeover) per discovered subdomain

This should significantly increase coverage for schools with multiple subdomains.
"""
from __future__ import annotations
from urllib.parse import urlparse
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

import asyncio
import json
import re
import aiohttp
import dns.asyncresolver
import dns.exception


# Common subdomain wordlist — guessing based on terms likely to be associated with a school
_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "admin", "portal",
    "owa", "exchange", "autodiscover", "lyncdiscover", "sip",
    "intranet", "staff", "parent", "parents", "students", "pupil",
    "moodle", "vle", "learn", "lms", "library", "resource", "resources",
    "curriculum", "calendar", "wiki", "sharepoint", "teams",
    "dev", "staging", "test", "beta", "demo",
    "cdn", "static", "assets", "media", "images",
    "api", "app", "apps",
    "backup", "helpdesk", "support", "monitor",
    "cpanel", "webdisk", "whm",
]

# Cloud service CNAMEs that indicate takeover risk if they resolve but the service isn't claimed
_TAKEOVER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.amazonaws\.com$",    re.I), "AWS S3 / CloudFront"),
    (re.compile(r"\.azurewebsites\.net$",re.I), "Azure Web Apps"),
    (re.compile(r"\.github\.io$",        re.I), "GitHub Pages"),
    (re.compile(r"\.netlify\.app$",      re.I), "Netlify"),
    (re.compile(r"\.vercel\.app$",       re.I), "Vercel"),
    (re.compile(r"\.pantheonsite\.io$",  re.I), "Pantheon"),
    (re.compile(r"\.herokudns\.com$",    re.I), "Heroku"),
    (re.compile(r"\.fastly\.net$",       re.I), "Fastly"),
    (re.compile(r"\.cloudfront\.net$",   re.I), "CloudFront"),
    (re.compile(r"\.wpengine\.com$",     re.I), "WP Engine"),
]


class SubdomainCheck(BaseCheck):
    name = "subdomain_enum"
    category = CheckCategory.DNS

    def __init__(
        self,
        http_semaphore: asyncio.Semaphore | None = None,
        dns_semaphore:  asyncio.Semaphore | None = None,
    ) -> None:
        self._http_sem = http_semaphore or asyncio.Semaphore(50)
        self._dns_sem  = dns_semaphore  or asyncio.Semaphore(200)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = target.domain
        if not domain:
            return findings

        # subdomains from CT logs
        ct_subs = await self._fetch_ct_subdomains(domain)

        # DNS brute-force
        brute_subs = await self._brute_force_subdomains(domain)

        all_subs: set[str] = set()
        for s in ct_subs | brute_subs:
            s = s.lower().strip(".")
            if s and s != domain and s.endswith("." + domain):
                all_subs.add(s)

        if not all_subs:
            findings.append(
                self.make_finding(
                    target, runkey, "subdomain_enum",
                    Status.INFO, Severity.INFO,
                    f"No additional subdomains discovered for {domain}",
                    evidence={"domain": domain},
                )
            )
            return findings

        findings.append(
            self.make_finding(
                target, runkey, "subdomain_enum",
                Status.INFO, Severity.INFO,
                f"Discovered {len(all_subs)} subdomain(s) for {domain}",
                evidence={
                    "domain": domain,
                    "subdomains": sorted(all_subs)[:50],
                    "ct_discovered": len(ct_subs),
                    "brute_discovered": len(brute_subs),
                },
            )
        )

        # Check for dangling CNAME
        dangling_tasks = [
            asyncio.create_task(self._check_dangling_cname(sub, target, runkey))
            for sub in sorted(all_subs)[:30]  # cap at 30 to avoid excessive DNS
        ]
        results = await asyncio.gather(*dangling_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _fetch_ct_subdomains(self, domain: str) -> set[str]:
        """Query crt.sh for subdomains via CT logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with self._http_sem:
                timeout = aiohttp.ClientTimeout(total=20, connect=8)
                connector = aiohttp.TCPConnector(ssl=True, limit=0)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get(url, headers={"User-Agent": "DfE-CyberExposureScanner/1.0"}) as resp:
                        if resp.status != 200:
                            return set()
                        data = await resp.json(content_type=None)
        except Exception:
            return set()

        subs: set[str] = set()
        for entry in (data if isinstance(data, list) else []):
            name = entry.get("name_value", "")
            for part in name.split("\n"):
                part = part.strip().lstrip("*.")
                if part.endswith("." + domain) or part == domain:
                    subs.add(part)
        return subs

    async def _brute_force_subdomains(self, domain: str) -> set[str]:
        """DNS brute-force against the common wordlist."""
        tasks = [
            asyncio.create_task(self._resolve_subdomain(f"{word}.{domain}"))
            for word in _WORDLIST
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        subs: set[str] = set()
        for fqdn, result in zip((f"{w}.{domain}" for w in _WORDLIST), results):
            if isinstance(result, bool) and result:
                subs.add(fqdn)
        return subs

    async def _resolve_subdomain(self, fqdn: str) -> bool:
        """Return True if the FQDN resolves to any A/AAAA/CNAME record."""
        async with self._dns_sem:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout  = 3
            resolver.lifetime = 5
            for qtype in ("A", "CNAME"):
                try:
                    await resolver.resolve(fqdn, qtype)
                    return True
                except (dns.exception.DNSException, Exception):
                    pass
        return False

    async def _check_dangling_cname(
        self, subdomain: str, target: ScanTarget, runkey: str
    ) -> list[Finding]:
        """Check if a subdomain CNAME points at an unclaimed cloud service."""
        async with self._dns_sem:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout  = 3
            resolver.lifetime = 5
            try:
                answers = await resolver.resolve(subdomain, "CNAME")
            except (dns.exception.DNSException, Exception):
                return []

        for rdata in answers:
            target_cname = str(rdata.target).rstrip(".")
            for pattern, service in _TAKEOVER_PATTERNS:
                if pattern.search(target_cname):
                    # Check if the CNAME target actually responds
                    is_live = await self._check_cname_live(target_cname)
                    if not is_live:
                        return [
                            self.make_finding(
                                target, runkey, "dns_dangling_cname",
                                Status.FAIL, Severity.HIGH,
                                f"Subdomain '{subdomain}' has a dangling CNAME to {service} "
                                f"({target_cname}) — potential subdomain takeover",
                                evidence={
                                    "subdomain": subdomain,
                                    "cname_target": target_cname,
                                    "service": service,
                                },
                            )
                        ]
        return []

    async def _check_cname_live(self, cname_target: str) -> bool:
        """Return True if the CNAME target responds to an HTTP request (not dangling)."""
        try:
            async with self._http_sem:
                timeout = aiohttp.ClientTimeout(total=8, connect=4)
                connector = aiohttp.TCPConnector(ssl=False, limit=0)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get(
                        f"https://{cname_target}/",
                        allow_redirects=True, max_redirects=3,
                        headers={"User-Agent": "DfE-CyberExposureScanner/1.0"},
                    ) as resp:
                        return resp.status < 500
        except Exception:
            return False
