"""DNS records security checks.

Uses dnspython async resolver to check:
- A/AAAA record presence
- CAA, DNSSEC
- Zone transfer
- Dangling CNAME (subdomain takeover indicators)
"""
from __future__ import annotations
from typing import Any

import asyncio
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

# Known takeover-prone CNAME targets (partial match against lower-cased CNAME value)
TAKEOVER_PATTERNS: list[str] = [
    ".s3.amazonaws.com",
    ".azurewebsites.net",
    ".github.io",
    ".herokuapp.com",
    ".ghost.io",
    ".surge.sh",
    ".netlify.app",
    ".pages.dev",
    ".fastly.net",
    ".pantheonsite.io",
    ".zendesk.com",
    ".helpscoutdocs.com",
    ".shopify.com",
    ".myshopify.com",
    ".tumblr.com",
    ".bitbucket.io",
]

class DNSRecordsCheck(BaseCheck):
    name = "dns_records"
    category = CheckCategory.DNS

    def __init__(self, semaphore: asyncio.Semaphore | None = None) -> None:
        self._semaphore = semaphore or asyncio.Semaphore(500)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = target.domain
        hostname = _extract_hostname(target.url)

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 15

            findings += await self._check_a_record(target, runkey, hostname, resolver)
            findings += await self._check_aaaa_record(target, runkey, hostname, resolver)
            findings += await self._check_caa_record(target, runkey, domain, resolver)
            findings += await self._check_dnssec(target, runkey, domain, resolver)
            findings += await self._check_zone_transfer(target, runkey, domain, resolver)
            findings += await self._check_dangling_cname(target, runkey, hostname, resolver)

        except Exception as exc:
            findings.append(self.make_error(target, runkey, "dns_records", exc))

        return findings

    # Individual checks
    async def _check_a_record(
        self,
        target: ScanTarget,
        runkey: str,
        hostname: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        async with self._semaphore:
            try:
                answer = await resolver.resolve(hostname, "A")
                ips = [str(rr) for rr in answer]
                return [
                    self.make_finding(
                        target, runkey, "dns_a_record",
                        Status.PASS, Severity.INFO,
                        f"A record resolves to {len(ips)} address(es)",
                        evidence={"addresses": ips},
                    )
                ]
            except dns.resolver.NXDOMAIN:
                return [
                    self.make_finding(
                        target, runkey, "dns_a_record",
                        Status.ERROR, Severity.HIGH,
                        f"DNS A record for '{hostname}' does not exist (NXDOMAIN)",
                        evidence={"hostname": hostname},
                    )
                ]
            except dns.resolver.NoAnswer:
                return [
                    self.make_finding(
                        target, runkey, "dns_a_record",
                        Status.WARN, Severity.MEDIUM,
                        f"No A record found for '{hostname}' (may have AAAA only)",
                        evidence={"hostname": hostname},
                    )
                ]
            except Exception as exc:
                return [self.make_error(target, runkey, "dns_a_record", exc)]

    async def _check_aaaa_record(
        self,
        target: ScanTarget,
        runkey: str,
        hostname: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        async with self._semaphore:
            try:
                answer = await resolver.resolve(hostname, "AAAA")
                ips = [str(rr) for rr in answer]
                return [
                    self.make_finding(
                        target, runkey, "dns_aaaa_record",
                        Status.INFO, Severity.INFO,
                        f"AAAA (IPv6) record present: {len(ips)} address(es)",
                        evidence={"addresses": ips},
                    )
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return [
                    self.make_finding(
                        target, runkey, "dns_aaaa_record",
                        Status.INFO, Severity.INFO,
                        f"No AAAA (IPv6) record found for '{hostname}'",
                        evidence={"hostname": hostname},
                    )
                ]
            except Exception as exc:
                return [self.make_error(target, runkey, "dns_aaaa_record", exc)]

    async def _check_caa_record(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        async with self._semaphore:
            try:
                answer = await resolver.resolve(domain, "CAA")
                records = [str(rr) for rr in answer]
                return [
                    self.make_finding(
                        target, runkey, "dns_caa_record",
                        Status.PASS, Severity.INFO,
                        f"CAA record is present ({len(records)} record(s))",
                        evidence={"records": records},
                    )
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return [
                    self.make_finding(
                        target, runkey, "dns_caa_record",
                        Status.WARN, Severity.MEDIUM,
                        "No CAA record found — any CA can issue certificates for this domain",
                        evidence={"domain": domain},
                    )
                ]
            except Exception as exc:
                return [self.make_error(target, runkey, "dns_caa_record", exc)]

    async def _check_dnssec(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        async with self._semaphore:
            try:
                answer = await resolver.resolve(domain, "DNSKEY")
                keys = [str(rr)[:80] for rr in answer]
                return [
                    self.make_finding(
                        target, runkey, "dns_dnssec",
                        Status.PASS, Severity.INFO,
                        f"DNSKEY record present — DNSSEC appears configured",
                        evidence={"dnskey_count": len(keys)},
                    )
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return [
                    self.make_finding(
                        target, runkey, "dns_dnssec",
                        Status.WARN, Severity.MEDIUM,
                        "No DNSKEY record found — DNSSEC may not be configured",
                        evidence={"domain": domain},
                    )
                ]
            except Exception as exc:
                return [self.make_error(target, runkey, "dns_dnssec", exc)]

    async def _check_zone_transfer(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        # First get the NS records
        async with self._semaphore:
            try:
                ns_answer = await resolver.resolve(domain, "NS")
                nameservers = [str(rr).rstrip(".") for rr in ns_answer]
            except Exception:
                return []

        vulnerable_ns: list[str] = []
        for ns in nameservers[:5]:  # limit to 5 nameservers
            try:
                # Attempt AXFR (zone transfer)
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns, domain, timeout=10, lifetime=15)
                )
                if zone:
                    vulnerable_ns.append(ns)
            except Exception:
                # AXFR refused or timed out — expected
                pass

        if vulnerable_ns:
            return [
                self.make_finding(
                    target, runkey, "dns_zone_transfer",
                    Status.FAIL, Severity.CRITICAL,
                    f"DNS zone transfer (AXFR) succeeded on {len(vulnerable_ns)} nameserver(s) — full zone data is exposed",
                    evidence={"vulnerable_nameservers": vulnerable_ns, "domain": domain},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "dns_zone_transfer",
                Status.PASS, Severity.INFO,
                "Zone transfer (AXFR) is refused on all tested nameservers",
                evidence={"tested_nameservers": nameservers[:5]},
            )
        ]

    async def _check_dangling_cname(
        self,
        target: ScanTarget,
        runkey: str,
        hostname: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        async with self._semaphore:
            try:
                cname_answer = await resolver.resolve(hostname, "CNAME")
                cname_target = str(cname_answer[0].target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return []  # No CNAME — nothing to check
            except Exception as exc:
                return [self.make_error(target, runkey, "dns_dangling_cname", exc)]

        # Check if the CNAME target matches known takeover-prone services
        cname_lower = cname_target.lower()
        matched_pattern: str | None = None
        for pattern in TAKEOVER_PATTERNS:
            if cname_lower.endswith(pattern):
                matched_pattern = pattern
                break

        # Check if the CNAME target resolves
        try:
            async with self._semaphore:
                await resolver.resolve(cname_target, "A")
            # Resolved fine
            if matched_pattern:
                return [
                    self.make_finding(
                        target, runkey, "dns_dangling_cname",
                        Status.WARN, Severity.MEDIUM,
                        f"CNAME points to a takeover-prone service ({matched_pattern}) but currently resolves",
                        evidence={"cname_target": cname_target, "pattern": matched_pattern},
                    )
                ]
            return []
        except dns.resolver.NXDOMAIN:
            severity = Severity.HIGH
            detail = f"CNAME '{cname_target}' points to a non-existent domain (potential subdomain takeover)"
            if matched_pattern:
                detail = f"CNAME '{cname_target}' matches takeover-prone pattern '{matched_pattern}' and NXDOMAIN — likely subdomain takeover"
                severity = Severity.HIGH
            return [
                self.make_finding(
                    target, runkey, "dns_dangling_cname",
                    Status.FAIL, severity,
                    detail,
                    evidence={"cname_target": cname_target, "pattern": matched_pattern},
                )
            ]
        except Exception:
            return []

def _extract_hostname(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
