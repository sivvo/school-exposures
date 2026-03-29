"""DNS-based blacklist (DNSBL) check for mail server IP reputation.

Resolves each MX host to its A record(s), then queries Spamhaus ZEN
(zen.spamhaus.org — the combined SBL + XBL + PBL list) for each IP.

A listing means the school's outbound mail is likely being rejected
by the majority of the internet.

Response code interpretation:
    127.0.0.2       SBL     — spam source               CRITICAL
    127.0.0.3       SBL CSS — snowshoe spam              CRITICAL
    127.0.0.4–7     XBL     — infected / botnet          CRITICAL
    127.0.0.9       DROP    — hijacked netblock           CRITICAL
    127.0.0.10–11   PBL     — end-user / dynamic IP      HIGH
    NXDOMAIN                — not listed                 PASS
"""
from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

_ZEN = "zen.spamhaus.org"

# Map the last octet of a 127.0.0.x response to (label, severity)
_CODE_MAP: dict[int, tuple[str, Severity]] = {
    2:  ("SBL — spam source",             Severity.CRITICAL),
    3:  ("SBL CSS — snowshoe spam",        Severity.CRITICAL),
    4:  ("XBL — infected host / botnet",   Severity.CRITICAL),
    5:  ("XBL — infected host / botnet",   Severity.CRITICAL),
    6:  ("XBL — infected host / botnet",   Severity.CRITICAL),
    7:  ("XBL — infected host / botnet",   Severity.CRITICAL),
    9:  ("DROP — hijacked netblock",       Severity.CRITICAL),
    10: ("PBL — end-user / dynamic IP",    Severity.HIGH),
    11: ("PBL — end-user / dynamic IP",    Severity.HIGH),
}

class DNSBLCheck(BaseCheck):
    name     = "dnsbl"
    category = CheckCategory.REPUTATION

    def __init__(self, semaphore: asyncio.Semaphore | None = None) -> None:
        self._sem = semaphore or asyncio.Semaphore(500)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        domain   = target.domain
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout  = 5
        resolver.lifetime = 10

        # Resolve MX 
        mx_hosts: list[str] = []
        try:
            async with self._sem:
                answer = await resolver.resolve(domain, "MX")
            mx_hosts = sorted(
                {str(rr.exchange).rstrip(".").lower() for rr in answer}
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []  # no MX (email_security check will already flag this)
        except Exception as exc:
            return [self.make_error(target, runkey, "dnsbl_mx_lookup", exc)]

        #  Resolve each MX host to IPs then check the DNSBL list
        findings: list[Finding] = []
        checked_ips: set[str] = set()

        for mx_host in mx_hosts:
            ips: list[str] = []
            try:
                async with self._sem:
                    a_answer = await resolver.resolve(mx_host, "A")
                ips = [str(rr) for rr in a_answer]
            except Exception:
                continue  # can't resolve MX host

            for ip in ips:
                if ip in checked_ips:
                    continue
                checked_ips.add(ip)
                findings += await self._check_ip(target, runkey, ip, mx_host, resolver)

        if not findings:
            if checked_ips:
                findings.append(self.make_finding(
                    target, runkey, "dnsbl",
                    Status.PASS, Severity.INFO,
                    f"Mail server IP(s) not listed in Spamhaus ZEN ({', '.join(sorted(checked_ips))})",
                    evidence={"checked_ips": sorted(checked_ips)},
                ))
        return findings

    async def _check_ip(
        self,
        target: ScanTarget,
        runkey: str,
        ip: str,
        mx_host: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{_ZEN}"
            async with self._sem:
                answer = await resolver.resolve(query, "A")
            responses = [str(rr) for rr in answer]
        except dns.resolver.NXDOMAIN:
            return []  # not listed
        except Exception as exc:
            return [self.make_error(target, runkey, "dnsbl", exc)]

        findings: list[Finding] = []
        seen_codes: set[int] = set()
        for resp_ip in responses:
            try:
                last_octet = int(resp_ip.split(".")[-1])
            except ValueError:
                continue
            if last_octet in seen_codes:
                continue
            seen_codes.add(last_octet)

            label, sev = _CODE_MAP.get(last_octet, (f"listed (code {last_octet})", Severity.HIGH))
            findings.append(self.make_finding(
                target, runkey, "dnsbl",
                Status.FAIL, sev,
                f"Mail server {ip} ({mx_host}) is listed in Spamhaus ZEN: {label}",
                evidence={
                    "ip":           ip,
                    "mx_host":      mx_host,
                    "dnsbl":        _ZEN,
                    "response":     resp_ip,
                    "listing_type": label,
                },
            ))
        return findings
