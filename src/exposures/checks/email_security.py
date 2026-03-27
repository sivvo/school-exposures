"""Email security checks: SPF, DMARC, MX records.

DKIM is skipped — requires knowing the selector in advance.
"""
from __future__ import annotations
from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

import asyncio
import re
import dns.asyncresolver
import dns.exception
import dns.resolver

class EmailSecurityCheck(BaseCheck):
    name = "email_security"
    category = CheckCategory.EMAIL_SECURITY

    def __init__(self, config: Any, semaphore: asyncio.Semaphore | None = None) -> None:
        self._cfg = config  # EmailSecurityCheckConfig
        self._semaphore = semaphore or asyncio.Semaphore(500)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = target.domain

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 15

            # Check MX records first
            mx_records, mx_findings = await self._check_mx(target, runkey, domain, resolver)
            findings += mx_findings

            if not mx_records:
                findings.append(
                    self.make_finding(
                        target, runkey, "email_security_skipped",
                        Status.INFO, Severity.INFO,
                        "No MX records found — email security checks skipped",
                        evidence={"domain": domain},
                    )
                )
                # Still check DKIM skip notice
                findings.append(self._dkim_skip_finding(target, runkey))
                return findings

            # SPF
            if self._cfg.check_spf:
                findings += await self._check_spf(target, runkey, domain, resolver)

            # DMARC
            if self._cfg.check_dmarc:
                findings += await self._check_dmarc(target, runkey, domain, resolver)

            # DKIM skip notice
            findings.append(self._dkim_skip_finding(target, runkey))

        except Exception as exc:
            findings.append(self.make_error(target, runkey, "email_security", exc))

        return findings

    # ------------------------------------------------------------------
    # MX record
    # ------------------------------------------------------------------

    async def _check_mx(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> tuple[list[str], list[Finding]]:
        async with self._semaphore:
            try:
                answer = await resolver.resolve(domain, "MX")
                records = sorted(
                    [(rr.preference, str(rr.exchange).rstrip(".")) for rr in answer]
                )
                mx_hostnames = [r[1] for r in records]
                finding = self.make_finding(
                    target, runkey, "mx_records_present",
                    Status.INFO, Severity.INFO,
                    f"MX records found: {len(records)} record(s)",
                    evidence={"mx_records": [{"preference": p, "exchange": e} for p, e in records]},
                )
                return mx_hostnames, [finding]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return [], []
            except Exception as exc:
                return [], [self.make_error(target, runkey, "mx_records_present", exc)]

    # ------------------------------------------------------------------
    # SPF policy
    # ------------------------------------------------------------------

    async def _check_spf(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        findings: list[Finding] = []
        spf_record: str | None = None

        async with self._semaphore:
            try:
                answer = await resolver.resolve(domain, "TXT")
                for rr in answer:
                    txt = "".join(part.decode() if isinstance(part, bytes) else part for part in rr.strings)
                    if txt.startswith("v=spf1"):
                        spf_record = txt
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as exc:
                return [self.make_error(target, runkey, "spf_present", exc)]

        if not spf_record:
            findings.append(
                self.make_finding(
                    target, runkey, "spf_present",
                    Status.FAIL, Severity.HIGH,
                    "No SPF record found — anyone can spoof email from this domain",
                    evidence={"domain": domain},
                )
            )
            return findings

        findings.append(
            self.make_finding(
                target, runkey, "spf_present",
                Status.PASS, Severity.INFO,
                "SPF record found",
                evidence={"spf_record": spf_record},
            )
        )

        # Check -all / ~all / +all / ?all mechanism
        all_match = re.search(r"([+~?-])all\b", spf_record, re.IGNORECASE)
        if not all_match:
            findings.append(
                self.make_finding(
                    target, runkey, "spf_all_mechanism",
                    Status.WARN, Severity.MEDIUM,
                    "SPF record has no 'all' mechanism",
                    evidence={"spf_record": spf_record},
                )
            )
        else:
            qualifier = all_match.group(1)
            if qualifier == "-":
                findings.append(
                    self.make_finding(
                        target, runkey, "spf_all_mechanism",
                        Status.PASS, Severity.INFO,
                        "SPF uses '-all' (hard fail) — recommended",
                        evidence={"qualifier": qualifier, "spf_record": spf_record},
                    )
                )
            elif qualifier == "~":
                findings.append(
                    self.make_finding(
                        target, runkey, "spf_all_mechanism",
                        Status.WARN, Severity.MEDIUM,
                        "SPF uses '~all' (soft fail) — consider upgrading to '-all'",
                        evidence={"qualifier": qualifier, "spf_record": spf_record},
                    )
                )
            elif qualifier == "+":
                findings.append(
                    self.make_finding(
                        target, runkey, "spf_all_mechanism",
                        Status.FAIL, Severity.CRITICAL,
                        "SPF uses '+all' — allows ALL senders; effectively no restriction",
                        evidence={"qualifier": qualifier, "spf_record": spf_record},
                    )
                )
            elif qualifier == "?":
                findings.append(
                    self.make_finding(
                        target, runkey, "spf_all_mechanism",
                        Status.WARN, Severity.HIGH,
                        "SPF uses '?all' (neutral) — provides no protection against spoofing",
                        evidence={"qualifier": qualifier, "spf_record": spf_record},
                    )
                )

        # Check DNS lookup count (RFC limit is 10)
        findings += await self._check_spf_lookup_count(target, runkey, domain, spf_record, resolver)

        return findings

    async def _check_spf_lookup_count(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        spf_record: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        """Count DNS-querying mechanisms in SPF (a, mx, include, redirect, exists, ptr)."""
        # Simple heuristic — count mechanism keywords that trigger DNS lookups
        lookup_mechanisms = re.findall(
            r"\b(include:|a:|mx:|ptr:|exists:|redirect=)", spf_record, re.IGNORECASE
        )
        # Also standalone 'a' and 'mx' without colon
        standalone = re.findall(r"(?:^| )(a|mx)(?= |$)", spf_record, re.IGNORECASE)
        total = len(lookup_mechanisms) + len(standalone)

        if total > 10:
            return [
                self.make_finding(
                    target, runkey, "spf_lookup_count",
                    Status.WARN, Severity.MEDIUM,
                    f"SPF record has approximately {total} DNS-querying mechanisms (RFC limit is 10)",
                    evidence={"estimated_lookups": total, "spf_record": spf_record},
                )
            ]
        return [
            self.make_finding(
                target, runkey, "spf_lookup_count",
                Status.PASS, Severity.INFO,
                f"SPF lookup count is approximately {total} (within RFC limit of 10)",
                evidence={"estimated_lookups": total},
            )
        ]

    # ------------------------------------------------------------------
    # DMARC check
    # ------------------------------------------------------------------

    async def _check_dmarc(
        self,
        target: ScanTarget,
        runkey: str,
        domain: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[Finding]:
        findings: list[Finding] = []
        dmarc_record: str | None = None
        dmarc_domain = f"_dmarc.{domain}"

        async with self._semaphore:
            try:
                answer = await resolver.resolve(dmarc_domain, "TXT")
                for rr in answer:
                    txt = "".join(part.decode() if isinstance(part, bytes) else part for part in rr.strings)
                    if txt.startswith("v=DMARC1"):
                        dmarc_record = txt
                        break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as exc:
                return [self.make_error(target, runkey, "dmarc_present", exc)]

        if not dmarc_record:
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_present",
                    Status.FAIL, Severity.HIGH,
                    "No DMARC record found — no email authentication policy enforced",
                    evidence={"dmarc_domain": dmarc_domain},
                )
            )
            return findings

        findings.append(
            self.make_finding(
                target, runkey, "dmarc_present",
                Status.PASS, Severity.INFO,
                "DMARC record found",
                evidence={"dmarc_record": dmarc_record},
            )
        )
        
        tags = _parse_dmarc_tags(dmarc_record)
        
        policy = tags.get("p", "").lower() # Policy check
        if policy == "none":
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_policy",
                    Status.WARN, Severity.MEDIUM,
                    "DMARC policy is 'none' — emails failing DMARC are not rejected or quarantined",
                    evidence={"policy": policy, "dmarc_record": dmarc_record},
                )
            )
        elif policy == "quarantine":
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_policy",
                    Status.PASS, Severity.INFO,
                    "DMARC policy is 'quarantine' — failing emails are quarantined",
                    evidence={"policy": policy},
                )
            )
        elif policy == "reject":
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_policy",
                    Status.PASS, Severity.INFO,
                    "DMARC policy is 'reject' — failing emails are rejected",
                    evidence={"policy": policy},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_policy",
                    Status.WARN, Severity.MEDIUM,
                    f"DMARC policy is unrecognised or missing: '{policy}'",
                    evidence={"policy": policy, "dmarc_record": dmarc_record},
                )
            )

        # pct check
        pct_str = tags.get("pct", "100")
        try:
            pct = int(pct_str)
        except ValueError:
            pct = 100

        if pct < 100 and policy in ("quarantine", "reject"):
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_pct",
                    Status.WARN, Severity.LOW,
                    f"DMARC pct={pct} — policy only applies to {pct}% of failing emails",
                    evidence={"pct": pct, "policy": policy},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_pct",
                    Status.PASS, Severity.INFO,
                    f"DMARC pct={pct}",
                    evidence={"pct": pct},
                )
            )

        # rua (aggregate report URI)
        rua = tags.get("rua", "")
        if rua:
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_rua",
                    Status.PASS, Severity.INFO,
                    "DMARC aggregate report URI (rua) is configured",
                    evidence={"rua": rua},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "dmarc_rua",
                    Status.WARN, Severity.LOW,
                    "DMARC rua (aggregate report URI) is not configured — no visibility into failures",
                )
            )

        return findings

    def _dkim_skip_finding(self, target: ScanTarget, runkey: str) -> Finding:
        return self.make_finding(
            target, runkey, "dkim_check",
            Status.INFO, Severity.INFO,
            "DKIM check skipped - requires selector knowledge",
        )

def _parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse DMARC tag=value pairs from a DMARC TXT record string."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags
