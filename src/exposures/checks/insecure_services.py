"""Insecure services synthesis check.

This check runs AFTER all other checks for a target have completed.
It takes the full list of findings and produces cross-cutting findings
by correlating results from different check categories.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck


class InsecureServicesCheck(BaseCheck):
    name = "insecure_services"
    category = CheckCategory.INSECURE_SERVICES

    def __init__(self) -> None:
        pass

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        # This check requires prior findings — use run_with_findings instead.
        # Called without prior findings, produce nothing.
        return []

    async def run_with_findings(
        self,
        target: ScanTarget,
        runkey: str,
        prior_findings: list[Finding],
    ) -> list[Finding]:
        """Analyse prior findings and produce cross-cutting findings."""
        findings: list[Finding] = []
        try:
            findings += self._check_http_port_with_redirect(target, runkey, prior_findings)
            findings += self._check_non_443_http_without_tls(target, runkey, prior_findings)
            findings += self._check_database_with_web_exposure(target, runkey, prior_findings)
            findings += self._check_tls_pass_with_weak_protocol(target, runkey, prior_findings)
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "insecure_services_synthesis", exc))
        return findings

    def _check_http_port_with_redirect(
        self,
        target: ScanTarget,
        runkey: str,
        prior: list[Finding],
    ) -> list[Finding]:
        """If HTTP correctly redirects to HTTPS AND port 80 is open in Censys, note it as informational."""
        https_enforced_pass = any(
            f.check_name == "https_enforced" and f.status == Status.PASS
            for f in prior
        )
        port_80_open = any(
            f.check_category == CheckCategory.NETWORK_EXPOSURE
            and f.evidence.get("port") == 80
            for f in prior
        )

        if https_enforced_pass and port_80_open:
            return [
                self.make_finding(
                    target, runkey, "http_port_open_with_redirect",
                    Status.INFO, Severity.INFO,
                    "HTTP port 80 is open but correctly redirects to HTTPS",
                )
            ]
        return []

    def _check_non_443_http_without_tls(
        self,
        target: ScanTarget,
        runkey: str,
        prior: list[Finding],
    ) -> list[Finding]:
        """If Censys shows a non-443 HTTP port open that isn't covered by TLS finding."""
        # Collect non-standard HTTP-ish ports from Censys findings
        http_ish_services = {"HTTP", "HTTPS", "HTTP_PROXY"}
        risky_ports: list[dict] = []
        for f in prior:
            if f.check_category != CheckCategory.NETWORK_EXPOSURE:
                continue
            port = f.evidence.get("port", 0)
            service = f.evidence.get("service", "").upper()
            if port and port not in (443, 80) and service in http_ish_services:
                risky_ports.append({"port": port, "service": service, "ip": f.evidence.get("ip", "")})

        tls_pass = any(
            f.check_category == CheckCategory.TLS and f.status == Status.PASS
            and f.check_name in ("tls_expired", "tls_hostname_mismatch")
            for f in prior
        )

        findings: list[Finding] = []
        for rp in risky_ports:
            if not tls_pass:
                findings.append(
                    self.make_finding(
                        target, runkey, "non_standard_http_without_tls",
                        Status.FAIL, Severity.HIGH,
                        f"Unencrypted HTTP service on non-standard port {rp['port']} (service: {rp['service']}, host: {rp['ip']})",
                        evidence=rp,
                    )
                )
            else:
                findings.append(
                    self.make_finding(
                        target, runkey, "non_standard_http_port",
                        Status.WARN, Severity.MEDIUM,
                        f"HTTP service on non-standard port {rp['port']} (service: {rp['service']}, host: {rp['ip']})",
                        evidence=rp,
                    )
                )
        return findings

    def _check_database_with_web_exposure(
        self,
        target: ScanTarget,
        runkey: str,
        prior: list[Finding],
    ) -> list[Finding]:
        """If a database port AND a component are both detected — elevated risk."""
        db_finding = next(
            (f for f in prior if f.check_name == "database_port_exposed"), None
        )
        if not db_finding:
            return []

        component_finding = next(
            (f for f in prior if f.check_name == "component_detected"), None
        )
        if not component_finding:
            return []

        return [
            self.make_finding(
                target, runkey, "database_and_web_colocated",
                Status.WARN, Severity.HIGH,
                "Database port is internet-exposed on the same host as a web application — consider network segmentation",
                evidence={
                    "database_finding": db_finding.check_name,
                    "component": component_finding.evidence.get("product", "unknown"),
                },
            )
        ]

    def _check_tls_pass_with_weak_protocol(
        self,
        target: ScanTarget,
        runkey: str,
        prior: list[Finding],
    ) -> list[Finding]:
        """If TLS cert is valid but weak protocol is accepted — summarise the contradiction."""
        tls_cert_ok = any(
            f.check_name in ("tls_expiry_days", "tls_hostname_mismatch")
            and f.status == Status.PASS
            for f in prior
        )
        weak_proto = next(
            (f for f in prior if f.check_name == "tls_weak_protocol" and f.status == Status.FAIL),
            None,
        )

        if tls_cert_ok and weak_proto:
            return [
                self.make_finding(
                    target, runkey, "valid_cert_weak_protocol",
                    Status.WARN, Severity.HIGH,
                    "TLS certificate is valid but server accepts deprecated protocol versions — downgrade attack possible",
                    evidence={"weak_protocol_detail": weak_proto.detail},
                )
            ]
        return []
