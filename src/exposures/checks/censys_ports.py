"""Censys network exposure check.

Queries Censys for open ports/services associated with a domain's certificates,
and generates findings for risky services.
"""
from __future__ import annotations

from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck
import asyncio

RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("insecure_port_ftp", Severity.HIGH, "FTP service exposed to internet on port 21 (unencrypted)"),
    23: ("insecure_port_telnet", Severity.CRITICAL, "Telnet service exposed to internet on port 23 (unencrypted)"),
    25: ("insecure_port_smtp_open_relay", Severity.HIGH, "SMTP port 25 exposed to internet (potential open relay)"),
    3389: ("admin_port_rdp", Severity.HIGH, "RDP (Remote Desktop) exposed to internet on port 3389"),
    5900: ("admin_port_vnc", Severity.HIGH, "VNC exposed to internet on port 5900"),
    3306: ("database_port_exposed", Severity.CRITICAL, "MySQL database port 3306 exposed to internet"),
    5432: ("database_port_exposed", Severity.CRITICAL, "PostgreSQL database port 5432 exposed to internet"),
    27017: ("database_port_exposed", Severity.CRITICAL, "MongoDB port 27017 exposed to internet"),
    6379: ("database_port_exposed", Severity.CRITICAL, "Redis port 6379 exposed to internet"),
    9200: ("database_port_exposed", Severity.CRITICAL, "Elasticsearch port 9200 exposed to internet"),
    22: ("ssh_exposed", Severity.INFO, "SSH exposed to internet on port 22"),
}

# Cloud provider ASN keywords that indicate unexpected hosting
CLOUD_ASN_KEYWORDS: list[str] = [
    "AMAZON", "MICROSOFT", "GOOGLE", "DIGITALOCEAN", "LINODE",
    "VULTR", "HETZNER", "OVH", "ALIBABA", "ORACLE",
]

class CensysPortsCheck(BaseCheck):
    name = "censys_ports"
    category = CheckCategory.NETWORK_EXPOSURE

    def __init__(self, config: Any, semaphore: asyncio.Semaphore | None = None) -> None:
        self._cfg = config  # CensysConfig
        self._semaphore = semaphore or asyncio.Semaphore(10)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []

        # Skip if Censys is not configured
        if not self._cfg.api_id or not self._cfg.api_secret:
            findings.append(
                self.make_finding(
                    target, runkey, "censys_not_configured",
                    Status.INFO, Severity.INFO,
                    "Censys not configured — network exposure check skipped",
                )
            )
            return findings

        try:
            async with self._semaphore:
                hosts_data = await asyncio.get_event_loop().run_in_executor(
                    None, self._query_censys, target.domain
                )
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "censys_query", exc))
            return findings

        if not hosts_data:
            findings.append(
                self.make_finding(
                    target, runkey, "censys_open_ports",
                    Status.INFO, Severity.INFO,
                    f"No Censys results found for domain '{target.domain}'",
                    evidence={"domain": target.domain},
                )
            )
            return findings

        # Aggregate all ports across all hosts
        all_ports: list[dict] = []
        for host in hosts_data:
            ip = host.get("ip", "unknown")
            asn_desc = host.get("autonomous_system", {}).get("description", "")
            services = host.get("services", [])
            for svc in services:
                port = svc.get("port", 0)
                transport = svc.get("transport_protocol", "TCP")
                service_name = svc.get("service_name", "unknown")
                all_ports.append({
                    "ip": ip,
                    "port": port,
                    "transport": transport,
                    "service": service_name,
                    "asn_description": asn_desc,
                })

        # Overall open ports info finding
        port_summary = [f"{p['ip']}:{p['port']}/{p['transport']} ({p['service']})" for p in all_ports[:50]]
        findings.append(
            self.make_finding(
                target, runkey, "censys_open_ports",
                Status.INFO, Severity.INFO,
                f"Censys found {len(all_ports)} open port(s) across {len(hosts_data)} host(s)",
                evidence={"domain": target.domain, "ports": port_summary, "host_count": len(hosts_data)},
            )
        )

        # Per-port risk findings
        reported_checks: set[str] = set()
        for port_info in all_ports:
            port = port_info["port"]
            ip = port_info["ip"]

            if port in RISKY_PORTS:
                check_name, severity, detail = RISKY_PORTS[port]
                dedup_key = f"{check_name}:{ip}:{port}"
                if dedup_key in reported_checks:
                    continue
                reported_checks.add(dedup_key)

                status = Status.FAIL if severity in (Severity.CRITICAL, Severity.HIGH) else Status.INFO
                if severity == Severity.INFO:
                    status = Status.INFO

                # SSH: include host key info if available
                evidence: dict = {"ip": ip, "port": port}

                findings.append(
                    self.make_finding(
                        target, runkey, check_name,
                        status, severity,
                        f"{detail} (host: {ip})",
                        evidence=evidence,
                    )
                )

            # Shadow IT: unexpected cloud provider ASN
            # TODO: validate this check - cursory review of the findings for a run didn't seem reliable
            asn_desc = port_info.get("asn_description", "").upper()
            if asn_desc:
                for keyword in CLOUD_ASN_KEYWORDS:
                    if keyword in asn_desc:
                        shadow_key = f"shadow_it:{ip}"
                        if shadow_key not in reported_checks:
                            reported_checks.add(shadow_key)
                            findings.append(
                                self.make_finding(
                                    target, runkey, "shadow_it_indicator",
                                    Status.WARN, Severity.MEDIUM,
                                    f"Host {ip} is hosted on a cloud provider ASN: {asn_desc}",
                                    evidence={"ip": ip, "asn_description": asn_desc},
                                )
                            )
                        break

        return findings

    def _query_censys(self, domain: str) -> list[dict]:
        """Synchronous Censys query — called in executor."""
        try:
            from censys.search import CensysHosts
        except ImportError:
            raise RuntimeError("censys package is not installed")

        import os
        os.environ["CENSYS_API_ID"] = self._cfg.api_id
        os.environ["CENSYS_API_SECRET"] = self._cfg.api_secret

        h = CensysHosts()
        query = f"services.tls.certificates.leaf_data.names: {domain}"
        results: list[dict] = []
        try:
            for page in h.search(query, per_page=100):
                if isinstance(page, dict):
                    results.append(page)
                elif hasattr(page, "__iter__"):
                    for item in page:
                        results.append(item)
                    break
                if len(results) >= 200:
                    break
        except Exception:
            pass
        return results
