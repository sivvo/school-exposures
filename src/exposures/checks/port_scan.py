"""Direct TCP port scan check.

Probes a configurable set of risky ports using asyncio TCP connections.
Provides basic network exposure data without requiring a Censys subscription.

Reuses the RISKY_PORTS severity table from the censys_ports check so
findings are consistent across both data sources.
"""
import asyncio

from __future__ import annotations
from typing import Any
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck
from .censys_ports import RISKY_PORTS

# Additional ports to scan beyond the RISKY_PORTS set
_EXTRA_PORTS: dict[int, tuple[str, Severity, str]] = {
    8080: ("http_alt_port", Severity.LOW,    "HTTP service on port 8080 (non-standard)"),
    8443: ("https_alt_port", Severity.LOW,   "HTTPS service on port 8443 (non-standard)"),
    8888: ("http_alt_port", Severity.LOW,    "HTTP service on port 8888 (non-standard)"),
    4443: ("https_alt_port", Severity.LOW,   "HTTPS service on port 4443 (non-standard)"),
    2222: ("ssh_alt_port", Severity.MEDIUM,  "SSH service on non-standard port 2222"),
    8022: ("ssh_alt_port", Severity.MEDIUM,  "SSH service on non-standard port 8022"),
}

ALL_PORTS: dict[int, tuple[str, Severity, str]] = {**RISKY_PORTS, **_EXTRA_PORTS}

# Ports that are frequently legitimately open and should only be INFO
_INFO_ONLY_PORTS = {80, 443, 22, 8080, 8443, 8888, 4443}

_CONNECT_TIMEOUT = 3.0  # seconds

async def _tcp_probe(host: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


class PortScanCheck(BaseCheck):
    name = "port_scan"
    category = CheckCategory.NETWORK_EXPOSURE

    def __init__(
        self,
        semaphore: asyncio.Semaphore | None = None,
        ports: list[int] | None = None,
        connect_timeout: float = _CONNECT_TIMEOUT,
    ) -> None:
        # Limit concurrency, we don't want to be a nuisance
        self._semaphore = semaphore or asyncio.Semaphore(50)
        self._ports = ports or list(ALL_PORTS.keys())
        self._timeout = connect_timeout

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        from urllib.parse import urlparse
        hostname = urlparse(target.url).hostname or ""
        if not hostname:
            return []

        tasks = [
            self._probe_port(target, runkey, hostname, port)
            for port in self._ports
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: list[int] = []
        findings: list[Finding] = []

        for port, result in zip(self._ports, results):
            if isinstance(result, Exception):
                continue
            if result:
                open_ports.append(port)

        if not open_ports:
            return [
                self.make_finding(
                    target, runkey, "port_scan_summary",
                    Status.PASS, Severity.INFO,
                    f"No risky ports open on {hostname} (scanned {len(self._ports)} ports)",
                    evidence={"hostname": hostname, "scanned_ports": self._ports},
                )
            ]

        # Summary finding
        findings.append(
            self.make_finding(
                target, runkey, "port_scan_summary",
                Status.INFO, Severity.INFO,
                f"Open ports on {hostname}: {', '.join(str(p) for p in sorted(open_ports))}",
                evidence={"hostname": hostname, "open_ports": sorted(open_ports)},
            )
        )

        # Per-port findings for risky ports
        for port in open_ports:
            if port not in ALL_PORTS:
                continue
            check_name, severity, detail = ALL_PORTS[port]

            if port in _INFO_ONLY_PORTS:
                status = Status.INFO
            elif severity in (Severity.CRITICAL, Severity.HIGH):
                status = Status.FAIL
            else:
                status = Status.WARN

            findings.append(
                self.make_finding(
                    target, runkey, check_name,
                    status, severity,
                    f"{detail} — open on {hostname}:{port}",
                    evidence={"hostname": hostname, "port": port},
                )
            )

        return findings

    async def _probe_port(
        self, target: ScanTarget, runkey: str, hostname: str, port: int
    ) -> bool:
        async with self._semaphore:
            return await _tcp_probe(hostname, port, self._timeout)
