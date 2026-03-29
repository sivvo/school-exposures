"""TLS/certificate security checks.

Uses the standard ssl module to connect and the cryptography library
to inspect the certificate in detail.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

import asyncio
import ipaddress
import socket
import ssl

class TLSCheck(BaseCheck):
    name = "tls"
    category = CheckCategory.TLS

    def __init__(self, config: Any, semaphore: asyncio.Semaphore | None = None) -> None:
        self._cfg = config  # TLSCheckConfig
        self._semaphore = semaphore or asyncio.Semaphore(50)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        hostname = _extract_hostname(target.url)
        port = _extract_port(target.url)

        try:
            async with self._semaphore:
                cert_data, ssl_version, ssl_error = await asyncio.get_event_loop().run_in_executor(
                    None, _connect_and_get_cert, hostname, port
                )
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "tls_connect", exc))
            return findings

        if ssl_error:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_connect",
                    Status.ERROR, Severity.HIGH,
                    f"TLS connection failed: {ssl_error}",
                    evidence={"error": ssl_error},
                )
            )
            return findings

        if not cert_data:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_connect",
                    Status.ERROR, Severity.HIGH,
                    "TLS connection succeeded but no certificate data was returned",
                )
            )
            return findings

        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception as exc:
            findings.append(self.make_error(target, runkey, "tls_cert_parse", exc))
            return findings

        now = datetime.now(timezone.utc)

        # Expiry check
        not_after = cert.not_valid_after_utc
        days_until_expiry = (not_after - now).days

        if days_until_expiry < 0:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_expired",
                    Status.FAIL, Severity.CRITICAL,
                    f"TLS certificate expired {abs(days_until_expiry)} days ago",
                    evidence={"not_after": not_after.isoformat(), "days_expired": abs(days_until_expiry)},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_expired",
                    Status.PASS, Severity.INFO,
                    "TLS certificate has not expired",
                    evidence={"not_after": not_after.isoformat()},
                )
            )

        if days_until_expiry < 0:
            # Already reported above; skip redundant expiry_days finding
            pass
        elif days_until_expiry < self._cfg.critical_expiry_days:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_expiry_days",
                    Status.FAIL, Severity.CRITICAL,
                    f"TLS certificate expires in {days_until_expiry} days (critical threshold: {self._cfg.critical_expiry_days})",
                    evidence={"days_until_expiry": days_until_expiry, "not_after": not_after.isoformat()},
                )
            )
        elif days_until_expiry < self._cfg.warn_expiry_days:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_expiry_days",
                    Status.WARN, Severity.HIGH,
                    f"TLS certificate expires in {days_until_expiry} days (warn threshold: {self._cfg.warn_expiry_days})",
                    evidence={"days_until_expiry": days_until_expiry, "not_after": not_after.isoformat()},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_expiry_days",
                    Status.PASS, Severity.INFO,
                    f"TLS certificate is valid for {days_until_expiry} more days",
                    evidence={"days_until_expiry": days_until_expiry, "not_after": not_after.isoformat()},
                )
            )

        # Hostname mismatch
        hostname_ok = _check_hostname_match(cert, hostname)
        if hostname_ok:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_hostname_mismatch",
                    Status.PASS, Severity.INFO,
                    f"Certificate hostname matches '{hostname}'",
                    evidence={"hostname": hostname},
                )
            )
        else:
            sans = _get_san_names(cert)
            cn = _get_cn(cert)
            findings.append(
                self.make_finding(
                    target, runkey, "tls_hostname_mismatch",
                    Status.FAIL, Severity.CRITICAL,
                    f"Certificate does not match hostname '{hostname}'",
                    evidence={"hostname": hostname, "cn": cn, "sans": sans},
                )
            )

        #  Self-signed check 
        is_self_signed = _is_self_signed(cert)
        if is_self_signed:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_self_signed",
                    Status.FAIL, Severity.HIGH,
                    "Certificate appears to be self-signed",
                    evidence={"subject": _cert_subject_str(cert), "issuer": _cert_issuer_str(cert)},
                )
            )
        else:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_self_signed",
                    Status.PASS, Severity.INFO,
                    "Certificate is signed by a CA",
                    evidence={"issuer": _cert_issuer_str(cert)},
                )
            )

        # Protocol version checks
        findings += await self._check_weak_protocols(target, runkey, hostname, port)

        #  Minimum protocol info 
        min_proto = ssl_version or "unknown"
        findings.append(
            self.make_finding(
                target, runkey, "tls_min_protocol",
                Status.INFO, Severity.INFO,
                f"TLS connection negotiated with protocol: {min_proto}",
                evidence={"protocol": min_proto},
            )
        )

        #  Certificate transparency (SCT extension)
        findings += self._check_cert_transparency(target, runkey, cert)

        return findings

    async def _check_weak_protocols(
        self,
        target: ScanTarget,
        runkey: str,
        hostname: str,
        port: int,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Test TLS 1.0
        tls10_accepted, _ = await asyncio.get_event_loop().run_in_executor(
            None, _test_protocol, hostname, port, ssl.TLSVersion.TLSv1
        )
        if tls10_accepted:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_weak_protocol",
                    Status.FAIL, Severity.CRITICAL,
                    "Server accepts TLS 1.0 (deprecated and insecure)",
                    evidence={"protocol": "TLSv1.0"},
                )
            )

        # Test TLS 1.1
        tls11_accepted, _ = await asyncio.get_event_loop().run_in_executor(
            None, _test_protocol, hostname, port, ssl.TLSVersion.TLSv1_1
        )
        if tls11_accepted:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_weak_protocol",
                    Status.FAIL, Severity.HIGH,
                    "Server accepts TLS 1.1 (deprecated)",
                    evidence={"protocol": "TLSv1.1"},
                )
            )

        if not tls10_accepted and not tls11_accepted:
            findings.append(
                self.make_finding(
                    target, runkey, "tls_weak_protocol",
                    Status.PASS, Severity.INFO,
                    "Server does not accept TLS 1.0 or TLS 1.1",
                )
            )

        return findings

    def _check_cert_transparency(
        self, target: ScanTarget, runkey: str, cert: x509.Certificate
    ) -> list[Finding]:
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            return [
                self.make_finding(
                    target, runkey, "tls_cert_transparency",
                    Status.PASS, Severity.INFO,
                    "Certificate contains SCT extension (Certificate Transparency)",
                )
            ]
        except x509.ExtensionNotFound:
            pass

        # Also check for embedded SCT via TLS extension — we can't easily do that
        # without a full TLS handshake parser, so just note it's absent in cert
        return [
            self.make_finding(
                target, runkey, "tls_cert_transparency",
                Status.WARN, Severity.LOW,
                "Certificate does not contain embedded SCT extension (Certificate Transparency)",
            )
        ]


# ---------------------------------------------------------------------------
# Low-level helpers (run in executor to avoid blocking event loop)
# ---------------------------------------------------------------------------

def _connect_and_get_cert(
    hostname: str, port: int
) -> tuple[bytes | None, str | None, str | None]:
    """Return (cert_der_bytes, ssl_version_str, error_str)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                return cert_der, version, None
    except Exception as exc:
        return None, None, str(exc)


def _test_protocol(
    hostname: str, port: int, version: ssl.TLSVersion
) -> tuple[bool, str | None]:
    """Return (accepted, error_string) for the given TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force min and max to the target version
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, str(exc)


def _extract_hostname(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _extract_port(url: str) -> int:
    from urllib.parse import urlparse
    p = urlparse(url)
    if p.port:
        return p.port
    return 443 if p.scheme == "https" else 80


def _get_san_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        names: list[str] = []
        for dns_name in san.get_values_for_type(x509.DNSName):
            names.append(dns_name)
        return names
    except x509.ExtensionNotFound:
        return []


def _get_cn(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return ""


def _cert_subject_str(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _cert_issuer_str(cert: x509.Certificate) -> str:
    return cert.issuer.rfc4514_string()


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def _check_hostname_match(cert: x509.Certificate, hostname: str) -> bool:
    """Check if hostname matches the cert's SANs or CN."""
    # Try SANs first
    sans = _get_san_names(cert)
    if sans:
        for san in sans:
            if _hostname_matches_pattern(san, hostname):
                return True
        return False
    # Fall back to CN
    cn = _get_cn(cert)
    if cn:
        return _hostname_matches_pattern(cn, hostname)
    return False


def _hostname_matches_pattern(pattern: str, hostname: str) -> bool:
    """Match a hostname against a certificate name pattern (supporting wildcards)."""
    pattern = pattern.lower()
    hostname = hostname.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if hostname.endswith("." + suffix):
            # Wildcard only covers one label
            left = hostname[: -(len(suffix) + 1)]
            return "." not in left
        return hostname == suffix
    return pattern == hostname
