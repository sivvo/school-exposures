"""Cloud storage exposure check.

Detects whether a target URL is backed by a public cloud storage bucket
(AWS S3, Azure Blob Storage, Google Cloud Storage, Cloudflare R2) via:
  1. Full CNAME chain resolution
  2. HTTP redirect chain inspection

For detected buckets, probes whether the bucket is publicly listable.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

# (provider, compiled_pattern, group_name_or_None)
# group_name is the named capture group for the bucket/account name, or None for path-style
_CLOUD_PATTERNS: list[tuple[str, re.Pattern, str | None]] = [
    # AWS S3 virtual-hosted: {bucket}.s3.amazonaws.com
    ("s3", re.compile(r"^(?P<bucket>[^.]+)\.s3\.amazonaws\.com$"), "bucket"),
    # AWS S3 regional virtual-hosted: {bucket}.s3.{region}.amazonaws.com
    ("s3", re.compile(r"^(?P<bucket>[^.]+)\.s3\.[a-z0-9-]+\.amazonaws\.com$"), "bucket"),
    # AWS S3 path-style: s3.amazonaws.com or s3.{region}.amazonaws.com
    ("s3", re.compile(r"^s3(?:\.[a-z0-9-]+)?\.amazonaws\.com$"), None),
    # Azure Blob: {account}.blob.core.windows.net
    ("azure", re.compile(r"^(?P<account>[^.]+)\.blob\.core\.windows\.net$"), "account"),
    # GCS virtual-hosted: {bucket}.storage.googleapis.com
    ("gcs", re.compile(r"^(?P<bucket>[^.]+)\.storage\.googleapis\.com$"), "bucket"),
    # GCS path-style: storage.googleapis.com
    ("gcs", re.compile(r"^storage\.googleapis\.com$"), None),
    # Cloudflare R2
    ("r2", re.compile(r"^[^.]+\.r2\.cloudflarestorage\.com$"), None),
]

# XML signatures in a public listing response body
_LISTING_SIGNATURES: dict[str, bytes] = {
    "s3": b"<ListBucketResult",
    "azure": b"<EnumerationResults",
    "gcs": b"<ListBucketResult",
}

_TIMEOUT = aiohttp.ClientTimeout(total=15, connect=5)
_HEADERS = {"User-Agent": "CyberExposureScanner/1.0"}


def _match_cloud_storage(hostname: str) -> tuple[str, str | None] | None:
    """Return (provider, name) if hostname is a cloud storage endpoint, else None."""
    h = hostname.lower().rstrip(".")
    for provider, pattern, group in _CLOUD_PATTERNS:
        m = pattern.match(h)
        if m:
            name = m.group(group) if group else None
            return provider, name
    return None


async def _resolve_cname_chain(
    hostname: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
    max_hops: int = 10,
) -> list[str]:
    """Walk the full CNAME chain and return all target hostnames."""
    chain: list[str] = []
    current = hostname.lower().rstrip(".")
    for _ in range(max_hops):
        try:
            async with semaphore:
                answer = await resolver.resolve(current, "CNAME")
            next_host = str(answer[0].target).rstrip(".")
            chain.append(next_host)
            current = next_host
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            break
        except Exception:
            break
    return chain


class CloudStorageCheck(BaseCheck):
    name = "cloud_storage"
    category = CheckCategory.CLOUD_STORAGE

    def __init__(
        self,
        http_semaphore: asyncio.Semaphore | None = None,
        dns_semaphore: asyncio.Semaphore | None = None,
    ) -> None:
        self._http_sem = http_semaphore or asyncio.Semaphore(200)
        self._dns_sem = dns_semaphore or asyncio.Semaphore(500)

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        hostname = urlparse(target.url).hostname or ""
        if not hostname:
            return []

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 15

        # 1. Check if the hostname itself is a cloud storage endpoint
        provider_name = _match_cloud_storage(hostname)
        storage_host = hostname
        linkage = "direct"

        # 2. Walk the full CNAME chain
        if not provider_name:
            chain = await _resolve_cname_chain(hostname, resolver, self._dns_sem)
            for hop in chain:
                match = _match_cloud_storage(hop)
                if match:
                    provider_name = match
                    storage_host = hop
                    linkage = "cname"
                    break

        # 3. Follow HTTP redirects if DNS gave us nothing
        final_url: str | None = None
        if not provider_name:
            final_url, provider_name, storage_host = await self._check_redirect(target.url)
            if provider_name:
                linkage = "redirect"

        if not provider_name:
            return []

        provider, bucket_name = provider_name
        return await self._probe_bucket(
            target, runkey, provider, bucket_name, storage_host, linkage, final_url
        )

    async def _check_redirect(
        self, url: str
    ) -> tuple[str | None, tuple[str, str | None] | None, str]:
        """Follow redirects and return (final_url, (provider, name), storage_host)."""
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(
                connector=connector, timeout=_TIMEOUT, headers=_HEADERS
            ) as session:
                async with self._http_sem:
                    async with session.get(
                        url, allow_redirects=True, max_redirects=10
                    ) as resp:
                        final_url = str(resp.url)
                        final_host = urlparse(final_url).hostname or ""
                        match = _match_cloud_storage(final_host)
                        if match:
                            return final_url, match, final_host
        except Exception:
            pass
        return None, None, ""

    async def _probe_bucket(
        self,
        target: ScanTarget,
        runkey: str,
        provider: str,
        bucket_name: str | None,
        storage_host: str,
        linkage: str,
        final_url: str | None,
    ) -> list[Finding]:
        # Build probe URL
        if provider == "s3":
            if bucket_name:
                probe_url = f"https://{storage_host}/"
            else:
                # Path-style: extract bucket from the path we landed on
                parsed = urlparse(final_url or "")
                parts = parsed.path.strip("/").split("/")
                if parts and parts[0]:
                    bucket_name = parts[0]
                    probe_url = f"https://{storage_host}/{bucket_name}/"
                else:
                    probe_url = f"https://{storage_host}/"
        elif provider == "azure":
            probe_url = f"https://{storage_host}/?comp=list"
        elif provider == "gcs":
            if bucket_name:
                probe_url = f"https://storage.googleapis.com/{bucket_name}/"
            else:
                probe_url = f"https://{storage_host}/"
        else:
            probe_url = f"https://{storage_host}/"

        evidence: dict[str, Any] = {
            "provider": provider,
            "storage_host": storage_host,
            "linkage": linkage,
            "probe_url": probe_url,
        }
        if bucket_name:
            evidence["bucket_name"] = bucket_name

        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            async with aiohttp.ClientSession(
                connector=connector, timeout=_TIMEOUT, headers=_HEADERS
            ) as session:
                async with self._http_sem:
                    async with session.get(probe_url, allow_redirects=False) as resp:
                        status_code = resp.status
                        body = await resp.content.read(2048)
        except Exception as exc:
            return [self.make_error(target, runkey, "cloud_storage_probe", exc)]

        evidence["http_status"] = status_code
        listing_sig = _LISTING_SIGNATURES.get(provider)

        if status_code == 200 and listing_sig and listing_sig in body:
            return [
                self.make_finding(
                    target, runkey, "cloud_storage_public_listing",
                    Status.FAIL, Severity.CRITICAL,
                    f"{provider.upper()} bucket is publicly listable ({storage_host})"
                    f" — linked via {linkage}",
                    evidence={
                        **evidence,
                        "body_snippet": body[:500].decode("utf-8", errors="replace"),
                    },
                )
            ]

        if status_code == 200:
            return [
                self.make_finding(
                    target, runkey, "cloud_storage_public_access",
                    Status.WARN, Severity.HIGH,
                    f"{provider.upper()} storage returns HTTP 200 ({storage_host})"
                    f" — may allow unauthenticated object access",
                    evidence=evidence,
                )
            ]

        if status_code == 404 and linkage == "cname":
            # Bucket doesn't exist but our domain CNAMEs to it — unclaimed bucket
            return [
                self.make_finding(
                    target, runkey, "cloud_storage_unclaimed_bucket",
                    Status.FAIL, Severity.HIGH,
                    f"CNAME points to {provider.upper()} storage ({storage_host})"
                    f" but the bucket does not exist — potential bucket takeover",
                    evidence=evidence,
                )
            ]

        if status_code == 403:
            # Bucket exists, access restricted — expected/good state
            # Only emit an INFO finding when linked via CNAME (confirms deliberate routing)
            if linkage in ("cname", "direct"):
                return [
                    self.make_finding(
                        target, runkey, "cloud_storage_detected",
                        Status.PASS, Severity.INFO,
                        f"Target routes to {provider.upper()} storage ({storage_host})"
                        f" — bucket exists and access is restricted (403)",
                        evidence=evidence,
                    )
                ]

        return []
