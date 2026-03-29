"""NVD (National Vulnerability Database) API v2 client.

Queries the NVD CVE API for vulnerabilities affecting a specific product version.
Results are cached by (product, version) for the lifetime of the instance,
so the same version appearing across many URLs only results in one API call.

Rate limits (enforced here):
  Without API key: 5 requests per 30 seconds
  With API key:   50 requests per 30 seconds

Reference: https://nvd.nist.gov/developers/vulnerabilities
Get a key from nvd.nist.gov
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
import aiohttp
import structlog
from typing import Any

logger = structlog.get_logger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map our detected product names (lowercase) to NVD CPE vendor:product strings.
# Add entries here when new products are detected in the environment.
# TODO: since the NVD data can be poor quality, this is both a maintenance hassle
# and probably quite low value. THINK ABOUT DELETING!!
CPE_MAP: dict[str, str] = {
    "apache":           "apache:http_server",
    "nginx":            "nginx:nginx",
    "php":              "php:php",
    "jquery":           "jquery:jquery",
    "bootstrap":        "twbs:bootstrap",
    "openssl":          "openssl:openssl",
    "drupal":           "drupal:drupal",
    "wordpress":        "wordpress:wordpress",
    "iis":              "microsoft:internet_information_server",
    "microsoft-iis":    "microsoft:internet_information_server",
    "tomcat":           "apache:tomcat",
    "node.js":          "nodejs:node.js",
    "node":             "nodejs:node.js",
    "express":          "expressjs:express",
    "spring":           "vmware:spring_framework",
    "struts":           "apache:struts",
    "log4j":            "apache:log4j",
    "jboss":            "redhat:jboss_enterprise_application_platform",
    "weblogic":         "oracle:weblogic_server",
    "lighttpd":         "lighttpd:lighttpd",
    "caddy":            "caddyserver:caddy",
}

# Minimum severity to bother returning (NVD CVSS baseSeverity strings).
# Medium is excluded — NVD CPE data quality means medium CVEs produce too many
# false positives at scale (wrong OS, wrong deployment mode, overly broad CPE
# ranges). Only high/critical are reliable enough to action across 24k schools.
# Even then, vulns don't take things like the OS into account meaning
# we still need to be careful about false positives.
_SEVERITY_INCLUDE = {"high", "critical"}

# Map NVD severity string to our Severity enum value
NVD_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
}


class NVDClient:
    """Async NVD CVE lookup client with per-(product, version) caching."""

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        # Rate: 5 req/30s without key = 1 per 6s; 50 req/30s with key = 1 per 0.6s
        self._min_interval: float = 0.6 if api_key else 6.0
        self._last_request: float = 0.0
        self._rate_lock = asyncio.Lock()
        self._cache: dict[tuple[str, str], list[dict]] = {}
        self._cache_locks: dict[tuple[str, str], asyncio.Lock] = {}

    @property
    def configured(self) -> bool:
        return True  # always usable; key only affects rate limit

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    async def get_cves(self, product: str, version: str) -> list[dict]:
        """Return CVEs affecting product/version. Cached — only one NVD call per unique pair."""
        key = (product.lower(), version.lower())

        if key in self._cache:
            return self._cache[key]

        if key not in self._cache_locks:
            self._cache_locks[key] = asyncio.Lock()

        async with self._cache_locks[key]:
            if key not in self._cache:
                self._cache[key] = await self._fetch(key[0], version)

        return self._cache[key]

    async def _fetch(self, product_lower: str, version: str) -> list[dict]:
        vendor_product = CPE_MAP.get(product_lower)
        if not vendor_product:
            # Unknown product — no CPE mapping, can't query NVD
            return []

        cpe_name = f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"

        # Build URL manually so isVulnerable appears without a value
        # (aiohttp params would encode it as isVulnerable= which NVD also accepts,
        # but building explicitly is clearer)
        qs = urllib.parse.urlencode({"cpeName": cpe_name}) + "&isVulnerable"
        url = f"{NVD_BASE}?{qs}"

        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        # Enforce rate limit
        async with self._rate_lock:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request = time.monotonic()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        results = _parse_response(data)
                        logger.debug(
                            "nvd_lookup",
                            product=product_lower,
                            version=version,
                            cve_count=len(results),
                        )
                        return results
                    elif resp.status == 404:
                        return []
                    elif resp.status == 403:
                        logger.warning("nvd_rate_limited", product=product_lower, version=version)
                        return []
                    else:
                        logger.warning("nvd_unexpected_status", status=resp.status,
                                       product=product_lower, version=version)
                        return []
        except Exception as exc:
            logger.warning("nvd_fetch_failed", product=product_lower, version=version, error=str(exc))
            return []


def _parse_response(data: dict) -> list[dict]:
    """Extract a flat list of CVE summary dicts from an NVD API response."""
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        # CVSS score — prefer v3.1 > v3.0 > v2
        score: float | None = None
        severity = "unknown"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                cvss = metrics[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "").lower()
                break

        if severity not in _SEVERITY_INCLUDE:
            continue

        results.append({
            "cve_id":      cve_id,
            "description": description[:300],
            "cvss_score":  score,
            "severity":    severity,
            "published":   cve.get("published", "")[:10],
        })

    # Return highest-severity CVEs first
    _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    results.sort(key=lambda c: _rank.get(c["severity"], 4))
    return results
