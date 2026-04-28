"""Technology component detection and vulnerability checks.

Tier 1: Header fingerprinting (always on).
Tier 2: Well-known path probing (config: check_well_known_paths).
CVE correlation: hardcoded minimal known-vulnerable version table.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urljoin, urlparse
from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from ..nvd import NVDClient, NVD_SEVERITY_MAP
from .base import BaseCheck
import asyncio
import re
import aiohttp

# Known vulnerable version table
# (product_lower -> list of (max_version_exclusive, severity, description))
# Versions are compared as tuples of ints.

#TODO think about the value of checks like this that need to be kept up to date

KNOWN_VULNERABLE: dict[str, list[tuple[tuple[int, ...], Severity, str]]] = {
    "apache": [
        ((2, 4, 54), Severity.HIGH, "Apache HTTP Server < 2.4.54 has known CVEs (e.g. CVE-2021-41773, CVE-2022-22720)"),
    ],
    "php": [
        ((7, 4, 0), Severity.CRITICAL, "PHP < 7.4 is end-of-life and has critical unpatched vulnerabilities"),
        ((8, 0, 0), Severity.HIGH, "PHP < 8.0 is end-of-life"),
    ],
    "jquery": [
        ((3, 5, 0), Severity.MEDIUM, "jQuery < 3.5.0 is vulnerable to XSS (CVE-2020-11022, CVE-2020-11023)"),
        ((3, 6, 0), Severity.LOW, "jQuery < 3.6.0 has known low-severity issues"),
    ],
    "bootstrap": [
        ((4, 0, 0), Severity.LOW, "Bootstrap < 4.0 has XSS vulnerabilities in older data- attributes"),
    ],
    "openssl": [
        ((1, 1, 1), Severity.CRITICAL, "OpenSSL < 1.1.1 is end-of-life with critical unpatched vulnerabilities"),
    ],
    "nginx": [
        ((1, 20, 0), Severity.MEDIUM, "nginx < 1.20.0 has known CVEs"),
    ],
    "drupal": [
        ((9, 0, 0), Severity.HIGH, "Drupal < 9.0 is end-of-life"),
    ],
    "wordpress": [
        ((6, 0, 0), Severity.MEDIUM, "WordPress < 6.0 may have unpatched vulnerabilities"),
    ],
}

# Well-known paths to probe
# this will generate false positives for sites that return the same page irrespective of url called
# obv that is crap practice and clearly wrong but it does mean a FP from a security perspective
WELL_KNOWN_PATHS: list[dict] = [
    {
        "path": "/.git/HEAD",
        "check_name": "git_exposed",
        "body_pattern": r"^ref:",
        "severity": Severity.CRITICAL,
        "detail": "Git repository HEAD file is publicly accessible — source code may be exposed",
    },
    {
        "path": "/.env",
        "check_name": "env_file_exposed",
        "body_pattern": r"=",
        "severity": Severity.CRITICAL,
        "detail": "Environment configuration file (.env) is publicly accessible — credentials may be exposed",
    },
    {
        "path": "/.DS_Store",
        "check_name": "ds_store_exposed",
        "body_pattern": None,
        "severity": Severity.HIGH,
        "detail": "macOS .DS_Store metadata file is publicly accessible — directory structure may be enumerable",
    },
    {
        "path": "/wp-login.php",
        "check_name": "wordpress_detected",
        "body_pattern": None,
        "severity": Severity.INFO,
        "detail": "WordPress login page detected",
    },
    {
        "path": "/wp-admin/",
        "check_name": "wordpress_admin_accessible",
        "body_pattern": None,
        "severity": Severity.INFO,
        "detail": "WordPress admin path is accessible",
    },
    {
        "path": "/administrator/",
        "check_name": "joomla_admin_detected",
        "body_pattern": None,
        "severity": Severity.INFO,
        "detail": "Joomla administrator path detected",
    },
    {
        "path": "/xmlrpc.php",
        "check_name": "wordpress_xmlrpc_enabled",
        "body_pattern": None,
        "severity": Severity.MEDIUM,
        "detail": "WordPress XML-RPC endpoint is enabled (can be abused for brute force and DDoS amplification)",
        "status": Status.WARN,
    },
    {
        "path": "/server-status",
        "check_name": "apache_server_status_exposed",
        "body_pattern": r"Apache",
        "severity": Severity.HIGH,
        "detail": "Apache server-status page is publicly accessible — server info exposed",
    },
    {
        "path": "/phpinfo.php",
        "check_name": "phpinfo_exposed",
        "body_pattern": r"PHP Version",
        "severity": Severity.HIGH,
        "detail": "phpinfo() page is publicly accessible — PHP configuration and environment variables exposed",
    },
    {
        "path": "/info.php",
        "check_name": "phpinfo_exposed",
        "body_pattern": r"PHP Version",
        "severity": Severity.HIGH,
        "detail": "phpinfo() page is publicly accessible (info.php) — PHP configuration exposed",
    },
    {
        "path": "/test.php",
        "check_name": "phpinfo_exposed",
        "body_pattern": r"PHP Version",
        "severity": Severity.HIGH,
        "detail": "phpinfo() page is publicly accessible (test.php) — PHP configuration exposed",
    },
    {
        "path": "/phpmyadmin/",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"phpMyAdmin|phpmyadmin",
        "severity": Severity.CRITICAL,
        "detail": "phpMyAdmin database admin interface is publicly accessible",
    },
    {
        "path": "/pma/",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"phpMyAdmin|phpmyadmin",
        "severity": Severity.CRITICAL,
        "detail": "phpMyAdmin (at /pma/) database admin interface is publicly accessible",
    },
    {
        "path": "/mysql/",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"phpMyAdmin|phpmyadmin",
        "severity": Severity.CRITICAL,
        "detail": "phpMyAdmin (at /mysql/) database admin interface is publicly accessible",
    },
    {
        "path": "/cpanel",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"cPanel|cpanel",
        "severity": Severity.CRITICAL,
        "detail": "cPanel web hosting control panel is publicly accessible",
    },
    {
        "path": "/grafana/",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"Grafana",
        "severity": Severity.HIGH,
        "detail": "Grafana monitoring dashboard is publicly accessible",
    },
    {
        "path": "/kibana/",
        "check_name": "admin_interface_exposed",
        "body_pattern": r"Kibana|kibana",
        "severity": Severity.HIGH,
        "detail": "Kibana analytics interface is publicly accessible — log data may be exposed",
    },    
    {
        "path": "/sims/",
        "check_name": "mis_internet_facing",
        "body_pattern": r"SIMS|Capita|sims\.net",
        "severity": Severity.CRITICAL,
        "detail": "SIMS school management system login appears internet-accessible — pupil/safeguarding data at risk",
    },
    {
        "path": "/bromcom/",
        "check_name": "mis_internet_facing",
        "body_pattern": r"Bromcom|bromcom",
        "severity": Severity.CRITICAL,
        "detail": "Bromcom MIS login appears internet-accessible — pupil/safeguarding data at risk",
    },
    {
        "path": "/arbor/",
        "check_name": "mis_internet_facing",
        "body_pattern": r"Arbor|arbor\.sc",
        "severity": Severity.CRITICAL,
        "detail": "Arbor MIS login appears internet-accessible — pupil/safeguarding data at risk",
    },
    {
        "path": "/SchoolPortal/",
        "check_name": "mis_internet_facing",
        "body_pattern": r"SchoolPortal|Civica",
        "severity": Severity.CRITICAL,
        "detail": "Civica SchoolPortal appears internet-accessible — pupil/safeguarding data at risk",
    },
    {
        "path": "/wp-json/wp/v2/",
        "check_name": "wordpress_rest_api_exposed",
        "body_pattern": r'"namespace"\s*:\s*"wp/v2"',
        "severity": Severity.MEDIUM,
        "detail": "WordPress REST API is publicly accessible — user enumeration and plugin detection possible",
        "status": Status.WARN,
    },
    {
        "path": "/wp-content/plugins/contact-form-7/readme.txt",
        "check_name": "wordpress_plugin_cf7",
        "body_pattern": r"Contact Form 7|contact-form-7",
        "severity": Severity.INFO,
        "detail": "Contact Form 7 WordPress plugin detected (version enumerable via readme.txt)",
        "status": Status.INFO,
    },
    {
        "path": "/wp-content/plugins/woocommerce/readme.txt",
        "check_name": "wordpress_plugin_woocommerce",
        "body_pattern": r"WooCommerce",
        "severity": Severity.INFO,
        "detail": "WooCommerce WordPress plugin detected (version enumerable via readme.txt)",
        "status": Status.INFO,
    },
    {
        "path": "/wp-content/plugins/elementor/readme.txt",
        "check_name": "wordpress_plugin_elementor",
        "body_pattern": r"Elementor",
        "severity": Severity.INFO,
        "detail": "Elementor WordPress plugin detected (version enumerable via readme.txt)",
        "status": Status.INFO,
    },
]

class ComponentsCheck(BaseCheck):
    name = "components"
    category = CheckCategory.COMPONENTS

    def __init__(
        self,
        config: Any,
        http_semaphore: asyncio.Semaphore | None = None,
        nvd_client: NVDClient | None = None,
    ) -> None:
        self._cfg = config  # ComponentsCheckConfig
        self._semaphore = http_semaphore or asyncio.Semaphore(200)
        self._nvd = nvd_client

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=0)
            timeout = aiohttp.ClientTimeout(total=20, connect=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Tier 1: Header fingerprinting
                headers = await self._fetch_headers(session, target.url)
                if headers:
                    header_findings = self._check_headers_for_components(target, runkey, headers)
                    findings += header_findings
                    # CVE correlation from headers
                    for f in header_findings:
                        if f.check_name == "component_detected" and f.evidence.get("version"):
                            cve_findings = await self._correlate_cve(
                                target, runkey,
                                f.evidence.get("product", ""),
                                f.evidence.get("version", ""),
                            )
                            findings += cve_findings

                # Tier 2: Well-known paths
                if self._cfg.check_well_known_paths:
                    path_findings = await self._check_well_known_paths(session, target, runkey)
                    findings += path_findings
                    
                    findings += await self._check_wordpress_plugins(session, target, runkey, findings)

                # robots.txt
                findings += await self._check_robots_txt(session, target, runkey)

                # security.txt
                findings += await self._check_security_txt(session, target, runkey)

        except Exception as exc:
            findings.append(self.make_error(target, runkey, "components", exc))

        return findings

    # Tier 1: Header fingerprinting
    
    async def _fetch_headers(
        self, session: aiohttp.ClientSession, url: str
    ) -> dict | None:
        async with self._semaphore:
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                    max_redirects=5,
                    headers={"User-Agent": "CyberExposureScanner/1.0"},
                ) as resp:
                    return dict(resp.headers)
            except Exception:
                return None

    def _check_headers_for_components(
        self, target: ScanTarget, runkey: str, headers: dict
    ) -> list[Finding]:
        findings: list[Finding] = []

        patterns: list[tuple[str, str]] = [
            ("Server", ""),
            ("X-Powered-By", ""),
            ("X-Generator", ""),
            ("X-Drupal-Cache", "Drupal"),
            ("Via", ""),
        ]

        # check for WordPress-specific headers
        wp_headers = ["X-WP-Total", "X-WP-TotalPages", "X-Pingback"]
        for wph in wp_headers:
            if _header(headers, wph):
                findings.append(
                    self.make_finding(
                        target, runkey, "component_detected",
                        Status.INFO, Severity.INFO,
                        "WordPress detected via response header",
                        evidence={"product": "WordPress", "version": "", "header": wph, "value": _header(headers, wph)},
                    )
                )

        for header_name, forced_product in patterns:
            value = _header(headers, header_name)
            if not value:
                continue

            # Skip X-Drupal-Cache if the forced product was set
            if forced_product:
                findings.append(
                    self.make_finding(
                        target, runkey, "component_detected",
                        Status.INFO, Severity.INFO,
                        f"{forced_product} detected via {header_name} header",
                        evidence={"product": forced_product, "version": "", "header": header_name, "value": value},
                    )
                )
                continue

            # Try to extract product/version from header value
            product, version = _parse_product_version(value)
            if product:
                findings.append(
                    self.make_finding(
                        target, runkey, "component_detected",
                        Status.INFO, Severity.INFO,
                        f"Component detected: {product}" + (f" {version}" if version else ""),
                        evidence={"product": product, "version": version, "header": header_name, "raw_value": value},
                    )
                )

        return findings
   
    # Tier 2: Well-known paths
    async def _check_well_known_paths(
        self,
        session: aiohttp.ClientSession,
        target: ScanTarget,
        runkey: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        tasks = [
            self._probe_path(session, target, runkey, path_cfg)
            for path_cfg in WELL_KNOWN_PATHS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings += result
            elif isinstance(result, Exception):
                pass 
        return findings

    async def _probe_path(
        self,
        session: aiohttp.ClientSession,
        target: ScanTarget,
        runkey: str,
        path_cfg: dict,
    ) -> list[Finding]:
        path = path_cfg["path"]
        full_url = urljoin(target.url.rstrip("/") + "/", path.lstrip("/"))
        check_name = path_cfg["check_name"]
        severity = path_cfg["severity"]
        detail = path_cfg["detail"]
        body_pattern = path_cfg.get("body_pattern")
        override_status = path_cfg.get("status")

        async with self._semaphore:
            try:
                async with session.get(
                    full_url,
                    allow_redirects=False,
                    headers={"User-Agent": "CyberExposureScanner/1.0"},
                ) as resp:
                    if resp.status != 200:
                        return []
                    # Read only as much as needed for pattern matching
                    raw = await resp.content.read(500)
                    body_preview = raw.decode("utf-8", errors="replace")
            except Exception:
                return []

        # If a body pattern is required, check it
        if body_pattern:
            if not re.search(body_pattern, body_preview, re.IGNORECASE):
                return []

        status = override_status if override_status else Status.FAIL
        if severity == Severity.INFO:
            status = Status.INFO

        return [
            self.make_finding(
                target, runkey, check_name,
                status, severity,
                detail,
                evidence={"url": full_url, "body_preview": body_preview[:200]},
            )
        ]
    
    async def _check_wordpress_plugins(
        self,
        session: aiohttp.ClientSession,
        target: ScanTarget,
        runkey: str,
        all_findings: list,
    ) -> list:
        """If WordPress is detected, check known vulnerable plugin versions."""
        is_wordpress = any(
            f.check_name in ("wordpress_detected", "wordpress_admin_accessible",
                             "wordpress_rest_api_exposed", "wordpress_plugin_cf7",
                             "wordpress_plugin_woocommerce", "wordpress_plugin_elementor")
            for f in all_findings
        )
        if not is_wordpress:
            return []

        _PLUGIN_VERSIONS: list[dict] = [
            {
                "slug": "contact-form-7",
                "check_name": "wordpress_plugin_cf7",
                "readme_path": "/wp-content/plugins/contact-form-7/readme.txt",
                "vulnerable_below": (5, 8, 0),
                "cve_hint": "CF7 < 5.8 has known CSRF/XSS vulnerabilities",
            },
            {
                "slug": "woocommerce",
                "check_name": "wordpress_plugin_woocommerce",
                "readme_path": "/wp-content/plugins/woocommerce/readme.txt",
                "vulnerable_below": (8, 0, 0),
                "cve_hint": "WooCommerce < 8.0 has known SQL injection and XSS vulnerabilities",
            },
            {
                "slug": "elementor",
                "check_name": "wordpress_plugin_elementor",
                "readme_path": "/wp-content/plugins/elementor/readme.txt",
                "vulnerable_below": (3, 14, 0),
                "cve_hint": "Elementor < 3.14 has known XSS vulnerabilities",
            },
        ]

        vuln_findings = []
        for plugin in _PLUGIN_VERSIONS:
            full_url = urljoin(target.url.rstrip("/") + "/", plugin["readme_path"].lstrip("/"))
            async with self._semaphore:
                try:
                    async with session.get(
                        full_url, allow_redirects=False,
                        headers={"User-Agent": "CyberExposureScanner/1.0"},
                    ) as resp:
                        if resp.status != 200:
                            continue
                        raw = await resp.content.read(2000)
                        body = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue

            # Extract Stable tag (version)
            m = re.search(r"Stable\s+tag\s*:\s*([\d.]+)", body, re.IGNORECASE)
            if not m:
                continue
            version_str = m.group(1)
            version_tuple = _parse_version_tuple(version_str)
            if not version_tuple:
                continue

            if version_tuple < plugin["vulnerable_below"]:
                vuln_findings.append(
                    self.make_finding(
                        target, runkey, "component_vulnerable_version",
                        Status.FAIL, Severity.HIGH,
                        f"WordPress plugin '{plugin['slug']}' version {version_str} is outdated: {plugin['cve_hint']}",
                        evidence={
                            "product": plugin["slug"],
                            "detected_version": version_str,
                            "vulnerable_below": ".".join(str(v) for v in plugin["vulnerable_below"]),
                            "readme_url": full_url,
                        },
                    )
                )

        return vuln_findings

    async def _check_robots_txt(
        self,
        session: aiohttp.ClientSession,
        target: ScanTarget,
        runkey: str,
    ) -> list[Finding]:
        robots_url = urljoin(target.url.rstrip("/") + "/", "robots.txt")
        async with self._semaphore:
            try:
                async with session.get(
                    robots_url,
                    allow_redirects=True,
                    headers={"User-Agent": "CyberExposureScanner/1.0"},
                ) as resp:
                    if resp.status != 200:
                        return []
                    body = await resp.text(errors="replace")
            except Exception:
                return []

        # Parse disallowed paths
        disallowed: list[str] = re.findall(r"^Disallow:\s*(.+)$", body, re.MULTILINE | re.IGNORECASE)
        sitemaps: list[str] = re.findall(r"^Sitemap:\s*(.+)$", body, re.MULTILINE | re.IGNORECASE)

        return [
            self.make_finding(
                target, runkey, "robots_txt",
                Status.INFO, Severity.INFO,
                f"robots.txt found with {len(disallowed)} Disallow directive(s)",
                evidence={
                    "url": robots_url,
                    "disallowed_paths": [d.strip() for d in disallowed[:50]],
                    "sitemaps": [s.strip() for s in sitemaps[:10]],
                },
            )
        ]

    async def _check_security_txt(
        self,
        session: aiohttp.ClientSession,
        target: ScanTarget,
        runkey: str,
    ) -> list[Finding]:
        security_txt_url = urljoin(target.url.rstrip("/") + "/", ".well-known/security.txt")
        async with self._semaphore:
            try:
                async with session.get(
                    security_txt_url,
                    allow_redirects=True,
                    headers={"User-Agent": "CyberExposureScanner/1.0"},
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        contacts = re.findall(r"^Contact:\s*(.+)$", body, re.MULTILINE | re.IGNORECASE)
                        return [
                            self.make_finding(
                                target, runkey, "security_txt",
                                Status.INFO, Severity.INFO,
                                "security.txt is present",
                                evidence={
                                    "url": security_txt_url,
                                    "contacts": [c.strip() for c in contacts[:5]],
                                },
                            )
                        ]
                    else:
                        return [
                            self.make_finding(
                                target, runkey, "security_txt",
                                Status.WARN, Severity.LOW,
                                "No security.txt found — no vulnerability disclosure policy advertised",
                                evidence={"expected_url": security_txt_url},
                            )
                        ]
            except Exception:
                return [
                    self.make_finding(
                        target, runkey, "security_txt",
                        Status.WARN, Severity.LOW,
                        "Could not fetch security.txt",
                        evidence={"expected_url": security_txt_url},
                    )
                ]

    async def _correlate_cve(
        self,
        target: ScanTarget,
        runkey: str,
        product: str,
        version: str,
    ) -> list[Finding]:
        if not product or not version:
            return []

        # Try live NVD lookup first
        if self._nvd:
            nvd_findings = await self._correlate_cve_nvd(target, runkey, product, version)
            if nvd_findings:
                return nvd_findings
            # NVD returned nothing (unknown product, network error, or genuinely no CVEs)
            # Fall through to hardcoded table as safety net

        return self._correlate_cve_hardcoded(target, runkey, product, version)

    async def _correlate_cve_nvd(
        self,
        target: ScanTarget,
        runkey: str,
        product: str,
        version: str,
    ) -> list[Finding]:
        """Query NVD API for CVEs affecting this product/version."""
        cves = await self._nvd.get_cves(product, version)
        if not cves:
            return []

        findings: list[Finding] = []
        for cve in cves:
            sev_str = NVD_SEVERITY_MAP.get(cve["severity"], "medium")
            from ..models import Severity as Sev
            severity = Sev(sev_str)
            findings.append(
                self.make_finding(
                    target, runkey, "component_vulnerable_version",
                    Status.FAIL, severity,
                    f"{product} {version} — {cve['cve_id']} (CVSS {cve['cvss_score']}): "
                    f"{cve['description'][:150]}",
                    evidence={
                        "product": product,
                        "detected_version": version,
                        "cve_id": cve["cve_id"],
                        "cvss_score": cve["cvss_score"],
                        "severity": cve["severity"],
                        "published": cve["published"],
                        "source": "nvd_live",
                    },
                )
            )

        return findings

    def _correlate_cve_hardcoded(
        self,
        target: ScanTarget,
        runkey: str,
        product: str,
        version: str,
    ) -> list[Finding]:
        """Fall back to hardcoded version table when NVD is unavailable."""
        product_lower = product.lower()
        version_tuple = _parse_version_tuple(version)
        if not version_tuple:
            return []

        findings: list[Finding] = []
        for known_product, vuln_list in KNOWN_VULNERABLE.items():
            if known_product in product_lower:
                for max_ver, severity, description in vuln_list:
                    if version_tuple < max_ver:
                        findings.append(
                            self.make_finding(
                                target, runkey, "component_vulnerable_version",
                                Status.FAIL, severity,
                                f"{product} {version}: {description}",
                                evidence={
                                    "product": product,
                                    "detected_version": version,
                                    "vulnerable_below": ".".join(str(v) for v in max_ver),
                                    "description": description,
                                    "source": "hardcoded_table",
                                },
                            )
                        )
                        break

        return findings

def _header(headers: dict, name: str) -> str | None:
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None

def _parse_product_version(value: str) -> tuple[str, str]:
    """Extract (product, version) from a header value like 'Apache/2.4.51 (Unix)'.

    Handles formats:
      - 'Apache/2.4.51 (Unix)'    -> ('Apache', '2.4.51')
      - 'PHP/7.3.0'               -> ('PHP', '7.3.0')
      - 'nginx'                   -> ('nginx', '')
      - 'Microsoft-IIS/10.0'      -> ('Microsoft-IIS', '10.0')
    """
    value = value.strip()
    if not value:
        return "", ""

    # Split on first '/' to get product and the rest
    if "/" in value:
        product_part, rest = value.split("/", 1)
        # Version is the first whitespace-delimited token
        version_token = rest.split()[0] if rest.split() else ""
        # Strip trailing punctuation that isn't part of version
        version = re.sub(r"[^0-9a-zA-Z.\-_].*$", "", version_token)
        product = product_part.strip()
    else:
        # No slash — the whole value is the product name
        product = value.split()[0] if value.split() else value
        version = ""

    return product, version


def _parse_version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a version string like '2.4.51' into (2, 4, 51)."""
    parts = re.split(r"[.\-]", version)
    try:
        ints: list[int] = []
        for p in parts[:4]:
            # Strip non-numeric suffix (e.g. '51rc1')
            m = re.match(r"^(\d+)", p)
            if m:
                ints.append(int(m.group(1)))
        return tuple(ints) if ints else None
    except ValueError:
        return None
