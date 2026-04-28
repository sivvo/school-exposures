"""Domain registration expiry check via WHOIS.

Checks when a domain's registration expires and flags domains that are
close to expiry or have already lapsed.

Thresholds chosen to minimise false positives for domains which commonly renew close to  expiry:

    Expired         = FAIL  / CRITICAL
    ≤ 14 days       = FAIL  / HIGH      (auto-renew window has likely closed)
    ≤ 60 days       = WARN  / MEDIUM    (actionable but not yet critical)
    > 60 days       = PASS  / INFO      (always emitted so dashboard has data)
TODO: validate these thresholds against actual historical data (later)
One WHOIS lookup per registered domain per run — deduplicated across
multiple URLs on the same domain via an in-process cache.
"""
from __future__ import annotations

import asyncio
import re
import sys
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..models import CheckCategory, Finding, ScanTarget, Severity, Status
from .base import BaseCheck

try:
    import whois as _whois_lib  # python-whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

# Days-to-expiry thresholds
_CRITICAL_DAYS = 0
_HIGH_DAYS      = 14
_MEDIUM_DAYS    = 60

# UK domain suffixes where Nominet does not publish expiry dates in public WHOIS.
# These are centrally managed / protected zones — not at risk of unmanaged lapse.
_UK_GOVT_SUFFIXES = frozenset([
    "gov.uk", "parliament.uk",
])
# for sch.uk : tldextract treats these as public suffixes, so
# 'carltoncolville.suffolk.sch.uk' resolves to registered_domain='suffolk.sch.uk'.
# But Nominet registers at the full hostname level — suffolk.sch.uk is only an
# LA zone delegation and fails a WHOIS lookup.  We use the full URL hostname
# for these suffixes instead.  Nominet still does not publish expiry dates for
# .sch.uk in public WHOIS, so findings for these domains will always be INFO.
_SCH_LIKE_SUFFIXES = frozenset(["sch.uk"])

# Combined set used for messaging
_UK_EDU_SUFFIXES = _SCH_LIKE_SUFFIXES

class DomainExpiryCheck(BaseCheck):
    name     = "domain_expiry"
    category = CheckCategory.DOMAIN_EXPIRY

    def __init__(self, semaphore: asyncio.Semaphore | None = None) -> None:
        # keep concurrency low to avoid registrar throttling
        self._sem    = semaphore or asyncio.Semaphore(5)
        self._cache: dict[str, list[Finding]] = {}
        self._locks: dict[str, asyncio.Lock]  = {}

    async def run(self, target: ScanTarget, runkey: str) -> list[Finding]:
        if not _WHOIS_AVAILABLE:
            return [self.make_error(
                target, runkey, "domain_expiry_check",
                RuntimeError("python-whois is not installed in the active environment"),
            )]

        domain = _whois_target(target.url, target.domain)
        if not domain:
            return []

        return await self._get_cached(domain, target, runkey)

    async def _get_cached(
        self, domain: str, target: ScanTarget, runkey: str
    ) -> list[Finding]:
        if domain in self._cache:
            return [f.model_copy(update={"url": target.url, "business_unit": target.business_unit})
                    for f in self._cache[domain]]

        if domain not in self._locks:
            self._locks[domain] = asyncio.Lock()

        async with self._locks[domain]:
            if domain in self._cache:
                return [f.model_copy(update={"url": target.url, "business_unit": target.business_unit})
                        for f in self._cache[domain]]
            findings = await self._lookup(domain, target, runkey)
            self._cache[domain] = findings

        return findings

    async def _lookup(
        self, domain: str, target: ScanTarget, runkey: str
    ) -> list[Finding]:
        loop = asyncio.get_running_loop()
        try:
            async with self._sem:
                result = await loop.run_in_executor(None, _whois_lib.whois, domain)
        except Exception as exc:
            return [self.make_error(target, runkey, "domain_expiry_lookup", exc)]

        expiry_date = _extract_expiry(result)
        if expiry_date is None:
            detail = _no_expiry_detail(domain)
            return [
                self.make_finding(
                    target, runkey, "domain_expiry",
                    Status.INFO, Severity.INFO,
                    detail,
                    evidence={"domain": domain, "registrar": _registrar(result)},
                )
            ]

        now  = datetime.now(timezone.utc)
        days = (expiry_date - now).days

        evidence: dict[str, Any] = {
            "domain":      domain,
            "expiry_date": expiry_date.date().isoformat(),
            "days_until_expiry": days,
            "registrar":   _registrar(result),
        }

        if days <= _CRITICAL_DAYS:
            return [self.make_finding(
                target, runkey, "domain_expiry",
                Status.FAIL, Severity.CRITICAL,
                f"Domain '{domain}' registration has EXPIRED ({abs(days)} days ago)",
                evidence=evidence,
            )]
        if days <= _HIGH_DAYS:
            return [self.make_finding(
                target, runkey, "domain_expiry",
                Status.FAIL, Severity.HIGH,
                f"Domain '{domain}' expires in {days} day(s) — renewal required urgently",
                evidence=evidence,
            )]
        if days <= _MEDIUM_DAYS:
            return [self.make_finding(
                target, runkey, "domain_expiry",
                Status.WARN, Severity.MEDIUM,
                f"Domain '{domain}' expires in {days} days",
                evidence=evidence,
            )]
        return [self.make_finding(
            target, runkey, "domain_expiry",
            Status.PASS, Severity.INFO,
            f"Domain '{domain}' expires in {days} days ({expiry_date.date().isoformat()})",
            evidence=evidence,
        )]


"""
manage the differences between: 
"Expiry date:", "Expiration date:", "Renewal date:" in raw WHOIS text.
Since it can vary in .uk records
"""

_RAW_EXPIRY_RE = re.compile(
    r'(?:expiry|expiration|renewal)\s*date\s*:\s*(.+)',
    re.IGNORECASE,
)
# Date formats seen in WHOIS responses across common TLDs
_RAW_DATE_FMTS = (
    "%d-%b-%Y",   # 25-Feb-2027  (Nominet standard)
    "%Y-%m-%d",   # 2027-02-25   (ISO, Verisign, many others)
    "%d/%m/%Y",   # 25/02/2027
    "%d-%m-%Y",   # 25-02-2027
)

def _extract_expiry(result: Any) -> datetime | None:
    """Pull the first usable expiry datetime from a whois result.

    Tries in order:
    1. result.expiration_date  — standard python-whois attribute
    2. result.expiry_date      — alternate attribute some parsers populate
    3. Raw WHOIS text scan     — handles Nominet "Expiry/Renewal date:" fields
      that python-whois misses for .sch.uk and other .uk third-level domains
    """
    for attr in ("expiration_date", "expiry_date"):
        dt = _coerce_date(getattr(result, attr, None))
        if dt is not None:
            return dt

    # Raw-text fallback
    text = getattr(result, "text", "") or ""
    m = _RAW_EXPIRY_RE.search(text)
    if m:
        date_str = m.group(1).strip().split()[0]  # drop trailing comments
        for fmt in _RAW_DATE_FMTS:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None

def _coerce_date(raw: Any) -> datetime | None:
    """Normalise a whois date value to a tz-aware datetime."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            raw = raw.replace(tzinfo=timezone.utc)
        return raw
    return None


def _whois_target(url: str, registered_domain: str) -> str:
    """Return the domain name to use for a WHOIS lookup.

    For most TLDs tldextract's registered_domain is correct.
    For .sch.uk tldextract strips too many levels — Nominet
    registers at the full hostname (e.g. carltoncolville.suffolk.sch.uk),
    not the LA zone (suffolk.sch.uk).  Use the URL hostname directly.
    """
    suffix = ".".join(registered_domain.lower().split(".")[-2:])
    if suffix in _SCH_LIKE_SUFFIXES:
        host = urlparse(url).hostname or registered_domain
        return host.removeprefix("www.")
    return registered_domain

def _no_expiry_detail(domain: str) -> str:
    """Return a contextual detail string when no expiry date can be found."""
    suffix = ".".join(domain.lower().split(".")[-2:])
    if suffix in _UK_GOVT_SUFFIXES:
        return (
            f"'{domain}' is a UK government-managed domain ({suffix}). "
            "Nominet does not publish expiry dates for these registrations."
        )
    if suffix in _UK_EDU_SUFFIXES:
        return (
            f"'{domain}' is a Nominet-managed educational domain ({suffix}). "
            "Expiry data is not available in the public WHOIS."
        )
    return f"WHOIS expiry date not available for '{domain}'"


def _registrar(result: Any) -> str | None:
    raw = getattr(result, "registrar", None)
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    return str(raw) if raw else None
