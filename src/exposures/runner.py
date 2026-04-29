"""
Main scan runner

Orchestrates loading targets, running checks concurrently,
streaming findings to output writers, and maintaining a checkpoint
for resume capability.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse
from tqdm.asyncio import tqdm
from .checks.base import BaseCheck
from .checks.censys_ports import CensysPortsCheck
from .checks.cert_transparency import CertTransparencyCheck
from .checks.cloud_storage import CloudStorageCheck
from .checks.components import ComponentsCheck
from .checks.dns_records import DNSRecordsCheck
from .checks.dnsbl import DNSBLCheck
from .checks.domain_expiry import DomainExpiryCheck
from .checks.email_security import EmailSecurityCheck
from .checks.http_headers import HttpHeadersCheck
from .checks.insecure_services import InsecureServicesCheck
from .checks.open_redirect import OpenRedirectCheck
from .checks.mixed_content import MixedContentCheck
from .checks.port_scan import PortScanCheck
from .checks.safe_browsing import SafeBrowsingCheck
from .checks.subdomain import SubdomainCheck
from .checks.tls import TLSCheck
from .config import Config
from .history import HistoryStore
from .nvd import NVDClient
from .models import CheckCategory, Finding, RunSummary, ScanTarget, Severity, Status
from .output.ndjson import NDJSONWriter
from .output.splunk_hec import SplunkHECWriter
import asyncio
import csv
import ipaddress
import json
import structlog
import tldextract

logger = structlog.get_logger(__name__)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_RESERVED_HOSTNAMES = {"localhost", "localhost.localdomain", "0.0.0.0"}
_RESERVED_TLD_SUFFIXES = (".internal", ".local", ".corp", ".home", ".lan", ".intranet", ".localdomain")


def _is_ssrf_risk(host: str) -> bool:
    """Return True if the host looks like an internal/private address """
    h = host.lower()
    if h in _RESERVED_HOSTNAMES:
        return True
    if any(h.endswith(tld) for tld in _RESERVED_TLD_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(h)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        pass
    return False


def normalise_url(raw: str) -> str:
    """Normalise a URL: add https:// if schemeless, strip trailing slash, lowercase host.
    Raises ValueError for private/internal addresses to prevent SSRF 
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL")

    # Add scheme if missing
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)

    # SSRF protection — reject private/internal addresses
    host = parsed.hostname or ""
    if _is_ssrf_risk(host):
        raise ValueError(f"URL hostname '{host}' is in a private/reserved range (SSRF risk rejected)")

    # Lowercase the host
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=parsed.path.rstrip("/") or "",
    )
    return urlunparse(normalized)


def extract_domain(url: str) -> str:
    """Return registered domain (e.g. 'example.com' from 'www.example.com')."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    # Fallback to hostname
    return urlparse(url).hostname or url

def load_targets(csv_path: str | Path) -> list[ScanTarget]:
    """Load and normalise targets from CSV file."""
    targets: list[ScanTarget] = []
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("CSV file is empty or has no header row")
        # Build case-insensitive field map: normalised_name -> actual_header
        field_map = {f.lower().strip().lstrip("\ufeff"): f for f in reader.fieldnames}
        if "url" not in field_map:
            raise ValueError("CSV must have a 'url' column")
        url_key = field_map["url"]
        bu_key = field_map.get("business_unit")
        # Optional GIAS metadata columns
        urn_key        = field_map.get("urn")
        la_key         = field_map.get("la_name")
        region_key     = field_map.get("region")
        type_key       = field_map.get("school_type")
        phase_key      = field_map.get("phase")

        for row in reader:
            raw_url = (row.get(url_key) or "").strip()
            business_unit = ((row.get(bu_key) or "").strip() if bu_key else "") or raw_url
            if not raw_url:
                continue
            try:
                normalised = normalise_url(raw_url)
                domain = extract_domain(normalised)
                targets.append(
                    ScanTarget(
                        url=normalised,
                        original_url=raw_url,
                        business_unit=business_unit,
                        domain=domain,
                        urn=       (row.get(urn_key)    or "").strip() if urn_key    else "",
                        la_name=   (row.get(la_key)     or "").strip() if la_key     else "",
                        region=    (row.get(region_key) or "").strip() if region_key else "",
                        school_type=(row.get(type_key)  or "").strip() if type_key   else "",
                        phase=     (row.get(phase_key)  or "").strip() if phase_key  else "",
                    )
                )
            except Exception as exc:
                logger.warning("target_normalisation_failed", raw_url=raw_url, error=str(exc))

    return targets

#################### 
# Checkpoint
####################
def checkpoint_path(output_dir: str | Path, runkey: str) -> Path:
    return Path(output_dir) / "checkpoints" / f"{runkey}.json"


def load_checkpoint(output_dir: str | Path, runkey: str) -> dict[str, bool]:
    """Load checkpoint dict {url: True} for completed URLs."""
    cp_path = checkpoint_path(output_dir, runkey)
    if cp_path.exists():
        try:
            with cp_path.open() as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}

def save_checkpoint(output_dir: str | Path, runkey: str, completed: dict[str, bool]) -> None:
    """Persist checkpoint to disk."""
    cp_path = checkpoint_path(output_dir, runkey)
    cp_path.parent.mkdir(parents=True, exist_ok=True)
    with cp_path.open("w") as fh:
        json.dump(completed, fh)


# Check registry
def build_checks(config: Config) -> dict[str, BaseCheck]:
    """Instantiate all enabled check objects."""
    http_sem = asyncio.Semaphore(config.concurrency.http_workers)
    dns_sem = asyncio.Semaphore(config.concurrency.dns_workers)
    tls_sem = asyncio.Semaphore(config.concurrency.tls_workers)
    censys_sem = asyncio.Semaphore(config.concurrency.censys_qps)
    nvd_client = NVDClient(api_key=config.checks.components.nvd_api_key)
    port_scan_sem = asyncio.Semaphore(config.concurrency.port_scan_workers)

    available: dict[str, BaseCheck] = {
        "http_headers": HttpHeadersCheck(config=config.checks.http_headers),
        "tls": TLSCheck(config=config.checks.tls, semaphore=tls_sem),
        "dns_records": DNSRecordsCheck(semaphore=dns_sem),
        "email_security": EmailSecurityCheck(config=config.checks.email_security, semaphore=dns_sem),
        "components": ComponentsCheck(config=config.checks.components, http_semaphore=http_sem, nvd_client=nvd_client),
        "censys_ports": CensysPortsCheck(config=config.censys, semaphore=censys_sem),
        "insecure_services": InsecureServicesCheck(),
        "open_redirect": OpenRedirectCheck(config=config.checks.open_redirect, semaphore=http_sem),
        "cert_transparency": CertTransparencyCheck(config=config.checks.cert_transparency),
        "cloud_storage":  CloudStorageCheck(http_semaphore=http_sem, dns_semaphore=dns_sem),
        "domain_expiry":  DomainExpiryCheck(),
        "safe_browsing":  SafeBrowsingCheck(api_key=config.checks.safe_browsing.api_key, semaphore=http_sem),
        "dnsbl":          DNSBLCheck(semaphore=dns_sem),
        "port_scan":      PortScanCheck(semaphore=port_scan_sem),
        "mixed_content":  MixedContentCheck(semaphore=http_sem),
        "subdomain_enum": SubdomainCheck(http_semaphore=http_sem, dns_semaphore=dns_sem),
    }
    return {name: check for name, check in available.items() if name in config.checks.enabled}


######## Per-target scan
async def scan_target(
    target: ScanTarget,
    runkey: str,
    checks: dict[str, BaseCheck],
) -> list[Finding]:
    """Run all enabled checks (except insecure_services) concurrently for one target."""
    # Run all primary checks concurrently
    primary_check_names = [n for n in checks if n != "insecure_services"]
    primary_tasks = [
        asyncio.create_task(checks[name].run(target, runkey), name=f"{name}:{target.url}")
        for name in primary_check_names
    ]

    results = await asyncio.gather(*primary_tasks, return_exceptions=True)
    all_findings: list[Finding] = []
    for name, result in zip(primary_check_names, results):
        if isinstance(result, list):
            all_findings.extend(result)
        elif isinstance(result, Exception):
            logger.error(
                "check_raised_unhandled_exception",
                check=name,
                url=target.url,
                error=str(result),
            )
            # Synthesise an error finding
            all_findings.append(
                Finding(
                    runkey=runkey,
                    url=target.url,
                    business_unit=target.business_unit,
                    check_category=CheckCategory.HTTP_HEADERS,  # fallback category
                    check_name=name,
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    detail=f"Unhandled exception in check '{name}': {result}",
                    evidence={"exception": str(result)},
                )
            )

    # Now run insecure_services synthesis with the collected findings
    if "insecure_services" in checks:
        insecure_check = checks["insecure_services"]
        if isinstance(insecure_check, InsecureServicesCheck):
            try:
                synthesis_findings = await insecure_check.run_with_findings(
                    target, runkey, all_findings
                )
                all_findings.extend(synthesis_findings)
            except Exception as exc:
                logger.error(
                    "insecure_services_synthesis_failed",
                    url=target.url,
                    error=str(exc),
                )

    return all_findings


# Findings stat helpers
def _update_summary_stats(summary: RunSummary, findings: list[Finding]) -> None:
    summary.total_findings += len(findings)
    for f in findings:
        sev = f.severity.value
        cat = f.check_category.value
        summary.findings_by_severity[sev] = summary.findings_by_severity.get(sev, 0) + 1
        summary.findings_by_category[cat] = summary.findings_by_category.get(cat, 0) + 1


async def run_scan(config: Config, runkey: str) -> RunSummary:
    """Full scan execution: load targets, run checks, write output, checkpoint."""
    started_at = datetime.now(timezone.utc)
    
    # Load and normalise targets
    logger.info("loading_targets", csv_path=config.input.csv_path)
    try:
        targets = load_targets(config.input.csv_path)
    except Exception as exc:
        logger.error("failed_to_load_targets", error=str(exc))
        raise

    logger.info("targets_loaded", count=len(targets))

    # Dry run - no scans
    if config.run.dry_run:
        print(f"\nDRY RUN — runkey: {runkey}")
        print(f"Would scan {len(targets)} target(s):\n")
        for t in targets:
            print(f"  {t.url}  [{t.business_unit}]  (domain: {t.domain}, original: {t.original_url})")
        print(f"\nEnabled checks: {', '.join(config.checks.enabled)}")
        print("No network traffic generated.")
        return RunSummary(
            runkey=runkey,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            total_targets=len(targets),
        )

    # Checkpoint / resume
    completed_urls: dict[str, bool] = {}
    resume_key = config.run.resume_runkey
    if resume_key:
        completed_urls = load_checkpoint(config.output.local_output_dir, resume_key)
        skipped = sum(1 for v in completed_urls.values() if v)
        logger.info("resume_checkpoint_loaded", resume_runkey=resume_key, already_completed=skipped)

    # Filter out already-completed targets
    pending_targets = [t for t in targets if not completed_urls.get(t.url, False)]
    logger.info(
        "scan_starting",
        runkey=runkey,
        total=len(targets),
        pending=len(pending_targets),
        skipped=len(targets) - len(pending_targets),
    )

    checks = build_checks(config)
    summary = RunSummary(
        runkey=runkey,
        started_at=started_at,
        total_targets=len(targets),
        completed_targets=len(targets) - len(pending_targets),
    )

    output_dir = Path(config.output.local_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Use async context managers so we can yield into them
    ndjson_writer: NDJSONWriter | None = None
    splunk_writer: SplunkHECWriter | None = None

    async def _open_writers() -> tuple[NDJSONWriter | None, SplunkHECWriter | None]:
        nj = None
        sp = None
        if config.output.log_locally:
            nj = NDJSONWriter(output_dir=output_dir, runkey=runkey)
            await nj.__aenter__()
        if config.output.send_to_splunk:
            if not config.splunk.url or not config.splunk.token:
                logger.warning(
                    "splunk_not_configured",
                    detail="send_to_splunk is true but splunk.url or splunk.token is empty",
                )
            else:
                sp = SplunkHECWriter(
                    url=config.splunk.url,
                    token=config.splunk.token,
                    index=config.splunk.index,
                    source=config.splunk.source,
                    verify_tls=config.splunk.verify_tls,
                    batch_size=config.splunk.batch_size,
                )
                await sp._start()
        return nj, sp

    async def _close_writers(nj: NDJSONWriter | None, sp: SplunkHECWriter | None) -> None:
        if nj:
            await nj.__aexit__(None, None, None)
        if sp:
            await sp.close()

    # History store 
    history: HistoryStore | None = None
    if config.history.enabled:
        history = HistoryStore(config.history.db_path)
        history.upsert_run(summary)  # register the run early so delta can find it

    _loop = asyncio.get_running_loop()

    async def _write_findings(findings: list[Finding]) -> None:
        if ndjson_writer:
            for finding in findings:
                await ndjson_writer.write(finding)
        if splunk_writer:
            for finding in findings:
                await splunk_writer.write(finding)
        if history:
            await _loop.run_in_executor(None, history.store_findings_batch, findings)

    ndjson_writer, splunk_writer = await _open_writers()

    try:
        checkpoint_lock = asyncio.Lock()

        async def process_target(target: ScanTarget) -> None:
            target_log = logger.bind(url=target.url, business_unit=target.business_unit)
            target_log.info("scanning_target")
            try:
                findings = await scan_target(target, runkey, checks)
                target_log.info("target_complete", findings_count=len(findings))

                # Stream findings to output writers (batch history write)
                await _write_findings(findings)

                # Update summary stats
                async with checkpoint_lock:
                    _update_summary_stats(summary, findings)
                    summary.completed_targets += 1
                    completed_urls[target.url] = True
                    save_checkpoint(config.output.local_output_dir, runkey, completed_urls)

            except Exception as exc:
                target_log.error("target_scan_failed", error=str(exc))
                summary.errors.append(f"{target.url}: {exc}")
                # Do NOT mark as completed so a --resume attempt will retry this target

        # Run all targets with tqdm progress bar
        # Using asyncio.gather with a semaphore to limit total concurrency at the
        # target level. Individual checks have their own semaphores.
        TARGET_CONCURRENCY = 50
        target_sem = asyncio.Semaphore(TARGET_CONCURRENCY)

        async def bounded_process(target: ScanTarget) -> None:
            async with target_sem:
                await process_target(target)

        tasks = [bounded_process(t) for t in pending_targets]
        for coro in tqdm.as_completed(
            tasks,
            total=len(pending_targets),
            desc="Scanning targets",
            unit="target",
            file=__import__("sys").stderr,
        ):
            await coro

        summary.completed_at = datetime.now(timezone.utc)
        logger.info(
            "scan_complete",
            runkey=runkey,
            total_targets=summary.total_targets,
            completed=summary.completed_targets,
            total_findings=summary.total_findings,
            errors=len(summary.errors),
        )

        if history:
            history.upsert_run(summary)
            prev_runkey = history.get_previous_runkey(runkey)
            if prev_runkey:
                delta = history.compute_delta(prev_runkey, runkey)
                delta_event = history.delta_to_splunk_event(delta, prev_runkey, runkey)
                new_count = sum(1 for d in delta if d.change == "new")
                resolved_count = sum(1 for d in delta if d.change == "resolved")
                logger.info(
                    "delta_computed",
                    prev_runkey=prev_runkey,
                    new=new_count,
                    resolved=resolved_count,
                    escalated=sum(1 for d in delta if d.change == "escalated"),
                )
                if splunk_writer:
                    await splunk_writer._send_raw([delta_event])
                if ndjson_writer:
                    await ndjson_writer.write_raw(delta_event)

        if ndjson_writer:
            await ndjson_writer.write_summary(summary)
        if splunk_writer:
            await splunk_writer.write_summary(summary)
            await splunk_writer.flush()

    finally:
        await _close_writers(ndjson_writer, splunk_writer)

    return summary
