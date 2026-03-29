"""CLI entry point for the cyber exposure scanner.

Usage:
    exposures scan [OPTIONS]
"""
from __future__ import annotations

import asyncio
import csv as csv_mod
import json
import sys
import uuid
from datetime import date
from pathlib import Path
from typing import Optional

import structlog
import typer
from dotenv import load_dotenv

# Load .env before anything else so env-var overrides in config.py see them
load_dotenv()

from .config import load_config
from .history import HistoryStore
from .runner import run_scan

def _configure_logging(level: str = "INFO") -> None:
    """Configure structlog to write to stderr in a human-readable format."""
    import logging

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

# ---------------------------------------------------------------------------
# Runkey generation
# Used to create a unique run identifier in order to group results and track 
# deltas between runs
# ---------------------------------------------------------------------------
def generate_runkey() -> str:
    """Generate a runkey in format YYYY-MM-DD-<8-char-uuid>."""
    today = date.today().strftime("%Y-%m-%d")
    short_uuid = str(uuid.uuid4()).replace("-", "")[:8]
    return f"{today}-{short_uuid}"

app = typer.Typer(
    name="exposures",
    help="Cyber exposure scanner — scans external URLs for security posture.",
    add_completion=False,
    no_args_is_help=True,
    invoke_without_command=True,
)

# Sub-app for the 'scan' subcommand.  We attach it as a group so that
# `exposures scan [OPTIONS]` works correctly regardless of how many
# top-level commands are registered.
scan_app = typer.Typer(name="scan", help="Scan URLs for cyber security exposure.", add_completion=False)
app.add_typer(scan_app, name="scan")

# ---------------------------------------------------------------------------
# Capability check - show which functions are available for scanning
# (e.g., key is available in the config file)
# or which functions user has called in the parameters
# ---------------------------------------------------------------------------
def _capability_line(status: str, label: str, detail: str) -> None:
    colours = {
        "OK":       typer.colors.GREEN,
        "DEGRADED": typer.colors.YELLOW,
        "DISABLED": typer.colors.RED,
        "INFO":     typer.colors.BRIGHT_BLACK,
    }
    badge = f"[{status}]"
    typer.secho(f"  {badge:<12}", fg=colours.get(status, typer.colors.WHITE), nl=False)
    typer.echo(f" {label:<14} {detail}")


def print_capabilities(cfg) -> None:
    """Print a capability summary before the scan starts."""
    typer.echo("\nCapabilities")
    typer.echo("─" * 60)

    outputs = []
    if cfg.output.send_to_splunk:
        if cfg.splunk.url and cfg.splunk.token:
            outputs.append(f"Splunk HEC ({cfg.splunk.url.split('//')[1].split('/')[0]})")
        else:
            _capability_line("DISABLED", "Splunk HEC",
                             "send_to_splunk=true but url/token not set — no events will be sent")
    if cfg.output.log_locally:
        outputs.append(f"local NDJSON ({cfg.output.local_output_dir})")
    if outputs:
        _capability_line("OK", "Output", " + ".join(outputs))

    if not cfg.output.send_to_splunk and not cfg.output.log_locally:
        _capability_line("DISABLED", "Output", "both send_to_splunk and log_locally are false — findings will be discarded")

    # Censys
    if "censys_ports" in cfg.checks.enabled:
        if cfg.censys.api_id and cfg.censys.api_secret:
            _capability_line("OK", "Censys",
                             f"network exposure check active (QPS limit: {cfg.concurrency.censys_qps})")
        else:
            _capability_line("DISABLED", "Censys",
                             "no credentials — censys_ports check will produce no findings")
    else:
        _capability_line("INFO", "Censys", "censys_ports not in enabled checks")

    # NVD / CVE
    if "components" in cfg.checks.enabled:
        if cfg.checks.components.nvd_api_key:
            _capability_line("OK", "NVD / CVE",
                             "live CVE lookups active (50 req/30s with API key)")
        else:
            _capability_line("DEGRADED", "NVD / CVE",
                             "live CVE lookups active, no API key — rate-limited to 5 req/30s "
                             "(get a free key at nvd.nist.gov/developers/request-an-api-key)")

    # History
    if cfg.history.enabled:
        _capability_line("OK", "History", f"SQLite at {cfg.history.db_path}")
    else:
        _capability_line("INFO", "History", "disabled — diff and delta events unavailable")

    # Enabled checks
    _capability_line("INFO", "Checks",
                     ", ".join(cfg.checks.enabled))

    typer.echo("─" * 60)
    typer.echo()


@scan_app.callback(invoke_without_command=True)
def scan(
    config_path: Path = typer.Option(
        "./config/settings.yaml",
        "--config",
        help="Path to settings.yaml",
        show_default=True,
    ),
    runkey: Optional[str] = typer.Option(
        None,
        "--runkey",
        help="Override auto-generated runkey (format: YYYY-MM-DD-xxxxxxxx)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Parse CSV and print targets without performing any network scanning",
        is_flag=True,
    ),
    resume_runkey: Optional[str] = typer.Option(
        None,
        "--resume-runkey",
        help="Resume a previous run, skipping already-completed targets",
    ),
    checks_override: Optional[str] = typer.Option(
        None,
        "--checks",
        help="Comma-separated list of checks to run (overrides config enabled list)",
    ),
    output_override: Optional[str] = typer.Option(
        None,
        "--output",
        help="Output mode: 'splunk', 'local', or 'both' (overrides config)",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    ),
) -> None:
    """Scan a list of URLs for cyber security exposure and send findings to Splunk."""

    _configure_logging(log_level)
    log = structlog.get_logger(__name__)

    try:
        cfg = load_config(config_path)
    except FileNotFoundError:
        typer.echo(
            f"ERROR: Configuration file not found: {config_path}\n"
            "Copy config/settings.yaml.example to config/settings.yaml and edit it.",
            err=True,
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"ERROR: Failed to load configuration: {exc}", err=True)
        raise typer.Exit(code=1)

    if dry_run:
        cfg.run.dry_run = True

    if resume_runkey:
        cfg.run.resume_runkey = resume_runkey

    if checks_override:
        requested = [c.strip() for c in checks_override.split(",") if c.strip()]
        known = {"http_headers", "tls", "dns_records", "email_security", "components", "censys_ports", "insecure_services", "open_redirect", "cert_transparency", "cloud_storage"}
        unknown = set(requested) - known
        if unknown:
            typer.echo(f"WARNING: Unknown checks specified: {', '.join(sorted(unknown))}", err=True)
        cfg.checks.enabled = [c for c in requested if c in known]

    if output_override:
        mode = output_override.lower().strip()
        if mode == "splunk":
            cfg.output.send_to_splunk = True
            cfg.output.log_locally = False
        elif mode == "local":
            cfg.output.send_to_splunk = False
            cfg.output.log_locally = True
        elif mode == "both":
            cfg.output.send_to_splunk = True
            cfg.output.log_locally = True
        else:
            typer.echo(
                f"ERROR: Invalid --output value '{output_override}'. Use 'splunk', 'local', or 'both'.",
                err=True,
            )
            raise typer.Exit(code=1)

    effective_runkey = runkey or generate_runkey()
    log.info("scan_initiated", runkey=effective_runkey, dry_run=cfg.run.dry_run)

    if not cfg.run.dry_run:
        print_capabilities(cfg)

    try:
        summary = asyncio.run(run_scan(cfg, effective_runkey))
    except KeyboardInterrupt:
        typer.echo("\nScan interrupted by user.", err=True)
        raise typer.Exit(code=130)
    except Exception as exc:
        log.error("scan_failed", error=str(exc), exc_info=True)
        typer.echo(f"ERROR: Scan failed: {exc}", err=True)
        raise typer.Exit(code=1)

    # ------------------------------------------------------------------
    # Print summary to stdout
    # TODO: this needs to be configurable, in a deployed server mode we don't 
    # want to be spamming the console
    # ------------------------------------------------------------------
    if not cfg.run.dry_run:
        typer.echo("\n" + "=" * 60)
        typer.echo(f"  Scan complete — runkey: {effective_runkey}")
        typer.echo("=" * 60)
        typer.echo(f"  Targets:       {summary.total_targets}")
        typer.echo(f"  Completed:     {summary.completed_targets}")
        typer.echo(f"  Total findings:{summary.total_findings}")
        if summary.findings_by_severity:
            typer.echo("\n  By severity:")
            for sev in ("critical", "high", "medium", "low", "info"):
                count = summary.findings_by_severity.get(sev, 0)
                if count:
                    typer.echo(f"    {sev.upper():10s} {count}")
        if summary.findings_by_category:
            typer.echo("\n  By category:")
            for cat, count in sorted(summary.findings_by_category.items()):
                typer.echo(f"    {cat:25s} {count}")
        if summary.errors:
            typer.echo(f"\n  Errors: {len(summary.errors)}")
            for err in summary.errors[:5]:
                typer.echo(f"    - {err}")
            if len(summary.errors) > 5:
                typer.echo(f"    ... and {len(summary.errors) - 5} more")
        typer.echo("=" * 60)
        if cfg.output.log_locally:
            output_file = Path(cfg.output.local_output_dir) / f"{effective_runkey}.ndjson"
            typer.echo(f"\n  Findings written to: {output_file}")


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

_SEV_COLOUR = {
    "critical": typer.colors.RED,
    "high":     typer.colors.BRIGHT_RED,
    "medium":   typer.colors.YELLOW,
    "low":      typer.colors.BRIGHT_BLACK,
    "info":     typer.colors.BRIGHT_BLACK,
}

def _load_ndjson(path: Path) -> list[dict]:
    findings = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Skip non-finding lines (delta events, summary events written inline)
                if "check_name" in obj:
                    findings.append(obj)
            except json.JSONDecodeError:
                pass
    return findings

def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"

def _print_table(findings: list[dict], show_evidence: bool) -> None:
    if not findings:
        typer.echo("  No findings match the filter criteria.")
        return

    # Column widths
    W_SEV  = 8
    W_STAT = 5
    W_CAT  = 20
    W_CHECK = 28
    W_BU   = 20
    W_URL  = 45
    W_DETAIL = 60

    header = (
        f"{'SEV':<{W_SEV}} {'ST':<{W_STAT}} {'CATEGORY':<{W_CAT}} "
        f"{'CHECK':<{W_CHECK}} {'BUSINESS UNIT':<{W_BU}} "
        f"{'URL':<{W_URL}} {'DETAIL':<{W_DETAIL}}"
    )
    sep = "-" * len(header)
    typer.echo(sep)
    typer.echo(header)
    typer.echo(sep)

    for f in findings:
        sev   = f.get("severity", "info")
        stat  = f.get("status", "")[:4]
        cat   = _truncate(f.get("check_category", ""), W_CAT)
        check = _truncate(f.get("check_name", ""), W_CHECK)
        bu    = _truncate(f.get("business_unit", ""), W_BU)
        url   = _truncate(f.get("url", ""), W_URL)
        detail = _truncate(f.get("detail", ""), W_DETAIL)

        line = (
            f"{sev:<{W_SEV}} {stat:<{W_STAT}} {cat:<{W_CAT}} "
            f"{check:<{W_CHECK}} {bu:<{W_BU}} "
            f"{url:<{W_URL}} {detail:<{W_DETAIL}}"
        )
        colour = _SEV_COLOUR.get(sev)
        if colour:
            typer.secho(line, fg=colour)
        else:
            typer.echo(line)

        if show_evidence and f.get("evidence"):
            typer.echo(f"  evidence: {json.dumps(f['evidence'])}")

    typer.echo(sep)

@app.command("report")
def report(
    runkey: str = typer.Argument(help="Run key to report on"),
    config_path: Path = typer.Option(
        "./config/settings.yaml", "--config", help="Path to settings.yaml"
    ),
    min_severity: str = typer.Option(
        "medium",
        "--severity", "-s",
        help="Minimum severity to include: critical, high, medium, low, info",
    ),
    status_filter: str = typer.Option(
        "fail,warn",
        "--status",
        help="Comma-separated statuses to include (fail, warn, pass, info, error)",
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Filter by check category (e.g. tls, http_headers, dns)",
    ),
    business_unit: Optional[str] = typer.Option(
        None, "--bu",
        help="Filter by business unit (partial match, case-insensitive)",
    ),
    url_filter: Optional[str] = typer.Option(
        None, "--url",
        help="Filter by URL (partial match, case-insensitive)",
    ),
    top: Optional[int] = typer.Option(
        None, "--top",
        help="Show only the top N worst findings",
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, csv, json",
    ),
    show_evidence: bool = typer.Option(
        False, "--evidence",
        help="Include raw evidence dict under each table row",
        is_flag=True,
    ),
) -> None:
    """Report findings from a scan run, filtered by severity and other criteria."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    output_dir = Path(cfg.output.local_output_dir)
    ndjson_path = output_dir / f"{runkey}.ndjson"

    if not ndjson_path.exists():
        typer.echo(f"ERROR: No findings file found at {ndjson_path}", err=True)
        typer.echo(f"  Run 'exposures runs' to list available run keys.", err=True)
        raise typer.Exit(code=1)

    all_findings = _load_ndjson(ndjson_path)
    if not all_findings:
        typer.echo("No findings in file.")
        raise typer.Exit(code=0)

    # Build severity threshold
    min_rank = _SEVERITY_RANK.get(min_severity.lower(), 0)
    allowed_statuses = {s.strip().lower() for s in status_filter.split(",")}

    filtered = []
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        stat = f.get("status", "").lower()

        if _SEVERITY_RANK.get(sev, 99) > min_rank:
            continue
        if stat not in allowed_statuses:
            continue
        if category and f.get("check_category", "").lower() != category.lower():
            continue
        if business_unit and business_unit.lower() not in f.get("business_unit", "").lower():
            continue
        if url_filter and url_filter.lower() not in f.get("url", "").lower():
            continue

        filtered.append(f)

    # Sort: severity asc (critical first), then url, then check_name
    filtered.sort(key=lambda f: (
        _SEVERITY_RANK.get(f.get("severity", "info"), 99),
        f.get("url", ""),
        f.get("check_name", ""),
    ))

    if top:
        filtered = filtered[:top]

    if not filtered:
        all_sev: dict[str, int] = {}
        all_stat: dict[str, int] = {}
        for f in all_findings:
            all_sev[f.get("severity", "?")] = all_sev.get(f.get("severity", "?"), 0) + 1
            all_stat[f.get("status", "?")] = all_stat.get(f.get("status", "?"), 0) + 1
        sev_str = "  ".join(f"{s.upper()}: {all_sev[s]}" for s in _SEVERITY_ORDER if s in all_sev)
        stat_str = "  ".join(f"{k}: {v}" for k, v in sorted(all_stat.items()))
        typer.echo(f"\nRun: {runkey}   Total in file: {len(all_findings)}")
        typer.echo(f"  No findings match --severity {min_severity} --status {status_filter}")
        typer.echo(f"  Available severities: {sev_str}")
        typer.echo(f"  Available statuses:   {stat_str}")
        typer.echo(f"  Try: exposures report {runkey} --severity low --status fail,warn,info")
        raise typer.Exit(code=0)

    # Header summary
    sev_counts: dict[str, int] = {}
    for f in filtered:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    count_str = "  ".join(
        f"{s.upper()}: {sev_counts[s]}"
        for s in _SEVERITY_ORDER
        if s in sev_counts
    )
    typer.echo(f"\nRun: {runkey}   Findings: {len(filtered)}   {count_str}\n")

    if output_format == "json":
        typer.echo(json.dumps(filtered, indent=2, default=str))

    elif output_format == "csv":
        writer = csv_mod.DictWriter(
            sys.stdout,
            fieldnames=["severity", "status", "check_category", "check_name",
                        "business_unit", "url", "detail", "timestamp"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(filtered)

    else:
        _print_table(filtered, show_evidence)

@app.command("runs")
def list_runs(
    config_path: Path = typer.Option(
        "./config/settings.yaml",
        "--config",
        help="Path to settings.yaml",
    ),
) -> None:
    """List all recorded scan runs from history."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    if not cfg.history.enabled:
        typer.echo("History is disabled in config (history.enabled = false).")
        raise typer.Exit(code=0)

    store = HistoryStore(cfg.history.db_path)
    runs = store.list_runs()

    if not runs:
        typer.echo("No runs recorded yet.")
        raise typer.Exit(code=0)

    typer.echo(f"\n{'RUNKEY':<35} {'STARTED':<25} {'TARGETS':>8} {'FINDINGS':>9}")
    typer.echo("-" * 80)
    for r in runs:
        started = (r.get("started_at") or "")[:19].replace("T", " ")
        typer.echo(
            f"{r['runkey']:<35} {started:<25} {r.get('total_targets', 0):>8} {r.get('total_findings', 0):>9}"
        )
    typer.echo("")

@app.command("diff")
def diff_runs(
    runkey_a: str = typer.Argument(help="Earlier run key"),
    runkey_b: str = typer.Argument(help="Later run key"),
    config_path: Path = typer.Option(
        "./config/settings.yaml",
        "--config",
        help="Path to settings.yaml",
    ),
    show_persisting: bool = typer.Option(
        False,
        "--show-persisting",
        help="Also show findings that persist unchanged between runs",
        is_flag=True,
    ),
) -> None:
    """Compare two scan runs and show what changed."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    store = HistoryStore(cfg.history.db_path)
    delta = store.compute_delta(runkey_a, runkey_b)

    if not delta:
        typer.echo(f"\nNo differences found between {runkey_a} and {runkey_b}.")
        raise typer.Exit(code=0)

    by_change: dict[str, list] = {}
    for d in delta:
        by_change.setdefault(d.change, []).append(d)

    order = ["new", "escalated", "de_escalated", "resolved"]
    if show_persisting:
        order.append("persisting")

    labels = {
        "new": "NEW FINDINGS",
        "escalated": "ESCALATED",
        "de_escalated": "DE-ESCALATED",
        "resolved": "RESOLVED",
        "persisting": "PERSISTING (unchanged)",
    }

    typer.echo(f"\nDiff: {runkey_a} -> {runkey_b}\n")

    for change_type in order:
        items = by_change.get(change_type, [])
        if not items:
            continue
        typer.echo(f"  {labels[change_type]} ({len(items)})")
        typer.echo("  " + "-" * 60)
        for d in sorted(items, key=lambda x: (x.url, x.check_name)):
            sev_info = ""
            if d.prev_severity and d.curr_severity and d.prev_severity != d.curr_severity:
                sev_info = f"  [{d.prev_severity} -> {d.curr_severity}]"
            elif d.curr_severity:
                sev_info = f"  [{d.curr_severity}]"
            typer.echo(f"    {d.url}")
            typer.echo(f"      {d.check_name}{sev_info}")
        typer.echo("")

    summary_parts = []
    for change_type in order:
        count = len(by_change.get(change_type, []))
        if count:
            summary_parts.append(f"{change_type}: {count}")
    typer.echo("  Summary: " + "  |  ".join(summary_parts))
    typer.echo("")

def main() -> None:
    """Package entry point."""
    app()

if __name__ == "__main__":
    main()
