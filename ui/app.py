#!/usr/bin/env python3
"""School Cyber Exposure — web dashboard.

Usage:
    python ui/app.py [--host 0.0.0.0] [--port 8000] (for remote access, else localhost)
    can't remember if fastapi uvicorn are handled during setup, else remember to install them
    #TODO fix this
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import secrets
import sqlite3
import uvicorn
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import time
from typing import Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

# set some default paths

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "output" / "history.db"
OUTPUT_DIR = ROOT / "output"
INDEX_HTML = Path(__file__).resolve().parent / "index.html"

# Category grouping - grouping types of findings to simplify the dashboard

CATEGORY_GROUPS: dict[str, list[str]] = {
    "web":            ["http_headers", "open_redirect"],
    "tls":            ["tls", "cert_transparency"],
    "dns":            ["dns"],
    "email":          ["email_security"],
    "infrastructure": ["network_exposure", "insecure_services", "cloud_storage", "components"],
    "domain_expiry":  ["domain_expiry"],
    "reputation":     ["reputation"],
}

CATEGORY_LABELS: dict[str, str] = {
    "web":            "Web",
    "tls":            "TLS / Certs",
    "dns":            "DNS",
    "email":          "Email",
    "infrastructure": "Infrastructure",
    "domain_expiry":  "Domain",
    "reputation":     "Reputation",
}

CATEGORY_TO_GROUP: dict[str, str] = {
    cat: group
    for group, cats in CATEGORY_GROUPS.items()
    for cat in cats
}

# Remediation guidance per check_name — links to NCSC or DfE guidance pages
# TODO: some (all) of these links arne't working when called from the finding page
REMEDIATION: dict[str, dict[str, str]] = {
    # HTTP headers
    "hsts_present":            {"title": "Enable HSTS",              "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls/using-http-strict-transport-security-hsts"},
    "hsts_max_age":            {"title": "Increase HSTS max-age",    "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls/using-http-strict-transport-security-hsts"},
    "csp_present":             {"title": "Add a Content Security Policy", "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/server-security/content-security-policy"},
    "csp_unsafe_inline":       {"title": "Remove unsafe-inline from CSP", "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/server-security/content-security-policy"},
    "csp_unsafe_eval":         {"title": "Remove unsafe-eval from CSP", "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/server-security/content-security-policy"},
    "x_frame_options":         {"title": "Add X-Frame-Options header", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"},
    "x_content_type_options":  {"title": "Add X-Content-Type-Options: nosniff", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
    "https_enforced":          {"title": "Redirect HTTP to HTTPS",    "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls/redirect-http-to-https"},
    "cookie_security":         {"title": "Secure cookie flags",       "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"},
    "open_redirect":           {"title": "Fix open redirect",         "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
    "mixed_content_active":    {"title": "Fix active mixed content",  "url": "https://developer.chrome.com/docs/devtools/console/reference/#mixed-content"},
    "mixed_content_passive":   {"title": "Fix passive mixed content", "url": "https://developer.chrome.com/docs/devtools/console/reference/#mixed-content"},
    # TLS
    "tls_expired":             {"title": "Renew TLS certificate",     "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls"},
    "tls_expiry_days":         {"title": "Renew TLS certificate",     "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls"},
    "tls_hostname_mismatch":   {"title": "Fix certificate hostname mismatch", "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls"},
    "tls_self_signed":         {"title": "Replace self-signed certificate", "url": "https://www.ncsc.gov.uk/collection/web-security-for-administrators/using-tls"},
    "tls_weak_protocol":       {"title": "Disable TLS 1.0 / 1.1",    "url": "https://www.ncsc.gov.uk/guidance/tls-external-facing-services"},
    # DNS
    "dns_caa_record":          {"title": "Add CAA DNS record",        "url": "https://www.ncsc.gov.uk/blog-post/protecting-your-users-from-fraudulent-certificates"},
    "dns_dnssec":              {"title": "Enable DNSSEC",             "url": "https://www.ncsc.gov.uk/guidance/introduction-to-dns-security"},
    "dns_zone_transfer":       {"title": "Disable DNS zone transfer", "url": "https://www.ncsc.gov.uk/guidance/introduction-to-dns-security"},
    "dns_dangling_cname":      {"title": "Fix dangling CNAME (subdomain takeover risk)", "url": "https://www.ncsc.gov.uk/news/subdomain-takeover-news"},
    # Email
    "spf_present":             {"title": "Add SPF record",            "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing"},
    "spf_all_mechanism":       {"title": "Tighten SPF -all policy",   "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing/anti-spoofing"},
    "dmarc_present":           {"title": "Add DMARC record",          "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing/dmarc"},
    "dmarc_policy":            {"title": "Enforce DMARC policy",      "url": "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing/dmarc"},
    # Components
    "git_exposed":             {"title": "Block access to .git directory", "url": "https://owasp.org/www-community/Source_Code_Disclosure"},
    "env_file_exposed":        {"title": "Block access to .env file", "url": "https://owasp.org/www-community/Source_Code_Disclosure"},
    "phpinfo_exposed":         {"title": "Remove phpinfo() page",     "url": "https://www.php.net/manual/en/function.phpinfo.php"},
    "apache_server_status_exposed": {"title": "Restrict Apache server-status", "url": "https://httpd.apache.org/docs/2.4/mod/mod_status.html"},
    "component_vulnerable_version": {"title": "Update vulnerable component", "url": "https://www.ncsc.gov.uk/guidance/vulnerability-management"},
    # Network
    "insecure_port_ftp":       {"title": "Disable FTP — use SFTP",   "url": "https://www.ncsc.gov.uk/guidance/using-ftp-securely"},
    "insecure_port_telnet":    {"title": "Disable Telnet — use SSH",  "url": "https://www.ncsc.gov.uk/guidance/ssh-usage-risk-and-mitigation"},
    "admin_port_rdp":          {"title": "Restrict RDP access",       "url": "https://www.ncsc.gov.uk/guidance/remote-desktop-services"},
    "database_port_exposed":   {"title": "Block database port from internet", "url": "https://www.ncsc.gov.uk/guidance/network-access-controls"},
    # Domain
    "domain_expiry":           {"title": "Renew domain registration", "url": "https://www.nominet.uk/"},
    # Storage
    "cloud_storage_public_listing": {"title": "Restrict cloud storage bucket", "url": "https://www.ncsc.gov.uk/guidance/cloud-security-guidance"},
    "cloud_storage_unclaimed_bucket": {"title": "Claim or remove bucket CNAME", "url": "https://www.ncsc.gov.uk/news/subdomain-takeover-news"},
}


# Risk score
# also set in index.html in the riskScore() JS function
# TODO - refactor to just one

def _risk_score(c: int, h: int, m: int) -> int:
    """ Tier-based score with diminishing returns. 1H=50, ~10H≈1C=75, ceiling≈100.
    The aim here is to try and manage the scoring so that criticals are at the top - obviously
    but so that a stack of mediums can never outweigh a single critical. there's an argument that enough highs
    can outweigh a single critical - and this is possible... we'll need to see how this is used in practice to see if the ratios
    are right or not
    """
    if c > 0:
        score = (65 + 25*(1-0.6**c)
                    + min(10*(1-0.6**h), 10)
                    + min(3*(1-0.9**m), 3))
    elif h > 0:
        score = 33 + 42*(1-0.6**h) + min(3*(1-0.9**m), 3)
    elif m > 0:
        score = 5 + 10*(1-0.8**m)
    else:
        return 0
    return round(min(score, 100))


# the reports are loading from the ndjson output files - the
# runkey comes in handy here for differntiating between runs

_EVIDENCE_CACHE_MAX = 5
_evidence_cache: dict[str, dict[tuple, dict]] = {}
_evidence_cache_order: list[str] = []

def _load_evidence(runkey: str) -> dict[tuple, dict]:
    if runkey in _evidence_cache:
        return _evidence_cache[runkey]
    index: dict[tuple, dict] = {}
    ndjson_path = OUTPUT_DIR / f"{runkey}.ndjson"
    # Validate path stays within OUTPUT_DIR
    try:
        ndjson_path.resolve().relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        return index
    if ndjson_path.exists():
        with open(ndjson_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    ts = (rec.get("timestamp") or "")[:26]
                    key = (rec.get("url"), rec.get("check_name"), ts)
                    index[key] = rec.get("evidence", {})
                except json.JSONDecodeError:
                    continue
    # Evict oldest entry when cache is full
    if len(_evidence_cache) >= _EVIDENCE_CACHE_MAX and _evidence_cache_order:
        oldest = _evidence_cache_order.pop(0)
        _evidence_cache.pop(oldest, None)
    _evidence_cache[runkey] = index
    _evidence_cache_order.append(runkey)
    return index

_SUPPRESSIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS suppressions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE(url, check_name)
);

CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    body        TEXT NOT NULL,
    author      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_url ON notes (url);
"""

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_suppressions() -> None:
    with _db() as conn:
        conn.executescript(_SUPPRESSIONS_SCHEMA)

def _init_suppressions_expiry() -> None:
    """Add expires_at column to suppressions if missing (safe migration)"""
    with _db() as conn:
        try:
            conn.execute("ALTER TABLE suppressions ADD COLUMN expires_at TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists

def _migrate_findings_schema() -> None:
    """Add GIAS metadata and evidence columns to findings table if missing."""
    new_cols = [
        ("la_name",     "TEXT NOT NULL DEFAULT ''"),
        ("region",      "TEXT NOT NULL DEFAULT ''"),
        ("urn",         "TEXT NOT NULL DEFAULT ''"),
        ("school_type", "TEXT NOT NULL DEFAULT ''"),
        ("phase",       "TEXT NOT NULL DEFAULT ''"),
        ("evidence",    "TEXT NOT NULL DEFAULT '{}'"),
    ]
    with _db() as conn:
        for col_name, col_def in new_cols:
            try:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass  # column already exists

_NOT_SUPPRESSED = """
    AND NOT EXISTS (
        SELECT 1 FROM suppressions s
        WHERE s.url = f.url AND s.check_name = f.check_name
          AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))
    )
"""

# HTTP Basic Auth — set DASHBOARD_USERNAME / DASHBOARD_PASSWORD env vars
# to enable. If DASHBOARD_PASSWORD is empty, auth is disabled (localhost use only).
# NOT production safe
_AUTH_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
_AUTH_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

_rl_store: dict[str, list[float]] = defaultdict(list)
_RL_WINDOW = 60          # seconds
_RL_READ_MAX   = 120     # read requests per minute per IP
_RL_WRITE_MAX  = 15      # write (POST/DELETE) requests per minute per IP

def _rate_limit_check(ip: str, max_req: int) -> bool:
    """Return True if allowed, False if rate limited."""
    now = time()
    timestamps = _rl_store[ip]
    timestamps[:] = [t for t in timestamps if now - t < _RL_WINDOW]
    if len(timestamps) >= max_req:
        return False
    timestamps.append(now)
    return True

####################################
# App entries
####################################
@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_suppressions()
    _init_suppressions_expiry()
    _migrate_findings_schema()
    yield

app = FastAPI(title="School Cyber Exposure", lifespan=lifespan)

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Combined auth + rate limiting middleware."""
    client_ip = (request.client.host if request.client else "unknown")

    # Rate limiting
    is_write = request.method in ("POST", "DELETE", "PUT", "PATCH")
    max_req = _RL_WRITE_MAX if is_write else _RL_READ_MAX
    if not _rate_limit_check(f"{client_ip}:{request.method}", max_req):
        return Response(
            status_code=429,
            content="Rate limit exceeded — try again shortly",
            headers={"Retry-After": str(_RL_WINDOW)},
        )

    # HTTP Basic Auth when DASHBOARD_PASSWORD is set
    if _AUTH_PASSWORD:
        # Always serve index.html so the browser can show the auth dialog
        if request.url.path not in ("/", "/favicon.ico"):
            auth = request.headers.get("Authorization", "")
            authorized = False
            if auth.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
                    username, _, password = decoded.partition(":")
                    authorized = (
                        secrets.compare_digest(username, _AUTH_USERNAME) and
                        secrets.compare_digest(password, _AUTH_PASSWORD)
                    )
                except Exception:
                    pass
            if not authorized:
                return Response(
                    status_code=401,
                    content="Unauthorized",
                    headers={"WWW-Authenticate": 'Basic realm="School Cyber Exposure"'},
                )

    return await call_next(request)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(INDEX_HTML)


@app.get("/api/remediation")
def get_remediation() -> dict[str, dict[str, str]]:
    """Static map of check_name -> {title, url} for remediation guidance links."""
    return REMEDIATION

@app.get("/api/la-names")
def list_la_names() -> list[str]:
    """Return distinct non-empty la_names from the findings table, sorted alphabetically."""
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT DISTINCT la_name FROM findings WHERE la_name != '' ORDER BY la_name"
        ).fetchall()
        conn.close()
        return [r["la_name"] for r in rows]
    except sqlite3.OperationalError:
        conn.close()
        return []


@app.get("/api/domain-suffixes")
def list_domain_suffixes() -> list[str]:
    """Return distinct domain suffixes present in the findings table, sorted by frequency.
    For country-code TLDs (2-char, e.g. .uk) returns the second-level suffix (e.g. .sch.uk,
    .co.uk). For generic TLDs returns just the TLD (e.g. .com, .org).
    """
    conn = _db()
    rows = conn.execute("SELECT DISTINCT url FROM findings").fetchall()
    conn.close()
    counts: dict[str, int] = {}
    for row in rows:
        host = row["url"].split("://", 1)[-1].split("/")[0].lower().rstrip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            suffix = ("." + ".".join(parts[-2:])) if len(tld) == 2 else ("." + tld)
            counts[suffix] = counts.get(suffix, 0) + 1
    return [s for s, _ in sorted(counts.items(), key=lambda x: -x[1])]


@app.get("/api/runs")
def list_runs() -> list[dict]:
    conn = _db()
    rows = conn.execute(
        "SELECT runkey, started_at, completed_at, total_targets, total_findings "
        "FROM runs ORDER BY started_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


_HIDE_NVD = "AND f.check_name != 'component_vulnerable_version'"

@app.get("/api/table")
def get_table(
    runkey:        str  = Query(...),
    search:        str  = Query(default=""),
    sev:           str  = Query(default="all"),   # all | medium | high | critical
    sort_col:      str  = Query(default="risk"),  # url | risk
    sort_dir:      str  = Query(default="desc"),  # asc | desc
    offset:        int  = Query(default=0,   ge=0),
    limit:         int  = Query(default=100, le=500),
    hide_nvd:      bool = Query(default=False),
    domain_suffix: str  = Query(default=""),  # e.g. ".sch.uk"
    la_name:       str  = Query(default=""),  # filter by LA / region
) -> dict:
    conn = _db()

    run = conn.execute("SELECT runkey FROM runs WHERE runkey = ?", (runkey,)).fetchone()
    if not run:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Run '{runkey}' not found")

    nvd_clause = _HIDE_NVD if hide_nvd else ""

    # LA name filter clause
    la_clause = ""
    la_params: list = []
    if la_name:
        la_clause = "AND (CASE WHEN f.la_name != '' THEN f.la_name ELSE f.business_unit END) = ?"
        la_params = [la_name]

    count_rows = conn.execute(
        f"""
        SELECT f.url,
            SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) AS c,
            SUM(CASE WHEN f.severity='high'     THEN 1 ELSE 0 END) AS h,
            SUM(CASE WHEN f.severity='medium'   THEN 1 ELSE 0 END) AS m
        FROM findings f
        WHERE f.runkey = ? AND f.severity IN ('critical','high','medium')
          {_NOT_SUPPRESSED}
          {nvd_clause}
          {la_clause}
        GROUP BY f.url
        """,
        (runkey, *la_params),
    ).fetchall()

    all_urls_query = (
        f"SELECT DISTINCT url FROM findings f WHERE runkey = ? {la_clause}"
    )
    all_urls: set[str] = {
        r["url"] for r in conn.execute(all_urls_query, (runkey, *la_params)).fetchall()
    }

    # include schools with no adverse findings - we have a "best" table as well as worst!
    url_counts: dict[str, dict[str, int]] = {
        r["url"]: {"c": r["c"], "h": r["h"], "m": r["m"]} for r in count_rows
    }
    for u in all_urls:
        url_counts.setdefault(u, {"c": 0, "h": 0, "m": 0})

    if search:
        sl = search.lower()
        url_counts = {k: v for k, v in url_counts.items() if sl in k.lower()}

    if domain_suffix:
        ds = domain_suffix.lower()
        url_counts = {k: v for k, v in url_counts.items()
                      if k.lower().rstrip("/").endswith(ds) or
                         f"/{ds}" in k.lower() or
                         k.lower().split("://", 1)[-1].split("/")[0].endswith(ds)}

    if sev == "medium":
        url_counts = {k: v for k, v in url_counts.items() if v["c"]+v["h"]+v["m"] > 0}
    elif sev == "high":
        url_counts = {k: v for k, v in url_counts.items() if v["c"]+v["h"] > 0}
    elif sev == "critical":
        url_counts = {k: v for k, v in url_counts.items() if v["c"] > 0}

    # Stats for the full filtered set (shown in stats bar)
    vals = list(url_counts.values())
    stats: dict[str, int] = {
        "total_c": sum(v["c"] for v in vals),
        "total_h": sum(v["h"] for v in vals),
        "total_m": sum(v["m"] for v in vals),
        "clean":   sum(1 for v in vals if v["c"]+v["h"]+v["m"] == 0),
    }

    rev = sort_dir == "desc"
    items = list(url_counts.items())
    if sort_col == "url":
        items.sort(key=lambda x: x[0].lower(), reverse=(not rev))
    else:
        items.sort(key=lambda x: _risk_score(x[1]["c"], x[1]["h"], x[1]["m"]), reverse=rev)

    total = len(items)
    page_urls = [url for url, _ in items[offset: offset + limit]]

    if not page_urls:
        conn.close()
        return {"total": total, "stats": stats, "rows": []}

    ph = ",".join("?" * len(page_urls))

    # category breakdown + coverage (current page only)
    cat_rows = conn.execute(
        f"""
        SELECT f.url, f.check_category, f.severity, COUNT(*) AS cnt
        FROM findings f
        WHERE f.runkey = ? AND f.url IN ({ph})
          AND f.severity IN ('critical','high','medium')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        GROUP BY f.url, f.check_category, f.severity
        """,
        (runkey, *page_urls),
    ).fetchall()

    sup_rows = conn.execute(
        f"""
        SELECT f.url, f.check_category, COUNT(*) AS cnt
        FROM findings f
        JOIN suppressions s ON s.url = f.url AND s.check_name = f.check_name
        WHERE f.runkey = ? AND f.url IN ({ph})
          AND f.severity IN ('critical','high','medium')
        GROUP BY f.url, f.check_category
        """,
        (runkey, *page_urls),
    ).fetchall()

    cov_rows = conn.execute(
        f"""
        SELECT url,
               COUNT(*) AS total,
               SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors
        FROM findings
        WHERE runkey = ? AND url IN ({ph})
        GROUP BY url
        """,
        (runkey, *page_urls),
    ).fetchall()
    conn.close()

    schools: dict[str, Any] = {
        url: {
            "url": url,
            "categories": {
                g: {"critical": 0, "high": 0, "medium": 0, "suppressed": 0}
                for g in CATEGORY_GROUPS
            },
            "coverage_warning": False,
        }
        for url in page_urls
    }
    for row in cat_rows:
        g = CATEGORY_TO_GROUP.get(row["check_category"])
        if g and row["url"] in schools:
            schools[row["url"]]["categories"][g][row["severity"]] += row["cnt"]
    for row in sup_rows:
        g = CATEGORY_TO_GROUP.get(row["check_category"])
        if g and row["url"] in schools:
            schools[row["url"]]["categories"][g]["suppressed"] += row["cnt"]
    for row in cov_rows:
        u, tot, err = row["url"], row["total"] or 0, row["errors"] or 0
        if u in schools and tot > 0:
            schools[u]["coverage_warning"] = (err / tot) > 0.20

    stats["coverage_warnings"] = sum(1 for s in schools.values() if s["coverage_warning"])

    return {
        "total": total,
        "stats": stats,
        "rows":  [schools[u] for u in page_urls],
    }

@app.get("/api/school-scores")
def get_school_scores(
    runkey:   str  = Query(...),
    hide_nvd: bool = Query(default=False),
) -> list[dict]:
    """Per-school c/h/m counts + risk score for all schools.  No pagination —
    intentionally small payload used only by the Worst Offenders modal.
    this is to show the top X """
    nvd_clause = _HIDE_NVD if hide_nvd else ""
    conn = _db()
    rows = conn.execute(
        f"""
        SELECT f.url,
            SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) AS c,
            SUM(CASE WHEN f.severity='high'     THEN 1 ELSE 0 END) AS h,
            SUM(CASE WHEN f.severity='medium'   THEN 1 ELSE 0 END) AS m
        FROM findings f
        WHERE f.runkey = ? AND f.severity IN ('critical','high','medium')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        GROUP BY f.url
        """,
        (runkey,),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        c, h, m = r["c"], r["h"], r["m"]
        result.append({"url": r["url"], "c": c, "h": h, "m": m,
                       "risk_score": _risk_score(c, h, m)})
    return result

@app.get("/api/trends")
def get_trends(urls: str = Query(default="")) -> dict:
    """
    Return per-school adverse counts (excluding suppressions) across the last
    10 runs, ordered oldest to newest.  Only includes runs where each school
    actually appeared.

    Response shape:
        {
          "runs": ["2026-03-10-abc", ...],   // last 10 runkeys, oldest first
          "data": {
            "http://school.uk": [5, 4, 3],  // counts for runs where present
            ...
          }
        }
    """
    conn = _db()

    recent_runs = conn.execute(
        "SELECT runkey, started_at FROM runs ORDER BY started_at DESC LIMIT 10"
    ).fetchall()
    recent_runs = list(reversed(recent_runs))  # oldest first
    run_keys = [r["runkey"] for r in recent_runs]

    if not run_keys:
        conn.close()
        return {"runs": [], "data": {}}

    placeholders = ",".join("?" * len(run_keys))
    rows = conn.execute(
        f"""
        SELECT f.url, f.runkey, COUNT(*) AS cnt
        FROM findings f
        WHERE f.runkey IN ({placeholders})
          AND f.severity IN ('critical', 'high', 'medium')
          {_NOT_SUPPRESSED}
        GROUP BY f.url, f.runkey
        """,
        run_keys,
    ).fetchall()

    # list counts only for runs where they appeared (had any finding)
    presence_rows = conn.execute(
        f"""
        SELECT DISTINCT url, runkey FROM findings
        WHERE runkey IN ({placeholders})
        """,
        run_keys,
    ).fetchall()
    conn.close()

    # Build lookup: (url, runkey) -> count
    counts: dict[tuple, int] = {}
    for row in rows:
        counts[(row["url"], row["runkey"])] = row["cnt"]

    presence: dict[str, set[str]] = {}
    for row in presence_rows:
        presence.setdefault(row["url"], set()).add(row["runkey"])

    # Optional URL filter — only return trends for the requested URLs (current page)
    url_filter: set[str] | None = None
    if urls:
        url_filter = set(u.strip() for u in urls.split(",") if u.strip())

    data: dict[str, list[int]] = {}
    for url in presence:
        if url_filter is not None and url not in url_filter:
            continue
        series = [
            counts.get((url, rk), 0)
            for rk in run_keys
            if rk in presence[url]
        ]
        if series:
            data[url] = series

    return {"runs": run_keys, "data": data}


###### Detail
@app.get("/api/detail")
def get_detail(
    runkey: str = Query(...),
    url: str = Query(...),
    category: str = Query(...),
) -> list[dict]:
    if category not in CATEGORY_GROUPS:
        raise HTTPException(status_code=400, detail=f"Unknown category: '{category}'")

    cats = CATEGORY_GROUPS[category]
    placeholders = ",".join("?" * len(cats))

    conn = _db()
    rows = conn.execute(
        f"""
        SELECT f.check_category, f.check_name, f.status, f.severity, f.detail, f.timestamp
        FROM findings f
        WHERE f.runkey = ? AND f.url = ? AND f.check_category IN ({placeholders})
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low'      THEN 3 WHEN 'info'  THEN 4 ELSE 5
            END,
            f.check_name
        """,
        (runkey, url, *cats),
    ).fetchall()

    findings = [dict(r) for r in rows]
    check_names = list({f["check_name"] for f in findings})

    # Batch first-seen query
    first_seen_map: dict[str, str] = {}
    if check_names:
        cn_placeholders = ",".join("?" * len(check_names))
        fs_rows = conn.execute(
            f"""
            SELECT f.check_name, MIN(r.started_at) AS first_seen
            FROM findings f
            JOIN runs r ON r.runkey = f.runkey
            WHERE f.url = ?
              AND f.check_name IN ({cn_placeholders})
              AND f.status IN ('fail', 'warn')
            GROUP BY f.check_name
            """,
            (url, *check_names),
        ).fetchall()
        for row in fs_rows:
            first_seen_map[row["check_name"]] = row["first_seen"]

    # Suppressions for this URL
    suppression_rows = conn.execute(
        "SELECT check_name, reason, created_at, id FROM suppressions WHERE url = ?",
        (url,),
    ).fetchall()
    conn.close()

    suppression_map: dict[str, dict] = {
        r["check_name"]: {"id": r["id"], "reason": r["reason"], "created_at": r["created_at"]}
        for r in suppression_rows
    }

    # Evidence from NDJSON
    evidence_index = _load_evidence(runkey)

    now = datetime.now(timezone.utc)

    for f in findings:
        ts = (f["timestamp"] or "")[:26]
        f["evidence"] = evidence_index.get((url, f["check_name"], ts), {})

        first_seen_str = first_seen_map.get(f["check_name"])
        if first_seen_str and f["status"] in ("fail", "warn"):
            try:
                fs = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
                if fs.tzinfo is None:
                    fs = fs.replace(tzinfo=timezone.utc)
                age = (now - fs).days
                f["first_seen"] = first_seen_str[:10]
                f["age_days"] = age
            except ValueError:
                f["first_seen"] = None
                f["age_days"] = None
        else:
            f["first_seen"] = None
            f["age_days"] = None

        sup = suppression_map.get(f["check_name"])
        if sup:
            f["suppressed"] = True
            f["suppression_id"] = sup["id"]
            f["suppression_reason"] = sup["reason"]
            f["suppression_date"] = sup["created_at"][:10]
        else:
            f["suppressed"] = False
            f["suppression_id"] = None
            f["suppression_reason"] = None
            f["suppression_date"] = None

    return findings


# Suppressions
class SuppressRequest(BaseModel):
    url: str = ""
    check_name: str
    reason: str = ""
    expires_days: int | None = None  # None = no expiry, positive int = expires in N days

    def model_post_init(self, __context: Any) -> None:
        if len(self.check_name) > 200:
            raise ValueError("check_name too long")
        if len(self.reason) > 1000:
            raise ValueError("reason too long")
        if self.url and len(self.url) > 2000:
            raise ValueError("url too long")
        if self.expires_days is not None and (self.expires_days < 1 or self.expires_days > 3650):
            raise ValueError("expires_days must be between 1 and 3650")


class BulkSuppressRequest(BaseModel):
    runkey: str
    check_name: str
    reason: str = ""
    expires_days: int | None = None

    def model_post_init(self, __context: Any) -> None:
        if len(self.check_name) > 200:
            raise ValueError("check_name too long")
        if len(self.reason) > 1000:
            raise ValueError("reason too long")
        if self.expires_days is not None and (self.expires_days < 1 or self.expires_days > 3650):
            raise ValueError("expires_days must be between 1 and 3650")


def _calc_expires_at(expires_days: int | None) -> str | None:
    """Calculate ISO expiry timestamp from days offset, or None for no expiry."""
    if expires_days is None:
        return None
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()


@app.post("/api/suppress", status_code=201)
def create_suppression(req: SuppressRequest) -> dict:
    if not req.url:
        raise HTTPException(status_code=400, detail="url is required for single suppression")
    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = _calc_expires_at(req.expires_days)
    try:
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO suppressions (url, check_name, reason, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (req.url, req.check_name, req.reason, created_at, expires_at),
            )
            row = conn.execute(
                "SELECT id FROM suppressions WHERE url = ? AND check_name = ?",
                (req.url, req.check_name),
            ).fetchone()
        return {"id": row["id"], "url": req.url, "check_name": req.check_name,
                "reason": req.reason, "created_at": created_at, "expires_at": expires_at}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/suppress/bulk", status_code=201)
def create_bulk_suppression(req: BulkSuppressRequest) -> dict:
    """Suppress a check_name across all URLs that have it as a fail/warn in a given run."""
    conn = _db()
    run = conn.execute("SELECT runkey FROM runs WHERE runkey = ?", (req.runkey,)).fetchone()
    if not run:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Run '{req.runkey}' not found")

    affected_urls = conn.execute(
        """
        SELECT DISTINCT url FROM findings
        WHERE runkey = ? AND check_name = ? AND status IN ('fail','warn')
        """,
        (req.runkey, req.check_name),
    ).fetchall()
    conn.close()

    if not affected_urls:
        return {"inserted": 0, "check_name": req.check_name, "urls": []}

    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = _calc_expires_at(req.expires_days)
    urls = [r["url"] for r in affected_urls]
    try:
        with _db() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO suppressions (url, check_name, reason, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [(url, req.check_name, req.reason, created_at, expires_at) for url in urls],
            )
        return {"inserted": len(urls), "check_name": req.check_name, "urls": urls}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/suppress/stats")
def get_suppression_stats() -> list[dict]:
    """Count of active suppressions grouped by check_name."""
    conn = _db()
    rows = conn.execute(
        """
        SELECT check_name, COUNT(*) AS count
        FROM suppressions
        GROUP BY check_name
        ORDER BY count DESC
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/api/suppress/{suppression_id}", status_code=200)
def delete_suppression(suppression_id: int) -> dict:
    with _db() as conn:
        row = conn.execute(
            "SELECT id FROM suppressions WHERE id = ?", (suppression_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Suppression not found")
        conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    return {"deleted": suppression_id}


@app.get("/api/suppressions")
def list_suppressions() -> list[dict]:
    conn = _db()
    rows = conn.execute(
        "SELECT * FROM suppressions ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


#### Notes ###
class NoteRequest(BaseModel):
    url: str
    body: str
    author: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.url:
            raise ValueError("url is required")
        if not self.body.strip():
            raise ValueError("body is required")
        if len(self.body) > 5000:
            raise ValueError("note body too long (max 5000 chars)")
        if len(self.author) > 200:
            raise ValueError("author too long")


@app.get("/api/notes")
def get_notes(url: str = Query(...)) -> list[dict]:
    """Fetch analyst notes for a school URL, newest first."""
    conn = _db()
    rows = conn.execute(
        "SELECT * FROM notes WHERE url = ? ORDER BY created_at DESC",
        (url,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/notes", status_code=201)
def create_note(req: NoteRequest) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db() as conn:
            conn.execute(
                "INSERT INTO notes (url, body, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (req.url, req.body.strip(), req.author.strip(), now, now),
            )
            row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
        return {"id": row["id"], "url": req.url, "body": req.body.strip(),
                "author": req.author.strip(), "created_at": now}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/api/notes/{note_id}", status_code=200)
def delete_note(note_id: int) -> dict:
    with _db() as conn:
        row = conn.execute("SELECT id FROM notes WHERE id = ?", (note_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Note not found")
        conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return {"deleted": note_id}


# Coverage 

@app.get("/api/coverage")
def get_coverage(runkey: str = Query(...)) -> list[dict]:
    """Per-school error rate for the given run. Flag schools where >20% of findings are errors."""
    conn = _db()
    rows = conn.execute(
        """
        SELECT url,
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors
        FROM findings
        WHERE runkey = ?
        GROUP BY url
        """,
        (runkey,),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        total  = r["total"] or 0
        errors = r["errors"] or 0
        result.append({
            "url":        r["url"],
            "total":      total,
            "errors":     errors,
            "error_rate": round(errors / total, 3) if total else 0,
            "warning":    (errors / total) > 0.20 if total else False,
        })
    return result

# schools not in this run's result set but previously were

@app.get("/api/missing")
def get_missing(runkey: str = Query(...)) -> list[str]:
    """Return URLs present in the immediately previous run that are absent from this run."""
    conn = _db()
    # Find the previous run by started_at
    prev = conn.execute(
        """
        SELECT runkey FROM runs
        WHERE started_at < (SELECT started_at FROM runs WHERE runkey = ?)
        ORDER BY started_at DESC LIMIT 1
        """,
        (runkey,),
    ).fetchone()
    if not prev:
        conn.close()
        return []
    prev_runkey = prev["runkey"]
    rows = conn.execute(
        """
        SELECT DISTINCT url FROM findings WHERE runkey = ?
          AND url NOT IN (SELECT DISTINCT url FROM findings WHERE runkey = ?)
        ORDER BY url
        """,
        (prev_runkey, runkey),
    ).fetchall()
    conn.close()
    return [r["url"] for r in rows]


# School summary
@app.get("/api/school")
def get_school(runkey: str = Query(...), url: str = Query(...)) -> dict:
    """All findings + coverage for a single school — used by the summary card."""
    conn = _db()

    # Coverage
    cov = conn.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors
        FROM findings WHERE runkey = ? AND url = ?
        """,
        (runkey, url),
    ).fetchone()
    total  = cov["total"]  or 0
    errors = cov["errors"] or 0

    # All findings for this school (all categories, all severities)
    rows = conn.execute(
        """
        SELECT check_category, check_name, status, severity, detail, timestamp
        FROM findings
        WHERE runkey = ? AND url = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low'      THEN 3 WHEN 'info'  THEN 4 ELSE 5
            END,
            check_category, check_name
        """,
        (runkey, url),
    ).fetchall()
    findings = [dict(r) for r in rows]

    check_names = list({f["check_name"] for f in findings})
    first_seen_map: dict[str, str] = {}
    if check_names:
        cn_ph = ",".join("?" * len(check_names))
        fs_rows = conn.execute(
            f"""
            SELECT f.check_name, MIN(r.started_at) AS first_seen
            FROM findings f JOIN runs r ON r.runkey = f.runkey
            WHERE f.url = ? AND f.check_name IN ({cn_ph}) AND f.status IN ('fail','warn')
            GROUP BY f.check_name
            """,
            (url, *check_names),
        ).fetchall()
        for r in fs_rows:
            first_seen_map[r["check_name"]] = r["first_seen"]

    sup_rows = conn.execute(
        "SELECT check_name, reason FROM suppressions WHERE url = ?", (url,)
    ).fetchall()
    conn.close()

    sup_map = {r["check_name"]: r["reason"] for r in sup_rows}
    now = datetime.now(timezone.utc)

    for f in findings:
        fs = first_seen_map.get(f["check_name"])
        if fs and f["status"] in ("fail", "warn"):
            try:
                dt = datetime.fromisoformat(fs.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                f["age_days"]   = (now - dt).days
                f["first_seen"] = fs[:10]
            except ValueError:
                f["age_days"] = f["first_seen"] = None
        else:
            f["age_days"] = f["first_seen"] = None

        f["suppressed"]         = f["check_name"] in sup_map
        f["suppression_reason"] = sup_map.get(f["check_name"])

    return {
        "url":      url,
        "coverage": {"total": total, "errors": errors,
                     "error_rate": round(errors / total, 3) if total else 0,
                     "warning": (errors / total) > 0.20 if total else False},
        "findings": findings,
    }


# Worst findings
@app.get("/api/worst-findings")
def get_worst_findings(
    runkey:   str  = Query(...),
    limit:    int  = Query(default=100, le=500),
    hide_nvd: bool = Query(default=False),
) -> list[dict]:
    """Top N adverse findings across all schools, ordered by severity then age (oldest first)."""
    nvd_clause = _HIDE_NVD if hide_nvd else ""
    conn = _db()
    rows = conn.execute(
        f"""
        SELECT f.url, f.check_category, f.check_name, f.status, f.severity, f.detail,
               (
                 SELECT MIN(r2.started_at)
                 FROM findings f2 JOIN runs r2 ON r2.runkey = f2.runkey
                 WHERE f2.url = f.url AND f2.check_name = f.check_name
                   AND f2.status IN ('fail','warn')
               ) AS first_seen
        FROM findings f
        WHERE f.runkey = ?
          AND f.severity IN ('critical','high','medium')
          AND f.status   IN ('fail','warn')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        ORDER BY
            CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 END,
            first_seen ASC
        LIMIT ?
        """,
        (runkey, limit),
    ).fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    result = []
    for r in rows:
        age = None
        if r["first_seen"]:
            try:
                dt = datetime.fromisoformat(r["first_seen"].replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = (now - dt).days
            except ValueError:
                pass
        result.append({**dict(r), "age_days": age})
    return result


# Prevalent issues 
@app.get("/api/prevalent-issues")
def get_prevalent_issues(
    runkey:   str  = Query(...),
    hide_nvd: bool = Query(default=False),
) -> list[dict]:
    """
    For each distinct (check_name, check_category, severity) in this run,
    count how many schools are affected.  Ordered by school_count DESC,
    then severity rank ASC.
    """
    nvd_clause = _HIDE_NVD if hide_nvd else ""
    conn = _db()

    total_schools = conn.execute(
        "SELECT COUNT(DISTINCT url) AS n FROM findings WHERE runkey = ?", (runkey,)
    ).fetchone()["n"] or 1

    rows = conn.execute(
        f"""
        SELECT f.check_name, f.check_category, f.severity,
               COUNT(DISTINCT f.url) AS school_count,
               COUNT(*)              AS total_count
        FROM findings f
        WHERE f.runkey = ?
          AND f.severity IN ('critical','high','medium')
          AND f.status   IN ('fail','warn')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        GROUP BY f.check_name, f.check_category, f.severity
        ORDER BY
            school_count DESC,
            CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 END
        """,
        (runkey,),
    ).fetchall()
    conn.close()

    return [
        {**dict(r), "pct_schools": round(r["school_count"] / total_schools * 100, 1)}
        for r in rows
    ]


#  Affected schools
@app.get("/api/affected-schools")
def get_affected_schools(
    runkey:     str = Query(...),
    check_name: str = Query(...),
) -> list[dict]:
    """Schools affected by a specific check in a given run (excluding suppressed)."""
    conn = _db()
    rows = conn.execute(
        f"""
        SELECT f.url, f.severity, f.status, f.detail
        FROM findings f
        WHERE f.runkey     = ?
          AND f.check_name = ?
          AND f.status IN ('fail','warn')
          {_NOT_SUPPRESSED}
        ORDER BY f.url
        """,
        (runkey, check_name),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Domain expiry page
_DE_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

@app.get("/api/domain-expiry")
def get_domain_expiry(
    runkey:   str = Query(...),
    search:   str = Query(default=""),
    sort_col: str = Query(default="days_until_expiry"),
    sort_dir: str = Query(default="asc"),
    offset:   int = Query(default=0,   ge=0),
    limit:    int = Query(default=100, le=500),
) -> dict:
    """Per-school domain expiry details for the dedicated domain expiry page."""
    conn = _db()
    rows = conn.execute(
        """
        SELECT url, check_name, status, severity, detail, timestamp
        FROM findings
        WHERE runkey = ? AND check_category = 'domain_expiry'
        ORDER BY url
        """,
        (runkey,),
    ).fetchall()
    conn.close()

    if not rows:
        return {"total": 0, "rows": []}

    evidence_index = _load_evidence(runkey)

    result = []
    for r in rows:
        ts = (r["timestamp"] or "")[:26]
        ev = evidence_index.get((r["url"], r["check_name"], ts), {})
        result.append({
            "url":               r["url"],
            "status":            r["status"],
            "severity":          r["severity"],
            "detail":            r["detail"],
            "expiry_date":       ev.get("expiry_date"),
            "days_until_expiry": ev.get("days_until_expiry"),
            "registrar":         ev.get("registrar"),
        })

    # Apply search filter
    if search:
        sl = search.lower()
        result = [r for r in result if sl in r["url"].lower()]

    # Sort
    rev = sort_dir == "desc"
    if sort_col == "url":
        result.sort(key=lambda x: x["url"].lower(), reverse=rev)
    elif sort_col == "severity":
        result.sort(key=lambda x: _DE_SEV_ORDER.get(x["severity"], 9), reverse=rev)
    elif sort_col == "registrar":
        result.sort(key=lambda x: (x["registrar"] or "").lower(), reverse=rev)
    elif sort_col == "expiry_date":
        result.sort(key=lambda x: x["expiry_date"] or "", reverse=rev)
    else:  # days_until_expiry (default)
        result.sort(key=lambda x: (x["days_until_expiry"] is None, x["days_until_expiry"] or 0),
                    reverse=rev)

    total = len(result)
    return {"total": total, "rows": result[offset: offset + limit]}

def _validate_runkey_path(runkey: str) -> Path:
    """Validate and return the NDJSON path for a runkey, rejecting path traversal."""
    candidate = (OUTPUT_DIR / f"{runkey}.ndjson").resolve()
    try:
        candidate.relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid runkey")
    return candidate


# Export
@app.get("/api/export")
def export_csv(
    runkey: str = Query(...),
    search: str = Query(default=""),
    sev: str = Query(default="all"),
    hide_nvd: bool = Query(default=False),
    la_name: str = Query(default=""),
) -> StreamingResponse:
    _validate_runkey_path(runkey)  # path traversal guard
    conn = _db()
    run = conn.execute("SELECT runkey FROM runs WHERE runkey = ?", (runkey,)).fetchone()
    if not run:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Run '{runkey}' not found")

    where_clauses = ["f.runkey = ?"]
    params: list = [runkey]

    if sev and sev != "all":
        where_clauses.append("f.severity = ?")
        params.append(sev)

    if hide_nvd:
        where_clauses.append("f.check_name != 'component_vulnerable_version'")

    if search:
        where_clauses.append("LOWER(f.url) LIKE ?")
        params.append(f"%{search.lower()}%")

    if la_name:
        where_clauses.append(
            "(CASE WHEN f.la_name != '' THEN f.la_name ELSE f.business_unit END) = ?"
        )
        params.append(la_name)

    where_sql = " AND ".join(where_clauses)

    rows = conn.execute(
        f"""
        SELECT f.url, f.check_category, f.check_name, f.status, f.severity, f.detail, f.timestamp
        FROM findings f
        WHERE {where_sql}
        ORDER BY f.url,
            CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low'      THEN 3 WHEN 'info'  THEN 4 ELSE 5
            END
        """,
        params,
    ).fetchall()

    suppression_rows = conn.execute(
        "SELECT url, check_name FROM suppressions"
    ).fetchall()
    conn.close()

    suppressed_set = {(r["url"], r["check_name"]) for r in suppression_rows}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["url", "check_category", "check_name", "status",
                     "severity", "detail", "timestamp", "suppressed"])
    for row in rows:
        writer.writerow([
            row["url"], row["check_category"], row["check_name"],
            row["status"], row["severity"], row["detail"], row["timestamp"],
            "yes" if (row["url"], row["check_name"]) in suppressed_set else "no",
        ])

    output.seek(0)
    filename = f"cyber-exposure-{runkey}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# Suppression expiry
@app.get("/api/suppress/expiring")
def get_expiring_suppressions(within_days: int = Query(default=14, ge=1, le=365)) -> list[dict]:
    """List suppressions expiring within the next N days."""
    conn = _db()
    rows = conn.execute(
        """
        SELECT * FROM suppressions
        WHERE expires_at IS NOT NULL
          AND expires_at > datetime('now')
          AND expires_at <= datetime('now', ? || ' days')
        ORDER BY expires_at ASC
        """,
        (str(within_days),),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/suppress/expiry-warning")
def get_expiry_warning(within_days: int = Query(default=14, ge=1)) -> dict:
    """Count of suppressions expiring within N days (for dashboard badge)."""
    conn = _db()
    row = conn.execute(
        """
        SELECT COUNT(*) AS n FROM suppressions
        WHERE expires_at IS NOT NULL
          AND expires_at > datetime('now')
          AND expires_at <= datetime('now', ? || ' days')
        """,
        (str(within_days),),
    ).fetchone()
    conn.close()
    return {"expiring_soon": row["n"] if row else 0, "within_days": within_days}


# Check-level trends for Analysis chart
@app.get("/api/check-trends")
def get_check_trends(runkey: str = Query(...), hide_nvd: bool = Query(default=False)) -> dict:
    """
    Return per-check-name fail/warn counts across last 10 runs for the top-10
    most prevalent issues in the current run.  Used for the Analysis trend chart.

    Response shape:
        {
          "runs": ["2026-03-10-abc", ...],   // last 10 runkeys, oldest-first
          "data": {
            "hsts_present": [1200, 1150, 1100, ...],
            ...
          }
        }
    """
    conn = _db()
    recent_runs = list(reversed(conn.execute(
        "SELECT runkey, started_at FROM runs ORDER BY started_at DESC LIMIT 10"
    ).fetchall()))
    run_keys = [r["runkey"] for r in recent_runs]

    if not run_keys:
        conn.close()
        return {"runs": [], "data": {}}

    nvd_clause = _HIDE_NVD if hide_nvd else ""
    # Top-10 check_names by school_count in the current run
    top_checks_rows = conn.execute(
        f"""
        SELECT f.check_name, COUNT(DISTINCT f.url) AS n
        FROM findings f
        WHERE f.runkey = ?
          AND f.severity IN ('critical','high','medium')
          AND f.status IN ('fail','warn')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        GROUP BY f.check_name
        ORDER BY n DESC
        LIMIT 10
        """,
        (runkey,),
    ).fetchall()
    top_checks = [r["check_name"] for r in top_checks_rows]

    if not top_checks:
        conn.close()
        return {"runs": run_keys, "data": {}}

    placeholders_rk = ",".join("?" * len(run_keys))
    placeholders_ck = ",".join("?" * len(top_checks))

    rows = conn.execute(
        f"""
        SELECT runkey, check_name, COUNT(DISTINCT url) AS n
        FROM findings
        WHERE runkey IN ({placeholders_rk})
          AND check_name IN ({placeholders_ck})
          AND severity IN ('critical','high','medium')
          AND status IN ('fail','warn')
        GROUP BY runkey, check_name
        """,
        (*run_keys, *top_checks),
    ).fetchall()
    conn.close()

    # Build (runkey, check_name) -> count
    counts: dict[tuple, int] = {(r["runkey"], r["check_name"]): r["n"] for r in rows}
    data: dict[str, list[int]] = {}
    for check in top_checks:
        data[check] = [counts.get((rk, check), 0) for rk in run_keys]

    return {"runs": run_keys, "data": data}


# Quick wins summary
# TODO: validate the ease of fix, these are an initial best guess
_EASE_OF_FIX: dict[str, tuple[str, int]] = {
    # (label, score): higher = easier to fix
    "hsts_present":            ("Add HTTP header",     3),
    "hsts_max_age":            ("Change header value", 3),
    "csp_present":             ("Add HTTP header",     3),
    "csp_unsafe_inline":       ("Update CSP value",    3),
    "csp_unsafe_eval":         ("Update CSP value",    3),
    "csp_wildcard":            ("Update CSP value",    3),
    "csp_missing_directive":   ("Update CSP value",    3),
    "x_frame_options":         ("Add HTTP header",     3),
    "x_content_type_options":  ("Add HTTP header",     3),
    "referrer_policy":         ("Add HTTP header",     3),
    "permissions_policy":      ("Add HTTP header",     3),
    "spf_present":             ("Add DNS TXT record",  3),
    "spf_all_mechanism":       ("Update DNS record",   3),
    "dmarc_present":           ("Add DNS TXT record",  3),
    "dns_caa_record":          ("Add DNS CAA record",  3),
    "https_enforced":          ("Web server config",   2),
    "tls_expiry_days":         ("Renew certificate",   2),
    "dmarc_policy":            ("Update DNS record",   2),
    "cookie_security":         ("Update web app code", 2),
    "tls_weak_protocol":       ("Web server config",   2),
    "tls_weak_cipher":         ("Web server config",   2),
    "open_redirect":           ("Code change required", 1),
    "mixed_content_active":    ("Code/template change", 1),
    "mixed_content_passive":   ("Code/template change", 1),
    "git_exposed":             ("Web server config",   2),
    "env_file_exposed":        ("Web server config",   2),
    "wordpress_xmlrpc_enabled":("WordPress config",    2),
}

@app.get("/api/quick-wins")
def get_quick_wins(runkey: str = Query(...), hide_nvd: bool = Query(default=False)) -> list[dict]:
    """
    Return prevalent issues ranked by a composite score of
    affected school count × ease of fix 
    """
    nvd_clause = _HIDE_NVD if hide_nvd else ""
    conn = _db()
    total_schools = conn.execute(
        "SELECT COUNT(DISTINCT url) AS n FROM findings WHERE runkey = ?", (runkey,)
    ).fetchone()["n"] or 1

    rows = conn.execute(
        f"""
        SELECT f.check_name, f.check_category, f.severity,
               COUNT(DISTINCT f.url) AS school_count
        FROM findings f
        WHERE f.runkey = ?
          AND f.severity IN ('critical','high','medium')
          AND f.status IN ('fail','warn')
          {_NOT_SUPPRESSED}
          {nvd_clause}
        GROUP BY f.check_name, f.check_category, f.severity
        """,
        (runkey,),
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        ease_label, ease_score = _EASE_OF_FIX.get(r["check_name"], ("Manual investigation", 1))
        composite = r["school_count"] * ease_score
        result.append({
            **dict(r),
            "ease_label":    ease_label,
            "ease_score":    ease_score,
            "composite":     composite,
            "pct_schools":   round(r["school_count"] / total_schools * 100, 1),
        })

    result.sort(key=lambda x: x["composite"], reverse=True)
    return result[:50]


#  Scan progress live view 
@app.get("/api/scan-status")
def get_scan_status() -> dict:
    """Read the most recent checkpoint file to report scan progress."""
    checkpoint_dir = OUTPUT_DIR / "checkpoints"
    if not checkpoint_dir.exists():
        return {"status": "no_scan", "runkey": None, "completed": 0, "total": 0, "pct": 0}

    checkpoints = sorted(
        checkpoint_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not checkpoints:
        return {"status": "no_scan", "runkey": None, "completed": 0, "total": 0, "pct": 0}

    latest = checkpoints[0]
    try:
        data: dict = json.loads(latest.read_text())
    except Exception:
        return {"status": "error", "runkey": latest.stem, "completed": 0, "total": 0, "pct": 0}

    completed = sum(1 for v in data.values() if v)
    total = len(data)
    pct = round(completed / total * 100) if total else 0
    # Heuristic: if completed == total, scan is done
    status = "complete" if (total > 0 and completed >= total) else "running"
    return {
        "status":    status,
        "runkey":    latest.stem,
        "completed": completed,
        "total":     total,
        "pct":       pct,
        "modified":  latest.stat().st_mtime,
    }


# LA / Region summary
# Relies on school metadata being present in the history DB
# Schools without metadata are grouped as "Unknown"
# TODO: this needs validating with Alison, i don't actually know the school grouping model

@app.get("/api/la-summary")
def get_la_summary(runkey: str = Query(...)) -> list[dict]:
    """
    Per-LA adverse finding summary for the given run.
    Groups by la_name when present, falls back to business_unit.
    """
    conn = _db()

    # Group by la_name when present, fall back to business_unit
    rows = conn.execute(
        f"""
        SELECT
            CASE WHEN f.la_name != '' THEN f.la_name ELSE f.business_unit END AS la_name,
            f.business_unit,
            COUNT(DISTINCT f.url) AS school_count,
            SUM(CASE WHEN f.severity='critical' AND f.status IN ('fail','warn') THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN f.severity='high'     AND f.status IN ('fail','warn') THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN f.severity='medium'   AND f.status IN ('fail','warn') THEN 1 ELSE 0 END) AS medium
        FROM findings f
        WHERE f.runkey = ?
          {_NOT_SUPPRESSED}
        GROUP BY CASE WHEN f.la_name != '' THEN f.la_name ELSE f.business_unit END
        ORDER BY critical DESC, high DESC, medium DESC
        """,
        (runkey,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# auth is configured via DASHBOARD_USERNAME / DASHBOARD_PASSWORD env vars
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="School Cyber Exposure dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"Starting dashboard at http://{args.host}:{args.port}")
    uvicorn.run(
        "app:app",
        host=args.host,
        port=args.port,
        reload=False,
        app_dir=str(Path(__file__).parent),
    )
