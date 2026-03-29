#!/usr/bin/env python3
"""School Cyber Exposure — web dashboard.

Usage:
    python ui/app.py [--host 0.0.0.0] [--port 8000] (for remote access, else localhost)
    can't remember if fastapi uvicorn are handled during setup, else remember to install them
    #TODO fix this
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
import uvicorn
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
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

_evidence_cache: dict[str, dict[tuple, dict]] = {}

def _load_evidence(runkey: str) -> dict[tuple, dict]:
    if runkey in _evidence_cache:
        return _evidence_cache[runkey]
    index: dict[tuple, dict] = {}
    ndjson_path = OUTPUT_DIR / f"{runkey}.ndjson"
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
    _evidence_cache[runkey] = index
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
"""

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_suppressions() -> None:
    with _db() as conn:
        conn.executescript(_SUPPRESSIONS_SCHEMA)

_NOT_SUPPRESSED = """
    AND NOT EXISTS (
        SELECT 1 FROM suppressions s
        WHERE s.url = f.url AND s.check_name = f.check_name
    )
"""

####################################
# App entries
####################################
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_suppressions()
    yield

app = FastAPI(title="School Cyber Exposure", lifespan=lifespan)

@app.get("/")
def index() -> FileResponse:
    return FileResponse(INDEX_HTML)


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
    runkey:   str  = Query(...),
    search:   str  = Query(default=""),
    sev:      str  = Query(default="all"),   # all | medium | high | critical
    sort_col: str  = Query(default="risk"),  # url | risk
    sort_dir: str  = Query(default="desc"),  # asc | desc
    offset:   int  = Query(default=0,   ge=0),
    limit:    int  = Query(default=100, le=500),
    hide_nvd: bool = Query(default=False),
) -> dict:
    conn = _db()

    run = conn.execute("SELECT runkey FROM runs WHERE runkey = ?", (runkey,)).fetchone()
    if not run:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Run '{runkey}' not found")

    nvd_clause = _HIDE_NVD if hide_nvd else ""

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
        GROUP BY f.url
        """,
        (runkey,),
    ).fetchall()

    all_urls: set[str] = {
        r["url"] for r in conn.execute(
            "SELECT DISTINCT url FROM findings WHERE runkey = ?", (runkey,)
        ).fetchall()
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
    conn.close()

    # Build lookup: (url, runkey) -> count
    counts: dict[tuple, int] = {}
    for row in rows:
        counts[(row["url"], row["runkey"])] = row["cnt"]

    # list counts only for runs where they appeared (had any finding)    
    conn = _db()
    presence_rows = conn.execute(
        f"""
        SELECT DISTINCT url, runkey FROM findings
        WHERE runkey IN ({placeholders})
        """,
        run_keys,
    ).fetchall()
    conn.close()

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


# ── Detail ────────────────────────────────────────────────────────────────────

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


# ── Suppressions ──────────────────────────────────────────────────────────────

class SuppressRequest(BaseModel):
    url: str
    check_name: str
    reason: str = ""

@app.post("/api/suppress", status_code=201)
def create_suppression(req: SuppressRequest) -> dict:
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO suppressions (url, check_name, reason, created_at) "
                "VALUES (?, ?, ?, ?)",
                (req.url, req.check_name, req.reason, created_at),
            )
            row = conn.execute(
                "SELECT id FROM suppressions WHERE url = ? AND check_name = ?",
                (req.url, req.check_name),
            ).fetchone()
        return {"id": row["id"], "url": req.url, "check_name": req.check_name,
                "reason": req.reason, "created_at": created_at}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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


# ── Coverage ─────────────────────────────────────────────────────────────────

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


# ── Missing schools ───────────────────────────────────────────────────────────
# (schools not in this run's result set)

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


# ── School summary ────────────────────────────────────────────────────────────

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


# ── Worst findings ───────────────────────────────────────────────────────────

@app.get("/api/worst-findings")
def get_worst_findings(
    runkey: str = Query(...),
    limit: int  = Query(default=100, le=500),
) -> list[dict]:
    """Top N adverse findings across all schools, ordered by severity then age (oldest first)."""
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
def get_prevalent_issues(runkey: str = Query(...)) -> list[dict]:
    """
    For each distinct (check_name, check_category, severity) in this run,
    count how many schools are affected.  Ordered by school_count DESC,
    then severity rank ASC.
    """
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

# Export
@app.get("/api/export")
def export_csv(runkey: str = Query(...)) -> StreamingResponse:
    conn = _db()
    run = conn.execute("SELECT runkey FROM runs WHERE runkey = ?", (runkey,)).fetchone()
    if not run:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Run '{runkey}' not found")

    rows = conn.execute(
        f"""
        SELECT f.url, f.check_category, f.check_name, f.status, f.severity, f.detail, f.timestamp
        FROM findings f
        WHERE f.runkey = ?
        ORDER BY f.url,
            CASE f.severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low'      THEN 3 WHEN 'info'  THEN 4 ELSE 5
            END
        """,
        (runkey,),
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

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# TODO NO SECURITY OR AUTH BUILT IN!!!!
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
