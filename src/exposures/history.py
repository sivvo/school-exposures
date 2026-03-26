"""Historical findings storage and run delta computation.

Uses SQLite to persist findings across runs and compute
what changed between two runs.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from .models import Finding, RunSummary

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    runkey      TEXT NOT NULL,
    url         TEXT NOT NULL,
    business_unit TEXT NOT NULL,
    check_category TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    status      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    detail      TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_runkey ON findings (runkey);
CREATE INDEX IF NOT EXISTS idx_findings_url    ON findings (url);

CREATE TABLE IF NOT EXISTS runs (
    runkey              TEXT PRIMARY KEY,
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    total_targets       INTEGER DEFAULT 0,
    total_findings      INTEGER DEFAULT 0,
    findings_by_severity TEXT DEFAULT '{}',
    findings_by_category TEXT DEFAULT '{}'
);
"""

# Numeric rank for severity comparison
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


class DeltaFinding(NamedTuple):
    url: str
    business_unit: str
    check_name: str
    check_category: str
    change: str          # "new" | "resolved" | "escalated" | "de_escalated" | "persisting"
    prev_severity: str | None
    curr_severity: str | None
    prev_status: str | None
    curr_status: str | None
    detail: str


class HistoryStore:
    """Thread-safe (single-writer) SQLite store for scan findings."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def store_finding(self, finding: Finding) -> None:
        ts = (
            finding.timestamp.isoformat()
            if finding.timestamp
            else datetime.now(timezone.utc).isoformat()
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO findings
                    (runkey, url, business_unit, check_category, check_name,
                     status, severity, detail, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.runkey,
                    finding.url,
                    finding.business_unit,
                    finding.check_category.value,
                    finding.check_name,
                    finding.status.value,
                    finding.severity.value,
                    finding.detail,
                    ts,
                ),
            )

    def upsert_run(self, summary: RunSummary) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs
                    (runkey, started_at, completed_at, total_targets, total_findings,
                     findings_by_severity, findings_by_category)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.runkey,
                    summary.started_at.isoformat(),
                    summary.completed_at.isoformat() if summary.completed_at else None,
                    summary.total_targets,
                    summary.total_findings,
                    json.dumps(summary.findings_by_severity),
                    json.dumps(summary.findings_by_category),
                ),
            )

    def list_runs(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_run_findings(self, runkey: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE runkey = ?", (runkey,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_previous_runkey(self, current_runkey: str) -> str | None:
        """Return the runkey of the run completed immediately before the given one."""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT runkey FROM runs
                WHERE runkey != ?
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (current_runkey,),
            ).fetchone()
            return row["runkey"] if row else None

    def compute_delta(self, prev_runkey: str, curr_runkey: str) -> list[DeltaFinding]:
        """Compare two runs; return a list of DeltaFinding entries."""
        prev_map = {
            (r["url"], r["check_name"]): r
            for r in self.get_run_findings(prev_runkey)
        }
        curr_map = {
            (r["url"], r["check_name"]): r
            for r in self.get_run_findings(curr_runkey)
        }

        delta: list[DeltaFinding] = []

        # Current run findings — new / escalated / de-escalated / persisting
        for key, curr in curr_map.items():
            url, check_name = key
            prev = prev_map.get(key)

            curr_issue = curr["status"] in ("fail", "warn")
            prev_issue = bool(prev and prev["status"] in ("fail", "warn"))

            if curr_issue and not prev_issue:
                change = "new"
            elif curr_issue and prev_issue and prev:
                cr = _SEVERITY_RANK.get(curr["severity"], 0)
                pr = _SEVERITY_RANK.get(prev["severity"], 0)
                if cr > pr:
                    change = "escalated"
                elif cr < pr:
                    change = "de_escalated"
                else:
                    change = "persisting"
            else:
                continue  # pass→pass or pass→pass — not interesting

            delta.append(
                DeltaFinding(
                    url=url,
                    business_unit=curr["business_unit"],
                    check_name=check_name,
                    check_category=curr["check_category"],
                    change=change,
                    prev_severity=prev["severity"] if prev else None,
                    curr_severity=curr["severity"],
                    prev_status=prev["status"] if prev else None,
                    curr_status=curr["status"],
                    detail=curr["detail"],
                )
            )

        # Resolved: was an issue in prev run, no longer an issue (or absent) in curr
        for key, prev in prev_map.items():
            url, check_name = key
            curr = curr_map.get(key)

            prev_issue = prev["status"] in ("fail", "warn")
            curr_issue = bool(curr and curr["status"] in ("fail", "warn"))

            if prev_issue and not curr_issue:
                delta.append(
                    DeltaFinding(
                        url=url,
                        business_unit=prev["business_unit"],
                        check_name=check_name,
                        check_category=prev["check_category"],
                        change="resolved",
                        prev_severity=prev["severity"],
                        curr_severity=curr["severity"] if curr else None,
                        prev_status=prev["status"],
                        curr_status=curr["status"] if curr else None,
                        detail=prev["detail"],
                    )
                )

        return delta

    def delta_to_splunk_event(
        self, delta: list[DeltaFinding], prev_runkey: str, curr_runkey: str
    ) -> dict:
        """Produce a single Splunk event summarising the delta between two runs."""
        by_change: dict[str, int] = {}
        for d in delta:
            by_change[d.change] = by_change.get(d.change, 0) + 1

        # Include detail for actionable changes only (new / resolved / escalated)
        detail_items = [
            {
                "url": d.url,
                "business_unit": d.business_unit,
                "check_name": d.check_name,
                "check_category": d.check_category,
                "change": d.change,
                "prev_severity": d.prev_severity,
                "curr_severity": d.curr_severity,
            }
            for d in delta
            if d.change in ("new", "resolved", "escalated")
        ]

        return {
            "time": datetime.now(timezone.utc).timestamp(),
            "sourcetype": "cyber_exposure:run_delta",
            "event": {
                "runkey": curr_runkey,
                "prev_runkey": prev_runkey,
                "new_findings": by_change.get("new", 0),
                "resolved_findings": by_change.get("resolved", 0),
                "escalated_findings": by_change.get("escalated", 0),
                "de_escalated_findings": by_change.get("de_escalated", 0),
                "persisting_findings": by_change.get("persisting", 0),
                "details": detail_items[:200],  # cap to avoid oversized events
            },
        }
