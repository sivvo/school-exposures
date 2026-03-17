"""NDJSON local file output writer.

Writes one JSON line per finding to {output_dir}/{runkey}.ndjson.
Writes a summary JSON file at end of run.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from ..models import Finding, RunSummary

logger = structlog.get_logger(__name__)


class NDJSONWriter:
    """Async NDJSON file writer for findings."""

    def __init__(self, output_dir: str | Path, runkey: str) -> None:
        self._output_dir = Path(output_dir)
        self._runkey = runkey
        self._findings_path = self._output_dir / f"{runkey}.ndjson"
        self._summary_path = self._output_dir / f"{runkey}_summary.json"
        self._file: Any = None
        self._count = 0

    async def __aenter__(self) -> "NDJSONWriter":
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._file = await aiofiles.open(self._findings_path, mode="w", encoding="utf-8")
        logger.info("ndjson_writer_opened", path=str(self._findings_path))
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def write(self, finding: Finding) -> None:
        """Write a single finding as a JSON line."""
        if self._file is None:
            raise RuntimeError("NDJSONWriter is not open — use as async context manager")
        line = json.dumps(finding.model_dump(mode="json")) + "\n"
        await self._file.write(line)
        self._count += 1

    async def write_raw(self, event: dict) -> None:
        """Write a pre-formed event dict (e.g. delta event) as a JSON line."""
        if self._file is None:
            raise RuntimeError("NDJSONWriter is not open")
        await self._file.write(json.dumps(event) + "\n")

    async def write_summary(self, summary: RunSummary) -> None:
        """Write the run summary to a separate JSON file."""
        summary_data = summary.model_dump(mode="json")
        async with aiofiles.open(self._summary_path, mode="w", encoding="utf-8") as f:
            await f.write(json.dumps(summary_data, indent=2))
        logger.info(
            "ndjson_summary_written",
            path=str(self._summary_path),
            total_findings=self._count,
        )

    async def close(self) -> None:
        """Flush and close the NDJSON file."""
        if self._file is not None:
            await self._file.flush()
            await self._file.close()
            self._file = None
            logger.info(
                "ndjson_writer_closed",
                path=str(self._findings_path),
                findings_written=self._count,
            )

    @property
    def findings_path(self) -> Path:
        return self._findings_path

    @property
    def summary_path(self) -> Path:
        return self._summary_path
