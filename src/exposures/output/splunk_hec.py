"""Splunk HEC (HTTP Event Collector) output writer.

Batches findings and POSTs them to Splunk HEC with async retry logic.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import aiohttp
import structlog

from ..models import Finding, RunSummary

logger = structlog.get_logger(__name__)


class SplunkHECWriter:
    """Async Splunk HEC writer with batching and retry."""

    def __init__(
        self,
        url: str,
        token: str,
        index: str,
        source: str,
        verify_tls: bool = True,
        batch_size: int = 100,
        flush_interval_s: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self._url = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._index = index
        self._source = source
        self._verify_tls = verify_tls
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._max_retries = max_retries

        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self._session: aiohttp.ClientSession | None = None
        self._flush_task: asyncio.Task | None = None
        self._closed = False

    async def __aenter__(self) -> "SplunkHECWriter":
        await self._start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def _start(self) -> None:
        connector = aiohttp.TCPConnector(ssl=self._verify_tls)
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=30),
        )
        self._flush_task = asyncio.create_task(self._periodic_flush())

    async def close(self) -> None:
        """Flush remaining events and close the session."""
        self._closed = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()
        if self._session:
            await self._session.close()
            self._session = None

    async def write(self, finding: Finding) -> None:
        """Buffer a finding for sending to Splunk. Auto-flushes when batch is full."""
        event = finding.to_splunk_event()
        event["index"] = self._index
        event["source"] = self._source
        batch_to_send: list[dict] = []
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                batch_to_send = self._buffer[:]
                self._buffer.clear()
                self._last_flush = time.monotonic()
        if batch_to_send:
            await self._send_batch(batch_to_send)

    async def write_summary(self, summary: RunSummary) -> None:
        """Send a run summary event to Splunk."""
        event = summary.to_splunk_event()
        event["index"] = self._index
        event["source"] = self._source
        await self._send_batch([event])

    async def flush(self) -> None:
        """Flush all buffered events immediately."""
        async with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.monotonic()
        await self._send_batch(batch)

    async def _periodic_flush(self) -> None:
        """Background task that flushes the buffer every flush_interval_s seconds."""
        while not self._closed:
            await asyncio.sleep(self._flush_interval_s)
            elapsed = time.monotonic() - self._last_flush
            if elapsed >= self._flush_interval_s:
                try:
                    await self.flush()
                except Exception as exc:
                    logger.warning("splunk_periodic_flush_error", error=str(exc))

    async def _send_raw(self, events: list[dict]) -> None:
        """Send pre-formed HEC event dicts (e.g. delta events) directly."""
        decorated = [{**e, "index": self._index, "source": self._source} for e in events]
        await self._send_batch(decorated)

    async def _send_batch(self, events: list[dict]) -> None:
        """POST a batch of events to Splunk HEC with exponential backoff retry."""
        if not events or not self._session:
            return

        # Splunk HEC expects newline-delimited JSON events (not a JSON array)
        payload = "\n".join(json.dumps(e) for e in events)

        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with self._session.post(self._url, data=payload) as resp:
                    if resp.status == 200:
                        logger.debug(
                            "splunk_batch_sent",
                            event_count=len(events),
                            attempt=attempt,
                        )
                        return
                    elif 400 <= resp.status < 500:
                        # Client error — don't retry
                        body = await resp.text()
                        logger.error(
                            "splunk_client_error",
                            status=resp.status,
                            body=body[:200],
                            event_count=len(events),
                        )
                        return
                    else:
                        body = await resp.text()
                        logger.warning(
                            "splunk_server_error",
                            status=resp.status,
                            body=body[:200],
                            attempt=attempt,
                        )
                        last_exc = RuntimeError(f"Splunk HTTP {resp.status}: {body[:100]}")
            except aiohttp.ClientError as exc:
                last_exc = exc
                logger.warning(
                    "splunk_connection_error",
                    error=str(exc),
                    attempt=attempt,
                )

            if attempt < self._max_retries:
                backoff = 2 ** (attempt - 1)  # 1s, 2s, 4s
                logger.info("splunk_retry_backoff", seconds=backoff, attempt=attempt)
                await asyncio.sleep(backoff)

        logger.error(
            "splunk_batch_failed_after_retries",
            event_count=len(events),
            error=str(last_exc),
        )
