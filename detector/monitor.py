"""
monitor.py
----------
Tails an Nginx JSON access log and pushes parsed LogEntry objects into a
shared asyncio.Queue for downstream consumers (anomaly detector, dashboard,
etc.).

Expected JSON log format (one object per line):
    {
        "time_local": "10/Jun/2025:12:34:56 +0000",
        "remote_addr": "1.2.3.4",
        "real_ip":     "1.2.3.4",          # optional X-Real-IP header
        "request":     "GET /path HTTP/1.1",
        "status":      "200",
        "body_bytes_sent": "512"
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import aiofiles

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# How long (seconds) to sleep between polls when no new data is available.
_POLL_INTERVAL: float = 0.1

# Nginx default time_local format  e.g. "10/Jun/2025:12:34:56 +0000"
_NGINX_TIME_FORMAT: str = "%d/%b/%Y:%H:%M:%S %z"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    """
    Immutable representation of a single parsed Nginx access-log line.

    Attributes
    ----------
    source_ip      : str   — Client IP (after fallback chain).
    timestamp      : str   — Raw timestamp string from the log.
    method         : str   — HTTP method (GET, POST, …).
    path           : str   — Request path (without query string).
    status         : int   — HTTP status code.
    response_size  : int   — Response body size in bytes.
    raw_timestamp  : float — Unix epoch derived from `timestamp`.
    """

    source_ip: str
    timestamp: str
    method: str
    path: str
    status: int
    response_size: int
    raw_timestamp: float  # Unix epoch, derived from the log timestamp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_ip(entry: dict) -> str:
    """
    Return the best available client IP from a parsed JSON log entry.

    Priority:
      1. ``remote_addr`` / ``source_ip``  — non-empty and not ``"-"``
      2. ``real_ip``                       — non-empty and not ``"-"``
      3. ``"unknown"``                     — final fallback
    """
    for field in ("remote_addr", "source_ip", "real_ip"):
        value = entry.get(field, "").strip()
        if value and value != "-":
            return value
    return "unknown"


def _parse_timestamp(ts_str: str) -> float:
    """
    Convert an Nginx ``time_local`` string to a Unix epoch float.

    Falls back to ``time.time()`` if the string cannot be parsed so that a
    single malformed timestamp never drops an otherwise-valid log line.
    """
    try:
        dt = datetime.strptime(ts_str, _NGINX_TIME_FORMAT)
        return dt.timestamp()
    except (ValueError, TypeError):
        pass

    # Second attempt: RFC-2822-style (handles some edge cases)
    try:
        dt = parsedate_to_datetime(ts_str)
        return dt.timestamp()
    except Exception:
        pass

    logger.debug("Could not parse timestamp %r – using current time", ts_str)
    return time.time()


def _parse_request(request_str: str) -> tuple[str, str]:
    """
    Split an Nginx ``$request`` value (e.g. ``"GET /index.html HTTP/1.1"``)
    into (method, path).  Returns ("UNKNOWN", "/") on failure.
    """
    parts = request_str.split(" ", 2)
    if len(parts) >= 2:
        method = parts[0].upper()
        # Keep only the path component, discard query string for cardinality
        raw_path = parts[1]
        path = raw_path.split("?", 1)[0] if "?" in raw_path else raw_path
        return method, path
    return "UNKNOWN", "/"


def _parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single JSON log line into a :class:`LogEntry`.

    Returns ``None`` on any parse error so the caller can skip bad lines.
    """
    line = line.strip()
    if not line:
        return None

    try:
        entry = json.loads(line)
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse error (offset %d): %s | raw=%r", exc.pos, exc.msg, line[:200])
        return None

    # --- IP resolution (with fallback chain) --------------------------------
    source_ip = _resolve_ip(entry)

    # --- Timestamp ----------------------------------------------------------
    timestamp_str = entry.get("time_local") or entry.get("time") or entry.get("timestamp") or ""
    raw_timestamp = _parse_timestamp(timestamp_str) if timestamp_str else time.time()

    # --- HTTP request line --------------------------------------------------
    request_str = entry.get("request", "")
    method, path = _parse_request(request_str)

    # --- Status code --------------------------------------------------------
    try:
        status = int(entry.get("status", 0))
    except (ValueError, TypeError):
        status = 0

    # --- Response size ------------------------------------------------------
    try:
        response_size = int(entry.get("body_bytes_sent") or entry.get("bytes_sent") or 0)
    except (ValueError, TypeError):
        response_size = 0

    return LogEntry(
        source_ip=source_ip,
        timestamp=timestamp_str,
        method=method,
        path=path,
        status=status,
        response_size=response_size,
        raw_timestamp=raw_timestamp,
    )


# ---------------------------------------------------------------------------
# Core tail coroutine
# ---------------------------------------------------------------------------

async def tail_log(log_path: str, queue: asyncio.Queue) -> None:
    """
    Continuously tail *log_path*, parse each new line as a JSON log entry,
    and put the resulting :class:`LogEntry` onto *queue*.

    Behaviour
    ---------
    * Seeks to **end-of-file** on first open so we only process *new* traffic.
    * Polls every :data:`_POLL_INTERVAL` seconds when no data is available.
    * Handles **file rotation**: if the path disappears (``FileNotFoundError``)
      or the inode changes (Nginx rotated the log), we wait briefly and
      re-open.

    Parameters
    ----------
    log_path : str
        Absolute (or relative) path to the Nginx JSON access log.
    queue : asyncio.Queue
        Destination queue; receives :class:`LogEntry` objects.
    """
    logger.info("Starting log tail: %s", log_path)

    # Track the inode so we can detect rotation even when the filename stays
    # the same (e.g. copytruncate rotation).
    current_inode: Optional[int] = None
    file_handle = None

    while True:
        # ------------------------------------------------------------------
        # (Re-)open the file
        # ------------------------------------------------------------------
        try:
            stat = os.stat(log_path)
            new_inode = stat.st_ino
        except FileNotFoundError:
            if file_handle is not None:
                logger.warning("Log file disappeared: %s – waiting for recreation", log_path)
                await file_handle.close()
                file_handle = None
                current_inode = None
            await asyncio.sleep(1.0)
            continue

        # Detect rotation: inode changed while we had a handle open
        if current_inode is not None and new_inode != current_inode:
            logger.info("Log rotation detected (inode %d -> %d): %s", current_inode, new_inode, log_path)
            if file_handle is not None:
                await file_handle.close()
                file_handle = None
            current_inode = None

        if file_handle is None:
            try:
                file_handle = await aiofiles.open(log_path, mode="r", encoding="utf-8", errors="replace")
                # On first open, seek to EOF so we don't replay historical log lines.
                await file_handle.seek(0, os.SEEK_END)
                current_inode = new_inode
                logger.info("Opened log file (inode=%d): %s", current_inode, log_path)
            except OSError as exc:
                logger.error("Cannot open log file %s: %s", log_path, exc)
                await asyncio.sleep(1.0)
                continue

        # ------------------------------------------------------------------
        # Read available lines
        # ------------------------------------------------------------------
        try:
            lines_read = 0
            async for raw_line in file_handle:
                entry = _parse_line(raw_line)
                if entry is not None:
                    await queue.put(entry)
                lines_read += 1

            if lines_read == 0:
                # No new data; yield control and poll again shortly.
                await asyncio.sleep(_POLL_INTERVAL)
            # If we did read lines, loop immediately to check for more.

        except OSError as exc:
            # Handle unexpected I/O errors gracefully (e.g. NFS hiccups).
            logger.error("I/O error while reading %s: %s – will reopen", log_path, exc)
            try:
                await file_handle.close()
            except Exception:
                pass
            file_handle = None
            current_inode = None
            await asyncio.sleep(1.0)
