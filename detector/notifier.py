"""
notifier.py — Slack webhook notifications and file-based audit logging.

Classes
-------
SlackNotifier
    Sends Slack Block Kit messages (ban/unban/global anomaly alerts)
    to a configured incoming-webhook URL using aiohttp.

AuditLogger
    Appends structured audit entries to a plain-text file using aiofiles.
"""

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import time
from datetime import datetime, timezone

import aiofiles
import aiohttp

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_duration(seconds: int | None) -> str:
    """Return a human-readable duration string, or 'permanent'."""
    if seconds is None:
        return "permanent"
    minutes, secs = divmod(int(seconds), 60)
    if minutes:
        return f"{minutes}m {secs}s" if secs else f"{minutes}m"
    return f"{secs}s"


def _utc_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------


class SlackNotifier:
    """
    Sends formatted Slack Block Kit messages to a webhook URL.

    Config keys:
        webhook_url      str   Slack incoming-webhook URL.
                               Falls back to SLACK_WEBHOOK_URL env var.
        enabled          bool  Master on/off switch (default True).
        timeout_seconds  int   HTTP request timeout in seconds (default 10).
    """

    def __init__(self, config: dict) -> None:
        self._webhook_url: str = config.get(
            "webhook_url", os.environ.get("SLACK_WEBHOOK_URL", "")
        )
        self._enabled: bool = bool(config.get("enabled", True))
        self._timeout: int = int(config.get("timeout_seconds", 10))
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create the underlying aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            logger.debug("SlackNotifier: aiohttp session created.")

    async def stop(self) -> None:
        """Close the underlying aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("SlackNotifier: aiohttp session closed.")

    # ------------------------------------------------------------------
    # Public alert methods
    # ------------------------------------------------------------------

    async def send_ban_alert(
        self,
        ip: str,
        condition: str,
        current_rate: float,
        baseline_mean: float,
        baseline_stddev: float,
        duration_seconds: int | None,
    ) -> bool:
        """
        Send a 🚨 BAN notification to Slack.

        Parameters
        ----------
        ip:
            The banned IP address.
        condition:
            Human-readable trigger condition, e.g. ``z_score=4.2``.
        current_rate:
            Observed request-rate that triggered the ban (req/s).
        baseline_mean:
            Rolling baseline mean used for comparison.
        baseline_stddev:
            Rolling baseline standard deviation.
        duration_seconds:
            Ban duration in seconds, or ``None`` for a permanent ban.
        """
        duration_str = _format_duration(duration_seconds)
        bt = chr(96)  # backtick — kept out of string literals to avoid linter noise
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "\U0001f6a8 IP BANNED",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*IP Address*\n{bt}{ip}{bt}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Condition*\n{condition}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Current Rate*\n{current_rate:.2f} req/s",
                        },
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Baseline*\n"
                                f"{baseline_mean:.2f} \u00b1 {baseline_stddev:.2f} req/s"
                            ),
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Ban Duration*\n{duration_str}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Timestamp*\n{_utc_iso()}",
                        },
                    ],
                },
                {"type": "divider"},
            ]
        }
        return await self._send(payload)

    async def send_unban_alert(
        self,
        ip: str,
        offense_count: int,
        next_duration: int | None,
    ) -> bool:
        """
        Send a ✅ UNBAN notification to Slack.

        Parameters
        ----------
        ip:
            The IP address that has been unbanned.
        offense_count:
            Total number of times this IP has been banned so far.
        next_duration:
            Duration (seconds) of the *next* ban if the IP re-offends,
            or ``None`` if the next offence would result in a permanent ban.
        """
        next_str = _format_duration(next_duration)
        bt = chr(96)
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "\u2705 IP UNBANNED",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*IP Address*\n{bt}{ip}{bt}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Total Offences*\n{offense_count}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Next Ban Duration (if re-offends)*\n{next_str}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Timestamp*\n{_utc_iso()}",
                        },
                    ],
                },
                {"type": "divider"},
            ]
        }
        return await self._send(payload)

    async def send_global_alert(
        self,
        condition: str,
        current_rate: float,
        baseline_mean: float,
        baseline_stddev: float,
    ) -> bool:
        """
        Send a ⚠️ GLOBAL TRAFFIC ANOMALY notification to Slack.

        Parameters
        ----------
        condition:
            Human-readable trigger condition.
        current_rate:
            Observed aggregate request-rate (req/s).
        baseline_mean:
            Rolling baseline mean.
        baseline_stddev:
            Rolling baseline standard deviation.
        """
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "\u26a0\ufe0f GLOBAL TRAFFIC ANOMALY",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Condition*\n{condition}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Current Rate*\n{current_rate:.2f} req/s",
                        },
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Baseline*\n"
                                f"{baseline_mean:.2f} \u00b1 {baseline_stddev:.2f} req/s"
                            ),
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Timestamp*\n{_utc_iso()}",
                        },
                    ],
                },
                {"type": "divider"},
            ]
        }
        return await self._send(payload)

    # ------------------------------------------------------------------
    # Low-level HTTP send
    # ------------------------------------------------------------------

    async def _send(self, payload: dict) -> bool:
        """
        POST *payload* as JSON to the configured Slack webhook URL.

        Returns ``True`` on success, ``False`` on any error or when
        notifications are disabled.
        """
        if not self._enabled or not self._webhook_url:
            logger.debug(
                "SlackNotifier._send: notifications disabled or no webhook URL — skipping."
            )
            return False

        if self._session is None or self._session.closed:
            logger.warning(
                "SlackNotifier._send called before start(); creating ad-hoc session."
            )
            await self.start()

        try:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            async with self._session.post(  # type: ignore[union-attr]
                self._webhook_url,
                json=payload,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(
                        "Slack webhook returned HTTP %d: %s",
                        resp.status,
                        body[:200],
                    )
                    return False
                return True
        except Exception:
            logger.exception("Failed to POST Slack webhook notification.")
            return False


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """
    Appends structured audit log entries to a plain-text file.

    Config keys:
        log_path  str  Absolute path to the audit log file.
                       Parent directories are created automatically.
                       Default: /var/log/anomaly-detector/audit.log
    """

    def __init__(self, config: dict) -> None:
        self._log_path: str = config.get(
            "log_path", "/var/log/anomaly-detector/audit.log"
        )
        # Ensure parent directory exists at construction time.
        pathlib.Path(self._log_path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public write helpers
    # ------------------------------------------------------------------

    async def log(
        self,
        action: str,
        ip: str | None,
        condition: str,
        rate: float,
        baseline: float,
        duration: str,
    ) -> None:
        """
        Append a BAN / UNBAN audit line.

        Example output::

            [2024-01-15T10:30:45Z] BAN 1.2.3.4 | z_score=4.2 | rate=12.50 | baseline=2.10 | 600s
        """
        ip_str = ip if ip else "-"
        entry = (
            f"[{_utc_iso()}] {action} {ip_str} | {condition} | "
            f"rate={rate:.2f} | baseline={baseline:.2f} | {duration}\n"
        )
        await self._write(entry)

    async def log_baseline_recalc(
        self,
        mean: float,
        stddev: float,
        source: str,
    ) -> None:
        """
        Append a BASELINE_RECALC audit line.

        Example output::

            [2024-01-15T10:30:45Z] BASELINE_RECALC - | source=rolling | mean=2.1000 | stddev=0.4500 | -
        """
        entry = (
            f"[{_utc_iso()}] BASELINE_RECALC - | source={source} | "
            f"mean={mean:.4f} | stddev={stddev:.4f} | -\n"
        )
        await self._write(entry)

    # ------------------------------------------------------------------
    # Internal write helper
    # ------------------------------------------------------------------

    async def _write(self, entry: str) -> None:
        """Append *entry* to the log file, serialised by a lock."""
        async with self._write_lock:
            try:
                async with aiofiles.open(self._log_path, mode="a") as fh:
                    await fh.write(entry)
            except OSError:
                logger.exception("AuditLogger: failed to write to %s", self._log_path)
