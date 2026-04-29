"""
unbanner.py — Auto-unban scheduler with exponential backoff.

Manages per-IP unban timers.  Once a ban duration elapses the IP is
automatically unblocked, a Slack notification is sent, and an audit
entry is written.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detector.blocker import Blocker
    from detector.notifier import AuditLogger
    from detector.notifier import SlackNotifier as Notifier

logger = logging.getLogger(__name__)


class UnbanScheduler:
    """
    Schedules automatic unbans using an exponential-backoff duration list.

    Config keys (all optional):
        unban_schedule  list[int]  Ban durations in seconds for successive
                                   offences.  Default: [600, 1800, 7200].
                                   When ``offense_count - 1 >= len(schedule)``
                                   the ban is considered permanent.
    """

    def __init__(
        self,
        config: dict,
        blocker: "Blocker",
        notifier: "Notifier",
        audit_logger: "AuditLogger",
    ) -> None:
        self._schedule: list[int] = config.get("unban_schedule", [600, 1800, 7200])
        self._blocker = blocker
        self._notifier = notifier
        self._audit_logger = audit_logger

        # Maps IP address -> (asyncio.Task, scheduled_unban_at_monotonic)
        self._pending: dict[str, tuple[asyncio.Task, float]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def schedule_unban(self, ip: str, offense_count: int) -> int | None:
        """
        Schedule an automatic unban for *ip*.

        Parameters
        ----------
        ip:
            The IPv4/IPv6 address to eventually unban.
        offense_count:
            How many times this IP has been banned (1-based).  Used to
            index into the backoff schedule.

        Returns
        -------
        int | None
            The ban duration in seconds, or ``None`` if the ban is
            permanent (``offense_count - 1 >= len(schedule)``).
        """
        idx = offense_count - 1

        if idx >= len(self._schedule):
            logger.info(
                "IP %s has reached offense #%d — ban is permanent (no unban scheduled).",
                ip,
                offense_count,
            )
            # Cancel any previously pending unban so it does not fire.
            await self.cancel_unban(ip)
            return None

        duration: int = self._schedule[idx]

        async with self._lock:
            # Cancel any in-flight unban task for this IP.
            if ip in self._pending:
                old_task, _ = self._pending[ip]
                if not old_task.done():
                    old_task.cancel()
                    logger.debug("Cancelled existing unban task for %s.", ip)
                del self._pending[ip]

            unban_at = time.monotonic() + duration
            task = asyncio.create_task(
                self._unban_after(ip, duration),
                name=f"unban-{ip}",
            )
            self._pending[ip] = (task, unban_at)

        logger.info(
            "Scheduled unban for %s in %d s (offense #%d, schedule index %d).",
            ip,
            duration,
            offense_count,
            idx,
        )
        return duration

    async def cancel_unban(self, ip: str) -> None:
        """
        Cancel a pending unban for *ip* (if any).

        Safe to call even when no task exists for the given IP.
        """
        async with self._lock:
            if ip not in self._pending:
                return
            task, _ = self._pending.pop(ip)
            if not task.done():
                task.cancel()
                logger.debug("Unban task for %s cancelled on request.", ip)

    def get_pending(self) -> dict[str, float]:
        """
        Return a snapshot of pending unbans.

        Returns
        -------
        dict[str, float]
            Maps each IP to the approximate number of seconds remaining
            until it is unbanned.  The value is clamped to ``0.0`` if
            the task is overdue but has not yet executed.
        """
        now = time.monotonic()
        return {
            ip: max(0.0, unban_at - now) for ip, (_, unban_at) in self._pending.items()
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _unban_after(self, ip: str, delay: float) -> None:
        """
        Wait *delay* seconds then unban *ip*, notify Slack, and write an
        audit entry.

        Designed to be wrapped in :func:`asyncio.create_task`.
        Cancellation via :meth:`cancel_unban` is handled gracefully.
        """
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            logger.debug("_unban_after for %s was cancelled during sleep.", ip)
            return

        # --- Unblock at the firewall / iptables layer ---
        try:
            await self._blocker.unban(ip)
            logger.info("Successfully unbanned %s via blocker.", ip)
        except Exception:
            logger.exception(
                "Blocker failed to unban %s; proceeding with notifications.", ip
            )

        # --- Slack notification ---
        try:
            next_duration: int | None = None
            try:
                current_idx = self._schedule.index(int(delay))
                next_idx = current_idx + 1
                if next_idx < len(self._schedule):
                    next_duration = self._schedule[next_idx]
            except (ValueError, IndexError):
                pass

            current_offense = (
                self._schedule.index(int(delay)) + 1
                if int(delay) in self._schedule
                else 0
            )
            await self._notifier.send_unban_alert(
                ip=ip,
                offense_count=current_offense,
                next_duration=next_duration,
            )
        except Exception:
            logger.exception("Failed to send unban Slack alert for %s.", ip)

        # --- Audit log ---
        try:
            await self._audit_logger.log(
                action="UNBAN",
                ip=ip,
                condition="scheduled_expiry",
                rate=0.0,
                baseline=0.0,
                duration=f"{int(delay)}s",
            )
        except Exception:
            logger.exception("Failed to write audit log entry for unban of %s.", ip)

        # --- Remove from pending ---
        async with self._lock:
            self._pending.pop(ip, None)

        logger.info("Unban cycle complete for %s.", ip)
