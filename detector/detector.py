"""
detector.py -- Anomaly Detection Engine

Uses two sliding window deques per IP (request timestamps and error tuples)
plus one global request window to detect traffic and error-rate anomalies.
"""

import asyncio
import logging
import math
import time
from collections import defaultdict, deque

from .monitor import LogEntry
from .baseline import BaselineTracker

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects per-IP and global traffic anomalies using sliding windows and
    z-score / rate-multiplier comparisons against a rolling baseline.
    """

    def __init__(self, config: dict, baseline: BaselineTracker) -> None:
        # ------------------------------------------------------------------ #
        # Configuration -- fall back to safe defaults when keys are absent.   #
        # ------------------------------------------------------------------ #
        self._window_seconds: float = float(
            config.get("window_seconds", 60)
        )
        self._z_score_threshold: float = float(
            config.get("z_score_threshold", 3.0)
        )
        self._rate_multiplier_threshold: float = float(
            config.get("rate_multiplier_threshold", 5.0)
        )
        self._error_rate_multiplier: float = float(
            config.get("error_rate_multiplier", 3.0)
        )

        self._baseline: BaselineTracker = baseline

        # Per-IP deque of raw request timestamps (float seconds).
        self._ip_windows: defaultdict[str, deque] = defaultdict(deque)

        # Per-IP deque of (timestamp: float, is_error: bool) tuples so we can
        # track 4xx/5xx rates independently from total request rates.
        self._ip_error_windows: defaultdict[str, deque] = defaultdict(deque)

        # Single global deque of request timestamps for fleet-wide detection.
        self._global_window: deque = deque()

        # Async lock so concurrent coroutines do not corrupt window state.
        self._lock: asyncio.Lock = asyncio.Lock()

    # ---------------------------------------------------------------------- #
    # Public API                                                               #
    # ---------------------------------------------------------------------- #

    async def record(
        self, entry: LogEntry
    ) -> tuple[str | None, str | None]:
        """
        Record one log entry and return an anomaly signal.

        Returns
        -------
        ("ip",     source_ip)  -- per-IP anomaly detected
        ("global", None)       -- global traffic spike (only if no IP anomaly)
        (None,     None)       -- nothing unusual
        """
        async with self._lock:
            now: float = time.time()
            ts: float = entry.raw_timestamp
            ip: str = entry.source_ip
            cutoff: float = now - self._window_seconds

            # ---------------------------------------------------------------- #
            # 1. Append the new request to the per-IP and global windows.      #
            # ---------------------------------------------------------------- #
            self._ip_windows[ip].append(ts)
            self._global_window.append(ts)

            # ---------------------------------------------------------------- #
            # 2. If this request is an error (HTTP 4xx/5xx), record it in the  #
            #    per-IP error window as well.                                   #
            # ---------------------------------------------------------------- #
            if entry.status >= 400:
                self._ip_error_windows[ip].append((ts, True))

            # ---------------------------------------------------------------- #
            # 3. Evict stale entries from the per-IP request window.           #
            # ---------------------------------------------------------------- #
            ip_window = self._ip_windows[ip]
            while ip_window and ip_window[0] < cutoff:
                ip_window.popleft()

            # ---------------------------------------------------------------- #
            # 4. Evict stale entries from the per-IP error window.             #
            # ---------------------------------------------------------------- #
            ip_err_window = self._ip_error_windows[ip]
            while ip_err_window and ip_err_window[0][0] < cutoff:
                ip_err_window.popleft()

            # ---------------------------------------------------------------- #
            # 5. Evict stale entries from the global window.                   #
            # ---------------------------------------------------------------- #
            while self._global_window and self._global_window[0] < cutoff:
                self._global_window.popleft()

            # ---------------------------------------------------------------- #
            # 6. Compute current rates (requests per second).                  #
            # ---------------------------------------------------------------- #
            ip_rate: float = len(ip_window) / self._window_seconds
            global_rate: float = len(self._global_window) / self._window_seconds

            # ---------------------------------------------------------------- #
            # 7. Fetch baseline statistics from the BaselineTracker.           #
            # ---------------------------------------------------------------- #
            baseline_mean: float = self._baseline.effective_mean
            baseline_std: float = self._baseline.effective_stddev
            baseline_mean: float = self._baseline.effective_mean
            baseline_std: float = self._baseline.effective_stddev
            baseline_error_rate: float = self._baseline.effective_error_rate

            # ---------------------------------------------------------------- #
            # 8. Determine effective thresholds for this IP.                   #
            #    If the IP current error rate is >= error_rate_multiplier *    #
            #    the baseline error rate, we treat it as a higher-risk IP and  #
            #    lower both thresholds by 30 % to be more sensitive.           #
            # ---------------------------------------------------------------- #
            ip_error_rate: float = (
                len(ip_err_window) / self._window_seconds
            )

            error_surge: bool = (
                baseline_error_rate > 0
                and ip_error_rate >= self._error_rate_multiplier * baseline_error_rate
            )

            if error_surge:
                # Lower both thresholds by 30 % -- we are already seeing a
                # disproportionate share of errors from this IP.
                effective_z = self._z_score_threshold * 0.7
                effective_mult = self._rate_multiplier_threshold * 0.7
            else:
                effective_z = self._z_score_threshold
                effective_mult = self._rate_multiplier_threshold

            # ---------------------------------------------------------------- #
            # 9. Per-IP anomaly check.                                         #
            #                                                                  #
            #    Flag an IP anomaly when EITHER:                               #
            #      a) z-score of the IP rate exceeds the effective z           #
            #         threshold -- statistically far from its own history.     #
            #      b) IP rate > effective_mult * baseline mean -- a simpler    #
            #         multiplicative guard that fires even when std is tiny.   #
            #                                                                  #
            #    Both conditions require baseline data (mean > 0) to avoid     #
            #    false positives during the warm-up period.                    #
            # ---------------------------------------------------------------- #
            ip_anomaly: bool = False

            if baseline_mean > 0:
                # a) z-score check: how many standard deviations above normal?
                if baseline_std > 0:
                    ip_z_score = (ip_rate - baseline_mean) / baseline_std
                else:
                    # std == 0 means baseline was perfectly flat; z-score is
                    # not meaningful here -- rely on multiplier check only.
                    ip_z_score = 0.0

                ip_exceeds_z = ip_z_score >= effective_z

                # b) raw multiplier check: rate > N * baseline mean
                ip_exceeds_mult = ip_rate >= effective_mult * baseline_mean

                ip_anomaly = ip_exceeds_z or ip_exceeds_mult

                if ip_anomaly:
                    logger.warning(
                        "IP anomaly detected: ip=%s rate=%.3f rps "
                        "baseline_mean=%.3f baseline_std=%.3f "
                        "z_score=%.2f error_surge=%s",
                        ip,
                        ip_rate,
                        baseline_mean,
                        baseline_std,
                        ip_z_score if baseline_std > 0 else float("nan"),
                        error_surge,
                    )

            # ---------------------------------------------------------------- #
            # 10. Global anomaly check.                                        #
            #                                                                  #
            #     Only evaluated when NO per-IP anomaly was found, so we do   #
            #     not double-signal the same traffic burst through both         #
            #     channels.                                                     #
            # ---------------------------------------------------------------- #
            global_anomaly: bool = False

            if not ip_anomaly and baseline_mean > 0:
                if baseline_std > 0:
                    global_z_score = (
                        (global_rate - baseline_mean)
                        / baseline_std
                    )
                else:
                    global_z_score = 0.0

                global_exceeds_z = global_z_score >= self._z_score_threshold
                global_exceeds_mult = (
                    global_rate
                    >= self._rate_multiplier_threshold * baseline_mean
                )

                global_anomaly = global_exceeds_z or global_exceeds_mult

                if global_anomaly:
                    logger.warning(
                        "Global anomaly detected: rate=%.3f rps "
                        "baseline_mean=%.3f baseline_std=%.3f z_score=%.2f",
                        global_rate,
                        baseline_mean,
                        baseline_std,
                        global_z_score if baseline_std > 0 else float("nan"),
                    )

            # ---------------------------------------------------------------- #
            # 11. Dominant-source escalation.                                  #
            #                                                                  #
            #     If a global anomaly fired but no IP anomaly fired, check    #
            #     whether one IP accounts for >= 60% of the global window.    #
            #     If so, the "distributed" attack is actually a single-source  #
            #     flood — escalate to an IP anomaly so the attacker gets       #
            #     banned rather than just alerting.                             #
            # ---------------------------------------------------------------- #
            if global_anomaly and not ip_anomaly:
                global_count = len(self._global_window)
                if global_count > 0:
                    ip_count_in_window = len(ip_window)
                    dominance = ip_count_in_window / global_count
                    if dominance >= 0.60:
                        logger.warning(
                            "Dominant-source escalation: ip=%s accounts for "
                            "%.0f%% of global traffic — reclassifying as IP anomaly.",
                            ip, dominance * 100,
                        )
                        return ("ip", ip)

            # ---------------------------------------------------------------- #
            # 12. Return the appropriate anomaly signal.                       #
            # ---------------------------------------------------------------- #
            if ip_anomaly:
                return ("ip", ip)
            if global_anomaly:
                return ("global", None)
            return (None, None)

    async def get_top_ips(self, n: int = 10) -> list[tuple[str, float]]:
        """
        Return the top *n* IPs ranked by current request rate (req/s) inside
        the sliding window, as a list of (ip, rps) tuples, highest first.
        """
        async with self._lock:
            now: float = time.time()
            cutoff: float = now - self._window_seconds

            rates: list[tuple[str, float]] = []
            for ip, window in self._ip_windows.items():
                # Evict stale entries inline so the rate is always fresh.
                while window and window[0] < cutoff:
                    window.popleft()
                if window:
                    rps = len(window) / self._window_seconds
                    rates.append((ip, rps))

            # Sort descending by rate and slice to the top-n.
            rates.sort(key=lambda x: x[1], reverse=True)
            return rates[:n]

    async def get_ip_rps(self, ip: str) -> float:
        """Return the current request rate (req/s) for a specific IP."""
        async with self._lock:
            now: float = time.time()
            cutoff: float = now - self._window_seconds
            window = self._ip_windows.get(ip)
            if not window:
                return 0.0
            while window and window[0] < cutoff:
                window.popleft()
            return len(window) / self._window_seconds

    async def get_global_rps(self) -> float:
        """Return the current global request rate in requests per second."""
        async with self._lock:
            now: float = time.time()
            cutoff: float = now - self._window_seconds

            # Evict stale entries before measuring.
            while self._global_window and self._global_window[0] < cutoff:
                self._global_window.popleft()

            return len(self._global_window) / self._window_seconds

    async def get_stats(self) -> dict:
        """
        Return a snapshot of detector statistics suitable for a dashboard.

        Fields
        ------
        global_rps          : float  -- current global request rate
        active_ip_count     : int    -- IPs with traffic inside the window
        top_ips             : list   -- [(ip, rps), ...] top-10 by rate
        window_seconds      : float  -- configured sliding-window width
        z_score_threshold   : float  -- configured z-score threshold
        rate_mult_threshold : float  -- configured rate multiplier threshold
        error_rate_mult     : float  -- configured error-rate multiplier
        """
        async with self._lock:
            now: float = time.time()
            cutoff: float = now - self._window_seconds

            # ---- refresh and measure the global window --------------------
            while self._global_window and self._global_window[0] < cutoff:
                self._global_window.popleft()
            global_rps = len(self._global_window) / self._window_seconds

            # ---- refresh and collect per-IP rates ------------------------
            ip_rates: list[tuple[str, float]] = []
            for ip, window in self._ip_windows.items():
                while window and window[0] < cutoff:
                    window.popleft()
                if window:
                    ip_rates.append((ip, len(window) / self._window_seconds))

            ip_rates.sort(key=lambda x: x[1], reverse=True)

            return {
                "global_rps": round(global_rps, 4),
                "active_ip_count": len(ip_rates),
                "top_ips": ip_rates[:10],
                "window_seconds": self._window_seconds,
                "z_score_threshold": self._z_score_threshold,
                "rate_mult_threshold": self._rate_multiplier_threshold,
                "error_rate_mult": self._error_rate_multiplier,
            }
