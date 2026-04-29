"""
baseline.py
-----------
Maintains a rolling, per-hour-of-day aware baseline for the per-second
request rate and error rate observed by the anomaly detector.

Design goals
~~~~~~~~~~~~
* **Recency without volatility** – The baseline uses a sliding 30-minute
  window so it adapts to traffic growth, but it isn't so short that a single
  spike immediately raises the threshold.

* **Time-of-day awareness** – Traffic patterns differ between 03:00 and
  13:00.  When enough hourly samples have accumulated, the baseline prefers
  samples from the *current hour* over the full global window.

* **Floor protection** – A configurable ``baseline_floor_rps`` prevents the
  mean from collapsing to near-zero during quiet periods, which would
  otherwise cause false positives on the first real request burst.

* **Async-safe** – All public methods are async and acquire an
  ``asyncio.Lock`` so the tracker can be shared between the ingestion
  coroutine and the dashboard handler without data races.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class BaselineTracker:
    """
    Tracks per-second request rates and error rates, maintaining a rolling
    baseline used by the anomaly-detection engine.

    Configuration keys (all read from *config* dict in ``__init__``)
    -----------------------------------------------------------------
    window_seconds              : int   – Width of the sliding detection
                                          window fed upstream (not used
                                          directly here, stored for
                                          reference by callers).
    baseline_window_minutes     : int   – How many minutes of history to
                                          keep in the global deque
                                          (default: 30).
    baseline_recalc_interval    : float – Minimum seconds between baseline
                                          recalculations (default: 60).
    min_samples_for_baseline    : int   – Minimum number of per-second
                                          samples required before the
                                          baseline is considered valid
                                          (default: 10).
    min_hourly_samples          : int   – Minimum samples in the current
                                          hour's slot before we prefer it
                                          over the global window
                                          (default: 60).
    baseline_floor_rps          : float – Minimum effective mean RPS; the
                                          computed mean is never allowed to
                                          fall below this value
                                          (default: 1.0).
    error_floor_rate            : float – Minimum effective error rate
                                          (fraction 0–1), prevents the
                                          detector from being hypersensitive
                                          to the very first errors during a
                                          quiet period (default: 0.01).
    """

    # Maximum number of recalculation history records to keep in memory.
    _MAX_RECALC_HISTORY: int = 500

    # Hard maximum for the global sample deque — 30 min × 60 s/min = 1 800.
    # We calculate the real cap from config but this is the upper bound.
    _ABSOLUTE_MAX_DEQUE: int = 60 * 60  # 1 hour safety cap

    def __init__(self, config: dict) -> None:
        # ------------------------------------------------------------------ #
        #  Configuration                                                       #
        # ------------------------------------------------------------------ #
        self._window_seconds: int = int(config.get("window_seconds", 60))
        self._baseline_window_minutes: int = int(config.get("baseline_window_minutes", 30))
        self._recalc_interval: float = float(config.get("baseline_recalc_interval", 60.0))
        self._min_samples: int = int(config.get("min_samples_for_baseline", 10))
        self._min_hourly_samples: int = int(config.get("min_hourly_samples", 60))
        self._floor_rps: float = float(config.get("baseline_floor_rps", 1.0))
        self._error_floor: float = float(config.get("error_floor_rate", 0.01))

        # Maximum number of per-second samples to keep (30 min × 60 s = 1 800)
        self._max_samples: int = min(
            self._baseline_window_minutes * 60,
            self._ABSOLUTE_MAX_DEQUE,
        )

        # ------------------------------------------------------------------ #
        #  Internal state                                                      #
        # ------------------------------------------------------------------ #

        # Global sliding window of (unix_timestamp, count_per_second) tuples.
        # Oldest entries are evicted once they age past baseline_window_minutes.
        self._global_counts: deque[Tuple[float, float]] = deque(maxlen=self._max_samples)

        # Per-hour-of-day reservoir of per-second RPS samples.
        # Key  : hour of day (0–23)
        # Value: list of float RPS values observed during that hour
        # We intentionally do NOT cap these lists so that they accumulate a
        # rich history across many days; the recalculation step uses only the
        # most recent N entries if desired (currently all of them).
        self._hourly_slots: Dict[int, List[float]] = {h: [] for h in range(24)}

        # Concurrency lock – all public async methods acquire this.
        self._lock: asyncio.Lock = asyncio.Lock()

        # Current effective baseline statistics (updated by _recalculate).
        self._effective_mean: float = self._floor_rps
        self._effective_stddev: float = max(1.0, self._floor_rps * 0.1)

        # Sliding window of (unix_timestamp, is_error: bool) tuples used to
        # compute the rolling error rate.  Same 30-min window as RPS counts.
        self._error_counts: deque[Tuple[float, bool]] = deque(maxlen=self._max_samples)
        self._effective_error_rate: float = self._error_floor

        # Unix timestamp of the last successful recalculation.
        # Initialised to 0 so the first call to maybe_recalculate always fires.
        self._last_recalc: float = 0.0

        # Audit trail of recalculation outcomes (newest last).
        self._recalc_history: List[dict] = []

        logger.info(
            "BaselineTracker initialised: window=%dm, recalc_interval=%.0fs, "
            "floor_rps=%.2f, error_floor=%.4f",
            self._baseline_window_minutes,
            self._recalc_interval,
            self._floor_rps,
            self._error_floor,
        )

    # ------------------------------------------------------------------ #
    #  Public async API                                                    #
    # ------------------------------------------------------------------ #

    async def record_second(self, count: int, error_count: int, ts: float) -> None:
        """
        Record a single per-second observation.

        Parameters
        ----------
        count       : int   – Total requests observed in the second ending at *ts*.
        error_count : int   – How many of those requests resulted in a 5xx response.
        ts          : float – Unix timestamp of the end of the second.

        Side effects
        ------------
        * Appends ``(ts, count)`` to ``_global_counts``.
        * Appends one ``(ts, bool)`` tuple per request to ``_error_counts``
          (we record at the *second* granularity: ``error_count`` errors out
          of ``count`` total are stored as a single fractional entry to keep
          memory proportional to seconds, not requests).
        * Evicts entries older than ``baseline_window_minutes`` from both deques.
        * Updates the current-hour slot in ``_hourly_slots``.
        """
        async with self._lock:
            rps = float(count)

            # -- Append to global sliding window --------------------------
            self._global_counts.append((ts, rps))

            # -- Evict expired entries (older than baseline_window_minutes) --
            # deque.maxlen already evicts from the left when full, but we
            # also want to evict by *time* so that a quiet period with few
            # samples doesn't keep stale high-traffic data artificially.
            cutoff = ts - (self._baseline_window_minutes * 60.0)
            while self._global_counts and self._global_counts[0][0] < cutoff:
                self._global_counts.popleft()

            # -- Error tracking (fractional record per second) -------------
            # Storing (ts, True) error_count times and (ts, False) for the
            # remainder gives an accurate rate but blows up memory for high
            # RPS.  Instead we store one tuple per second: (ts, error_bool)
            # where error_bool is True if there was at least one error in
            # this second.  For the rate calculation we weight by count.
            # Simpler and good enough for anomaly detection purposes.
            is_error_second = error_count > 0
            self._error_counts.append((ts, is_error_second))

            # Evict old error records
            while self._error_counts and self._error_counts[0][0] < cutoff:
                self._error_counts.popleft()

            # -- Hour-of-day slot update -----------------------------------
            hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
            self._hourly_slots[hour].append(rps)

            # Bound the per-hour list to avoid unbounded memory growth over
            # many days of operation.  We keep the most recent 7 days worth
            # of per-hour samples (7 × 60 min × 60 s = 25 200 per slot).
            max_hourly = 7 * 60 * 60
            if len(self._hourly_slots[hour]) > max_hourly:
                # Trim oldest entries – slicing creates a copy so we reassign.
                self._hourly_slots[hour] = self._hourly_slots[hour][-max_hourly:]

    async def maybe_recalculate(self, now: float) -> bool:
        """
        Recalculate the baseline if enough time has elapsed since the last
        recalculation.

        Parameters
        ----------
        now : float – Current Unix timestamp (pass ``time.time()``).

        Returns
        -------
        bool – ``True`` if a recalculation was performed, ``False`` otherwise.
        """
        async with self._lock:
            if now - self._last_recalc >= self._recalc_interval:
                self._recalculate(now)
                return True
            return False

    # ------------------------------------------------------------------ #
    #  Internal recalculation logic (called while lock is held)           #
    # ------------------------------------------------------------------ #

    def _recalculate(self, now: float) -> None:
        """
        Recompute ``_effective_mean``, ``_effective_stddev``, and
        ``_effective_error_rate`` from current sample data.

        Called from :meth:`maybe_recalculate` (lock already held).

        Algorithm
        ~~~~~~~~~
        1. **Choose the sample source.**
           - If the current hour's slot has at least ``min_hourly_samples``
             entries, use those samples (``source = "hourly"``).
           - Otherwise fall back to all per-second samples in
             ``_global_counts`` (``source = "global"``).

        2. **Compute population mean and standard deviation.**
           We use *population* std (dividing by N) rather than sample std
           (dividing by N-1) because we consider the deque to be the full
           population of interest for threshold setting, not a sample of a
           wider distribution.

        3. **Apply floors.**
           - ``effective_mean = max(computed_mean, baseline_floor_rps)``
           - If ``computed_stddev == 0`` (perfectly constant traffic or only
             one sample), set ``stddev = max(1.0, mean * 0.1)`` to avoid a
             zero-width detection band.

        4. **Error rate.**
           Computed as the fraction of per-second intervals in the last 30
           minutes that contained at least one error, then floored at
           ``error_floor_rate``.

        5. **Audit trail.**
           Appends a record to ``_recalc_history`` (capped at 500 entries).
        """
        # ------------------------------------------------------------------ #
        #  1. Sample source selection                                          #
        # ------------------------------------------------------------------ #
        current_hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
        hourly_samples = self._hourly_slots.get(current_hour, [])

        if len(hourly_samples) >= self._min_hourly_samples:
            samples = hourly_samples
            source = "hourly"
        else:
            # Fall back to the global sliding window
            samples = [count for (_ts, count) in self._global_counts]
            source = "global"

        n = len(samples)

        if n < self._min_samples:
            # Not enough data yet – keep current (initialised) values and
            # just update the recalc timestamp so we don't spin needlessly.
            logger.debug(
                "Baseline recalc skipped: only %d samples (need %d), source=%s",
                n, self._min_samples, source,
            )
            self._last_recalc = now
            return

        # ------------------------------------------------------------------ #
        #  2. Population mean and standard deviation                           #
        # ------------------------------------------------------------------ #
        mean = sum(samples) / n

        # Population variance: Σ(xᵢ - μ)² / N
        variance = sum((x - mean) ** 2 for x in samples) / n
        stddev = math.sqrt(variance)

        # ------------------------------------------------------------------ #
        #  3. Apply floors                                                     #
        # ------------------------------------------------------------------ #
        effective_mean = max(mean, self._floor_rps)

        if stddev == 0.0:
            # Perfectly constant traffic – use a small relative spread so the
            # detection band has a sensible width.
            effective_stddev = max(1.0, effective_mean * 0.1)
        else:
            effective_stddev = stddev

        # ------------------------------------------------------------------ #
        #  4. Error rate                                                       #
        # ------------------------------------------------------------------ #
        error_window = list(self._error_counts)
        if error_window:
            error_seconds = sum(1 for (_ts, is_err) in error_window if is_err)
            computed_error_rate = error_seconds / len(error_window)
        else:
            computed_error_rate = 0.0

        effective_error_rate = max(computed_error_rate, self._error_floor)

        # ------------------------------------------------------------------ #
        #  5. Commit results                                                   #
        # ------------------------------------------------------------------ #
        old_mean = self._effective_mean
        old_stddev = self._effective_stddev

        self._effective_mean = effective_mean
        self._effective_stddev = effective_stddev
        self._effective_error_rate = effective_error_rate
        self._last_recalc = now

        logger.info(
            "Baseline recalculated [%s/%dh]: n=%d, mean=%.2f (was %.2f), "
            "stddev=%.2f (was %.2f), error_rate=%.4f",
            source, current_hour, n,
            effective_mean, old_mean,
            effective_stddev, old_stddev,
            effective_error_rate,
        )

        # Audit record
        record = {
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "effective_mean": effective_mean,
            "effective_stddev": effective_stddev,
            "source": source,
        }
        self._recalc_history.append(record)

        # Trim history to the last _MAX_RECALC_HISTORY entries
        if len(self._recalc_history) > self._MAX_RECALC_HISTORY:
            self._recalc_history = self._recalc_history[-self._MAX_RECALC_HISTORY:]

    # ------------------------------------------------------------------ #
    #  Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def effective_mean(self) -> float:
        """Current effective mean request rate (requests/second)."""
        return self._effective_mean

    @property
    def effective_stddev(self) -> float:
        """Current effective standard deviation of the request rate."""
        return self._effective_stddev

    @property
    def effective_error_rate(self) -> float:
        """Current effective fraction of seconds that contained >= 1 error."""
        return self._effective_error_rate

    @property
    def recalc_history(self) -> List[dict]:
        """
        Read-only view of the recalculation audit trail (newest last).

        Each entry is a dict with keys:
            ``timestamp``       – ISO-8601 string
            ``effective_mean``  – float
            ``effective_stddev``– float
            ``source``          – ``"hourly"`` or ``"global"``
        """
        # Return a shallow copy so callers cannot mutate the internal list.
        return list(self._recalc_history)

    # ------------------------------------------------------------------ #
    #  Dashboard / diagnostic helper                                       #
    # ------------------------------------------------------------------ #

    async def get_stats(self) -> dict:
        """
        Return a snapshot of the tracker's current state as a plain dict,
        suitable for serialisation to JSON (e.g. for a status endpoint).

        Fields
        ------
        effective_mean          : float
        effective_stddev        : float
        effective_error_rate    : float
        global_sample_count     : int   – current size of the sliding window
        last_recalc_iso         : str   – ISO-8601 timestamp of last recalc
        recalc_count            : int   – total recalculations performed
        hourly_sample_counts    : dict  – {hour_str: count} for all 24 hours
        floor_rps               : float
        error_floor_rate        : float
        baseline_window_minutes : int
        recalc_interval_seconds : float
        """
        async with self._lock:
            last_recalc_iso = (
                datetime.fromtimestamp(self._last_recalc, tz=timezone.utc).isoformat()
                if self._last_recalc > 0.0
                else None
            )
            hourly_counts = {
                str(h): len(samples)
                for h, samples in self._hourly_slots.items()
            }
            return {
                "effective_mean": self._effective_mean,
                "effective_stddev": self._effective_stddev,
                "effective_error_rate": self._effective_error_rate,
                "global_sample_count": len(self._global_counts),
                "last_recalc_iso": last_recalc_iso,
                "recalc_count": len(self._recalc_history),
                "hourly_sample_counts": hourly_counts,
                "floor_rps": self._floor_rps,
                "error_floor_rate": self._error_floor,
                "baseline_window_minutes": self._baseline_window_minutes,
                "recalc_interval_seconds": self._recalc_interval,
            }
