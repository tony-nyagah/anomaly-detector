"""
main.py - Entry point for the HNG anomaly-detection daemon.

Orchestrates all async components via asyncio.gather() and runs them
concurrently as a long-lived daemon process.
"""

import asyncio
import logging
import os
import signal
import time
import yaml
from pathlib import Path
from dotenv import load_dotenv

from .monitor import tail_log, LogEntry
from .baseline import BaselineTracker
from .detector import AnomalyDetector
from .blocker import Blocker
from .unbanner import UnbanScheduler
from .notifier import SlackNotifier, AuditLogger
from .dashboard import Dashboard

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load and return the merged configuration dictionary.

    The config file path is read from the CONFIG_PATH environment variable
    (defaults to ./config.yaml).  SLACK_WEBHOOK_URL env var overrides
    config.yaml's slack.webhook_url.
    """
    load_dotenv()
    config_path = Path(os.environ.get("CONFIG_PATH", "./config.yaml"))
    with open(config_path, "r") as fh:
        config: dict = yaml.safe_load(fh)

    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        config.setdefault("slack", {})["webhook_url"] = webhook

    return config


def _setup_logging(config: dict) -> None:
    """Configure the root logger from config."""
    level_name: str = config.get("logging", {}).get("level", "INFO")
    level: int = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _get_ban_duration(offense_count: int, blocking_config: dict) -> int | None:
    """Return ban duration in seconds for a given 1-based offense count.

    Uses the unban_schedule list from blocking config:
      offense 1 -> schedule[0]  (e.g. 600 s / 10 min)
      offense 2 -> schedule[1]  (e.g. 1800 s / 30 min)
      offense 3 -> schedule[2]  (e.g. 7200 s / 2 h)
      offense 4+ -> None (permanent)

    Returns None when offense_count-1 >= len(schedule) (permanent ban).
    """
    schedule: list = blocking_config.get("unban_schedule", [600, 1800, 7200])
    idx: int = offense_count - 1
    if idx >= len(schedule):
        return None          # permanent
    return int(schedule[idx])


# ---------------------------------------------------------------------------
# Core processing loop
# ---------------------------------------------------------------------------

async def _process_loop(
    queue: asyncio.Queue,
    detector: AnomalyDetector,
    baseline: BaselineTracker,
    blocker: Blocker,
    unbanner: UnbanScheduler,
    notifier: SlackNotifier,
    audit_logger: AuditLogger,
    config: dict,
) -> None:
    """Consume log entries from the queue and act on every detected anomaly.

    Responsibilities:
    - Feed each LogEntry to the AnomalyDetector.
    - On "ip" anomaly: ban the IP, schedule unban, send Slack alert, audit log.
    - On "global" anomaly: send Slack alert, audit log.
    - Track per-second request/error counts and feed them into BaselineTracker.
    - Trigger a baseline recalculation check every 60 seconds (monotonic timer).
    """
    blocking_config: dict = config.get("blocking", {})

    # Monotonic timer for 60-second baseline recalculation check
    last_recalc_check: float = time.monotonic()

    # Per-second counter: bucket requests by integer second
    last_second: int = int(time.time())
    second_count: int = 0
    second_error_count: int = 0

    # Cooldown: skip repeat bans for the same IP within 5 seconds
    recently_banned: dict[str, float] = {}
    BAN_COOLDOWN = 5.0

    while True:
        try:
            entry: LogEntry = await queue.get()
            queue.task_done()

            # ------------------------------------------------------------------
            # Per-second counter bookkeeping
            # Flush the previous second's counts into baseline when we advance
            # ------------------------------------------------------------------
            entry_second: int = int(entry.raw_timestamp)
            if entry_second != last_second:
                await baseline.record_second(
                    second_count, second_error_count, float(last_second)
                )
                second_count = 0
                second_error_count = 0
                last_second = entry_second

            second_count += 1
            if entry.status >= 400:
                second_error_count += 1

            # ------------------------------------------------------------------
            # Anomaly detection
            # ------------------------------------------------------------------
            kind, ip = await detector.record(entry)

            if kind == "ip" and ip:
                now = time.time()
                # Skip if we just banned this IP recently (cooldown)
                if now - recently_banned.get(ip, 0) < BAN_COOLDOWN:
                    queue.task_done() if False else None  # no-op
                elif not blocker.is_banned(ip):
                    offense_count: int = blocker.get_offense_count(ip) + 1
                    duration_seconds = _get_ban_duration(offense_count, blocking_config)

                    # Compute condition description for alerts/audit
                    mean = baseline.effective_mean
                    stddev = baseline.effective_stddev
                    ip_rps = await detector.get_ip_rps(ip)
                    if stddev > 0:
                        z = (ip_rps - mean) / stddev
                        condition = f"z_score={z:.2f} rate={ip_rps:.2f}rps"
                    else:
                        condition = f"rate={ip_rps:.2f}rps (>{mean:.2f}x mean)"

                    duration_str = (
                        f"{duration_seconds}s"
                        if duration_seconds is not None
                        else "permanent"
                    )

                    banned = await blocker.ban(ip, duration_seconds)
                    if banned:
                        recently_banned[ip] = now
                        await unbanner.schedule_unban(ip, offense_count)
                        await notifier.send_ban_alert(
                            ip=ip,
                            condition=condition,
                            current_rate=ip_rps,
                            baseline_mean=mean,
                            baseline_stddev=stddev,
                            duration_seconds=duration_seconds,
                        )
                        await audit_logger.log(
                            action="BAN",
                            ip=ip,
                            condition=condition,
                            rate=ip_rps,
                            baseline=mean,
                            duration=duration_str,
                        )
                        logger.warning(
                            "Banned %s for %s (offense #%d, %s)",
                            ip, duration_str, offense_count, condition,
                        )

            elif kind == "global":
                mean = baseline.effective_mean
                stddev = baseline.effective_stddev
                global_rps = await detector.get_global_rps()
                if stddev > 0:
                    z = (global_rps - mean) / stddev
                    condition = f"global_z_score={z:.2f} rate={global_rps:.2f}rps"
                else:
                    condition = f"global_rate={global_rps:.2f}rps (>{mean:.2f}x mean)"

                await notifier.send_global_alert(
                    condition=condition,
                    current_rate=global_rps,
                    baseline_mean=mean,
                    baseline_stddev=stddev,
                )
                await audit_logger.log(
                    action="GLOBAL_ALERT",
                    ip=None,
                    condition=condition,
                    rate=global_rps,
                    baseline=mean,
                    duration="-",
                )
                logger.warning("Global anomaly: %s", condition)

            # ------------------------------------------------------------------
            # Periodic baseline recalculation (every 60 s, monotonic)
            # ------------------------------------------------------------------
            now_mono: float = time.monotonic()
            if now_mono - last_recalc_check >= 60.0:
                last_recalc_check = now_mono
                recalculated: bool = await baseline.maybe_recalculate(time.time())
                if recalculated:
                    mean = baseline.effective_mean
                    stddev = baseline.effective_stddev
                    # Pick source from most recent recalc history entry
                    history = baseline.recalc_history
                    source = history[-1]["source"] if history else "global"
                    await audit_logger.log_baseline_recalc(
                        mean=mean, stddev=stddev, source=source
                    )
                    logger.info(
                        "Baseline recalculated: mean=%.3f stddev=%.3f source=%s",
                        mean, stddev, source,
                    )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Error in process loop: %s", exc)


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

async def _shutdown(
    tasks: list,
    notifier: SlackNotifier,
    dashboard: Dashboard,
) -> None:
    """Cancel all running tasks and clean up resources."""
    logger.info("Shutting down anomaly detector daemon...")

    for task in tasks:
        if not task.done():
            task.cancel()

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception) and not isinstance(
            result, asyncio.CancelledError
        ):
            logger.error("Task raised during shutdown: %s", result)

    try:
        await notifier.stop()
    except Exception as exc:
        logger.error("Error stopping notifier: %s", exc)

    logger.info("Shutdown complete.")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Orchestrate and run the anomaly-detection daemon.

    Initialisation order:
    1. Load config + set up logging
    2. AuditLogger
    3. SlackNotifier (+ await start())
    4. BaselineTracker
    5. AnomalyDetector
    6. Blocker
    7. UnbanScheduler
    8. Dashboard

    Then launches three concurrent tasks via asyncio.gather():
    - tail_log: tails the Nginx JSON access log
    - _process_loop: processes entries and acts on anomalies
    - dashboard.start: serves the FastAPI metrics UI
    """
    config: dict = _load_config()
    _setup_logging(config)
    logger.info("HNG Anomaly Detection Daemon starting...")
    start_time: float = time.time()

    # Build components in dependency order
    audit_logger = AuditLogger(config.get("audit", {}))

    notifier = SlackNotifier(config.get("slack", {}))
    await notifier.start()

    baseline = BaselineTracker(config["detection"])
    detector_inst = AnomalyDetector(config["detection"], baseline)
    blocker = Blocker(config.get("blocking", {}))
    unbanner = UnbanScheduler(
        config.get("blocking", {}), blocker, notifier, audit_logger
    )
    dashboard = Dashboard(
        config.get("dashboard", {}),
        detector_inst,
        baseline,
        blocker,
        unbanner,
        start_time=start_time,
    )

    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    tasks: list = [
        asyncio.create_task(
            tail_log(config["nginx"]["log_path"], queue),
            name="tail_log",
        ),
        asyncio.create_task(
            _process_loop(
                queue, detector_inst, baseline, blocker,
                unbanner, notifier, audit_logger, config,
            ),
            name="process_loop",
        ),
        asyncio.create_task(
            dashboard.start(),
            name="dashboard",
        ),
    ]

    def _request_shutdown() -> None:
        logger.info("SIGTERM received — requesting graceful shutdown.")
        for t in tasks:
            if not t.done():
                t.cancel()

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, _request_shutdown)
    except (NotImplementedError, RuntimeError):
        pass  # Not available on all platforms

    try:
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Interrupt received.")
    except asyncio.CancelledError:
        logger.info("Tasks cancelled.")
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
    finally:
        await _shutdown(tasks, notifier, dashboard)


if __name__ == "__main__":
    asyncio.run(main())
