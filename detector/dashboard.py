"""
dashboard.py -- FastAPI + HTMX live metrics dashboard for the anomaly detector.

Serves a fully self-contained dark-theme HTML page that polls /metrics every
3 seconds via HTMX and replaces the main content area with freshly-rendered
card fragments.  All HTML, CSS, and the inline Jinja2 page template are
defined here -- no separate template files are required.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import psutil
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Template

if TYPE_CHECKING:
    from detector.detector import AnomalyDetector
    from detector.baseline import BaselineTracker
    from detector.blocker import Blocker
    from detector.unbanner import UnbanScheduler


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_uptime(total_seconds: float) -> str:
    """Convert a duration in seconds to a compact Xd XXh XXm XXs string."""
    sec = int(total_seconds)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s   = divmod(rem, 60)
    parts: list[str] = []
    if d:
        parts.append(f"{d}d")
    parts.append(f"{h:02d}h")
    parts.append(f"{m:02d}m")
    parts.append(f"{s:02d}s")
    return " ".join(parts)


def _fmt_bytes(n: float) -> str:
    """Format a byte count as a human-readable string, e.g. 3.2 GB."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _pbar_class(pct: float) -> str:
    """Return a CSS fill-class for a progress bar based on usage %."""
    if pct >= 90.0:
        return "pbar-crit"
    if pct >= 70.0:
        return "pbar-warn"
    return "pbar-ok"


# ---------------------------------------------------------------------------
# Inline Jinja2 full-page template  (no separate template file)
# ---------------------------------------------------------------------------
# jinja2.Template() uses autoescape=False by default, so {{ inner_html }}
# outputs raw HTML without entity-escaping -- exactly what we need here.

_PAGE_TEMPLATE = Template(
    """\
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
  <title>HNG Anomaly Detector - Live Metrics</title>
  <script src=\"https://unpkg.com/htmx.org@2.0.3\"></script>
  <style>
    /* -- CSS custom properties ----------------------------------------- */
    :root {
      --bg-page  : #0d1117;
      --bg-card  : #161b22;
      --border   : #30363d;
      --accent   : #58a6ff;
      --fg       : #e6edf3;
      --muted    : #8b949e;
      --green    : #3fb950;
      --red      : #f85149;
      --yellow   : #d29922;
      --radius   : 8px;
      --gap      : 16px;
    }

    /* -- Reset ---------------------------------------------------------- */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background : var(--bg-page);
      color      : var(--fg);
      font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\",
                   Helvetica, Arial, sans-serif;
      font-size  : 14px;
      line-height: 1.5;
      min-height : 100vh;
    }

    /* -- Header --------------------------------------------------------- */
    header {
      background     : var(--bg-card);
      border-bottom  : 1px solid var(--border);
      padding        : 14px 24px;
      display        : flex;
      align-items    : center;
      justify-content: space-between;
      flex-wrap      : wrap;
      gap            : 10px;
      position       : sticky;
      top            : 0;
      z-index        : 99;
    }
    header h1 {
      font-size     : 18px;
      font-weight   : 700;
      color         : var(--accent);
      letter-spacing: 0.02em;
    }
    .hdr-right {
      display    : flex;
      gap        : 20px;
      align-items: center;
      color      : var(--muted);
      font-size  : 13px;
    }
    .hdr-right strong { color: var(--fg); }

    /* -- HTMX loading indicator ----------------------------------------- */
    .htmx-indicator {
      opacity   : 0;
      transition: opacity 0.25s;
      color     : var(--accent);
      font-size : 12px;
    }
    .htmx-request .htmx-indicator { opacity: 1; }
    @keyframes blink-anim {
      0%, 100% { opacity: 1;   }
      50%      { opacity: 0.2; }
    }
    .blink-dot {
      display        : inline-block;
      width          : 7px;
      height         : 7px;
      background     : var(--accent);
      border-radius  : 50%;
      animation      : blink-anim 1.1s ease-in-out infinite;
      vertical-align : middle;
      margin-right   : 4px;
    }

    /* -- Main wrapper ---------------------------------------------------- */
    main {
      max-width: 1440px;
      margin   : 0 auto;
      padding  : 24px var(--gap);
    }

    /* -- Card grid ------------------------------------------------------- */
    .grid {
      display              : grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap                  : var(--gap);
      align-items          : start;
    }

    /* -- Card ------------------------------------------------------------ */
    .card {
      background   : var(--bg-card);
      border       : 1px solid var(--border);
      border-radius: var(--radius);
      padding      : 18px 20px;
    }
    .card-title {
      font-size     : 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color         : var(--muted);
      font-weight   : 700;
      padding-bottom: 10px;
      margin-bottom : 14px;
      border-bottom : 1px solid var(--border);
    }

    /* -- Big metric number ----------------------------------------------- */
    .big-num {
      font-size           : 52px;
      font-weight         : 800;
      line-height         : 1;
      margin              : 6px 0 4px;
      font-variant-numeric: tabular-nums;
      color               : var(--accent);
    }
    .big-num-red  { color: var(--red);    }
    .big-num-warn { color: var(--yellow); }
    .sub-label {
      color    : var(--muted);
      font-size: 12px;
    }

    /* -- Badges ---------------------------------------------------------- */
    .badge {
      display      : inline-flex;
      align-items  : center;
      gap          : 5px;
      padding      : 3px 11px;
      border-radius: 20px;
      font-size    : 12px;
      font-weight  : 600;
    }
    .badge-green  { background: rgba(63,185,80,.15);  color: var(--green);  border: 1px solid rgba(63,185,80,.35);  }
    .badge-red    { background: rgba(248,81,73,.15);  color: var(--red);    border: 1px solid rgba(248,81,73,.35);  }
    .badge-yellow { background: rgba(210,153,34,.15); color: var(--yellow); border: 1px solid rgba(210,153,34,.35); }

    /* -- Key-value pairs ------------------------------------------------- */
    .kv-row {
      display        : flex;
      justify-content: space-between;
      align-items    : baseline;
      padding        : 6px 0;
      border-bottom  : 1px solid rgba(48,54,61,.55);
    }
    .kv-row:last-child { border-bottom: none; }
    .kv-key    { color: var(--muted); font-size: 13px; }
    .kv-val    { color: var(--fg);    font-weight: 600; font-size: 13px; }
    .kv-accent { color: var(--accent); }
    .kv-red    { color: var(--red);    }
    .kv-green  { color: var(--green);  }
    .kv-yellow { color: var(--yellow); }

    /* -- Table ----------------------------------------------------------- */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    thead th {
      color        : var(--muted);
      text-align   : left;
      padding      : 4px 6px 10px 0;
      font-weight  : 500;
      border-bottom: 1px solid var(--border);
    }
    tbody td {
      padding        : 8px 6px 8px 0;
      border-bottom  : 1px solid rgba(48,54,61,.4);
      vertical-align : middle;
    }
    tbody tr:last-child td { border-bottom: none; }
    .mono {
      font-family: \"SFMono-Regular\", Consolas, \"Liberation Mono\", Menlo, monospace;
      font-size  : 12px;
    }
    .td-banned { color: var(--red);   }
    .td-active { color: var(--green); }

    /* -- Progress bars --------------------------------------------------- */
    .pbar-track {
      background   : rgba(48,54,61,.9);
      border-radius: 4px;
      height       : 7px;
      overflow     : hidden;
      margin-top   : 7px;
    }
    .pbar-fill {
      height       : 100%;
      border-radius: 4px;
      transition   : width .5s ease, background-color .5s ease;
    }
    .pbar-ok   { background: var(--accent); }
    .pbar-warn { background: var(--yellow); }
    .pbar-crit { background: var(--red);    }

    /* -- Resource rows --------------------------------------------------- */
    .res-row { margin-bottom: 16px; }
    .res-row:last-child { margin-bottom: 0; }
    .res-header {
      display        : flex;
      justify-content: space-between;
      align-items    : baseline;
    }
    .res-label { color: var(--muted); font-size: 12px; }
    .res-value { font-weight: 700; font-size: 15px; }

    /* -- Banned IP list -------------------------------------------------- */
    .banned-big {
      font-size  : 52px;
      font-weight: 800;
      color      : var(--red);
      line-height: 1;
      margin     : 6px 0 10px;
    }
    .banned-list {
      border-top : 1px solid var(--border);
      margin-top : 12px;
      padding-top: 4px;
    }
    .banned-entry {
      display      : flex;
      align-items  : center;
      gap          : 8px;
      padding      : 7px 0;
      border-bottom: 1px solid rgba(48,54,61,.4);
      font-size    : 12px;
    }
    .banned-entry:last-child { border-bottom: none; }
    .ban-ip    { color: var(--red);    font-family: monospace; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .ban-cnt   { color: var(--muted);  white-space: nowrap; }
    .ban-timer { color: var(--yellow); white-space: nowrap; }
    .ban-perm  { color: var(--red);    white-space: nowrap; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }

    /* -- Status row ------------------------------------------------------ */
    .status-row { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }

    /* -- Empty state ----------------------------------------------------- */
    .empty { color: var(--muted); font-size: 12px; text-align: center; padding: 16px 0; }
  </style>
</head>
<body>
  <header>
    <h1>&#x1F6E1; HNG Anomaly Detector &#x2014; Live Metrics</h1>
    <div class=\"hdr-right\">
      <span>Uptime: <strong>{{ uptime }}</strong></span>
      <span>UTC: <strong>{{ utc_now }}</strong></span>
      <span class=\"htmx-indicator\">
        <span class=\"blink-dot\"></span>refreshing&hellip;
      </span>
    </div>
  </header>

  <main
    hx-get=\"/metrics\"
    hx-trigger=\"every 3s\"
    hx-swap=\"innerHTML\"
    hx-indicator=\"header .htmx-indicator\"
  >
    {{ inner_html }}
  </main>
</body>
</html>
"""
)


# ---------------------------------------------------------------------------
# Per-card rendering functions
# ---------------------------------------------------------------------------

def _card_status(uptime_secs: float, active_ip_count: int, banned_count: int) -> str:
    """Card 1 -- system status, uptime, and high-level IP counts."""
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">System Status</div>"
        "<div class=\"status-row\">"
        "<span class=\"badge badge-green\">&#x1F7E2; ACTIVE</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Uptime</span>"
        f"<span class=\"kv-val\">{_fmt_uptime(uptime_secs)}</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Active IPs (window)</span>"
        f"<span class=\"kv-val\">{active_ip_count}</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Currently Banned</span>"
        f"<span class=\"kv-val kv-red\">{banned_count}</span>"
        "</div>"
        "</div>"
    )


def _card_traffic(global_rps: float, eff_mean: float, eff_std: float) -> str:
    """Card 2 -- current global request rate vs baseline mean/stddev."""
    if eff_std > 0 and global_rps > eff_mean + 2 * eff_std:
        num_extra = " big-num-red"
    elif eff_std > 0 and global_rps > eff_mean + eff_std:
        num_extra = " big-num-warn"
    else:
        num_extra = ""
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">Global Traffic</div>"
        f"<div class=\"big-num{num_extra}\">{global_rps:.2f}</div>"
        "<div class=\"sub-label\">requests / second</div>"
        "<div style=\"margin-top:18px\">"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Baseline Mean</span>"
        f"<span class=\"kv-val kv-accent\">{eff_mean:.3f} req/s</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Baseline &#x3C3; (stddev)</span>"
        f"<span class=\"kv-val\">{eff_std:.3f} req/s</span>"
        "</div>"
        "</div>"
        "</div>"
    )


def _card_banned(
    banned_ips: dict[str, dict],
    pending_unbans: dict[str, float],
) -> str:
    """Card 3 -- banned IP count with per-entry offense count and countdown."""
    banned_count = len(banned_ips)
    if banned_ips:
        row_parts: list[str] = []
        for ip, info in sorted(banned_ips.items()):
            offenses  = info.get("offense_count", 1)
            duration  = info.get("duration")      # None means permanent
            remaining = pending_unbans.get(ip)    # None means no pending task
            if remaining is not None:
                timer_html = f"<span class=\"ban-timer\">&#x23F1; {_fmt_uptime(remaining)}</span>"
            elif duration is None:
                timer_html = "<span class=\"ban-perm\">permanent</span>"
            else:
                timer_html = "<span class=\"ban-cnt\">&#x2014;</span>"
            plural = "s" if offenses != 1 else ""
            row_parts.append(
                f"<div class=\"banned-entry\">"
                f"<span class=\"ban-ip mono\">{ip}</span>"
                f"<span class=\"ban-cnt\">#{offenses} offense{plural}</span>"
                f"{timer_html}"
                f"</div>"
            )
        list_html = "\n".join(row_parts)
    else:
        list_html = "<div class=\"empty\">No IPs currently banned</div>"
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">Banned IPs</div>"
        f"<div class=\"banned-big\">{banned_count}</div>"
        "<div class=\"sub-label\">active bans</div>"
        f"<div class=\"banned-list\">{list_html}</div>"
        "</div>"
    )


def _card_top_ips(
    top_ips: list[tuple[str, float]],
    banned_ips: dict[str, dict],
) -> str:
    """Card 4 -- top-10 IPs ranked by current request rate."""
    if top_ips:
        row_parts: list[str] = []
        for ip, rps in top_ips[:10]:
            if ip in banned_ips:
                status_cell = "<span class=\"td-banned\">&#x25CF; Banned</span>"
            else:
                status_cell = "<span class=\"td-active\">&#x25CF; Active</span>"
            row_parts.append(
                f"<tr>"
                f"<td class=\"mono\">{ip}</td>"
                f"<td>{rps:.3f}</td>"
                f"<td>{status_cell}</td>"
                f"</tr>"
            )
        tbody = "\n".join(row_parts)
    else:
        tbody = "<tr><td colspan=\"3\" class=\"empty\">No traffic recorded yet</td></tr>"
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">Top 10 IPs by Traffic</div>"
        "<table>"
        "<thead><tr>"
        "<th>IP Address</th>"
        "<th>req/s</th>"
        "<th>Status</th>"
        "</tr></thead>"
        f"<tbody>{tbody}</tbody>"
        "</table>"
        "</div>"
    )


def _card_resources(cpu_pct: float, mem: "psutil.svmem") -> str:
    """Card 5 -- CPU and memory usage with animated progress bars."""
    mem_pct   = mem.percent
    mem_used  = float(mem.used)
    mem_total = float(mem.total)
    cpu_w     = min(max(cpu_pct, 0.0), 100.0)
    mem_w     = min(max(mem_pct, 0.0), 100.0)
    cpu_cls   = _pbar_class(cpu_pct)
    mem_cls   = _pbar_class(mem_pct)
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">System Resources</div>"
        # CPU row
        "<div class=\"res-row\">"
        "<div class=\"res-header\">"
        "<span class=\"res-label\">CPU Usage</span>"
        f"<span class=\"res-value\" style=\"color:var(--accent)\">{cpu_pct:.1f}%</span>"
        "</div>"
        f"<div class=\"pbar-track\"><div class=\"pbar-fill {cpu_cls}\" style=\"width:{cpu_w:.1f}%\"></div></div>"
        "</div>"
        # Memory row
        "<div class=\"res-row\">"
        "<div class=\"res-header\">"
        "<span class=\"res-label\">Memory Usage</span>"
        f"<span class=\"res-value\" style=\"color:var(--green)\">{mem_pct:.1f}%</span>"
        "</div>"
        f"<div class=\"pbar-track\"><div class=\"pbar-fill {mem_cls}\" style=\"width:{mem_w:.1f}%\"></div></div>"
        f"<div class=\"sub-label\" style=\"margin-top:6px\">{_fmt_bytes(mem_used)} used of {_fmt_bytes(mem_total)}</div>"
        "</div>"
        "</div>"
    )


def _card_baseline(base_stats: dict) -> str:
    """Card 6 -- baseline tracker statistics."""
    eff_mean    = base_stats.get("effective_mean", 0.0)
    eff_std     = base_stats.get("effective_stddev", 0.0)
    interval    = base_stats.get("recalc_interval_seconds", 60.0)
    last_recalc = base_stats.get("last_recalc_iso") or "&#x2014;"
    win_min     = base_stats.get("baseline_window_minutes", 0)
    samples     = base_stats.get("global_sample_count", 0)
    recalc_cnt  = base_stats.get("recalc_count", 0)
    return (
        "<div class=\"card\">"
        "<div class=\"card-title\">Baseline Statistics</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Effective Mean</span>"
        f"<span class=\"kv-val kv-accent\">{eff_mean:.4f} req/s</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Effective Stddev</span>"
        f"<span class=\"kv-val\">{eff_std:.4f} req/s</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Recalc Interval</span>"
        f"<span class=\"kv-val\">{interval:.0f} s</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Last Recalculation</span>"
        f"<span class=\"kv-val mono\" style=\"font-size:11px\">{last_recalc}</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Window Size</span>"
        f"<span class=\"kv-val\">{win_min} min</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Samples in Window</span>"
        f"<span class=\"kv-val\">{samples}</span>"
        "</div>"
        "<div class=\"kv-row\">"
        "<span class=\"kv-key\">Total Recalculations</span>"
        f"<span class=\"kv-val\">{recalc_cnt}</span>"
        "</div>"
        "</div>"
    )


# ---------------------------------------------------------------------------
# Fragment assembly
# ---------------------------------------------------------------------------

def _render_cards(
    det_stats     : dict,
    base_stats    : dict,
    banned_ips    : dict[str, dict],
    pending_unbans: dict[str, float],
    cpu_pct       : float,
    mem           : "psutil.svmem",
    uptime_secs   : float,
) -> str:
    """
    Assemble all six dashboard cards into a single <div class="grid"> HTML
    fragment that HTMX swaps into <main> on every polling cycle.
    """
    global_rps      = det_stats.get("global_rps", 0.0)
    active_ip_count = det_stats.get("active_ip_count", 0)
    top_ips: list[tuple[str, float]] = det_stats.get("top_ips", [])
    eff_mean   = base_stats.get("effective_mean", 0.0)
    eff_std    = base_stats.get("effective_stddev", 0.0)
    banned_count = len(banned_ips)

    cards = "".join([
        _card_status(uptime_secs, active_ip_count, banned_count),
        _card_traffic(global_rps, eff_mean, eff_std),
        _card_banned(banned_ips, pending_unbans),
        _card_top_ips(top_ips, banned_ips),
        _card_resources(cpu_pct, mem),
        _card_baseline(base_stats),
    ])
    return f"<div class=\"grid\">{cards}</div>"


# ---------------------------------------------------------------------------
# Dashboard class
# ---------------------------------------------------------------------------

class Dashboard:
    """
    FastAPI + HTMX live metrics dashboard.

    Parameters
    ----------
    config:
        The ``dashboard`` section of the application config dict.
        Expected keys: ``host`` (str, default ``"0.0.0.0"``) and
        ``port`` (int, default ``8080``).
    detector:
        Running :class:`~detector.detector.AnomalyDetector` instance.
    baseline:
        Running :class:`~detector.baseline.BaselineTracker` instance.
    blocker:
        Running :class:`~detector.blocker.Blocker` instance.
    unbanner:
        Running :class:`~detector.unbanner.UnbanScheduler` instance.
    start_time:
        ``time.time()`` timestamp recorded when the daemon started,
        used to compute the displayed uptime.
    """

    def __init__(
        self,
        config    : dict,
        detector  : "AnomalyDetector",
        baseline  : "BaselineTracker",
        blocker   : "Blocker",
        unbanner  : "UnbanScheduler",
        start_time: float,
    ) -> None:
        self._config     = config
        self._detector   = detector
        self._baseline   = baseline
        self._blocker    = blocker
        self._unbanner   = unbanner
        self._start_time = start_time

        self._host: str = str(config.get("host", "0.0.0.0"))
        self._port: int = int(config.get("port", 8080))

        self._app: FastAPI = FastAPI(
            title    ="HNG Anomaly Detector Dashboard",
            docs_url =None,
            redoc_url=None,
        )
        self._server    : Optional[uvicorn.Server] = None
        self._serve_task: Optional[asyncio.Task]   = None

        self._register_routes()

    # -----------------------------------------------------------------------
    # Route registration
    # -----------------------------------------------------------------------

    def _register_routes(self) -> None:
        """Attach GET / and GET /metrics routes to the FastAPI application."""
        app = self._app

        @app.get("/", response_class=HTMLResponse)
        async def index() -> HTMLResponse:
            return await self._render_full_page()

        @app.get("/metrics", response_class=HTMLResponse)
        async def metrics() -> HTMLResponse:
            fragment = await self._gather_and_render()
            return HTMLResponse(content=fragment)

    # -----------------------------------------------------------------------
    # Internal render helpers
    # -----------------------------------------------------------------------

    async def _gather_and_render(self) -> str:
        """
        Fetch stats from all subsystems concurrently, then build the HTML
        cards fragment returned by the /metrics polling endpoint.

        Strategy
        --------
        * The detector and baseline ``get_stats()`` coroutines are awaited
          together via :func:`asyncio.gather` (true concurrency).
        * The blocker and unbanner return plain in-memory dict copies
          (no I/O), so they are called synchronously without blocking.
        * ``psutil`` functions may briefly block; they are run in the
          default thread-pool executor so the event loop stays responsive.
        """
        loop = asyncio.get_running_loop()

        # Concurrent async stats from the detector and baseline tracker.
        det_stats, base_stats = await asyncio.gather(
            self._detector.get_stats(),
            self._baseline.get_stats(),
        )

        # Synchronous in-memory snapshots -- safe to call on the event loop.
        banned_ips     = self._blocker.get_banned_ips()
        pending_unbans = self._unbanner.get_pending()

        # Offload potentially blocking psutil calls to a thread executor.
        cpu_pct, mem = await asyncio.gather(
            loop.run_in_executor(None, psutil.cpu_percent, None),
            loop.run_in_executor(None, psutil.virtual_memory),
        )

        uptime_secs = time.time() - self._start_time

        return _render_cards(
            det_stats      = det_stats,
            base_stats     = base_stats,
            banned_ips     = banned_ips,
            pending_unbans = pending_unbans,
            cpu_pct        = cpu_pct,
            mem            = mem,
            uptime_secs    = uptime_secs,
        )

    async def _render_full_page(self) -> HTMLResponse:
        """
        Render the complete HTML page by embedding the current metrics
        fragment inside the inline Jinja2 page template.
        """
        uptime_secs = time.time() - self._start_time
        utc_now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        inner_html  = await self._gather_and_render()

        html = _PAGE_TEMPLATE.render(
            uptime    =_fmt_uptime(uptime_secs),
            utc_now   =utc_now,
            inner_html=inner_html,
        )
        return HTMLResponse(content=html)

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """
        Start the uvicorn HTTP server and await it.

        This coroutine blocks until the server exits.  Callers should
        wrap it in :func:`asyncio.create_task` so the dashboard runs
        concurrently with the rest of the daemon::

            task = asyncio.create_task(dashboard.start())
            ...
            await dashboard.stop()
            await task
        """
        uv_config = uvicorn.Config(
            app       =self._app,
            host      =self._host,
            port      =self._port,
            log_level ="warning",
            access_log=False,
        )
        self._server     = uvicorn.Server(uv_config)
        self._serve_task = asyncio.ensure_future(self._server.serve())
        await self._serve_task

    async def stop(self) -> None:
        """
        Gracefully shut down the dashboard HTTP server.

        Sets the uvicorn ``should_exit`` flag, then waits up to 5 s for
        the server task to finish cleanly before cancelling it forcefully.
        """
        if self._server is not None:
            self._server.should_exit = True

        if self._serve_task is not None and not self._serve_task.done():
            try:
                await asyncio.wait_for(self._serve_task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._serve_task.cancel()
