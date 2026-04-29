# HNG Anomaly Detector — Real-Time DDoS & Anomaly Detection Engine

> **Live Dashboard:** `https://<your-dashboard-subdomain>` (updated before grading)  
> **Server IP:** `<your-server-ip>` (updated before grading)  
> **GitHub Repo:** `https://github.com/<your-username>/anomaly-detector` (public)  
> **Blog Post:** `<link-to-blog-post>` (updated after writing)

---

## Why Python?

Python was chosen for its ecosystem richness (`asyncio`, `aiofiles`, `aiohttp`, `FastAPI`) and the speed of development it enables for a complex async daemon. The `asyncio` event loop lets all components — log tailer, detector, unbanner, dashboard server — run concurrently in a single process without threads. `uv` is used as the package manager for speed and reproducibility.

---

## Architecture

```
                ┌─────────────────────────────────────────────────────┐
                │                 Docker Host (VPS)                   │
                │                                                     │
                │   ┌──────────┐    HNG-nginx-logs volume             │
                │   │  Client  │──▶ ┌────────┐ ─writes─▶ /var/log/  │
                │   └──────────┘    │  Nginx │           nginx/      │
                │                   └────────┘           hng-access  │
                │                       │                .log        │
                │                       ▼                    │       │
                │                 ┌───────────┐              │       │
                │                 │ Nextcloud │              │       │
                │                 └───────────┘              │       │
                │                                            │       │
                │   ┌────────────────────────────────────────┘       │
                │   │           reads (read-only)                     │
                │   ▼                                                 │
                │  ┌─────────────────────────────────────────────┐   │
                │  │            Anomaly Detector Daemon           │   │
                │  │                                              │   │
                │  │  monitor.py ──▶ queue ──▶ detector.py        │   │
                │  │                              │               │   │
                │  │                    ┌─────────┴────────┐      │   │
                │  │                    ▼                  ▼      │   │
                │  │              blocker.py          notifier.py │   │
                │  │              (iptables)          (Slack)     │   │
                │  │                    │                         │   │
                │  │              unbanner.py                     │   │
                │  │              (backoff)                       │   │
                │  │                                              │   │
                │  │  baseline.py ◀── per-second counts           │   │
                │  │                                              │   │
                │  │  dashboard.py ──▶ :8080 (FastAPI + HTMX)    │   │
                │  └─────────────────────────────────────────────┘   │
                └─────────────────────────────────────────────────────┘
```

---

## How the Sliding Window Works

Each incoming request from `monitor.py` gets recorded in two `collections.deque` structures inside `detector.py`:

1. **Per-IP window** (`_ip_windows[ip]`): a deque of Unix timestamps, one per request from that IP.
2. **Global window** (`_global_window`): a deque of Unix timestamps for every request, regardless of IP.

**Eviction logic:** On every call to `record()`, we compute a `cutoff = now - window_seconds` (60 seconds). We then call `popleft()` on each deque as long as the oldest entry is older than the cutoff:

```python
while window and window[0] < cutoff:
    window.popleft()
```

Since timestamps are appended in chronological order, this is O(k) where k is the number of expired entries — not O(n). The current rate is simply `len(window) / window_seconds`.

**No rate-limiting libraries.** No `slowapi`, no `time.rate`, no per-minute buckets. Pure deques.

---

## How the Baseline Works

**Window size:** 30 minutes of per-second samples (up to 1800 data points in `_global_counts`).

**Recalculation interval:** Every 60 seconds, `maybe_recalculate()` fires `_recalculate()`.

**Per-hour slots:** `_hourly_slots[hour]` accumulates per-second RPS values for each of the 24 hours of the day. This lets the system learn that midnight traffic is lighter than noon traffic.

**Source selection logic:**
- If the current hour's slot has ≥ `min_hourly_samples` (60) data points, use the hourly data as the baseline source. This reflects current-hour traffic patterns.
- Otherwise, fall back to the full 30-minute rolling window.

**Floor values:** 
- `baseline_floor_rps = 1.0` — the effective mean can never drop below 1.0 req/s. This prevents the z-score from firing on the first request of the day.
- `error_floor_rate = 0.05` — the baseline error rate never drops below 5%. Prevents division-by-near-zero in error surge calculations.

**Zero stddev:** If all samples are identical (stddev = 0), we set `stddev = max(1.0, mean * 0.1)` to avoid a degenerate z-score.

---

## Detection Logic

Given a current IP rate `r`, baseline mean `μ`, and stddev `σ`:

```
z_score = (r - μ) / σ
```

An anomaly fires if **either**:
- `z_score > 3.0` (more than 3 standard deviations above normal), OR
- `r > 5.0 × μ` (raw rate is 5× the baseline mean)

**Error surge tightening:** If an IP's current 4xx/5xx rate is ≥ 3× the baseline error rate, we tighten both thresholds by 30% (`threshold × 0.7`) for that IP specifically. This catches slow-burn attacks that stay under the normal rate threshold but generate lots of errors.

**Global vs. Per-IP:** Per-IP anomaly takes priority. If an IP fires, no global alert is sent for the same event. Global anomalies (everyone spiking at once) send a Slack alert but do not trigger iptables blocks.

---

## Setup Instructions (Fresh VPS → Running Stack)

### 1. Provision a VPS

- Minimum: **2 vCPU, 2 GB RAM**, Ubuntu 22.04 LTS
- Open ports: `80` (HTTP), `8080` (dashboard), `22` (SSH)

### 2. Install Docker & Docker Compose

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker compose version  # verify
```

### 3. Clone the repo

```bash
git clone https://github.com/<your-username>/anomaly-detector.git
cd anomaly-detector
```

### 4. Configure environment

```bash
cp .env.example .env
nano .env  # Fill in all values
```

Required values in `.env`:
- `MYSQL_ROOT_PASSWORD` — MariaDB root password
- `MYSQL_PASSWORD` — Nextcloud DB password
- `NEXTCLOUD_ADMIN_PASSWORD` — Nextcloud admin password
- `SERVER_IP` — Your VPS public IP
- `SLACK_WEBHOOK_URL` — From Slack app > Incoming Webhooks

### 5. Configure Slack webhook

1. Go to https://api.slack.com/apps → Create New App → From scratch
2. Enable "Incoming Webhooks"
3. Add to a workspace, copy the webhook URL
4. Paste into `.env` as `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`

### 6. (Optional) Edit thresholds

```bash
nano detector/config.yaml
```

### 7. Start the stack

```bash
docker compose up -d
docker compose logs -f detector  # watch the daemon
```

### 8. Set up dashboard domain/subdomain

Point a subdomain (e.g., `metrics.yourdomain.com`) to your VPS IP and optionally add nginx reverse proxy for port 8080, or access directly via `http://your-server-ip:8080`.

### 9. Verify everything

```bash
# Check all containers are healthy
docker compose ps

# Watch anomaly detector logs
docker compose logs -f detector

# Test detection manually (from another machine)
ab -n 500 -c 100 http://your-server-ip/  # Apache Bench

# Check iptables
sudo iptables -L INPUT -n
```

---

## Repository Structure

```
anomaly-detector/
├── detector/
│   ├── __init__.py          # Package init
│   ├── __main__.py          # python -m detector entry point
│   ├── main.py              # Orchestrator — asyncio.gather of all components
│   ├── monitor.py           # Async log tailer — reads Nginx JSON lines → queue
│   ├── baseline.py          # Rolling 30-min baseline (mean + stddev, per-hour slots)
│   ├── detector.py          # Sliding window anomaly detection
│   ├── blocker.py           # iptables DROP rule management
│   ├── unbanner.py          # Auto-unban with backoff schedule
│   ├── notifier.py          # Slack webhook alerts + structured audit logger
│   ├── dashboard.py         # FastAPI + HTMX live metrics UI (:8080)
│   ├── config.yaml          # All thresholds — no hardcoded values
│   ├── pyproject.toml       # uv project definition
│   ├── requirements.txt     # pip-compatible dependency list
│   └── Dockerfile           # Container build
├── nginx/
│   └── nginx.conf           # Reverse proxy config with JSON logging
├── docs/
│   └── architecture.png     # System architecture diagram
├── screenshots/             # Required grading screenshots
├── docker-compose.yml       # Full stack orchestration
├── .env.example             # Environment variable template
├── TASK.md                  # Original task brief
└── README.md                # This file
```

---

## Blog Post

> Link: `<link-to-blog-post>` *(will be published and linked before submission)*

---

## Submission

- **Submission link:** https://forms.gle/cVBE8dkw6BCV8REo9
- **Deadline:** 29th April 2026, 11:59 PM WAT
