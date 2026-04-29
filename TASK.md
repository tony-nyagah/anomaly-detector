# HNG DevOps Stage 3 — Anomaly Detection / DDoS Detection Engine

## Deadline
**April 30, 2026 — 1:59 AM**

## Submission
- Submission link: https://forms.gle/cVBE8dkw6BCV8REo9
- Submission deadline: **29th April, 11:59 PM WAT**
- Points: 100 | Pass Mark: 70

---

## Task Overview

Build an anomaly detection engine that watches all incoming HTTP traffic in real time,
learns what "normal" looks like, and automatically responds when something deviates —
whether from a single aggressive IP or a global traffic spike.

### Pre-built Nextcloud image (DO NOT modify):
`kefaslungu/hng-nextcloud` — https://hub.docker.com/r/kefaslungu/hng-nextcloud

---

## Infrastructure Requirements

- [ ] Linux VPS (min 2 vCPU, 2 GB RAM) — AWS, GCP, DigitalOcean, Linode, Vultr, Hetzner, etc.
- [ ] Deploy Nextcloud stack using Docker Compose
- [ ] Nginx as reverse proxy in front of Nextcloud with JSON access logs enabled
- [ ] Nginx logs shared via named Docker volume: **`HNG-nginx-logs`**
  - Nginx writes to it; Nextcloud and detector mount it read-only
- [ ] Nginx trusts and forwards real client IP via `X-Forwarded-For`
- [ ] Access logs in JSON format at `/var/log/nginx/hng-access.log`
  - Required fields: `source_ip`, `timestamp`, `method`, `path`, `status`, `response_size`

---

## Daemon Requirements

Language: **Python** (with `uv` for dependency management)
Architecture: async, continuously running daemon — NOT a cron job or one-shot script

### Modules

| File           | Responsibility                                              |
|----------------|-------------------------------------------------------------|
| `main.py`      | Entry point, orchestrates all async components              |
| `monitor.py`   | Tail & parse Nginx JSON access log line by line             |
| `baseline.py`  | Rolling 30-min baseline (mean + stddev), per-hour slots     |
| `detector.py`  | Anomaly detection — z-score, rate multiplier, error surge   |
| `blocker.py`   | iptables DROP rule management                               |
| `unbanner.py`  | Auto-unban with backoff schedule                            |
| `notifier.py`  | Slack webhook alerts                                        |
| `dashboard.py` | FastAPI + HTMX live metrics web UI                          |
| `config.yaml`  | All thresholds and configuration                            |

---

## Detection Logic

### Sliding Window
- Two deque-based windows over last **60 seconds**: one per-IP, one global
- No rate-limiting libraries allowed

### Rolling Baseline
- Compute mean + stddev from rolling **30-minute window** of per-second counts
- Recalculate every **60 seconds**
- Maintain per-hour slots (24 slots)
- Prefer current hour's baseline when it has enough data

### Anomaly Flags
- Z-score > **3.0**, OR
- Rate > **5× baseline mean**
- (whichever fires first)

### Error Surge
- If IP's 4xx/5xx rate is **3× baseline error rate** → tighten detection thresholds

---

## Response Actions

### Blocking
- Per-IP anomaly → `iptables DROP` rule + Slack alert **within 10 seconds**
- Global anomaly → Slack alert only

### Auto-Unban Schedule (backoff)
1. 10 minutes
2. 30 minutes
3. 2 hours
4. Permanent (4th offense)

Send Slack notification on **every unban**.

---

## Slack Alerts

Store webhook URL in `config.yaml`. Each alert must include:
- Condition that fired
- Current rate
- Baseline (mean/stddev)
- Timestamp
- Ban duration (where applicable)

---

## Live Metrics Dashboard

- Refresh every **≤ 3 seconds**
- Must be served at a **domain or subdomain** (this is what gets submitted)
- Show:
  - [ ] Banned IPs
  - [ ] Global req/s
  - [ ] Top 10 source IPs
  - [ ] CPU / memory usage
  - [ ] Effective mean / stddev
  - [ ] Uptime

---

## Audit Log

Write structured entries for every ban, unban, baseline recalculation:

```
[timestamp] ACTION ip | condition | rate | baseline | duration
```

---

## Repository Structure

```
detector/
  main.py
  monitor.py
  baseline.py
  detector.py
  blocker.py
  unbanner.py
  notifier.py
  dashboard.py
  config.yaml
  requirements.txt
  pyproject.toml        ← uv project file
nginx/
  nginx.conf
docs/
  architecture.png
screenshots/
  tool-running.png
  ban-slack.png
  unban-slack.png
  global-alert-slack.png
  iptables-banned.png
  audit-log.png
  baseline-graph.png
README.md
TASK.md
docker-compose.yml
```

---

## Required Screenshots

| File                    | What it shows                                          |
|-------------------------|--------------------------------------------------------|
| `tool-running.png`      | Daemon running, processing log lines                   |
| `ban-slack.png`         | Slack ban notification                                 |
| `unban-slack.png`       | Slack unban notification                               |
| `global-alert-slack.png`| Slack global anomaly notification                      |
| `iptables-banned.png`   | `sudo iptables -L -n` showing a blocked IP             |
| `audit-log.png`         | Structured log with ban/unban/baseline recalc events   |
| `baseline-graph.png`    | Baseline over time — at least 2 hourly slots visible   |

---

## README Checklist

- [ ] Server IP and metrics dashboard URL (live during grading)
- [ ] Language choice and why
- [ ] Sliding window explanation (deque structure + eviction logic)
- [ ] Baseline explanation (window size, recalculation interval, floor values)
- [ ] Setup instructions (fresh VPS → fully running stack)
- [ ] GitHub repo link (public)
- [ ] Blog post link

---

## Blog Post

Platform: Hashnode, Dev.to, Medium, or personal site.

Must cover:
- What the project does and why it matters
- How the sliding window works
- How the baseline learns from traffic
- How the detection logic makes a decision
- How iptables blocks an IP

Write it for someone who has never worked on security tooling.

---

## Rules

### DO:
- Build your own detection logic
- Keep all thresholds in `config.yaml`
- Test before submitting
- Comment baseline and detection code

### DON'T:
- ❌ Use Fail2Ban (instant disqualification)
- ❌ Use rate-limiting libraries (slowapi, golang.org/x/time/rate, etc.)
- ❌ Fake sliding window with a per-minute counter
- ❌ Hardcode `effective_mean`
- ❌ Disable login or upload endpoints
- ❌ Use any language other than Python or Go
