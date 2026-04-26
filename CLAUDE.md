# CLAUDE.md — CyberIDS Project Guide

> This file guides Claude Code throughout the entire project. Read it fully before
> writing any code. Re-read the relevant section before starting each phase.

---

## Project Overview

**CyberIDS** is a cloud-native, AI-augmented Intrusion Detection System built for
the Cyber X Cloud Hackathon. It combines Snort 3 (open-source IPS) with a machine
learning anomaly detection layer and an LLM interpretation layer, deployed via
Docker Compose and Kubernetes.

**Judging criteria this project must satisfy:**
- Log analysis & parsing (15%)
- Anomaly detection — rule-based + ML (10%)
- Alert mechanism & responsiveness (10%)
- Usability & UX (10%)
- Clarity, demo & communication (15%)
- Creativity & innovation (15%)
- Attendance components (20%)

---

## Architecture (Do Not Deviate From This)

```
[Snort 3 / Log Simulator]
        ↓ writes → /data/snort_alerts.jsonl  (append-only, one JSON object per line)
[Log Parser & Normalizer]        pipeline/parser.py
        ↓
[Feature Extractor]              pipeline/features.py   ← extensibility/plugin layer
     ↓             ↓
[Rule Engine]   [Isolation Forest]
pipeline/        pipeline/
rule_engine.py   ml_detector.py
     ↓             ↓
[Alert Aggregator & Deduplicator]   pipeline/aggregator.py
        ↓
[SHAP Explainer]                    pipeline/explainer.py
        ↓
[LLM Interpreter]                   pipeline/llm.py
(Phi-3 mini via Ollama, <5B params)
        ↓
[FastAPI Backend]    dashboard/api.py
        ↓       ↓
[Web Dashboard]   [alerts.jsonl log]
dashboard/        data/alerts.jsonl
static/index.html
```

**Snort is infrastructure, not a Python module.** It runs as a separate binary/container
and writes to `/data/snort_alerts.jsonl`. The Python pipeline only reads that file.
Never import or call Snort from Python.

---

## Project Structure (Create Exactly This)

```
cyber-ids/
├── CLAUDE.md                          ← this file
├── README.md
├── .env                               ← environment config (never commit secrets)
├── .gitignore
├── requirements.txt
│
├── simulator/
│   └── log_generator.py               ← generates Snort-format JSON alerts
│
├── pipeline/
│   ├── __init__.py
│   ├── parser.py                      ← tails snort_alerts.jsonl, emits LogEvent
│   ├── features.py                    ← sliding-window feature extraction
│   ├── rule_engine.py                 ← threshold-based detection rules
│   ├── ml_detector.py                 ← Isolation Forest model
│   ├── aggregator.py                  ← dedup, merge, severity ranking
│   ├── explainer.py                   ← SHAP explainability
│   └── llm.py                         ← Ollama/Phi-3 LLM interpretation
│
├── dashboard/
│   ├── api.py                         ← FastAPI app + WebSocket
│   └── static/
│       └── index.html                 ← single-file SOC dashboard
│
├── target-app/
│   ├── app.py                         ← deliberately vulnerable Flask app
│   ├── templates/
│   │   ├── index.html
│   │   ├── login.html
│   │   └── dashboard.html
│   └── Dockerfile
│
├── snort/
│   ├── snort.lua                      ← minimal Snort 3 config
│   └── rules/
│       └── custom.rules               ← 5 custom detection rules
│
├── models/                            ← gitignored, populated at build/runtime
│   └── .gitkeep
│
├── data/                              ← gitignored, runtime volume
│   └── .gitkeep
│
├── k8s/
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── persistent-volume.yaml
│   ├── simulator-deployment.yaml
│   ├── pipeline-deployment.yaml
│   ├── dashboard-deployment.yaml
│   ├── target-app-deployment.yaml
│   ├── ollama-deployment.yaml
│   └── ingress.yaml
│
├── train.py                           ← standalone model training script
├── main.py                            ← pipeline orchestrator entry point
├── Dockerfile.pipeline
├── Dockerfile.simulator
├── Dockerfile.dashboard
├── Dockerfile.target-app
└── docker-compose.yml
```

---

## Absolute Rules (Follow These Without Exception)

1. **Every config value comes from environment variables.** No hardcoded IPs, ports,
   thresholds, or paths anywhere in the code. All env vars have sensible defaults.

2. **Every Python module has a `if __name__ == "__main__":` self-test block** that
   runs independently and prints PASS/FAIL.

3. **Graceful degradation is mandatory:**
   - If Ollama is unreachable → use a fallback explanation string, keep running
   - If `models/isolation_forest.pkl` is missing → auto-train on startup, keep running
   - If `/data/snort_alerts.jsonl` doesn't exist → wait and retry, keep running

4. **Use Python's `logging` module throughout.** No bare `print()` except in `main.py`'s
   formatted terminal output and self-test blocks.

5. **All file writes must be atomic.** Write to a `.tmp` file, then `os.replace()` to
   the final path. This prevents partial reads.

6. **Thread safety is required** everywhere shared state exists. Use `threading.Lock()`
   for the aggregator's alert deque and any shared queues.

7. **Docker images must be minimal.** Use `python:3.11-slim`, always include
   `.dockerignore`, no dev dependencies in production images.

8. **Every Kubernetes manifest must have resource requests AND limits** on every
   container. No exceptions.

9. **The dashboard WebSocket must auto-reconnect** with exponential backoff
   (1s, 2s, 4s, 8s, max 30s).

10. **Complete each phase fully before starting the next.** After each phase, verify
    the self-test blocks pass before moving on.

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama inference server URL |
| `OLLAMA_MODEL` | `phi3:mini` | Model name to use |
| `ALERT_LOG_PATH` | `/data/alerts.jsonl` | Output alert log file |
| `SNORT_ALERT_PATH` | `/data/snort_alerts.jsonl` | Snort input log file |
| `ISOLATION_FOREST_CONTAMINATION` | `0.05` | IF contamination parameter |
| `MODEL_PATH` | `models/isolation_forest.pkl` | Saved model path |
| `SLIDING_WINDOW_SECONDS` | `60` | Feature extraction window |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins before alert |
| `PORT_SCAN_THRESHOLD` | `20` | Unique ports before alert |
| `DATA_EXFIL_BYTES` | `10000` | Bytes threshold for exfil alert |
| `ALERT_DEDUP_SECONDS` | `30` | Deduplication window |
| `DASHBOARD_PORT` | `8000` | FastAPI server port |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `DEMO_MODE` | `true` | Use simulator (true) or real Snort (false) |

---

## Data Schemas (Use Exactly These)

### Snort Alert Input (one line = one JSON object in snort_alerts.jsonl)
```json
{
  "timestamp": "2026/04/25-14:32:01.123456",
  "src_addr": "192.168.1.105",
  "dst_addr": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 22,
  "proto": "TCP",
  "sid": 1000001,
  "gid": 1,
  "rev": 1,
  "msg": "SSH Brute Force Attempt",
  "priority": 1,
  "bytes": 512,
  "action": "alert"
}
```

### Internal LogEvent (pipeline/parser.py output)
```python
@dataclass
class LogEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    sid: int
    msg: str
    priority: int
    bytes: int
    raw: dict
```

### Feature Vector (pipeline/features.py output)
```python
@dataclass
class FeatureVector:
    src_ip: str
    timestamp: datetime
    features: dict  # keys defined below
    source_event: LogEvent

# Feature keys (all numeric):
# failed_logins_60s    — failed SSH/auth attempts from src_ip in window
# unique_ports_10s     — unique dst_ports hit by src_ip in 10s
# requests_per_min     — total events from src_ip per minute
# is_off_hours         — 1 if hour < 6 or hour > 22, else 0
# is_new_ip            — 1 if src_ip never seen before this session
# bytes_out_60s        — total outbound bytes from src_ip in window
# unique_dst_ips_60s   — unique destination IPs from src_ip in window
# error_rate           — ratio of failed to total events (0.0 to 1.0)
```

### Alert (pipeline/aggregator.py output)
```python
@dataclass
class Alert:
    alert_id: str          # uuid4
    type: str              # BRUTE_FORCE | PORT_SCAN | SQL_INJECTION | OFF_HOURS | DATA_EXFIL | ML_ANOMALY
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: datetime
    detection_source: str  # rule_engine | ml | both
    rule_name: str         # rule that fired, or "isolation_forest"
    feature_vector: dict   # the features dict
    shap_factors: list     # [{"feature": str, "value": float, "shap_contribution": float}]
    llm_explanation: str   # human-readable sentence from LLM
    anomaly_score: float   # IF score 0.0–1.0, or 1.0 for rule-only alerts
```

---

## Detection Rules Reference

Implement these exactly in `pipeline/rule_engine.py`:

| Rule Name | Condition | Severity |
|---|---|---|
| `BRUTE_FORCE` | `failed_logins_60s > BRUTE_FORCE_THRESHOLD` | CRITICAL |
| `PORT_SCAN` | `unique_ports_10s > PORT_SCAN_THRESHOLD` | HIGH |
| `SQL_INJECTION` | `sid == 1000002` | HIGH |
| `OFF_HOURS_ACCESS` | `is_off_hours == 1 AND error_rate < 0.5` | MEDIUM |
| `DATA_EXFIL` | `bytes_out_60s > DATA_EXFIL_BYTES AND is_new_ip == 1` | HIGH |

---

## Attack Scenarios (Simulator Must Cover All 5)

| Scenario | SID | Pattern |
|---|---|---|
| SSH Brute Force | 1000001 | 20–60 failed logins from one IP, port 22, within 60s |
| SQL Injection | 1000002 | HTTP POST to port 80/443 with SQLi payload in URI |
| Port Scan | 1000003 | One IP → 20+ different dst_ports within 10s |
| Off-Hours Access | 1000004 | Successful login between 00:00–05:00 |
| Data Exfiltration | 1000005 | Large bytes_out to new/unknown destination IP |

Between attacks, generate realistic normal traffic (successful logins,
normal HTTP GETs, DNS lookups) at a ratio of roughly 10:1 normal:attack.

---

## Target App Requirements (target-app/)

A deliberately vulnerable Flask web application called **"VaultBank"** — a fake
fintech portal. It must look realistic and professional (not like a security lab tool).

Pages required:
- `/` — landing page with login form
- `/login` — POST endpoint (vulnerable to SQLi, no rate limiting)
- `/dashboard` — account overview (requires session)
- `/transfer` — fund transfer form (vulnerable to parameter tampering)
- `/admin` — admin panel accessible with `admin:admin` credentials

Vulnerabilities to include (intentional, for demo purposes):
- SQL injection on the login form (string concatenation, no parameterization)
- No brute force protection (no login attempt limiting)
- Weak session tokens (predictable)
- No CSRF protection

The app does NOT need a real database — use a hardcoded dict of users.
Style it as a dark, professional fintech dashboard. It must look like something
worth protecting.

---

## Dashboard Design Requirements

**Aesthetic: Dark industrial SOC (Security Operations Center)**

- Background: `#0d1117`
- Font: monospace for IPs/codes, sans-serif for prose
- Severity colors: CRITICAL=`#ef4444`, HIGH=`#f97316`, MEDIUM=`#eab308`, LOW=`#22c55e`
- Detection source badges: Rule=blue, ML=purple, Both=green

Required UI elements:
1. Header — "CyberIDS" logo + live green pulse dot (pipeline status)
2. Stats row — Total / Critical / High / Medium / Alerts per minute
3. Live alert table — Time · Severity · Type · Source IP · Detection Source · Explanation
4. LLM explanation panel — shows full explanation for selected alert
5. "Simulate Attack" button — calls `POST /api/simulate`
6. WebSocket live updates — new alerts slide in at top of table
7. Auto-reconnect on disconnect

Single HTML file only. No external CDN dependencies. No framework.
Vanilla JS + CSS only.

---

## Kubernetes Resource Limits (Memory-Constrained — 5.5GB Cluster)

The deployment machine has ~7.6GB RAM total, minikube allocated 5.5GB.
These limits are non-negotiable — exceeding them will cause OOMKill:

| Service | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---|---|---|---|---|
| simulator | 100m | 200m | 64Mi | 128Mi |
| pipeline | 250m | 500m | 512Mi | 1Gi |
| dashboard | 100m | 200m | 128Mi | 256Mi |
| target-app | 100m | 200m | 128Mi | 256Mi |
| ollama | 500m | 1000m | 1Gi | 2Gi |

---

## Docker Compose Services

```
simulator    → Dockerfile.simulator  → writes /data/snort_alerts.jsonl
pipeline     → Dockerfile.pipeline   → reads snort_alerts.jsonl, writes alerts.jsonl
dashboard    → Dockerfile.dashboard  → serves UI + API on port 8000
target-app   → Dockerfile.target-app → vulnerable Flask app on port 5000
ollama       → ollama/ollama image   → LLM inference on port 11434
```

Shared volumes:
- `shared_data` → mounted by simulator + pipeline at `/data`
- `alerts_data` → mounted by pipeline + dashboard at `/data`
- `ollama_data` → mounted by ollama at `/root/.ollama`

All services on network `ids-net`.

Pipeline must `depends_on` simulator and ollama with health checks.
Ollama health check: `curl -f http://localhost:11434/api/tags`

---

## Snort 3 Configuration

Snort runs as a separate container (`snort3` official image or built from source).
It watches the `target-app` container's network interface via packet capture.

Config file `snort/snort.lua` must output alerts in `alert_json` format to
`/data/snort_alerts.jsonl`.

In `DEMO_MODE=true`, the simulator replaces Snort entirely — same output format,
same file path. The rest of the pipeline is identical either way.

---

## Phase Completion Checklist

Before marking any phase complete, verify:

- [ ] All files in the phase exist with correct paths
- [ ] `if __name__ == "__main__":` self-test passes with PASS output
- [ ] No hardcoded config values — everything from env vars
- [ ] Logging uses `logging` module, not `print()`
- [ ] Type hints on all function signatures
- [ ] Graceful error handling with try/except on all I/O operations

---

## Demo Script (For Judges)

The demo must tell this story in under 3 minutes:

1. **"Here is the target"** — open VaultBank in browser, show it looks real
2. **"Here is the threat"** — click "Simulate Attack" on dashboard
3. **"Here is detection"** — watch alerts appear in real-time on dashboard
4. **"Here is intelligence"** — point to LLM explanation column
5. **"Here is deployment"** — `kubectl get pods -n cyber-ids` shows everything running

Practice this flow. It must work first try.