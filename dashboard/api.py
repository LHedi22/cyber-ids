"""
FastAPI dashboard backend.

Shared state is injected by main.py via set_pipeline() after import.
WebSocket fan-out: a background task drains the shared _alert_queue and
copies each message into per-client subscriber queues so all connected
browsers receive every alert, regardless of how many tabs are open.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

SNORT_ALERT_PATH = os.getenv("SNORT_ALERT_PATH", "/data/snort_alerts.jsonl")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8000"))

STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# Shared state — injected by main.py after import
# ---------------------------------------------------------------------------
_aggregator = None          # AlertAggregator instance
_alert_queue: Optional[asyncio.Queue] = None
_log_queue:   Optional[asyncio.Queue] = None
_pipeline_running: bool = False

# Per-client subscriber queues for WebSocket fan-out (alerts)
_subscribers: set[asyncio.Queue] = set()
_subscribers_lock = asyncio.Lock()

# Per-client subscriber queues for log terminal fan-out
_log_subscribers: set[asyncio.Queue] = set()
_log_subscribers_lock = asyncio.Lock()


def set_pipeline(
    aggregator,
    alert_queue: asyncio.Queue,
    log_queue: Optional[asyncio.Queue] = None,
    running: bool = True,
) -> None:
    """Called by main.py to inject live pipeline state into the API."""
    global _aggregator, _alert_queue, _log_queue, _pipeline_running
    _aggregator = aggregator
    _alert_queue = alert_queue
    _log_queue = log_queue
    _pipeline_running = running
    log.info("Dashboard pipeline state configured (running=%s)", running)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(application: FastAPI):
    asyncio.create_task(_broadcast_task(),     name="alert-broadcaster")
    asyncio.create_task(_log_broadcast_task(), name="log-broadcaster")
    yield


app = FastAPI(title="CyberIDS Dashboard", version="1.0", lifespan=_lifespan)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Background broadcast task
# ---------------------------------------------------------------------------

async def _broadcast_task() -> None:
    """Drain _alert_queue and fan-out each message to all WebSocket subscribers."""
    while True:
        if _alert_queue is None:
            await asyncio.sleep(0.1)
            continue
        try:
            message = await asyncio.wait_for(_alert_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            log.warning("Broadcast task error: %s", exc)
            continue

        # Copy to every subscriber's personal queue (drop if subscriber is slow)
        async with _subscribers_lock:
            dead = set()
            for q in _subscribers:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    log.debug("Slow WebSocket subscriber dropped message")
                except Exception:
                    dead.add(q)
            _subscribers.difference_update(dead)


async def _log_broadcast_task() -> None:
    """Drain _log_queue and fan-out each log line to all terminal WebSocket subscribers."""
    while True:
        if _log_queue is None:
            await asyncio.sleep(0.1)
            continue
        try:
            line = await asyncio.wait_for(_log_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            log.warning("Log broadcast task error: %s", exc)
            continue

        async with _log_subscribers_lock:
            dead = set()
            for q in _log_subscribers:
                try:
                    q.put_nowait(line)
                except asyncio.QueueFull:
                    pass
                except Exception:
                    dead.add(q)
            _log_subscribers.difference_update(dead)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse({"error": "Dashboard UI not yet built"}, status_code=503)


@app.get("/api/alerts")
async def get_alerts() -> JSONResponse:
    if _aggregator is None:
        return JSONResponse({"alerts": []})
    alerts = _aggregator.get_recent(50)
    return JSONResponse({"alerts": [a.to_dict() for a in alerts]})


@app.get("/api/stats")
async def get_stats() -> JSONResponse:
    if _aggregator is None:
        return JSONResponse({
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "alerts_per_minute": 0.0, "top_attacking_ips": [],
        })
    return JSONResponse(_aggregator.get_stats())


@app.get("/api/health")
async def health() -> JSONResponse:
    model_loaded = False
    ollama_ok = False
    try:
        from pipeline.ml_detector import IsolationForestDetector
        from pipeline.llm import LLMInterpreter
        # Check model file exists as a lightweight proxy for "model loaded"
        model_path = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
        model_loaded = os.path.exists(model_path)
        ollama_ok = LLMInterpreter().health_check()
    except Exception:
        pass

    return JSONResponse({
        "status": "ok",
        "pipeline": _pipeline_running,
        "ollama": ollama_ok,
        "model_loaded": model_loaded,
    })


@app.post("/api/simulate")
async def simulate_attack() -> JSONResponse:
    """
    Write multi-event attack bursts to SNORT_ALERT_PATH so sliding-window features
    accumulate to anomalous levels — triggering both rule-based and ML detection.

    Each scenario uses a dedicated attacker IP so dedup/merge logic is exercised
    independently per scenario.
    """
    def _ev(src: str, dst: str, sport: int, dport: int, proto: str,
            sid: int, msg: str, pri: int, bytes_: int,
            ts: "datetime | None" = None) -> dict:
        t = (ts or datetime.now(timezone.utc)).strftime("%Y/%m/%d-%H:%M:%S.%f")
        return {
            "timestamp": t, "src_addr": src, "dst_addr": dst,
            "src_port": sport, "dst_port": dport, "proto": proto,
            "sid": sid, "gid": 1, "rev": 1, "msg": msg,
            "priority": pri, "bytes": bytes_, "action": "alert",
        }

    if _aggregator is not None:
        _aggregator.clear()

    os.makedirs(
        os.path.dirname(SNORT_ALERT_PATH) if os.path.dirname(SNORT_ALERT_PATH) else ".",
        exist_ok=True,
    )

    # Force a known off-hours timestamp (03:00 UTC) so the rule always fires
    # regardless of when the demo is run.
    off_hours_ts = datetime.now(timezone.utc).replace(hour=3, minute=0, second=0, microsecond=0)

    # Each tuple: (label, events_factory, delay_between_events_seconds)
    # Events are created lazily inside the loop so timestamps are fresh per event.
    scenarios: list[tuple[str, list, float]] = [
        # 1. SSH Brute Force — 25 events: failed_logins_60s=25, error_rate=1.0
        #    Rule fires at event 6 (>5 threshold); ML fires on extreme outliers
        (
            "SSH Brute Force",
            [_ev("10.99.0.1", "192.168.1.5", 54001, 22, "TCP",
                 1000001, "SSH Brute Force Attempt", 1, 512)
             for _ in range(25)],
            0.05,
        ),
        # 2. Port Scan — 25 events to 25 distinct ports: unique_ports_10s=25
        #    Rule fires at event 21 (>20 threshold); ML fires on extreme unique_ports
        (
            "Port Scan",
            [_ev("10.99.0.3", "192.168.1.5", 54003, port, "TCP",
                 1000003, "Port Scan Detected", 2, 64)
             for port in range(1, 26)],
            0.02,
        ),
        # 3. SQL Injection — 3 events; rule fires on SID match (first event)
        (
            "SQL Injection",
            [_ev("10.99.0.2", "192.168.1.5", 54002, 80, "TCP",
                 1000002, "SQL Injection Attempt Detected", 2, 1024)
             for _ in range(3)],
            0.3,
        ),
        # 4. Off-Hours Access — 3 events with forced 03:00 UTC timestamp
        #    error_rate=0.0 (SID 1000004 is a successful login, not a failure)
        #    Rule fires when is_off_hours=1 AND error_rate < 0.5
        (
            "Off-Hours Access",
            [_ev("10.99.0.4", "192.168.1.5", 54004, 22, "TCP",
                 1000004, "Off-Hours Successful Login", 3, 400, off_hours_ts)
             for _ in range(3)],
            0.2,
        ),
        # 5. Data Exfiltration — 3 x 50 KB chunks: bytes_out_60s=150 000
        #    Rule fires at event 1 (50000 > threshold, port 4444 non-standard)
        #    ML fires on extreme bytes_out_60s (30× training max)
        (
            "Data Exfiltration",
            [_ev("10.99.0.5", "203.0.113.99", 54005, 4444, "TCP",
                 1000005, "Possible Data Exfiltration", 2, 50000)
             for _ in range(3)],
            0.3,
        ),
    ]

    total = 0
    try:
        for label, events, delay in scenarios:
            log.info("Simulate: starting %s (%d events)", label, len(events))
            for event in events:
                with open(SNORT_ALERT_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
                    f.flush()
                total += 1
                await asyncio.sleep(delay)
            await asyncio.sleep(0.5)  # brief inter-scenario gap
    except OSError as exc:
        log.error("Failed to write simulate events: %s", exc)
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=500)

    log.info("Simulated attack complete: %d events written to %s", total, SNORT_ALERT_PATH)
    return JSONResponse({"status": "attack sequence triggered", "count": total})


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    await websocket.accept()

    # Give this client its own subscriber queue (maxsize prevents memory blowup)
    client_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    async with _subscribers_lock:
        _subscribers.add(client_queue)

    try:
        # Send last 10 alerts immediately on connect
        if _aggregator is not None:
            recent = _aggregator.get_recent(10)
            for alert in reversed(recent):  # oldest first so client renders in order
                await websocket.send_json(alert.to_dict())

        # Stream new alerts as they arrive
        while True:
            try:
                message = await asyncio.wait_for(client_queue.get(), timeout=15.0)
                await websocket.send_json(message)
            except asyncio.TimeoutError:
                # Send a keepalive ping so the browser doesn't drop the connection
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        log.debug("WebSocket client disconnected")
    except Exception as exc:
        log.warning("WebSocket error: %s", exc)
    finally:
        async with _subscribers_lock:
            _subscribers.discard(client_queue)


@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket) -> None:
    await websocket.accept()

    client_queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    async with _log_subscribers_lock:
        _log_subscribers.add(client_queue)

    try:
        while True:
            try:
                line = await asyncio.wait_for(client_queue.get(), timeout=15.0)
                await websocket.send_text(line)
            except asyncio.TimeoutError:
                await websocket.send_text("__ping__")
    except WebSocketDisconnect:
        log.debug("Log WebSocket client disconnected")
    except Exception as exc:
        log.debug("Log WebSocket error: %s", exc)
    finally:
        async with _log_subscribers_lock:
            _log_subscribers.discard(client_queue)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from unittest.mock import MagicMock
    from fastapi.testclient import TestClient

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    # Mock aggregator
    mock_agg = MagicMock()
    mock_agg.get_recent.return_value = []
    mock_agg.get_stats.return_value = {
        "total": 0, "critical": 0, "high": 0,
        "medium": 0, "low": 0, "alerts_per_minute": 0.0,
        "top_attacking_ips": [],
    }

    set_pipeline(mock_agg, asyncio.Queue(), asyncio.Queue(), running=True)

    client = TestClient(app)

    # Test /api/health
    resp = client.get("/api/health")
    if resp.status_code != 200:
        _fail(f"/api/health returned {resp.status_code}")
    body = resp.json()
    if body.get("status") != "ok":
        _fail(f"/api/health body missing 'status': {body}")
    if "pipeline" not in body:
        _fail(f"/api/health missing 'pipeline' key: {body}")

    # Test /api/alerts
    resp = client.get("/api/alerts")
    if resp.status_code != 200:
        _fail(f"/api/alerts returned {resp.status_code}")
    body = resp.json()
    if "alerts" not in body:
        _fail(f"/api/alerts missing 'alerts' key: {body}")
    if not isinstance(body["alerts"], list):
        _fail(f"alerts should be a list, got {type(body['alerts'])}")

    # Test /api/stats
    resp = client.get("/api/stats")
    if resp.status_code != 200:
        _fail(f"/api/stats returned {resp.status_code}")
    body = resp.json()
    for key in ("total", "critical", "high", "medium", "low", "alerts_per_minute"):
        if key not in body:
            _fail(f"/api/stats missing key '{key}': {body}")

    print("PASS: api self-test")
