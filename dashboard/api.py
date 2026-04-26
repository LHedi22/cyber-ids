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
_pipeline_running: bool = False

# Per-client subscriber queues for WebSocket fan-out
_subscribers: set[asyncio.Queue] = set()
_subscribers_lock = asyncio.Lock()


def set_pipeline(aggregator, alert_queue: asyncio.Queue, running: bool = True) -> None:
    """Called by main.py to inject live pipeline state into the API."""
    global _aggregator, _alert_queue, _pipeline_running
    _aggregator = aggregator
    _alert_queue = alert_queue
    _pipeline_running = running
    log.info("Dashboard pipeline state configured (running=%s)", running)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(application: FastAPI):
    asyncio.create_task(_broadcast_task(), name="alert-broadcaster")
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
    Write one event for each of the 5 attack SIDs directly to SNORT_ALERT_PATH.
    The LogTailer picks them up and feeds them through the pipeline automatically.
    """
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d-%H:%M:%S.%f")

    attack_events = [
        # SSH Brute Force
        {"timestamp": ts, "src_addr": "10.99.0.1", "dst_addr": "192.168.1.5",
         "src_port": 54001, "dst_port": 22, "proto": "TCP", "sid": 1000001,
         "gid": 1, "rev": 1, "msg": "SSH Brute Force Attempt", "priority": 1,
         "bytes": 512, "action": "alert"},
        # SQL Injection
        {"timestamp": ts, "src_addr": "10.99.0.2", "dst_addr": "192.168.1.5",
         "src_port": 54002, "dst_port": 80, "proto": "TCP", "sid": 1000002,
         "gid": 1, "rev": 1, "msg": "SQL Injection Attempt Detected", "priority": 2,
         "bytes": 1024, "action": "alert"},
        # Port Scan
        {"timestamp": ts, "src_addr": "10.99.0.3", "dst_addr": "192.168.1.5",
         "src_port": 54003, "dst_port": 443, "proto": "TCP", "sid": 1000003,
         "gid": 1, "rev": 1, "msg": "Port Scan Detected", "priority": 2,
         "bytes": 64, "action": "alert"},
        # Off-Hours Access
        {"timestamp": ts, "src_addr": "10.99.0.4", "dst_addr": "192.168.1.5",
         "src_port": 54004, "dst_port": 22, "proto": "TCP", "sid": 1000004,
         "gid": 1, "rev": 1, "msg": "Off-Hours Successful Login", "priority": 3,
         "bytes": 400, "action": "alert"},
        # Data Exfiltration
        {"timestamp": ts, "src_addr": "10.99.0.5", "dst_addr": "203.0.113.99",
         "src_port": 54005, "dst_port": 4444, "proto": "TCP", "sid": 1000005,
         "gid": 1, "rev": 1, "msg": "Possible Data Exfiltration", "priority": 2,
         "bytes": 50000, "action": "alert"},
    ]

    os.makedirs(
        os.path.dirname(SNORT_ALERT_PATH) if os.path.dirname(SNORT_ALERT_PATH) else ".",
        exist_ok=True,
    )
    try:
        with open(SNORT_ALERT_PATH, "a", encoding="utf-8") as f:
            for event in attack_events:
                f.write(json.dumps(event) + "\n")
            f.flush()
        log.info("Simulated attack: wrote %d events to %s", len(attack_events), SNORT_ALERT_PATH)
        return JSONResponse({"status": "attack sequence triggered", "count": len(attack_events)})
    except OSError as exc:
        log.error("Failed to write simulate events: %s", exc)
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=500)


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

    set_pipeline(mock_agg, asyncio.Queue(), running=True)

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
