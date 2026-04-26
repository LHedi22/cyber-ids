"""
CyberIDS main orchestrator.

Startup order:
  1. Logging + banner
  2. ML model auto-train/load
  3. Initialise pipeline components
  4. Start LogTailer (daemon thread)
  5. Start FastAPI dashboard (daemon thread, own asyncio loop)
  6. Enter processing loop (main thread, blocking)

Thread model:
  main thread   — consumes LogEvents from queue, runs pipeline, writes alerts
  log-tailer    — tails snort_alerts.jsonl, feeds queue
  dashboard     — uvicorn + asyncio event loop for FastAPI + WebSocket

Alert bridging:
  main thread → asyncio.run_coroutine_threadsafe(loop, queue.put) → dashboard loop
"""

import asyncio
import json
import logging
import os
import queue
import sys
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

import colorama
from colorama import Fore, Style
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
SNORT_ALERT_PATH = os.getenv("SNORT_ALERT_PATH", "/data/snort_alerts.jsonl")
ALERT_LOG_PATH = os.getenv("ALERT_LOG_PATH", "/data/alerts.jsonl")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8000"))

# ---------------------------------------------------------------------------
# Logging — configure before any imports that use logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Late imports (after logging configured)
# ---------------------------------------------------------------------------
from pipeline.aggregator import AlertAggregator
from pipeline.explainer import SHAPExplainer
from pipeline.features import FeatureExtractor
from pipeline.llm import LLMInterpreter
from pipeline.ml_detector import FEATURE_ORDER, IsolationForestDetector
from pipeline.parser import LogEvent, LogTailer
from pipeline.rule_engine import Alert, RuleEngine

# ---------------------------------------------------------------------------
# Shared state: bridge between sync main thread and async dashboard loop
# ---------------------------------------------------------------------------
_dashboard_loop:      Optional[asyncio.AbstractEventLoop] = None
_dashboard_queue:     Optional[asyncio.Queue] = None
_dashboard_log_queue: Optional[asyncio.Queue] = None


# ---------------------------------------------------------------------------
# WebSocket log handler — streams every log record to the browser terminal
# ---------------------------------------------------------------------------

class WebSocketLogHandler(logging.Handler):
    """
    Forwards formatted log records into the dashboard's asyncio event loop
    via call_soon_threadsafe + put_nowait, so it never blocks the caller.
    """

    _local = threading.local()  # guards against accidental re-entrant emit

    def __init__(self, loop: asyncio.AbstractEventLoop, log_q: asyncio.Queue) -> None:
        super().__init__()
        self._loop = loop
        self._log_q = log_q

    def _put(self, line: str) -> None:
        try:
            self._log_q.put_nowait(line)
        except asyncio.QueueFull:
            pass

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._local, "active", False):
            return
        self._local.active = True
        try:
            line = self.format(record)
            self._loop.call_soon_threadsafe(self._put, line)
        except Exception:
            pass
        finally:
            self._local.active = False


def push_to_dashboard(alert: Alert) -> None:
    """Thread-safe push of an alert into the dashboard's asyncio event loop."""
    if _dashboard_loop is None or _dashboard_queue is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(
            _dashboard_queue.put(_alert_to_dict(alert)),
            _dashboard_loop,
        )
    except Exception as exc:
        log.debug("Dashboard push failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_to_dict(alert: Alert) -> dict:
    d = asdict(alert)
    d["timestamp"] = alert.timestamp.isoformat()
    return d


def _alert_severity_color(severity: str) -> str:
    return {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH":     Fore.RED + Style.DIM,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }.get(severity, Fore.WHITE)


def _print_event_line(event: LogEvent, events_per_min: int) -> None:
    if log.isEnabledFor(logging.DEBUG):
        ts = event.timestamp.strftime("%H:%M:%S")
        print(
            f"{Style.DIM}{Fore.WHITE}[{ts}] ℹ  "
            f"{event.src_ip:<15} → {event.dst_ip}:{event.dst_port:<5} "
            f"{event.proto:<4} [events/min: {events_per_min}]"
            f"{Style.RESET_ALL}"
        )


def _print_alert_line(alert: Alert) -> None:
    ts = alert.timestamp.strftime("%H:%M:%S")
    color = _alert_severity_color(alert.severity)
    explanation = alert.llm_explanation[:80] if alert.llm_explanation else alert.rule_name
    line = (
        f"{color}[{ts}] [ALERT] {alert.severity:<8} {alert.type:<20} "
        f"{alert.src_ip:<15} \"{explanation}\""
        f"{Style.RESET_ALL}"
    )
    try:
        print(line)
    except UnicodeEncodeError:
        # Windows cp1252 console fallback — strip ANSI codes
        import re
        print(re.sub(r'\x1b\[[0-9;]*m', '', line).encode('ascii', errors='replace').decode('ascii'))


def _write_alert_atomic(alert: Alert) -> None:
    """Append alert as a JSON line; flush immediately for streaming consumers."""
    os.makedirs(os.path.dirname(ALERT_LOG_PATH) if os.path.dirname(ALERT_LOG_PATH) else ".", exist_ok=True)
    line = json.dumps(_alert_to_dict(alert)) + "\n"
    try:
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
    except OSError as exc:
        log.error("Failed to write alert log: %s", exc)


def _print_banner() -> None:
    colorama.init(autoreset=True)
    banner = r"""
  ____      _              _____ ____  ____
 / ___|   _| |__   ___ _ _|_ _||  _ \/ ___|
| |  | | | | '_ \ / _ \ '__| | | | | \___ \
| |__| |_| | |_) |  __/ |  | | | |_| |___) |
 \____\__, |_.__/ \___|_| |___||____/|____/
      |___/
"""
    print(Fore.CYAN + Style.BRIGHT + banner + Style.RESET_ALL)
    print(Fore.CYAN + "  AI-Augmented Intrusion Detection System  v1.0" + Style.RESET_ALL)
    print(Fore.CYAN + "  Hackathon Edition — CyberSkyHack" + Style.RESET_ALL)
    print()


# ---------------------------------------------------------------------------
# Dashboard thread
# ---------------------------------------------------------------------------

def _run_dashboard(
    loop: asyncio.AbstractEventLoop,
    alert_q: asyncio.Queue,
    log_q: asyncio.Queue,
    aggregator: AlertAggregator,
) -> None:
    asyncio.set_event_loop(loop)
    try:
        from dashboard.api import app, set_pipeline
        set_pipeline(aggregator, alert_q, log_q, running=True)
        import uvicorn
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=DASHBOARD_PORT,
            log_level="warning",
            loop="none",        # we supply our own loop
        )
        server = uvicorn.Server(config)
        loop.run_until_complete(server.serve())
    except ImportError as exc:
        log.warning("Dashboard not available (%s) — running pipeline only", exc)
        loop.run_forever()
    except Exception as exc:
        log.error("Dashboard crashed: %s", exc)


def _start_dashboard(aggregator: AlertAggregator) -> None:
    global _dashboard_loop, _dashboard_queue, _dashboard_log_queue
    _dashboard_loop      = asyncio.new_event_loop()
    _dashboard_queue     = asyncio.Queue(maxsize=500)
    _dashboard_log_queue = asyncio.Queue(maxsize=1000)

    thread = threading.Thread(
        target=_run_dashboard,
        args=(_dashboard_loop, _dashboard_queue, _dashboard_log_queue, aggregator),
        daemon=True,
        name="dashboard",
    )
    thread.start()
    # Brief pause to let uvicorn bind the port before printing READY
    time.sleep(1.0)


# ---------------------------------------------------------------------------
# ML alert builder
# ---------------------------------------------------------------------------

def _build_ml_alert(fv, score: float) -> Alert:
    event = fv.source_event
    severity = "CRITICAL" if score >= 0.85 else "HIGH" if score >= 0.65 else "MEDIUM"
    return Alert(
        alert_id=str(uuid.uuid4()),
        type="ML_ANOMALY",
        severity=severity,
        src_ip=fv.src_ip,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        timestamp=fv.timestamp,
        detection_source="ml",
        rule_name="isolation_forest",
        feature_vector=fv.features,
        shap_factors=[],
        llm_explanation="",
        anomaly_score=score,
    )


# ---------------------------------------------------------------------------
# Processing loop
# ---------------------------------------------------------------------------

def _process_alert(
    alert: Alert,
    fv,
    shap_explainer: SHAPExplainer,
    llm: LLMInterpreter,
    aggregator: AlertAggregator,
) -> Optional[Alert]:
    # SHAP: only for ML-detected anomalies
    if alert.detection_source == "ml":
        try:
            alert.shap_factors = shap_explainer.explain(fv.features)
        except Exception as exc:
            log.warning("SHAP explain failed: %s", exc)

    # LLM interpretation
    try:
        alert.llm_explanation = llm.interpret(alert)
    except Exception as exc:
        log.warning("LLM interpret failed: %s", exc)

    return aggregator.process(alert)


def run() -> None:
    _print_banner()

    # --- ML model ---
    log.info("Initialising ML detector...")
    detector = IsolationForestDetector()
    detector.auto_train_if_needed()

    # --- Pipeline components ---
    event_queue: queue.Queue = queue.Queue(maxsize=2000)
    feature_extractor = FeatureExtractor()
    rule_engine = RuleEngine()
    shap_explainer = SHAPExplainer(detector)
    llm = LLMInterpreter()
    aggregator = AlertAggregator()

    # --- LogTailer ---
    tailer = LogTailer(SNORT_ALERT_PATH, event_queue)
    tailer.start()
    log.info("LogTailer started on %s", SNORT_ALERT_PATH)

    # --- Dashboard ---
    _start_dashboard(aggregator)

    # Attach WebSocket log handler so every log record streams to the browser terminal
    ws_handler = WebSocketLogHandler(_dashboard_loop, _dashboard_log_queue)
    ws_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    ))
    logging.getLogger().addHandler(ws_handler)

    print(
        Fore.GREEN + Style.BRIGHT
        + f"[READY] Pipeline running. Dashboard at http://localhost:{DASHBOARD_PORT}"
        + Style.RESET_ALL
    )
    print()

    # --- Main processing loop ---
    events_per_min = 0
    events_this_minute = 0
    minute_start = time.monotonic()

    try:
        while True:
            try:
                event: LogEvent = event_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Rolling events-per-minute counter
            events_this_minute += 1
            elapsed = time.monotonic() - minute_start
            if elapsed >= 60.0:
                events_per_min = events_this_minute
                events_this_minute = 0
                minute_start = time.monotonic()

            _print_event_line(event, events_per_min)

            # Feature extraction
            try:
                fv = feature_extractor.extract(event)
            except Exception as exc:
                log.error("Feature extraction failed: %s", exc)
                continue

            # Rule engine
            alerts_to_process = []
            try:
                rule_alert = rule_engine.evaluate(fv)
                if rule_alert is not None:
                    alerts_to_process.append(rule_alert)
            except Exception as exc:
                log.error("Rule engine failed: %s", exc)

            # ML detector
            try:
                is_anomaly, score = detector.predict(fv.features)
                if is_anomaly:
                    alerts_to_process.append(_build_ml_alert(fv, score))
            except Exception as exc:
                log.error("ML predict failed: %s", exc)

            # Enrich + aggregate each alert
            for alert in alerts_to_process:
                final = _process_alert(alert, fv, shap_explainer, llm, aggregator)
                if final is not None:
                    _write_alert_atomic(final)
                    push_to_dashboard(final)
                    _print_alert_line(final)

    except KeyboardInterrupt:
        print()
        print(Fore.YELLOW + "[SHUTDOWN] Pipeline stopped." + Style.RESET_ALL)
        sys.exit(0)


if __name__ == "__main__":
    run()
