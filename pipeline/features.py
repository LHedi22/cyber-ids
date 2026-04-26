"""
Feature extractor: sliding-window computation over LogEvent streams.

Extensibility guide — adding a new feature:
  1. Add a key to the FEATURE_KEYS tuple below (documents the contract).
  2. In _compute_features(), read from `window` (the 60s deque for src_ip)
     or `window_10s` (the 10s deque) and compute your value.
  3. Assign it to features[YOUR_KEY] before the return.
  4. Update any downstream consumers (rule_engine, explainer) that need it.
  No other files need changing.
"""

import logging
import os
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Deque

from dotenv import load_dotenv

from pipeline.parser import LogEvent

load_dotenv()

log = logging.getLogger(__name__)

SLIDING_WINDOW_SECONDS = int(os.getenv("SLIDING_WINDOW_SECONDS", "60"))
SHORT_WINDOW_SECONDS = 10  # fixed window for port-scan detection

# SIDs treated as "failed" authentication events
# SID 1000004 is "Off-Hours Successful Login" — a valid credential, NOT a failure
FAILED_AUTH_SIDS = {1000001}

# Document the full feature contract in one place
FEATURE_KEYS = (
    "failed_logins_60s",    # failed SSH/auth attempts from src_ip in 60s window
    "unique_ports_10s",     # unique dst_ports hit by src_ip in last 10s
    "requests_per_min",     # total events from src_ip in 60s window
    "is_off_hours",         # 1 if hour < 6 or hour > 22, else 0
    "is_new_ip",            # 1 if src_ip never seen before this session
    "bytes_out_60s",        # total outbound bytes from src_ip in 60s window
    "unique_dst_ips_60s",   # unique destination IPs from src_ip in 60s window
    "error_rate",           # ratio of failed to total events (0.0–1.0)
)


@dataclass
class FeatureVector:
    src_ip: str
    timestamp: datetime
    features: dict
    source_event: LogEvent = field(repr=False)


def _is_failed_event(event: LogEvent) -> bool:
    """Heuristic: classify an event as a failed/suspicious authentication attempt."""
    if event.sid in FAILED_AUTH_SIDS:
        return True
    # Failed SSH: port 22, highest Snort priority (1 = most severe = typical failed auth)
    if event.dst_port == 22 and event.priority == 1:
        return True
    return False


class FeatureExtractor:
    """
    Computes sliding-window features for each LogEvent.

    Internal state (all protected by self._lock):
      _history[ip]      — deque of LogEvent, 60s window
      _history_10s[ip]  — deque of LogEvent, 10s window
      _seen_ips         — set of IPs observed since startup
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: dict[str, Deque[LogEvent]] = defaultdict(deque)
        self._history_10s: dict[str, Deque[LogEvent]] = defaultdict(deque)
        self._seen_ips: set[str] = set()

    def extract(self, event: LogEvent) -> FeatureVector:
        """Main entry point: prune stale events, then compute all features."""
        with self._lock:
            src = event.src_ip
            is_new = src not in self._seen_ips
            self._seen_ips.add(src)

            # Append to both windows
            self._history[src].append(event)
            self._history_10s[src].append(event)

            # Prune stale events from the left of each deque
            cutoff_60s = event.timestamp - timedelta(seconds=SLIDING_WINDOW_SECONDS)
            cutoff_10s = event.timestamp - timedelta(seconds=SHORT_WINDOW_SECONDS)

            window = self._history[src]
            while window and window[0].timestamp < cutoff_60s:
                window.popleft()

            window_10s = self._history_10s[src]
            while window_10s and window_10s[0].timestamp < cutoff_10s:
                window_10s.popleft()

            features = self._compute_features(event, window, window_10s, is_new)

        return FeatureVector(
            src_ip=src,
            timestamp=event.timestamp,
            features=features,
            source_event=event,
        )

    def _compute_features(
        self,
        event: LogEvent,
        window: Deque[LogEvent],
        window_10s: Deque[LogEvent],
        is_new: bool,
    ) -> dict:
        """
        Compute all 8 features from the current windows.
        `window`     — 60s deque for this src_ip (already pruned, includes current event)
        `window_10s` — 10s deque for this src_ip (already pruned, includes current event)
        `is_new`     — True if this is the first time we've seen this src_ip
        """
        total = len(window)
        failed_count = sum(1 for e in window if _is_failed_event(e))

        features: dict = {}

        # --- 60-second features ---

        # How many failed auth events in the last 60s from this IP
        features["failed_logins_60s"] = failed_count

        # Total event rate per minute (window is already 60s wide)
        features["requests_per_min"] = total

        # Total bytes sent by this IP in the 60s window
        features["bytes_out_60s"] = sum(e.bytes for e in window)

        # Number of unique destination IPs contacted in 60s
        features["unique_dst_ips_60s"] = len({e.dst_ip for e in window})

        # Ratio of failed events to total (0.0 if no events)
        features["error_rate"] = failed_count / total if total else 0.0

        # --- 10-second features ---

        # Number of unique destination ports in the short window (port scan indicator)
        features["unique_ports_10s"] = len({e.dst_port for e in window_10s})

        # --- Static / session features ---

        # Off-hours: before 06:00 or after 22:00
        features["is_off_hours"] = 1 if (event.timestamp.hour < 6 or event.timestamp.hour > 22) else 0

        # New IP never seen before this session
        features["is_new_ip"] = 1 if is_new else 0

        return features

    def seen_ip_count(self) -> int:
        """Number of unique source IPs observed since startup."""
        with self._lock:
            return len(self._seen_ips)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from datetime import timezone

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    def _make_event(
        src_ip: str = "10.0.0.1",
        dst_ip: str = "192.168.1.1",
        dst_port: int = 22,
        sid: int = 1000001,
        priority: int = 1,
        bytes_: int = 512,
        ts: datetime | None = None,
    ) -> LogEvent:
        ts = ts or datetime.now(timezone.utc)
        return LogEvent(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=54321,
            dst_port=dst_port,
            proto="TCP",
            sid=sid,
            msg="test",
            priority=priority,
            bytes=bytes_,
            raw={},
        )

    extractor = FeatureExtractor()
    base_ts = datetime.now(timezone.utc)

    # --- Test 1: failed_logins_60s and error_rate ---
    # Feed 50 failed SSH events (SID 1000001) + 10 normal events (SID 2000001, port 80)
    for i in range(50):
        extractor.extract(_make_event(sid=1000001, priority=1, ts=base_ts))
    last_fv = None
    for i in range(10):
        last_fv = extractor.extract(_make_event(sid=2000001, priority=4, dst_port=80, ts=base_ts))

    # After 50 failed + 10 normal, failed_logins_60s should be exactly 50
    failed = last_fv.features["failed_logins_60s"]
    if failed != 50:
        _fail(f"failed_logins_60s={failed}, expected 50")

    error_rate = last_fv.features["error_rate"]
    # 50 failed out of 60 total = 0.833...
    if not (0.80 <= error_rate <= 0.90):
        _fail(f"error_rate={error_rate:.3f}, expected ~0.82")

    # --- Test 2: unique_ports_10s ---
    extractor2 = FeatureExtractor()
    scan_ts = datetime.now(timezone.utc)
    last_scan_fv = None
    for port in range(1, 26):  # 25 unique ports
        fv = extractor2.extract(_make_event(
            src_ip="10.1.1.1",
            dst_port=port,
            sid=1000003,
            ts=scan_ts,  # all same timestamp = all within 10s window
        ))
        last_scan_fv = fv

    unique_ports = last_scan_fv.features["unique_ports_10s"]
    if unique_ports < 20:
        _fail(f"unique_ports_10s={unique_ports}, expected >=20")

    # --- Test 3: is_new_ip ---
    extractor3 = FeatureExtractor()
    fv_new = extractor3.extract(_make_event(src_ip="10.2.2.2", ts=base_ts))
    if fv_new.features["is_new_ip"] != 1:
        _fail("is_new_ip should be 1 for first-seen IP")

    fv_repeat = extractor3.extract(_make_event(src_ip="10.2.2.2", ts=base_ts))
    if fv_repeat.features["is_new_ip"] != 0:
        _fail("is_new_ip should be 0 for already-seen IP")

    print("PASS: features self-test")
