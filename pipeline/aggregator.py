"""
Alert aggregator: deduplication, rule+ML merging, and a bounded alert store.

Dedup window  = ALERT_DEDUP_SECONDS (default 30s): suppress exact (src_ip, type) repeats.
Merge window  = MERGE_WINDOW_SECONDS (5s): if rule_engine and ml both flag the same
                src_ip within this window, merge into a single "both" alert with
                one-level severity upgrade.

The deque (maxlen=500) is the sole in-memory alert store; no external DB needed
for the demo. get_stats() scans the deque — O(n) but n <= 500 so it's fast enough.
"""

import logging
import os
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import List, Optional

from dotenv import load_dotenv

from pipeline.rule_engine import Alert

load_dotenv()

log = logging.getLogger(__name__)

ALERT_DEDUP_SECONDS = int(os.getenv("ALERT_DEDUP_SECONDS", "30"))
MERGE_WINDOW_SECONDS = 5
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _upgrade_severity(severity: str) -> str:
    """Promote severity one level; CRITICAL stays CRITICAL."""
    idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


class AlertAggregator:
    """
    Thread-safe alert store with deduplication and rule/ML merge logic.

    All public methods acquire self._lock before touching self._alerts.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._alerts: deque[Alert] = deque(maxlen=500)
        # Tracks last-seen time for dedup: key = (src_ip, type)
        self._last_seen: dict[tuple, datetime] = {}
        # Tracks pending single-source alerts for merge: key = src_ip
        # value = Alert waiting for its counterpart within MERGE_WINDOW_SECONDS
        self._pending_merge: dict[str, Alert] = {}

    # ------------------------------------------------------------------
    # Core processing
    # ------------------------------------------------------------------

    def process(self, alert: Alert) -> Optional[Alert]:
        """
        Run dedup → merge checks, store, and return the final alert or None.

        Returns None when the alert is suppressed by dedup.
        Returns a merged alert (detection_source="both") when rule+ML converge.
        Returns the original alert when neither condition applies.
        """
        with self._lock:
            now = alert.timestamp

            # --- Deduplication ---
            dedup_key = (alert.src_ip, alert.type)
            last = self._last_seen.get(dedup_key)
            if last is not None:
                age = (now - last).total_seconds()
                if age < ALERT_DEDUP_SECONDS:
                    log.debug(
                        "Suppressed duplicate %s from %s (%.1fs ago)",
                        alert.type, alert.src_ip, age,
                    )
                    return None

            self._last_seen[dedup_key] = now

            # --- Rule + ML merge ---
            final_alert = self._try_merge(alert, now)

            self._alerts.append(final_alert)
            log.info(
                "Alert stored: %s [%s] from %s via %s",
                final_alert.type, final_alert.severity,
                final_alert.src_ip, final_alert.detection_source,
            )
            return final_alert

    def _try_merge(self, incoming: Alert, now: datetime) -> Alert:
        """
        If a complementary alert (same src_ip, opposite source) exists in the
        pending window, merge them and clear the pending slot.
        Otherwise, park the incoming alert as pending and return it as-is.
        """
        src = incoming.src_ip
        pending = self._pending_merge.get(src)

        if pending is not None:
            age = (now - pending.timestamp).total_seconds()
            sources = {pending.detection_source, incoming.detection_source}

            if age <= MERGE_WINDOW_SECONDS and sources == {"rule_engine", "ml"}:
                # Prefer the rule_engine alert as the base (has rule_name and type set)
                base = pending if pending.detection_source == "rule_engine" else incoming
                merged = Alert(
                    alert_id=base.alert_id,
                    type=base.type,
                    severity=_upgrade_severity(base.severity),
                    src_ip=base.src_ip,
                    dst_ip=base.dst_ip,
                    dst_port=base.dst_port,
                    timestamp=base.timestamp,
                    detection_source="both",
                    rule_name=base.rule_name,
                    feature_vector=base.feature_vector,
                    shap_factors=incoming.shap_factors if incoming.detection_source == "ml" else base.shap_factors,
                    llm_explanation=incoming.llm_explanation or base.llm_explanation,
                    anomaly_score=max(base.anomaly_score, incoming.anomaly_score),
                )
                del self._pending_merge[src]
                log.info(
                    "Merged rule+ML alert for %s: %s → %s severity",
                    src, base.severity, merged.severity,
                )
                return merged

        # Park as pending (overwrites any expired pending for this IP)
        self._pending_merge[src] = incoming
        return incoming

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_recent(self, n: int = 50) -> List[Alert]:
        """Return the last n alerts, newest first."""
        with self._lock:
            alerts = list(self._alerts)
        return list(reversed(alerts))[:n]

    def get_stats(self) -> dict:
        """Aggregate counts and top-attacker stats over the full deque."""
        with self._lock:
            alerts = list(self._alerts)

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)

        severity_counts: Counter = Counter()
        ip_counts: Counter = Counter()
        recent_count = 0

        for a in alerts:
            severity_counts[a.severity] += 1
            ip_counts[a.src_ip] += 1
            ts = a.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                recent_count += 1

        top_ips = [
            {"ip": ip, "count": count}
            for ip, count in ip_counts.most_common(5)
        ]

        return {
            "total": len(alerts),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "alerts_per_minute": float(recent_count),
            "top_attacking_ips": top_ips,
        }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import uuid
    from datetime import timezone

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    def _make_alert(
        src_ip: str = "10.0.0.1",
        alert_type: str = "BRUTE_FORCE",
        severity: str = "CRITICAL",
        detection_source: str = "rule_engine",
        ts: Optional[datetime] = None,
    ) -> Alert:
        ts = ts or datetime.now(timezone.utc)
        return Alert(
            alert_id=str(uuid.uuid4()),
            type=alert_type,
            severity=severity,
            src_ip=src_ip,
            dst_ip="192.168.1.1",
            dst_port=22,
            timestamp=ts,
            detection_source=detection_source,
            rule_name=alert_type,
            feature_vector={},
            shap_factors=[],
            llm_explanation="",
            anomaly_score=1.0,
        )

    agg = AlertAggregator()

    # --- Test 1: deduplication ---
    ts_base = datetime.now(timezone.utc)
    a1 = _make_alert(ts=ts_base)
    r1 = agg.process(a1)
    if r1 is None:
        _fail("first alert should not be suppressed")

    a2 = _make_alert(ts=ts_base)  # same src_ip + type, same second
    r2 = agg.process(a2)
    if r2 is not None:
        _fail("duplicate alert within dedup window should be suppressed")

    # --- Test 2: rule + ML merge ---
    agg2 = AlertAggregator()
    rule_alert = _make_alert(
        src_ip="10.1.1.1", detection_source="rule_engine",
        alert_type="PORT_SCAN", severity="HIGH", ts=ts_base,
    )
    ml_alert = _make_alert(
        src_ip="10.1.1.1", detection_source="ml",
        alert_type="ML_ANOMALY", severity="HIGH", ts=ts_base,
    )

    r_rule = agg2.process(rule_alert)
    r_ml = agg2.process(ml_alert)

    if r_ml is None:
        _fail("ML alert should not be suppressed (different type key)")
    if r_ml.detection_source != "both":
        _fail(f"merged alert should have detection_source='both', got '{r_ml.detection_source}'")
    if r_ml.severity != "CRITICAL":  # HIGH upgraded once = CRITICAL
        _fail(f"merged severity should be CRITICAL (upgraded from HIGH), got {r_ml.severity}")

    # --- Test 3: get_stats() ---
    agg3 = AlertAggregator()
    severities = ["CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for i, sev in enumerate(severities):
        agg3.process(_make_alert(
            src_ip=f"10.2.0.{i}",        # unique IP per alert avoids dedup
            alert_type=f"TYPE_{sev}_{i}",  # unique type per alert
            severity=sev,
            ts=ts_base,
        ))
    stats = agg3.get_stats()

    if stats["total"] != 5:
        _fail(f"total={stats['total']}, expected 5")
    if stats["critical"] != 2:
        _fail(f"critical={stats['critical']}, expected 2")
    if stats["high"] != 1:
        _fail(f"high={stats['high']}, expected 1")
    if stats["medium"] != 1:
        _fail(f"medium={stats['medium']}, expected 1")
    if stats["low"] != 1:
        _fail(f"low={stats['low']}, expected 1")
    if not isinstance(stats["top_attacking_ips"], list):
        _fail("top_attacking_ips should be a list")

    # --- Test 4: get_recent() order ---
    agg4 = AlertAggregator()
    for i in range(5):
        agg4.process(_make_alert(src_ip=f"10.3.0.{i}", alert_type=f"T{i}", ts=ts_base))
    recent = agg4.get_recent(3)
    if len(recent) != 3:
        _fail(f"get_recent(3) returned {len(recent)} items")
    # newest first means last inserted comes first
    if recent[0].src_ip != "10.3.0.4":
        _fail(f"get_recent newest-first failed: {recent[0].src_ip}")

    print("PASS: aggregator self-test")
