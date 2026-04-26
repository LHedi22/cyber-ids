"""
Rule engine: evaluates threshold-based detection rules against FeatureVectors.

Rules fire in priority order (CRITICAL first). The first matching rule wins —
a single event produces at most one rule-based alert. The ML detector runs
separately and may produce an additional ML_ANOMALY alert for the same event.
"""

import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

from pipeline.features import FeatureVector
from pipeline.parser import LogEvent

load_dotenv()

log = logging.getLogger(__name__)


@dataclass
class Alert:
    alert_id: str           # uuid4
    type: str               # BRUTE_FORCE | PORT_SCAN | SQL_INJECTION | OFF_HOURS_ACCESS | DATA_EXFIL | ML_ANOMALY
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: datetime
    detection_source: str   # rule_engine | ml | both
    rule_name: str          # rule that fired, or "isolation_forest"
    feature_vector: dict
    shap_factors: list = field(default_factory=list)   # filled by explainer
    llm_explanation: str = ""                          # filled by LLM
    anomaly_score: float = 1.0                         # IF score; 1.0 for rule-only

    def to_dict(self) -> dict:
        """JSON-safe serialization (datetime → ISO string)."""
        return {
            "alert_id": self.alert_id,
            "type": self.type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "detection_source": self.detection_source,
            "rule_name": self.rule_name,
            "feature_vector": self.feature_vector,
            "shap_factors": self.shap_factors,
            "llm_explanation": self.llm_explanation,
            "anomaly_score": self.anomaly_score,
        }


def _new_alert(
    alert_type: str,
    severity: str,
    rule_name: str,
    fv: FeatureVector,
) -> Alert:
    event: LogEvent = fv.source_event
    return Alert(
        alert_id=str(uuid.uuid4()),
        type=alert_type,
        severity=severity,
        src_ip=fv.src_ip,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        timestamp=fv.timestamp,
        detection_source="rule_engine",
        rule_name=rule_name,
        feature_vector=fv.features,
        shap_factors=[],
        llm_explanation="",
        anomaly_score=1.0,
    )


class RuleEngine:
    """
    Evaluates all 5 detection rules in CRITICAL-first order.
    Returns the first matching Alert, or None if no rule fires.
    All thresholds are read from env vars once at construction time.
    """

    def __init__(self) -> None:
        self.brute_force_threshold = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
        self.port_scan_threshold = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
        self.data_exfil_bytes = int(os.getenv("DATA_EXFIL_BYTES", "10000"))

        # Rules in evaluation order: BRUTE_FORCE → DATA_EXFIL → PORT_SCAN → SQL_INJECTION → OFF_HOURS_ACCESS
        self._rules = [
            self._rule_brute_force,
            self._rule_data_exfil,
            self._rule_port_scan,
            self._rule_sql_injection,
            self._rule_off_hours_access,
        ]

    def evaluate(self, fv: FeatureVector) -> Optional[Alert]:
        """
        Run all rules in order and return the first Alert that fires, or None.
        Logs each match at WARNING level.
        """
        for rule in self._rules:
            alert = rule(fv)
            if alert is not None:
                log.warning(
                    "ALERT [%s] %s src=%s rule=%s",
                    alert.severity, alert.type, alert.src_ip, alert.rule_name,
                )
                return alert
        return None

    # ------------------------------------------------------------------
    # Individual rules — each returns Alert or None
    # ------------------------------------------------------------------

    def _rule_brute_force(self, fv: FeatureVector) -> Optional[Alert]:
        """CRITICAL: failed_logins_60s > BRUTE_FORCE_THRESHOLD"""
        if fv.features["failed_logins_60s"] > self.brute_force_threshold:
            return _new_alert("BRUTE_FORCE", "CRITICAL", "BRUTE_FORCE", fv)
        return None

    def _rule_port_scan(self, fv: FeatureVector) -> Optional[Alert]:
        """HIGH: unique_ports_10s > PORT_SCAN_THRESHOLD"""
        if fv.features["unique_ports_10s"] > self.port_scan_threshold:
            return _new_alert("PORT_SCAN", "HIGH", "PORT_SCAN", fv)
        return None

    def _rule_sql_injection(self, fv: FeatureVector) -> Optional[Alert]:
        """HIGH: source event SID == 1000002"""
        if fv.source_event.sid == 1000002:
            return _new_alert("SQL_INJECTION", "HIGH", "SQL_INJECTION", fv)
        return None

    def _rule_data_exfil(self, fv: FeatureVector) -> Optional[Alert]:
        """HIGH: bytes_out_60s > DATA_EXFIL_BYTES on a non-standard port"""
        if (
            fv.features["bytes_out_60s"] > self.data_exfil_bytes
            and fv.source_event.dst_port not in (80, 443, 22, 53)
        ):
            return _new_alert("DATA_EXFIL", "HIGH", "DATA_EXFIL", fv)
        return None

    def _rule_off_hours_access(self, fv: FeatureVector) -> Optional[Alert]:
        """MEDIUM: is_off_hours == 1 AND error_rate < 0.5"""
        if fv.features["is_off_hours"] == 1 and fv.features["error_rate"] < 0.5:
            return _new_alert("OFF_HOURS_ACCESS", "MEDIUM", "OFF_HOURS_ACCESS", fv)
        return None


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

    def _make_fv(
        src_ip: str = "10.0.0.1",
        dst_ip: str = "192.168.1.1",
        dst_port: int = 80,
        sid: int = 2000001,
        failed_logins_60s: int = 0,
        unique_ports_10s: int = 0,
        bytes_out_60s: int = 0,
        is_new_ip: int = 0,
        is_off_hours: int = 0,
        error_rate: float = 0.0,
        requests_per_min: int = 1,
        unique_dst_ips_60s: int = 1,
    ) -> FeatureVector:
        from pipeline.parser import LogEvent
        from pipeline.features import FeatureVector

        ts = datetime.now(timezone.utc)
        event = LogEvent(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip, src_port=54321,
            dst_port=dst_port, proto="TCP", sid=sid, msg="test",
            priority=4, bytes=500, raw={},
        )
        return FeatureVector(
            src_ip=src_ip,
            timestamp=ts,
            features={
                "failed_logins_60s": failed_logins_60s,
                "unique_ports_10s": unique_ports_10s,
                "requests_per_min": requests_per_min,
                "is_off_hours": is_off_hours,
                "is_new_ip": is_new_ip,
                "bytes_out_60s": bytes_out_60s,
                "unique_dst_ips_60s": unique_dst_ips_60s,
                "error_rate": error_rate,
            },
            source_event=event,
        )

    engine = RuleEngine()

    # Test 1: BRUTE_FORCE
    alert = engine.evaluate(_make_fv(failed_logins_60s=10))
    if alert is None or alert.type != "BRUTE_FORCE":
        _fail(f"expected BRUTE_FORCE alert, got {alert}")
    if alert.severity != "CRITICAL":
        _fail(f"BRUTE_FORCE severity should be CRITICAL, got {alert.severity}")
    if alert.detection_source != "rule_engine":
        _fail(f"detection_source should be 'rule_engine', got {alert.detection_source}")

    # Test 2: PORT_SCAN
    alert = engine.evaluate(_make_fv(unique_ports_10s=25))
    if alert is None or alert.type != "PORT_SCAN":
        _fail(f"expected PORT_SCAN alert, got {alert}")
    if alert.severity != "HIGH":
        _fail(f"PORT_SCAN severity should be HIGH, got {alert.severity}")

    # Test 3: SQL_INJECTION
    alert = engine.evaluate(_make_fv(sid=1000002))
    if alert is None or alert.type != "SQL_INJECTION":
        _fail(f"expected SQL_INJECTION alert, got {alert}")

    # Test 4: DATA_EXFIL — large bytes on non-standard port (port 4444 simulates C2 channel)
    alert = engine.evaluate(_make_fv(bytes_out_60s=50000, dst_port=4444))
    if alert is None or alert.type != "DATA_EXFIL":
        _fail(f"expected DATA_EXFIL alert, got {alert}")

    # Test 5: OFF_HOURS_ACCESS
    alert = engine.evaluate(_make_fv(is_off_hours=1, error_rate=0.1))
    if alert is None or alert.type != "OFF_HOURS_ACCESS":
        _fail(f"expected OFF_HOURS_ACCESS alert, got {alert}")
    if alert.severity != "MEDIUM":
        _fail(f"OFF_HOURS_ACCESS severity should be MEDIUM, got {alert.severity}")

    # Test 6: no alert on normal traffic
    alert = engine.evaluate(_make_fv())
    if alert is not None:
        _fail(f"expected no alert for normal traffic, got {alert.type}")

    # Test 7: priority order — BRUTE_FORCE shadows DATA_EXFIL and PORT_SCAN when all conditions met
    alert = engine.evaluate(_make_fv(failed_logins_60s=10, bytes_out_60s=50000, dst_port=4444, unique_ports_10s=25))
    if alert is None or alert.type != "BRUTE_FORCE":
        _fail(f"BRUTE_FORCE should shadow DATA_EXFIL/PORT_SCAN, got {alert}")

    print("PASS: rule_engine self-test")
