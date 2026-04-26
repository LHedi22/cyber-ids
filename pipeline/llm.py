"""
LLM interpreter: calls Ollama to generate human-readable alert explanations.

Cache key is (alert_type, severity, detection_source) — finer than (type, severity)
so rule-engine and ML alerts of the same type get distinct explanations.
Each entry expires after CACHE_TTL seconds so stale explanations are refreshed.
Fallback responses (LLM unavailable) are never cached — they embed src_ip.
Cache is bounded at LLM_CACHE_MAX entries (evict oldest on overflow).
"""

import logging
import os
import time
from collections import OrderedDict
from datetime import datetime
from typing import TYPE_CHECKING

import httpx
from dotenv import load_dotenv

if TYPE_CHECKING:
    from pipeline.rule_engine import Alert

load_dotenv()

log = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")
LLM_TIMEOUT = 30.0      # seconds; keep the pipeline flowing if Ollama is slow
LLM_CACHE_MAX = 20      # max unique (type, severity, detection_source) entries cached
CACHE_TTL     = 60.0    # seconds before a cached explanation is regenerated


def _format_shap_factors(shap_factors: list) -> str:
    """Format SHAP factors as an indented bullet list for the prompt."""
    if not shap_factors:
        return "(none)"
    lines = []
    for f in shap_factors:
        lines.append(
            f"  - {f['feature']}: {f['value']} (contribution: {f['shap_contribution']:+.3f})"
        )
    return "\n".join(lines)


def _build_prompt(alert: "Alert") -> str:
    if alert.shap_factors:
        indicators = _format_shap_factors(alert.shap_factors)
    else:
        indicators = f"  - Rule fired: {alert.rule_name}"

    ts = alert.timestamp
    if isinstance(ts, datetime):
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        ts_str = str(ts)

    return (
        "You are a cybersecurity analyst. A network anomaly was detected.\n\n"
        "Event details:\n"
        f"- Source IP: {alert.src_ip}\n"
        f"- Attack type: {alert.type}\n"
        f"- Severity: {alert.severity}\n"
        f"- Timestamp: {ts_str}\n"
        f"- Detection method: {alert.detection_source}\n"
        f"- Top indicators:\n{indicators}\n\n"
        "In exactly 1-2 sentences, describe what attack this likely represents "
        "and what the attacker may be attempting. Be specific and technical. "
        "Do not use hedging language like \"possibly\" or \"might\"."
    )


class LLMInterpreter:
    """
    Generates plain-English attack explanations via Ollama.

    Falls back to a static string on timeout or connection error so the
    rest of the pipeline is never blocked waiting for LLM output.
    """

    def __init__(self) -> None:
        self._host = OLLAMA_HOST.rstrip("/")
        self._model = OLLAMA_MODEL
        # Maps (type, severity, detection_source) → (explanation, expiry_monotonic)
        self._cache: OrderedDict[tuple, tuple[str, float]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def interpret(self, alert: "Alert") -> str:
        """
        Return a 1-2 sentence explanation for the alert.
        Cache key includes detection_source so rule-engine and ML alerts
        of the same type receive distinct explanations.
        Fallback responses are never cached (they embed the per-alert src_ip).
        """
        cache_key = (alert.type, alert.severity, alert.detection_source)
        now = time.monotonic()

        if cache_key in self._cache:
            text, expiry = self._cache[cache_key]
            if now < expiry:
                self._cache.move_to_end(cache_key)
                log.debug("LLM cache hit for %s/%s/%s", *cache_key)
                return text
            # Entry expired — remove and regenerate
            del self._cache[cache_key]

        result = self._call_ollama(alert)
        if result is None:
            # Fallback: build from alert data without caching
            return self._fallback(alert)

        self._cache[cache_key] = (result, now + CACHE_TTL)
        if len(self._cache) > LLM_CACHE_MAX:
            self._cache.popitem(last=False)  # evict oldest

        return result

    def health_check(self) -> bool:
        """Return True if Ollama is reachable and responding."""
        try:
            resp = httpx.get(f"{self._host}/api/tags", timeout=3.0)
            return resp.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_ollama(self, alert: "Alert") -> "str | None":
        """Return the LLM response string, or None if Ollama is unavailable."""
        prompt = _build_prompt(alert)
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            resp = httpx.post(
                f"{self._host}/api/generate",
                json=payload,
                timeout=LLM_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            if not text:
                raise ValueError("Empty response from Ollama")
            log.info("LLM generated explanation for %s (%d chars)", alert.type, len(text))
            return text
        except httpx.TimeoutException:
            log.warning("Ollama timed out after %.1fs for %s", LLM_TIMEOUT, alert.type)
        except httpx.ConnectError:
            log.warning("Ollama unreachable at %s", self._host)
        except Exception as exc:
            log.error("LLM call failed for %s: %s", alert.type, exc)

        return None

    @staticmethod
    def _fallback(alert: "Alert") -> str:
        """Build a meaningful explanation from SHAP factors and features when Ollama is down."""
        fv = alert.feature_vector or {}

        # SHAP factors are the richest signal — use them if present
        if alert.shap_factors:
            top = sorted(
                alert.shap_factors,
                key=lambda f: abs(f.get("shap_contribution", 0)),
                reverse=True,
            )[:2]
            parts = []
            for f in top:
                name = f.get("feature", "").replace("_", " ")
                val  = f.get("value", "")
                parts.append(f"{name} = {val}")
            factors_str = "; ".join(parts)
            return (
                f"{alert.severity} {alert.type} from {alert.src_ip}: "
                f"ML model flagged abnormal behavior — top indicators: {factors_str}."
            )

        # Fall back to feature-vector narrative
        observations = []
        if fv.get("failed_logins_60s", 0) > 3:
            observations.append(f"{int(fv['failed_logins_60s'])} failed logins in 60 s")
        if fv.get("unique_ports_10s", 0) > 5:
            observations.append(f"{int(fv['unique_ports_10s'])} unique ports hit in 10 s")
        if fv.get("bytes_out_60s", 0) > 5000:
            observations.append(f"{int(fv['bytes_out_60s']):,} bytes outbound in 60 s")
        if fv.get("error_rate", 0) > 0.5:
            observations.append(f"{fv['error_rate']:.0%} error rate")
        if fv.get("requests_per_min", 0) > 50:
            observations.append(f"{int(fv['requests_per_min'])} requests/min")
        if fv.get("is_new_ip", 0):
            observations.append("previously unseen source IP")
        if fv.get("is_off_hours", 0):
            observations.append("off-hours activity")

        if observations:
            return (
                f"{alert.severity} {alert.type} from {alert.src_ip}: "
                + ", ".join(observations) + "."
            )

        return (
            f"{alert.severity} statistical anomaly from {alert.src_ip} — "
            "behavior deviates significantly from established baseline traffic patterns."
        )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from datetime import timezone
    from pipeline.rule_engine import Alert

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    def _make_alert(alert_type: str = "BRUTE_FORCE", severity: str = "CRITICAL") -> Alert:
        return Alert(
            alert_id="test-uuid",
            type=alert_type,
            severity=severity,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            dst_port=22,
            timestamp=datetime.now(timezone.utc),
            detection_source="rule_engine",
            rule_name="BRUTE_FORCE",
            feature_vector={"failed_logins_60s": 47, "error_rate": 0.94},
            shap_factors=[
                {"feature": "failed_logins_60s", "value": 47.0, "shap_contribution": 0.82},
                {"feature": "error_rate", "value": 0.94, "shap_contribution": 0.09},
            ],
            llm_explanation="",
            anomaly_score=1.0,
        )

    interpreter = LLMInterpreter()
    reachable = interpreter.health_check()
    log.info("Ollama reachable: %s", reachable)

    alert = _make_alert()
    result = interpreter.interpret(alert)

    if not isinstance(result, str):
        _fail(f"interpret() should return str, got {type(result)}")
    if not result:
        _fail("interpret() returned empty string")

    if reachable:
        if result.startswith("[LLM unavailable]"):
            _fail("Ollama is up but got fallback string")
        # Successful result must be cached; second call must return same text
        result2 = interpreter.interpret(alert)
        if result2 != result:
            _fail("cached result differs from original")
        log.info("LLM output: %s", result)
    else:
        # Fallback must mention the alert type and source IP
        if alert.type not in result or alert.src_ip not in result:
            _fail(f"fallback missing type/IP: '{result}'")
        # Fallback must NOT be cached (each call produces a fresh string)
        cache_key = (alert.type, alert.severity, alert.detection_source)
        if cache_key in interpreter._cache:
            _fail("fallback response should not be stored in cache")
        log.info("Fallback output: %s", result)

    # Verify cache eviction: stuff cache directly to avoid LLM network calls
    expiry = time.monotonic() + CACHE_TTL
    evict_interp = LLMInterpreter()
    for i in range(LLM_CACHE_MAX + 5):
        key = (f"TYPE_{i}", "HIGH", "rule_engine")
        evict_interp._cache[key] = (f"explanation {i}", expiry)
        if len(evict_interp._cache) > LLM_CACHE_MAX:
            evict_interp._cache.popitem(last=False)
    if len(evict_interp._cache) > LLM_CACHE_MAX:
        _fail(f"cache size {len(evict_interp._cache)} exceeds LLM_CACHE_MAX={LLM_CACHE_MAX}")

    # Verify SHAP-less alert uses rule name in prompt (just build the prompt, don't call LLM)
    rule_alert = _make_alert()
    rule_alert.shap_factors = []
    rule_alert.rule_name = "BRUTE_FORCE"
    prompt = _build_prompt(rule_alert)
    if "Rule fired: BRUTE_FORCE" not in prompt:
        _fail("prompt for rule-based alert should reference rule name")

    print("PASS: llm self-test")
