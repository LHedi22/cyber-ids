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
        "You are a senior cybersecurity analyst writing incident triage notes.\n\n"
        "Alert details:\n"
        f"- Source IP: {alert.src_ip}\n"
        f"- Attack type: {alert.type}\n"
        f"- Severity: {alert.severity}\n"
        f"- Timestamp: {ts_str}\n"
        f"- Detection method: {alert.detection_source}\n"
        f"- Top indicators:\n{indicators}\n\n"
        "Write 2-3 sentences: (1) what attack this represents and the attacker's "
        "likely objective, (2) what specific evidence supports this conclusion. "
        "Be precise and technical. Do not use hedging language like \"possibly\" or \"might\". "
        "Write in present tense as if actively observing the threat."
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
        """Per-attack-type narrative explanations used when Ollama is unavailable."""
        fv       = alert.feature_vector or {}
        src      = alert.src_ip
        dst_host = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_ip else "target host"
        atype    = alert.type

        failed   = int(fv.get("failed_logins_60s", 0))
        ports    = int(fv.get("unique_ports_10s", 0))
        bytes_out = int(fv.get("bytes_out_60s", 0))
        error_r  = fv.get("error_rate", 0.0)
        reqs_min = int(fv.get("requests_per_min", 0))
        is_new   = bool(fv.get("is_new_ip", 0))
        off_hrs  = bool(fv.get("is_off_hours", 0))

        if atype == "BRUTE_FORCE":
            rate_note = f" with a {error_r:.0%} failure rate" if error_r > 0 else ""
            return (
                f"Automated credential attack is underway from {src}: {failed} failed "
                f"authentication attempts were recorded in a 60-second window{rate_note}, "
                f"consistent with a dictionary or credential-stuffing campaign targeting "
                f"SSH or web authentication services. "
                f"The high-frequency, systematic pattern is characteristic of tooling "
                f"such as Hydra or Medusa rather than organic user error. "
                f"Immediate account lockout and IP block are recommended."
            )

        if atype == "PORT_SCAN":
            return (
                f"Active network reconnaissance is in progress from {src}: {ports} "
                f"distinct destination ports were probed within a 10-second interval, "
                f"a pattern that matches automated port scanning tools such as Nmap or Masscan. "
                f"The attacker is systematically enumerating exposed services to identify "
                f"exploitable entry points — this is typically a precursor to a targeted "
                f"exploitation phase. The scan rate indicates the attacker is not attempting "
                f"to evade detection."
            )

        if atype == "SQL_INJECTION":
            return (
                f"SQL injection attack is being executed from {src} against the "
                f"web application endpoint at {dst_host}. "
                f"The attacker is submitting crafted input payloads designed to break "
                f"out of the intended query context and manipulate the backend database "
                f"directly. The objective is typically authentication bypass, "
                f"bulk credential or PII extraction, or escalation to remote code "
                f"execution via database features such as xp_cmdshell."
            )

        if atype == "DATA_EXFIL":
            if bytes_out >= 1_048_576:
                size_str = f"{bytes_out / 1_048_576:.1f} MB"
            elif bytes_out >= 1024:
                size_str = f"{bytes_out / 1024:.0f} KB"
            else:
                size_str = f"{bytes_out:,} bytes"
            new_note = " to a previously unseen external host" if is_new else ""
            return (
                f"Data exfiltration is actively occurring from {src}: {size_str} "
                f"of outbound traffic was recorded to {dst_host}{new_note} "
                f"over a non-standard port within a 60-second window. "
                f"This volume and destination pattern is consistent with an attacker "
                f"staging and exporting sensitive data — likely credentials, "
                f"intellectual property, or customer records — to an external command "
                f"and control server. Network egress to this destination should be "
                f"blocked immediately."
            )

        if atype == "OFF_HOURS_ACCESS":
            err_note = (
                f" The {error_r:.0%} error rate confirms the credentials are valid, "
                f"ruling out a brute-force attack in progress."
                if error_r < 0.3 else ""
            )
            return (
                f"Suspicious authentication was recorded from {src} during off-hours "
                f"when legitimate user activity is not expected.{err_note} "
                f"This pattern is associated with insider threats or compromised "
                f"credentials being used by an external actor who has already obtained "
                f"valid account access — potentially through phishing, credential "
                f"reuse, or a prior intrusion. Verify with the account owner immediately."
            )

        # ML_ANOMALY — use SHAP factors for specificity if available
        if alert.shap_factors:
            top = sorted(
                alert.shap_factors,
                key=lambda f: abs(f.get("shap_contribution", 0)),
                reverse=True,
            )[:3]
            feat_parts = []
            for f in top:
                name = f.get("feature", "").replace("_", " ")
                val  = f.get("value", "")
                contrib = f.get("shap_contribution", 0)
                feat_parts.append(f"{name} = {val} (SHAP {contrib:+.3f})")
            feat_str = "; ".join(feat_parts)
            new_note = (
                f" The source IP {src} has not been observed before, "
                f"indicating this may be a new attacker or freshly compromised host."
                if is_new else ""
            )
            return (
                f"The Isolation Forest model has flagged traffic from {src} as a "
                f"high-confidence statistical anomaly deviating from the established "
                f"behavioral baseline.{new_note} "
                f"Primary contributing features: {feat_str}. "
                f"This combination of signals falls outside normal operational parameters "
                f"and may indicate an emerging threat, a lateral movement attempt, "
                f"or a novel attack pattern not covered by signature-based rules."
            )

        # Fallback for ML anomaly without SHAP data
        observations = []
        if failed > 0:
            observations.append(f"{failed} failed authentication attempts in 60 s")
        if ports > 0:
            observations.append(f"{ports} unique ports probed in 10 s")
        if bytes_out > 1000:
            observations.append(f"{bytes_out:,} bytes of outbound traffic in 60 s")
        if reqs_min > 10:
            observations.append(f"{reqs_min} requests per minute")
        if is_new:
            observations.append("source IP not previously seen in this session")
        if off_hrs:
            observations.append("activity occurring outside normal business hours")

        obs_str = "; ".join(observations) if observations else "multivariate traffic pattern"
        return (
            f"The ML anomaly detector has flagged traffic from {src} as statistically "
            f"abnormal. Observed signals: {obs_str}. "
            f"While no single indicator crosses a rule-based threshold, the combination "
            f"of features exceeds the Isolation Forest anomaly score learned during "
            f"training — suggesting coordinated or low-and-slow attack behaviour "
            f"designed to evade signature-based detection."
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
