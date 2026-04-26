"""
SHAP explainer for ML-detected anomalies.

Only called for IsolationForest alerts — rule-based alerts skip SHAP entirely
since they have an explicit rule name that already explains why they fired.

TreeExplainer is cached after first construction: building it from 100 IF trees
takes ~0.5s; reusing it keeps per-alert overhead under 5ms.
"""

import logging
from typing import List, Optional

import numpy as np
import shap

from pipeline.ml_detector import FEATURE_ORDER, IsolationForestDetector

log = logging.getLogger(__name__)

TOP_N = 3  # number of top SHAP contributors to return


class SHAPExplainer:
    """
    Wraps shap.TreeExplainer for the trained IsolationForest.

    Usage:
        explainer = SHAPExplainer(detector)
        factors = explainer.explain(feature_dict)
    """

    def __init__(self, detector: IsolationForestDetector) -> None:
        self._detector = detector
        self._explainer: Optional[shap.TreeExplainer] = None

    def _get_explainer(self) -> Optional[shap.TreeExplainer]:
        """Lazy-initialise and cache the TreeExplainer."""
        if self._explainer is not None:
            return self._explainer
        if self._detector._model is None:
            log.warning("Cannot build TreeExplainer: model not loaded")
            return None
        try:
            self._explainer = shap.TreeExplainer(self._detector._model)
            log.info("TreeExplainer initialised for IsolationForest")
        except Exception as exc:
            log.error("Failed to build TreeExplainer: %s", exc)
            self._explainer = None
        return self._explainer

    def explain(self, features: dict) -> List[dict]:
        """
        Compute SHAP values for one feature vector and return the top-N
        contributors sorted by absolute SHAP value descending.

        Returns a list of dicts:
            [{"feature": str, "value": float, "shap_contribution": float}, ...]

        On any failure, returns a single-item fallback using the raw feature
        with the highest absolute value so callers always get a non-empty list.
        """
        try:
            return self._compute_shap(features)
        except Exception as exc:
            log.error("SHAP explain() failed: %s — using raw-feature fallback", exc)
            return self._fallback(features)

    def _compute_shap(self, features: dict) -> List[dict]:
        explainer = self._get_explainer()
        if explainer is None:
            return self._fallback(features)

        # Build input array in canonical order, then scale
        X_raw = np.array([[features[k] for k in FEATURE_ORDER]], dtype=float)

        if self._detector._scaler is not None:
            X_scaled = self._detector._scaler.transform(X_raw)
        else:
            X_scaled = X_raw

        # shap_values returns shape (1, n_features) for a single-row input
        shap_values = explainer.shap_values(X_scaled)
        values_row = np.array(shap_values[0])  # shape: (n_features,)

        # Pair each feature with its SHAP value and raw value
        contributions = [
            {
                "feature": FEATURE_ORDER[i],
                "value": float(features[FEATURE_ORDER[i]]),
                "shap_contribution": float(values_row[i]),
            }
            for i in range(len(FEATURE_ORDER))
        ]

        # Sort by absolute SHAP contribution descending, take top N
        contributions.sort(key=lambda x: abs(x["shap_contribution"]), reverse=True)
        return contributions[:TOP_N]

    def _fallback(self, features: dict) -> List[dict]:
        """Return the single feature with the highest absolute raw value."""
        if not features:
            return [{"feature": "unknown", "value": 0.0, "shap_contribution": 0.0}]
        top_key = max(features, key=lambda k: abs(features[k]))
        return [{"feature": top_key, "value": float(features[top_key]), "shap_contribution": 0.0}]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import os
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    from pipeline.ml_detector import IsolationForestDetector

    detector = IsolationForestDetector()
    detector.auto_train_if_needed()

    if detector._model is None:
        _fail("model failed to load/train")

    explainer = SHAPExplainer(detector)

    anomalous = {
        "failed_logins_60s": 50,
        "unique_ports_10s": 40,
        "requests_per_min": 200,
        "is_off_hours": 1,
        "is_new_ip": 1,
        "bytes_out_60s": 80000,
        "unique_dst_ips_60s": 30,
        "error_rate": 0.95,
    }

    result = explainer.explain(anomalous)

    if not isinstance(result, list):
        _fail(f"explain() should return a list, got {type(result)}")

    if len(result) != TOP_N:
        _fail(f"expected {TOP_N} factors, got {len(result)}: {result}")

    required_keys = {"feature", "value", "shap_contribution"}
    for i, item in enumerate(result):
        missing = required_keys - item.keys()
        if missing:
            _fail(f"item {i} missing keys {missing}: {item}")
        if not isinstance(item["feature"], str):
            _fail(f"item {i} 'feature' should be str, got {type(item['feature'])}")
        if not isinstance(item["value"], (int, float)):
            _fail(f"item {i} 'value' should be numeric, got {type(item['value'])}")
        if not isinstance(item["shap_contribution"], (int, float)):
            _fail(f"item {i} 'shap_contribution' should be numeric, got {type(item['shap_contribution'])}")

    # Verify all returned feature names are valid
    for item in result:
        if item["feature"] not in FEATURE_ORDER:
            _fail(f"unknown feature name: {item['feature']}")

    # Verify caching: second call reuses same explainer object
    explainer2_ref = explainer._explainer
    explainer.explain(anomalous)
    if explainer._explainer is not explainer2_ref:
        _fail("TreeExplainer was not cached between calls")

    # Verify fallback on unloaded model
    empty_detector = IsolationForestDetector()
    fallback_explainer = SHAPExplainer(empty_detector)
    fallback = fallback_explainer.explain(anomalous)
    if len(fallback) != 1:
        _fail(f"fallback should return 1 item, got {len(fallback)}")
    if fallback[0]["feature"] not in anomalous:
        _fail(f"fallback feature not in input: {fallback[0]['feature']}")

    print("PASS: explainer self-test")
