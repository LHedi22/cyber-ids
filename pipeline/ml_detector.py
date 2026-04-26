"""
ML anomaly detector: IsolationForest over the 8-feature vector.

Score normalization convention:
  IsolationForest.decision_function() returns negative values for outliers.
  We invert and normalize to [0, 1] so anomaly_score=1.0 means maximally anomalous.
  The min/max bounds are stored alongside the model so predictions are consistent
  across restarts without re-fitting.
"""

import logging
import os
import random
from typing import List, Tuple

import joblib
import numpy as np
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

load_dotenv()

log = logging.getLogger(__name__)

MODEL_PATH = os.getenv("MODEL_PATH", "models/isolation_forest.pkl")
CONTAMINATION = float(os.getenv("ISOLATION_FOREST_CONTAMINATION", "0.05"))

# Canonical feature order — must match features.py FEATURE_KEYS order
FEATURE_ORDER = [
    "failed_logins_60s",
    "unique_ports_10s",
    "requests_per_min",
    "is_off_hours",
    "is_new_ip",
    "bytes_out_60s",
    "unique_dst_ips_60s",
    "error_rate",
]


def _dict_to_array(features: dict) -> np.ndarray:
    """Convert a feature dict to a row vector in canonical order."""
    return np.array([[features[k] for k in FEATURE_ORDER]], dtype=float)


def _generate_synthetic_normal(n: int = 5000) -> List[dict]:
    """
    Generate synthetic normal traffic feature vectors for auto-training.
    Distributions are calibrated to typical low-threat network behaviour.
    """
    samples = []
    for _ in range(n):
        samples.append({
            "failed_logins_60s":  random.choices([0, 1, 2, 3, 4], weights=[60, 20, 10, 7, 3])[0],
            "unique_ports_10s":   random.choices([1, 2, 3, 4, 5, 6], weights=[50, 25, 12, 7, 4, 2])[0],
            "requests_per_min":   random.randint(1, 30),
            "is_off_hours":       1 if random.random() < 0.20 else 0,
            "is_new_ip":          1 if random.random() < 0.10 else 0,
            "bytes_out_60s":      random.randint(100, 5000),
            "unique_dst_ips_60s": random.randint(1, 5),
            "error_rate":         round(random.uniform(0.0, 0.2), 3),
        })
    return samples


class IsolationForestDetector:
    """
    Wraps IsolationForest with scaler, calibrated score normalization,
    and graceful auto-train-on-startup behaviour.
    """

    def __init__(self) -> None:
        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        # Score bounds fitted during training for [0,1] normalization
        self._score_min: float = -0.5
        self._score_max: float = 0.5

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, feature_vectors: List[dict]) -> None:
        """
        Fit scaler + IsolationForest on the provided feature dicts.
        Saves model bundle to MODEL_PATH.
        """
        if not feature_vectors:
            raise ValueError("Cannot train on empty feature_vectors list")

        X = np.array([[fv[k] for k in FEATURE_ORDER] for fv in feature_vectors], dtype=float)

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)

        # Compute score bounds on training data so normalization is stable
        raw_scores = self._model.decision_function(X_scaled)
        self._score_min = float(raw_scores.min())
        self._score_max = float(raw_scores.max())

        os.makedirs(os.path.dirname(MODEL_PATH) if os.path.dirname(MODEL_PATH) else ".", exist_ok=True)
        bundle = {
            "model": self._model,
            "scaler": self._scaler,
            "score_min": self._score_min,
            "score_max": self._score_max,
            "feature_order": FEATURE_ORDER,
        }
        joblib.dump(bundle, MODEL_PATH)

        log.info(
            "IsolationForest trained: n_samples=%d contamination=%.2f features=%s saved=%s",
            len(feature_vectors), CONTAMINATION, FEATURE_ORDER, MODEL_PATH,
        )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> bool:
        """Load model bundle from MODEL_PATH. Returns True on success."""
        if not os.path.exists(MODEL_PATH):
            log.warning("Model file not found: %s", MODEL_PATH)
            return False
        try:
            bundle = joblib.load(MODEL_PATH)
            self._model = bundle["model"]
            self._scaler = bundle["scaler"]
            self._score_min = bundle["score_min"]
            self._score_max = bundle["score_max"]
            log.info("Model loaded from %s", MODEL_PATH)
            return True
        except Exception as exc:
            log.error("Failed to load model from %s: %s", MODEL_PATH, exc)
            return False

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features: dict) -> Tuple[bool, float]:
        """
        Predict whether a feature dict is anomalous.
        Returns (is_anomaly: bool, anomaly_score: float in [0, 1]).
        Returns (False, 0.0) if the model is not loaded.
        """
        if self._model is None or self._scaler is None:
            return False, 0.0

        try:
            X = _dict_to_array(features)
            X_scaled = self._scaler.transform(X)

            # IsolationForest: -1 = anomaly, 1 = normal
            label = int(self._model.predict(X_scaled)[0])
            is_anomaly = label == -1

            raw = float(self._model.decision_function(X_scaled)[0])

            # Normalize to [0, 1], inverted so higher = more anomalous
            score_range = self._score_max - self._score_min
            if score_range > 0:
                normalized = (raw - self._score_min) / score_range
                anomaly_score = float(np.clip(1.0 - normalized, 0.0, 1.0))
            else:
                anomaly_score = 1.0 if is_anomaly else 0.0

            return is_anomaly, anomaly_score

        except Exception as exc:
            log.error("predict() failed: %s", exc)
            return False, 0.0

    # ------------------------------------------------------------------
    # Auto-train
    # ------------------------------------------------------------------

    def auto_train_if_needed(self) -> None:
        """
        If MODEL_PATH does not exist, generate synthetic normal data and train.
        Call this at startup for graceful first-run behaviour.
        """
        if os.path.exists(MODEL_PATH):
            self.load()
            return
        log.info("No model found at %s — auto-training on synthetic data...", MODEL_PATH)
        synthetic = _generate_synthetic_normal(5000)
        self.train(synthetic)
        log.info("Auto-training complete.")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        sys.exit(1)

    # Use a temp path so the self-test doesn't clobber the real model
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["MODEL_PATH"] = os.path.join(tmpdir, "test_model.pkl")

        detector = IsolationForestDetector()
        detector.auto_train_if_needed()

        if detector._model is None:
            _fail("model is None after auto_train_if_needed()")

        # --- Anomalous vectors (clearly outside normal distribution) ---
        anomalous = [
            {"failed_logins_60s": 50, "unique_ports_10s": 40, "requests_per_min": 200,
             "is_off_hours": 1, "is_new_ip": 1, "bytes_out_60s": 80000,
             "unique_dst_ips_60s": 30, "error_rate": 0.95},
            {"failed_logins_60s": 60, "unique_ports_10s": 35, "requests_per_min": 150,
             "is_off_hours": 0, "is_new_ip": 1, "bytes_out_60s": 60000,
             "unique_dst_ips_60s": 25, "error_rate": 0.90},
            {"failed_logins_60s": 45, "unique_ports_10s": 50, "requests_per_min": 300,
             "is_off_hours": 1, "is_new_ip": 1, "bytes_out_60s": 100000,
             "unique_dst_ips_60s": 40, "error_rate": 0.85},
            {"failed_logins_60s": 30, "unique_ports_10s": 60, "requests_per_min": 250,
             "is_off_hours": 1, "is_new_ip": 0, "bytes_out_60s": 90000,
             "unique_dst_ips_60s": 20, "error_rate": 0.80},
            {"failed_logins_60s": 55, "unique_ports_10s": 45, "requests_per_min": 180,
             "is_off_hours": 0, "is_new_ip": 1, "bytes_out_60s": 70000,
             "unique_dst_ips_60s": 35, "error_rate": 0.92},
        ]

        # --- Normal vectors (well within training distribution) ---
        normal = [
            {"failed_logins_60s": 0, "unique_ports_10s": 1, "requests_per_min": 5,
             "is_off_hours": 0, "is_new_ip": 0, "bytes_out_60s": 500,
             "unique_dst_ips_60s": 1, "error_rate": 0.0},
            {"failed_logins_60s": 1, "unique_ports_10s": 2, "requests_per_min": 10,
             "is_off_hours": 0, "is_new_ip": 0, "bytes_out_60s": 1200,
             "unique_dst_ips_60s": 2, "error_rate": 0.05},
            {"failed_logins_60s": 0, "unique_ports_10s": 1, "requests_per_min": 3,
             "is_off_hours": 1, "is_new_ip": 0, "bytes_out_60s": 300,
             "unique_dst_ips_60s": 1, "error_rate": 0.0},
            {"failed_logins_60s": 2, "unique_ports_10s": 3, "requests_per_min": 15,
             "is_off_hours": 0, "is_new_ip": 1, "bytes_out_60s": 2000,
             "unique_dst_ips_60s": 3, "error_rate": 0.10},
            {"failed_logins_60s": 0, "unique_ports_10s": 2, "requests_per_min": 8,
             "is_off_hours": 0, "is_new_ip": 0, "bytes_out_60s": 800,
             "unique_dst_ips_60s": 2, "error_rate": 0.0},
        ]

        anomaly_hits = sum(1 for fv in anomalous if detector.predict(fv)[0])
        normal_hits = sum(1 for fv in normal if detector.predict(fv)[0])

        if anomaly_hits < 4:
            _fail(f"only {anomaly_hits}/5 anomalous vectors detected (need >=4)")
        if normal_hits > 1:
            _fail(f"{normal_hits}/5 normal vectors flagged as anomalous (need <=1)")

        # Verify score range
        _, score = detector.predict(anomalous[0])
        if not (0.0 <= score <= 1.0):
            _fail(f"anomaly_score={score} out of [0, 1] range")

        # Verify (False, 0.0) when model not loaded
        empty = IsolationForestDetector()
        result = empty.predict(normal[0])
        if result != (False, 0.0):
            _fail(f"unloaded detector should return (False, 0.0), got {result}")

    print("PASS: ml_detector self-test")
