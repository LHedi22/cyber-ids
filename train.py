#!/usr/bin/env python3
"""
train.py — CyberIDS standalone model training script.

Generates synthetic traffic data, trains IsolationForest on normal samples only,
validates detection rates on attack samples, and saves the model bundle.

Usage:
    python train.py
    python train.py --samples 20000 --attack-samples 1000 --seed 0
"""

import argparse
import os
import random
import sys
import time

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

N_NORMAL_DEFAULT = 10_000
N_ATTACK_DEFAULT = 500
SEP = "─" * 45   # ─────…


# ---------------------------------------------------------------------------
# Synthetic data generators
# ---------------------------------------------------------------------------

def _gen_train_normal(n: int) -> list[dict]:
    """
    Generate n feature dicts representing normal (benign) network traffic.

    Distributions match _generate_synthetic_normal() in pipeline/ml_detector.py
    so that auto-train and explicit train produce comparable models.
    """
    out = []
    for _ in range(n):
        out.append({
            "failed_logins_60s":  random.choices([0, 1, 2, 3, 4], weights=[60, 20, 10, 7, 3])[0],
            "unique_ports_10s":   random.choices([1, 2, 3, 4, 5, 6], weights=[50, 25, 12, 7, 4, 2])[0],
            "requests_per_min":   random.randint(1, 30),
            "is_off_hours":       1 if random.random() < 0.20 else 0,
            "is_new_ip":          1 if random.random() < 0.10 else 0,
            "bytes_out_60s":      random.randint(100, 5000),
            "unique_dst_ips_60s": random.randint(1, 5),
            "error_rate":         round(random.uniform(0.0, 0.20), 3),
        })
    return out


def _gen_validate_normal(n: int) -> list[dict]:
    """
    Generate n clearly-benign feature dicts for false-positive validation.

    Uses a tighter distribution than training so we can verify the model
    does NOT flag unambiguously normal traffic. (Training samples include
    borderline-normal edge cases like 20% off-hours; validation does not.)
    """
    out = []
    for _ in range(n):
        out.append({
            "failed_logins_60s":  random.choices([0, 1], weights=[85, 15])[0],
            "unique_ports_10s":   random.choices([1, 2, 3], weights=[65, 25, 10])[0],
            "requests_per_min":   random.randint(1, 15),
            "is_off_hours":       0,
            "is_new_ip":          0,
            "bytes_out_60s":      random.randint(100, 2500),
            "unique_dst_ips_60s": random.randint(1, 3),
            "error_rate":         round(random.uniform(0.0, 0.08), 3),
        })
    return out


def _gen_attacks(n: int) -> list[dict]:
    """
    Generate n synthetic attack feature dicts across 5 attack types.

    Only used for validation — never fed into training.
    Distributions are calibrated to be clearly outside normal range
    so that a well-trained model can reliably detect them.
    """
    per_type = n // 5
    remainder = n - per_type * 4
    attacks: list[dict] = []

    # ── 1. SSH Brute Force ──────────────────────────────────────────
    # High failed logins, targeting one port, very high error rate
    for _ in range(per_type):
        attacks.append({
            "failed_logins_60s":  random.randint(15, 80),
            "unique_ports_10s":   random.randint(1, 3),
            "requests_per_min":   random.randint(40, 120),
            "is_off_hours":       random.choice([0, 1]),
            "is_new_ip":          random.choice([0, 1]),
            "bytes_out_60s":      random.randint(300, 2500),
            "unique_dst_ips_60s": random.randint(1, 2),
            "error_rate":         round(random.uniform(0.70, 0.99), 3),
        })

    # ── 2. Port Scan ────────────────────────────────────────────────
    # Many unique ports hit in 10 s, many unique destination IPs
    for _ in range(per_type):
        attacks.append({
            "failed_logins_60s":  random.randint(0, 2),
            "unique_ports_10s":   random.randint(30, 200),
            "requests_per_min":   random.randint(80, 400),
            "is_off_hours":       random.choice([0, 1]),
            "is_new_ip":          1,
            "bytes_out_60s":      random.randint(100, 1200),
            "unique_dst_ips_60s": random.randint(20, 80),
            "error_rate":         round(random.uniform(0.10, 0.45), 3),
        })

    # ── 3. Data Exfiltration ─────────────────────────────────────────
    # Massive bytes_out to a brand-new (never-seen) external IP
    for _ in range(per_type):
        attacks.append({
            "failed_logins_60s":  random.randint(0, 2),
            "unique_ports_10s":   random.randint(1, 3),
            "requests_per_min":   random.randint(2, 15),
            "is_off_hours":       random.choice([0, 1]),
            "is_new_ip":          1,
            "bytes_out_60s":      random.randint(60_000, 500_000),
            "unique_dst_ips_60s": random.randint(1, 3),
            "error_rate":         round(random.uniform(0.0, 0.10), 3),
        })

    # ── 4. Web / SQL Injection ──────────────────────────────────────
    # Automated high-rate requests with elevated payloads and error rate
    for _ in range(per_type):
        attacks.append({
            "failed_logins_60s":  random.randint(0, 5),
            "unique_ports_10s":   random.randint(1, 3),
            "requests_per_min":   random.randint(100, 500),
            "is_off_hours":       random.choice([0, 1]),
            "is_new_ip":          random.choice([0, 1]),
            "bytes_out_60s":      random.randint(8_000, 90_000),
            "unique_dst_ips_60s": random.randint(1, 3),
            "error_rate":         round(random.uniform(0.30, 0.70), 3),
        })

    # ── 5. Off-Hours Intrusion (takes remainder to reach exact n) ───
    # Successful logins at unusual hours with elevated failed attempts
    for _ in range(remainder):
        attacks.append({
            "failed_logins_60s":  random.randint(8, 40),
            "unique_ports_10s":   random.randint(2, 8),
            "requests_per_min":   random.randint(20, 80),
            "is_off_hours":       1,
            "is_new_ip":          random.choice([0, 1]),
            "bytes_out_60s":      random.randint(1_000, 20_000),
            "unique_dst_ips_60s": random.randint(1, 6),
            "error_rate":         round(random.uniform(0.50, 0.95), 3),
        })

    random.shuffle(attacks)
    return attacks


# ---------------------------------------------------------------------------
# Batch validation helper
# ---------------------------------------------------------------------------

def _batch_count_anomalies(detector, vectors: list[dict]) -> int:
    """
    Count anomalies in vectors using a single sklearn batch predict call.

    Bypasses the per-sample dict→numpy overhead of detector.predict(), making
    validation of 10k+ samples 100x faster than calling predict() in a loop.
    Accesses detector internals directly — safe because both live in train.py.
    """
    import numpy as np
    from pipeline.ml_detector import FEATURE_ORDER

    X = np.array([[fv[k] for k in FEATURE_ORDER] for fv in vectors], dtype=float)
    X_scaled = detector._scaler.transform(X)
    labels = detector._model.predict(X_scaled)   # -1 = anomaly, 1 = normal
    return int((labels == -1).sum())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _progress(label: str, fn, *args, **kwargs):
    """Run fn(*args, **kwargs), printing label + elapsed time."""
    print(f"  {label}", end="", flush=True)
    t0 = time.monotonic()
    result = fn(*args, **kwargs)
    print(f"  ✓  ({time.monotonic() - t0:.1f}s)")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train CyberIDS IsolationForest anomaly detection model",
    )
    parser.add_argument(
        "--samples", type=int, default=N_NORMAL_DEFAULT,
        metavar="N",
        help=f"Number of normal training samples (default: {N_NORMAL_DEFAULT:,})",
    )
    parser.add_argument(
        "--attack-samples", type=int, default=N_ATTACK_DEFAULT,
        metavar="N",
        help=f"Number of attack validation samples (default: {N_ATTACK_DEFAULT})",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    # Import after dotenv so MODEL_PATH / CONTAMINATION env vars are set
    try:
        from pipeline.ml_detector import IsolationForestDetector, CONTAMINATION, MODEL_PATH
    except ImportError as exc:
        print(
            f"\n  ERROR: Cannot import pipeline.ml_detector — {exc}\n"
            "  Run from the project root:  python train.py\n",
            file=sys.stderr,
        )
        sys.exit(1)

    print()
    print("  CyberIDS — Isolation Forest Training")
    print(SEP)

    # --- Generate data ---
    train_normal = _progress(
        f"Generating {args.samples:,} normal training samples ...",
        _gen_train_normal, args.samples,
    )
    val_normal = _progress(
        f"Generating {args.samples:,} normal validation samples ...",
        _gen_validate_normal, args.samples,
    )
    attacks = _progress(
        f"Generating {args.attack_samples:,} attack validation samples ...",
        _gen_attacks, args.attack_samples,
    )

    # --- Train (normal data only) ---
    detector = IsolationForestDetector()
    _progress(
        f"Training IsolationForest  (n={args.samples:,}, contamination={CONTAMINATION}) ...",
        detector.train, train_normal,
    )

    # --- Validate (batch — avoids 20k individual predict calls) ---
    print("  Validating ...", end="", flush=True)
    t_val = time.monotonic()

    attack_detected = _batch_count_anomalies(detector, attacks)
    normal_flagged  = _batch_count_anomalies(detector, val_normal)

    print(f"  ✓  ({time.monotonic() - t_val:.1f}s)")

    attack_pct = attack_detected / args.attack_samples * 100
    normal_pct = normal_flagged  / args.samples        * 100

    # --- Report ---
    print()
    print("  Training complete.")
    print(SEP)
    print(f"  Samples trained on:   {args.samples:>9,}")
    print(f"  Contamination:        {CONTAMINATION:>9.2f}")
    print(
        f"  Validation (attacks): {attack_detected:>5}/{args.attack_samples}"
        f"  detected  ({attack_pct:5.1f}%)"
    )
    print(
        f"  Validation (normal):  {normal_flagged:>5}/{args.samples}"
        f"  flagged   ({normal_pct:5.1f}%)"
    )
    print(f"  Model saved to:       {MODEL_PATH}")
    print()

    # Warn if results look suspicious
    warn = False
    if attack_pct < 75.0:
        print(
            f"  WARNING  low attack detection {attack_pct:.1f}%"
            " — consider retraining with --seed or wider attack distributions",
            file=sys.stderr,
        )
        warn = True
    if normal_pct > 15.0:
        print(
            f"  WARNING  high false-positive rate {normal_pct:.1f}%"
            " — consider reducing contamination or increasing training samples",
            file=sys.stderr,
        )
        warn = True

    sys.exit(1 if warn else 0)


if __name__ == "__main__":
    main()
