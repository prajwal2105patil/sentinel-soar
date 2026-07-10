"""Synthetic labelled feature dataset for training the risk scorer.

IMPORTANT / HONESTY: this is SYNTHETIC data. It is generated from documented,
deliberately-overlapping distributions that encode SOC domain knowledge (malicious
sources tend to have more failed auths, higher failure ratios, privileged targets,
faster cadence, and bad reputation — but none of these alone is decisive). It is
NOT the 18-IP rule-detection label set, which is far too small to train/evaluate a
model honestly. Keeping the training data separate is what avoids circular
validation: the model is judged on a held-out split of THIS set (see ml/model.py).

The distributions overlap on purpose so the problem is non-trivial — a perfect
score would be a red flag, not a feature.
"""
from __future__ import annotations

import numpy as np

# Column order MUST match ml.features.FEATURE_NAMES.
#   failed_count, distinct_users, targets_privileged, failure_ratio,
#   mean_gap_seconds, off_hours_frac, is_known_bad


def make_dataset(n_per_class: int = 300, seed: int = 7, label_noise: float = 0.08):
    """Return (X, y): X is (2*n_per_class, 7) float features, y is 0/1 labels.

    Distributions overlap heavily and ~`label_noise` of labels are flipped, so a
    linear model lands around 0.85-0.93 on held-out data — realistic, not a
    suspiciously-perfect 1.0. The overlap is the point: benign brute-force-shaped
    noise and malicious low-and-slow both exist in the wild.
    """
    rng = np.random.default_rng(seed)

    def malicious(n: int) -> np.ndarray:
        return np.column_stack([
            rng.integers(2, 12, n).astype(float),                 # failed_count (low floor -> overlap)
            rng.integers(1, 6, n).astype(float),                  # distinct_users
            (rng.random(n) < 0.65).astype(float),                 # targets_privileged
            np.clip(rng.normal(0.78, 0.18, n), 0.20, 1.0),        # failure_ratio
            rng.uniform(3, 600, n),                               # mean_gap_seconds (fast..slow)
            np.clip(rng.normal(0.45, 0.30, n), 0.0, 1.0),         # off_hours_frac
            (rng.random(n) < 0.60).astype(float),                 # is_known_bad
        ])

    def benign(n: int) -> np.ndarray:
        return np.column_stack([
            rng.integers(0, 6, n).astype(float),                  # failed_count (overlaps malicious)
            rng.integers(1, 4, n).astype(float),                  # distinct_users
            (rng.random(n) < 0.20).astype(float),                 # targets_privileged
            np.clip(rng.normal(0.50, 0.28, n), 0.0, 1.0),         # failure_ratio (successes mixed in)
            rng.uniform(15, 6000, n),                             # mean_gap_seconds (wide)
            np.clip(rng.normal(0.25, 0.22, n), 0.0, 1.0),         # off_hours_frac
            (rng.random(n) < 0.15).astype(float),                 # is_known_bad
        ])

    X = np.vstack([malicious(n_per_class), benign(n_per_class)])
    y = np.r_[np.ones(n_per_class, dtype=int), np.zeros(n_per_class, dtype=int)]

    if label_noise:                          # flip a fraction of labels (real data is noisy)
        flip = rng.random(len(y)) < label_noise
        y[flip] = 1 - y[flip]

    order = rng.permutation(len(y))          # shuffle so the split isn't class-ordered
    return X[order], y[order]
