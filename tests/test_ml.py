"""Tests for the ML risk scorer: dataset, held-out metrics, live scoring, FN recovery."""
from __future__ import annotations

import numpy as np
import pytest

from core import db
from core.ingest import ingest
from ml import model
from ml.dataset import make_dataset
from ml.features import FEATURE_NAMES, features_for_ip

ML_HIGH = 0.70


@pytest.fixture(scope="module")
def conn():
    ingest()
    c = db.connect()
    yield c
    c.close()


# ------------------------------------------------------------------ dataset
def test_dataset_shape_and_balance():
    X, y = make_dataset(n_per_class=300, seed=7)
    assert X.shape == (600, len(FEATURE_NAMES))
    # label noise means it isn't exactly 300/300, but must stay roughly balanced
    assert 0.4 < y.mean() < 0.6


def test_dataset_is_deterministic():
    X1, y1 = make_dataset(seed=7)
    X2, y2 = make_dataset(seed=7)
    assert np.array_equal(X1, X2) and np.array_equal(y1, y2)


# ------------------------------------------------------------------ model
def test_held_out_metrics_are_honest_not_perfect():
    m = model.held_out_metrics()
    assert 0.80 <= m["precision"] <= 0.99   # good but not a suspicious 1.0
    assert m["recall"] >= 0.80
    assert m["roc_auc"] >= 0.85
    assert m["n_test"] >= 100


def test_score_is_a_probability_and_deterministic():
    feats = {n: 0.0 for n in FEATURE_NAMES}
    s1 = model.get_scorer().score_features(feats)
    s2 = model.get_scorer().score_features(feats)
    assert 0.0 <= s1 <= 1.0 and s1 == s2


# ------------------------------------------------------------------ live scoring
def test_features_cover_all_names(conn):
    feats = features_for_ip(conn, "45.133.1.88")
    assert set(feats) == set(FEATURE_NAMES)


def test_ml_recovers_rule_false_negative(conn):
    # 62.4.5.9 is malicious but below the brute-force rule threshold (deliberate FN).
    # The behavioural model must flag it high-risk.
    assert model.assess_ip(conn, "62.4.5.9")["risk_score"] >= ML_HIGH


def test_ml_keeps_benign_users_low(conn):
    # Legit users must not be pushed into the high band (no new false alarms).
    for ip in ("198.51.100.7", "103.21.58.10"):
        assert model.assess_ip(conn, ip)["risk_score"] < ML_HIGH
