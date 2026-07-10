"""The risk-scorer model: train, evaluate on a held-out split, score live IPs.

A StandardScaler + LogisticRegression pipeline (interpretable, tiny, deterministic).
The DEPLOYED scorer is fit on the TRAIN split only, and the reported metrics are
computed on the held-out TEST split — so the numbers describe exactly the model
that does the scoring (no train-on-everything-then-quote-training-accuracy trick).
"""
from __future__ import annotations

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.dataset import make_dataset
from ml.features import FEATURE_NAMES, features_for_ip, to_vector


class RiskScorer:
    def __init__(self, pipe):
        self._pipe = pipe

    def score_vector(self, vec: list[float]) -> float:
        """P(malicious) in [0, 1] for an ordered feature vector."""
        return float(self._pipe.predict_proba([vec])[0, 1])

    def score_features(self, features: dict) -> float:
        return self.score_vector(to_vector(features))

    def coefficients(self) -> dict:
        lr = self._pipe.named_steps["logisticregression"]
        return dict(zip(FEATURE_NAMES, (round(float(c), 3) for c in lr.coef_[0])))


def train(seed: int = 7, test_size: float = 0.3) -> tuple[RiskScorer, dict]:
    """Train on a stratified split; return (scorer_fit_on_train, held_out_metrics)."""
    X, y = make_dataset(seed=seed)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=seed)

    pipe = make_pipeline(StandardScaler(),
                         LogisticRegression(max_iter=1000, random_state=seed))
    pipe.fit(X_tr, y_tr)

    proba = pipe.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "precision": round(float(precision_score(y_te, pred)), 3),
        "recall": round(float(recall_score(y_te, pred)), 3),
        "f1": round(float(f1_score(y_te, pred)), 3),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 3),
        "n_train": int(len(y_tr)),
        "n_test": int(len(y_te)),
    }
    return RiskScorer(pipe), metrics


_SCORER: RiskScorer | None = None
_METRICS: dict | None = None


def get_scorer() -> RiskScorer:
    """Lazily train + cache the deterministic model (sub-second, ~600 samples)."""
    global _SCORER, _METRICS
    if _SCORER is None:
        _SCORER, _METRICS = train()
    return _SCORER


def held_out_metrics() -> dict:
    if _METRICS is None:
        get_scorer()
    return _METRICS


def assess_ip(conn, source_ip: str) -> dict:
    """Score a live source IP from the event store. Returns risk_score + band +
    the features behind it (so a verdict citing it stays explainable)."""
    feats = features_for_ip(conn, source_ip)
    score = get_scorer().score_features(feats)
    band = "high" if score >= 0.70 else "medium" if score >= 0.40 else "low"
    return {"risk_score": round(score, 3), "risk_band": band, "features": feats}
