"""Behavioural feature extraction for the ML risk scorer.

Pulls per-source-IP aggregates straight out of the SQLite event store with SQL
(the same store the rules query) and combines them with enrichment reputation.
The SAME FEATURE_NAMES / order is used by the synthetic training set
(ml/dataset.py), so a live IP and a training row are directly comparable.
"""
from __future__ import annotations

from datetime import datetime

from core import enrich

FEATURE_NAMES = [
    "failed_count",        # number of failed auth attempts
    "distinct_users",      # distinct usernames the source touched
    "targets_privileged",  # 1 if it targeted root/admin/postgres/... else 0
    "failure_ratio",       # failed / (failed + success) auth attempts
    "mean_gap_seconds",    # avg seconds between failed attempts (cadence)
    "off_hours_frac",      # fraction of activity outside 08:00-20:00
    "is_known_bad",        # 1 if enrichment flags the source reputation as bad
]

_PRIVILEGED = {"root", "admin", "administrator", "postgres", "oracle", "sa"}
_NO_BURST_GAP = 3600.0   # neutral cadence when there aren't >=2 failures to time


def _ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def _hour(s: str) -> int:
    return datetime.fromisoformat(s).hour


def features_for_ip(conn, source_ip: str) -> dict:
    """Compute the FEATURE_NAMES vector (as a dict) for one source IP."""
    rows = [dict(r) for r in conn.execute(
        "SELECT event_type, username, ts FROM events WHERE source_ip=? ORDER BY ts",
        (source_ip,))]

    failed = [r for r in rows if "fail" in (r["event_type"] or "")]
    success = [r for r in rows if r["event_type"] in
               ("auth_success", "cloud_login", "cloud_root_login")]
    attempts = len(failed) + len(success)
    users = {r["username"] for r in rows if r["username"]}

    fail_ts = [_ts(r["ts"]) for r in failed]
    gaps = [b - a for a, b in zip(fail_ts, fail_ts[1:])]
    mean_gap = (sum(gaps) / len(gaps)) if gaps else _NO_BURST_GAP

    hours = [_hour(r["ts"]) for r in rows]
    off = (sum(1 for h in hours if h < 8 or h >= 20) / len(hours)) if hours else 0.0

    return {
        "failed_count": float(len(failed)),
        "distinct_users": float(len(users)),
        "targets_privileged": 1.0 if (users & _PRIVILEGED) else 0.0,
        "failure_ratio": (len(failed) / attempts) if attempts else 0.0,
        "mean_gap_seconds": float(mean_gap),
        "off_hours_frac": float(off),
        "is_known_bad": 1.0 if enrich.enrich_ip(source_ip)["reputation"]["is_known_bad"] else 0.0,
    }


def to_vector(features: dict) -> list[float]:
    """Ordered feature vector for the model."""
    return [float(features[name]) for name in FEATURE_NAMES]
