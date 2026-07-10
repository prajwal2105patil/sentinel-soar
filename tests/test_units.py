"""Unit tests for the individual components: enrich, cage, respond, triage."""
from __future__ import annotations

import sqlite3

import pytest

from core import auth, db, detect, enrich, respond, triage
from core.cage import Cage, validate_alert


# ------------------------------------------------------------------ enrich
def test_enrich_known_bad_geo():
    e = enrich.enrich_ip("45.133.1.88")
    assert e["enriched"] is True
    assert e["geo"]["city"] == "Amsterdam"
    assert e["reputation"]["is_known_bad"] is True


def test_enrich_internal_ip():
    e = enrich.enrich_ip("10.0.0.5")
    assert e["reputation"]["category"] == "internal"
    assert e["geo"] is None


def test_enrich_documentation_range_is_not_private():
    # Regression: Python 3.12 folds TEST-NET ranges into is_private; our mock uses
    # them as public stand-ins, so they must resolve to geo, not "internal".
    e = enrich.enrich_ip("203.0.113.44")
    assert e["reputation"]["category"] != "internal"
    assert e["geo"] is not None


def test_enrich_none():
    e = enrich.enrich_ip(None)
    assert e["enriched"] is False


# ------------------------------------------------------------------ cage
def test_cage_contains_exception():
    cage = Cage(db.connect())

    def boom():
        raise RuntimeError("kaboom")

    assert cage.run("boom", boom, fallback="safe") == "safe"
    assert cage.contained == 1
    assert cage.escapes == 0


def test_cage_selfcheck_zero_escapes():
    cage = Cage(db.connect())
    cage.selfcheck()
    assert cage.escapes == 0
    assert cage.contained >= 5


@pytest.mark.parametrize("bad", [None, {}, {"source_ip": None}, "x", {"rule_id": "x"}])
def test_validate_alert_rejects_malformed(bad):
    with pytest.raises((TypeError, ValueError)):
        validate_alert(bad)


# ------------------------------------------------------------------ respond
def test_response_critical_gates_all_actions():
    alert = {"rule_id": "RULE-BRUTE-FORCE-001", "severity": "critical"}
    r = respond.build_response(alert, "malicious")
    assert r["requires_analyst"] is True
    assert all(a["requires_approval"] for a in r["actions"])


def test_response_high_gates_only_account_action():
    alert = {"rule_id": "RULE-BRUTE-FORCE-001", "severity": "high"}
    r = respond.build_response(alert, "malicious")
    gated = {a["action"] for a in r["actions"] if a["requires_approval"]}
    assert "disable_account" in gated
    assert "block_source_ip" not in gated


def test_response_benign_is_suppressed():
    alert = {"rule_id": "RULE-BRUTE-FORCE-001", "severity": "low"}
    r = respond.build_response(alert, "benign")
    assert r["suppressed"] is True
    assert r["actions"] == []


# ------------------------------------------------------------------ triage
def test_triage_brute_force_malicious():
    alert = {"source_ip": "1.2.3.4", "event_count": 8}
    v = triage.triage(alert, {"event_ids": [1], "targeted_users": ["root"], "window_seconds": 120,
                              "success_after_failures": None})
    assert v["verdict"] == "malicious"


def test_triage_review_benign_when_low_and_clean():
    alert = {"source_ip": "198.51.100.7", "event_count": 1}
    ev = {"review": True, "username": "prajwal", "failure_count": 1, "event_ids": [4, 5]}
    enr = {"reputation": {"category": "residential", "is_known_bad": False}}
    v = triage.triage(alert, ev, enr)
    assert v["verdict"] == "benign"


def test_triage_review_escalates_when_known_bad():
    alert = {"source_ip": "45.133.1.88", "event_count": 2}
    ev = {"review": True, "username": "x", "failure_count": 2, "event_ids": [1, 2]}
    enr = {"reputation": {"category": "bulletproof-hosting", "is_known_bad": True}}
    v = triage.triage(alert, ev, enr)
    assert v["verdict"] == "suspicious"


# ------------------------------------------------------------------ enrich caching (#7)
def test_enrich_is_cached_and_returns_independent_copies():
    enrich._enrich_ip_cached.cache_clear()
    a = enrich.enrich_ip("45.133.1.88")
    b = enrich.enrich_ip("45.133.1.88")
    assert a == b and a is not b                          # deep copies: equal, distinct
    assert enrich._enrich_ip_cached.cache_info().hits >= 1  # second call hit the cache
    # mutating a returned copy must not corrupt the cache or the intel table
    a["reputation"]["is_known_bad"] = False
    assert enrich.enrich_ip("45.133.1.88")["reputation"]["is_known_bad"] is True


# ------------------------------------------------------------------ auth config (#3)
def test_expected_key_dev_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_ENV", raising=False)
    assert auth.expected_key() == auth.DEV_API_KEY


def test_expected_key_prod_requires_key(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "prod")
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        auth.expected_key()


def test_expected_key_prod_with_key(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "prod")
    monkeypatch.setenv("SENTINEL_API_KEY", "real-key")
    assert auth.expected_key() == "real-key"


# ------------------------------------------------------------------ impossible-travel dt=0 (#1)
_IT_RULE = {
    "id": "R-IT", "name": "Impossible Travel", "severity": "high",
    "kind": "impossible_travel", "match": {"event_type": "auth_success"},
    "group_by": "username", "params": {"max_kmh": 900, "min_distance_km": 50}, "mitre": [],
}


def _mem_conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(db.SCHEMA)
    return c


def _add_success(c, ts, user, ip):
    c.execute("INSERT INTO events (ts, event_type, username, source_ip, host, raw) "
              "VALUES (?, 'auth_success', ?, ?, 'h', 'raw')", (ts, user, ip))


def test_impossible_travel_same_timestamp_colocated_not_flagged():
    # Regression: two same-second logins from co-located IPs (dt=0) must NOT be
    # flagged — previously dt=0 forced implied speed to infinity -> false positive.
    c = _mem_conn()
    _add_success(c, "2025-06-14T08:00:00+00:00", "bob", "198.51.100.7")   # Mumbai
    _add_success(c, "2025-06-14T08:00:00+00:00", "bob", "198.51.100.23")  # Mumbai (same geo)
    c.commit()
    assert detect._evaluate_impossible_travel(c, _IT_RULE) == []


def test_impossible_travel_same_timestamp_faraway_is_flagged():
    # Genuinely impossible: same second, Mumbai vs Amsterdam -> still caught.
    c = _mem_conn()
    _add_success(c, "2025-06-14T08:00:00+00:00", "bob", "198.51.100.7")   # Mumbai
    _add_success(c, "2025-06-14T08:00:00+00:00", "bob", "45.133.1.88")    # Amsterdam
    c.commit()
    out = detect._evaluate_impossible_travel(c, _IT_RULE)
    assert len(out) == 1 and out[0]["source_ip"] == "45.133.1.88"
