"""API surface tests via FastAPI TestClient (no server needed)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.app import app

KEY = {"X-API-Key": "dev-sentinel-key"}


@pytest.fixture(scope="module")
def client(pipeline) -> TestClient:
    # depend on `pipeline` so events.db + alerts table exist before API calls
    return TestClient(app)


def test_health_is_public(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_auth_required(client):
    assert client.get("/cases").status_code == 401
    assert client.get("/cases", headers={"X-API-Key": "wrong"}).status_code == 401


def test_investigate_returns_verdict_attack_response(client):
    payload = {
        "rule_id": "RULE-BRUTE-FORCE-001", "source_ip": "45.133.1.88",
        "event_count": 6, "severity": "critical", "username": "postgres",
        "evidence": {"event_ids": [17, 18], "targeted_users": ["postgres"],
                     "success_after_failures": {"username": "postgres", "ts": "2025-06-14T09:05:40+00:00"}},
    }
    r = client.post("/investigate", json=payload, headers=KEY)
    assert r.status_code == 200
    j = r.json()
    assert j["verdict"] == "malicious"
    assert {"T1110", "T1021.004"}.issubset({t["id"] for t in j["attack"]})
    # critical alert -> all actions analyst-gated
    assert all(a["requires_approval"] for a in j["response"]["actions"])


def test_investigate_malformed_returns_422(client):
    r = client.post("/investigate",
                    json={"rule_id": "X", "source_ip": "1.1.1.1", "event_count": 1, "evidence": None},
                    headers=KEY)
    assert r.status_code == 422


def test_ingest_and_cases(client):
    r = client.post("/ingest",
                    json={"lines": ["Jun 14 11:00:00 web01 sshd[9]: Failed password for root "
                                    "from 9.9.9.9 port 1 ssh2"]},
                    headers=KEY)
    assert r.status_code == 200 and r.json()["loaded"] == 1

    r = client.get("/cases", headers=KEY)
    assert r.status_code == 200
    assert r.json()["count"] >= 1
