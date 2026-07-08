"""FastAPI surface for Sentinel-SOAR.

Endpoints (all require the X-API-Key header — see core/auth.py):
  POST /ingest      append raw log line(s) to the event store
  POST /investigate run one alert through the agent -> verdict + ATT&CK + response
  GET  /cases       list persisted, investigated alerts

Run:  uvicorn api.app:app --reload
Health check `GET /` is public.
"""
from __future__ import annotations

import functools
import json

import yaml
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import investigator
from core import cage as cage_mod
from core import db
from core.auth import require_api_key
from core.ingest import _parse_line

app = FastAPI(title="Sentinel-SOAR", version="0.3.0",
              description="AiStrike-mirroring mini SOAR — detect, triage, investigate, respond.")

RULES_DIR = db.ROOT / "detections" / "rules"


@functools.lru_cache(maxsize=1)
def _rule_meta() -> dict[str, dict]:
    """rule_id -> {title, mitre, severity} for enriching investigate payloads."""
    out = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        r = yaml.safe_load(path.read_text(encoding="utf-8"))
        out[r["id"]] = {"title": r["name"], "mitre": r.get("mitre", []),
                        "severity": r.get("severity", "medium")}
    return out


# ------------------------------------------------------------------ models
class IngestBody(BaseModel):
    lines: list[str] = Field(..., description="Raw auth-log lines to ingest.")


class AlertBody(BaseModel):
    rule_id: str
    source_ip: str
    event_count: int
    evidence: dict
    severity: str | None = None
    username: str | None = None
    title: str | None = None
    mitre: list[str] | None = None


# ------------------------------------------------------------------ routes
@app.get("/")
def health() -> dict:
    return {"service": "sentinel-soar", "status": "ok", "version": app.version,
            "langgraph": investigator.HAS_LANGGRAPH}


@app.post("/ingest")
def ingest(body: IngestBody, _: str = Depends(require_api_key)) -> dict:
    conn = db.connect()
    loaded, skipped = 0, 0
    for line in body.lines:
        ev = _parse_line(line)
        if ev is None:
            skipped += 1
            continue
        conn.execute(
            "INSERT INTO events (ts, event_type, username, source_ip, host, raw) "
            "VALUES (:ts, :event_type, :username, :source_ip, :host, :raw)", ev)
        loaded += 1
    conn.commit()
    conn.close()
    return {"loaded": loaded, "skipped": skipped}


@app.post("/investigate")
def investigate(body: AlertBody, _: str = Depends(require_api_key)) -> dict:
    meta = _rule_meta().get(body.rule_id, {})
    alert = {
        "rule_id": body.rule_id,
        "title": body.title or meta.get("title", body.rule_id),
        "severity": body.severity or meta.get("severity", "medium"),
        "source_ip": body.source_ip,
        "username": body.username,
        "event_count": body.event_count,
        "evidence": body.evidence,
        "mitre": body.mitre if body.mitre is not None else meta.get("mitre", []),
    }
    conn = db.connect()
    cage = cage_mod.Cage(conn)
    try:
        cage_mod.validate_alert(alert)
    except (TypeError, ValueError) as exc:
        conn.close()
        raise HTTPException(status_code=422, detail=f"invalid alert: {exc}")

    case = investigator.investigate(alert, cage)
    case["id"] = db.insert_alert(conn, alert, case)
    conn.close()
    return case


@app.get("/cases")
def cases(_: str = Depends(require_api_key)) -> dict:
    conn = db.connect()
    rows = conn.execute(
        "SELECT id, rule_id, title, severity, source_ip, username, verdict, escalated, "
        "attack, response, created_at FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["escalated"] = bool(d["escalated"])
        d["attack"] = json.loads(d["attack"]) if d["attack"] else []
        d["response"] = json.loads(d["response"]) if d["response"] else {}
        out.append(d)
    return {"count": len(out), "cases": out}
