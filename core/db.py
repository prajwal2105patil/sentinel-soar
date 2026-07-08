"""SQLite event store + schema.

Zero-setup, SQL-native store (mirrors the DREADNOUGHT warehouse decision). Holds
three tables: `events` (parsed log lines), `alerts` (detections + verdicts), and
`audit_log` (append-only record of every action the platform takes).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Repo-root-relative paths so the tool runs identically from any working dir.
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,          -- ISO-8601 event time
    event_type  TEXT NOT NULL,          -- auth_failure | auth_success | other
    username    TEXT,
    source_ip   TEXT,
    host        TEXT,
    raw         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    source_ip      TEXT,
    username       TEXT,
    event_count    INTEGER NOT NULL,
    first_ts       TEXT,
    last_ts        TEXT,
    evidence       TEXT,                -- JSON: cited event ids + summary
    enrichment     TEXT,                -- JSON: geo + reputation for source_ip
    attack         TEXT,                -- JSON: resolved MITRE ATT&CK techniques
    verdict        TEXT,                -- malicious | suspicious | benign
    verdict_reason TEXT,
    escalated      INTEGER DEFAULT 1,   -- 1 = sent to analyst; 0 = auto-suppressed
    response       TEXT,                -- JSON: selected playbook + actions + approval
    auto_triaged   INTEGER DEFAULT 0,   -- 1 if the agent triaged with no human
    created_at     TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    actor   TEXT NOT NULL,             -- which module/agent acted
    action  TEXT NOT NULL,
    target  TEXT,
    detail  TEXT                       -- JSON payload
);
"""


def connect() -> sqlite3.Connection:
    """Open (creating if needed) the event DB and ensure the schema exists."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_alert(conn: sqlite3.Connection, raw: dict[str, Any], case: dict[str, Any]) -> int:
    """Persist an investigated case to the alerts table. Shared by the batch
    pipeline and the API so both write identical rows. Returns the new alert id."""
    cur = conn.execute(
        "INSERT INTO alerts (rule_id, title, severity, source_ip, username, event_count, "
        "first_ts, last_ts, evidence, enrichment, attack, verdict, verdict_reason, "
        "escalated, response, auto_triaged, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (raw.get("rule_id"), raw.get("title"), raw.get("severity"), raw.get("source_ip"),
         raw.get("username"), raw.get("event_count"), raw.get("first_ts"), raw.get("last_ts"),
         json.dumps(raw.get("evidence")), json.dumps(case["enrichment"]),
         json.dumps(case["attack"]), case["verdict"], case["reason"],
         int(case["escalated"]), json.dumps(case["response"]), 1,
         datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    conn.commit()
    return int(cur.lastrowid)
