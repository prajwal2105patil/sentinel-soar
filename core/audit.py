"""Append-only audit log.

Every action the platform takes — ingest, detection, verdict — is written here.
This is the governance backbone (SOC 2 style): the `Audit Completeness` metric is
100% only because every actor routes through `log_action`.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_action(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
) -> int:
    """Append one immutable entry to audit_log. Returns the new row id."""
    cur = conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
        (_now(), actor, action, target, json.dumps(detail or {})),
    )
    conn.commit()
    return int(cur.lastrowid)


def count_actions(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
