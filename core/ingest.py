"""Ingest: parse sample_auth.log -> `events` table via SQL.

Run:  python -m core.ingest

Idempotent: clears and reloads the `events` table each run so re-ingesting is
never a broken mid-state. Every run is recorded in the audit log.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from core import audit, db

LOG_PATH = db.DATA_DIR / "sample_auth.log"

# syslog assumes the current year; the sample log is dated but yearless. Pin it so
# the demo is deterministic across runs and machines.
DEFAULT_YEAR = 2025
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_TS_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)")
_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_OK_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


def _parse_line(line: str) -> dict | None:
    """Return a normalized event dict, or None if the line is unparseable."""
    m = _TS_RE.match(line)
    if not m:
        return None
    ts = datetime(
        DEFAULT_YEAR,
        _MONTHS[m.group("mon")],
        int(m.group("day")),
        *(int(x) for x in m.group("time").split(":")),
        tzinfo=timezone.utc,
    ).isoformat(timespec="seconds")
    host = m.group("host")

    if (fm := _FAIL_RE.search(line)):
        return {"ts": ts, "event_type": "auth_failure", "username": fm.group("user"),
                "source_ip": fm.group("ip"), "host": host, "raw": line.rstrip("\n")}
    if (om := _OK_RE.search(line)):
        return {"ts": ts, "event_type": "auth_success", "username": om.group("user"),
                "source_ip": om.group("ip"), "host": host, "raw": line.rstrip("\n")}
    return {"ts": ts, "event_type": "other", "username": None,
            "source_ip": None, "host": host, "raw": line.rstrip("\n")}


def ingest(log_path: Path = LOG_PATH) -> int:
    """Parse the log into the events table. Returns the number of events loaded."""
    # Rebuild the store from scratch so each pipeline run is clean and the schema
    # is current (events.db is disposable / git-ignored).
    if db.DB_PATH.exists():
        db.DB_PATH.unlink()
    conn = db.connect()
    audit.log_action(conn, actor="ingest", action="ingest_start",
                     target=str(log_path), detail={"source": log_path.name})

    conn.execute("DELETE FROM events")  # idempotent reload
    events, skipped = [], 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = _parse_line(line)
        if ev is None:
            skipped += 1
            continue
        events.append(ev)

    conn.executemany(
        "INSERT INTO events (ts, event_type, username, source_ip, host, raw) "
        "VALUES (:ts, :event_type, :username, :source_ip, :host, :raw)",
        events,
    )
    conn.commit()

    by_type = dict(conn.execute(
        "SELECT event_type, COUNT(*) FROM events GROUP BY event_type").fetchall())
    audit.log_action(conn, actor="ingest", action="ingest_complete", target=str(log_path),
                     detail={"loaded": len(events), "skipped": skipped, "by_type": by_type})

    print(f"[ingest] loaded {len(events)} events ({skipped} skipped) -> {db.DB_PATH.name}")
    for et, n in sorted(by_type.items()):
        print(f"         {et:<14} {n}")
    conn.close()
    return len(events)


if __name__ == "__main__":
    ingest()
