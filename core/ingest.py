"""Ingest: pluggable telemetry sources -> `events` table via SQL.

Sources:
  auth        data/sample_auth.log     (syslog sshd lines)      source='auth'
  cloudtrail  data/cloudtrail.jsonl    (CloudTrail-style JSON)  source='cloudtrail'

Run:  python -m core.ingest

Idempotent: rebuilds the event store each run so re-ingesting is never a broken
mid-state. Every run is recorded in the audit log.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from core import audit, db

LOG_PATH = db.DATA_DIR / "sample_auth.log"
CLOUD_PATH = db.DATA_DIR / "cloudtrail.jsonl"

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


# ------------------------------------------------------------------ auth source
def _parse_line(line: str) -> dict | None:
    """Return a normalized auth event dict, or None if the line is unparseable."""
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
                "source_ip": fm.group("ip"), "host": host, "source": "auth",
                "raw": line.rstrip("\n")}
    if (om := _OK_RE.search(line)):
        return {"ts": ts, "event_type": "auth_success", "username": om.group("user"),
                "source_ip": om.group("ip"), "host": host, "source": "auth",
                "raw": line.rstrip("\n")}
    return {"ts": ts, "event_type": "other", "username": None,
            "source_ip": None, "host": host, "source": "auth", "raw": line.rstrip("\n")}


def _load_auth(log_path: Path) -> tuple[list[dict], int]:
    events, skipped = [], 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = _parse_line(line)
        if ev is None:
            skipped += 1
            continue
        events.append(ev)
    return events, skipped


# ------------------------------------------------------------------ cloud source
def _parse_cloud_record(rec: dict) -> dict | None:
    """Map one CloudTrail-style record into the events schema, or None if unusable.

    event_type mapping:
      ConsoleLogin Success + userName==root  -> cloud_root_login
      CreateAccessKey                        -> cloud_create_access_key
      ConsoleLogin Success (non-root)        -> cloud_login
      ConsoleLogin Failure                   -> cloud_login_failure
      anything else                          -> cloud_other
    host carries the awsRegion (the closest analogue to a host boundary).
    """
    try:
        ts = datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00")) \
            .isoformat(timespec="seconds")
        name = rec.get("eventName")
        user = (rec.get("userIdentity") or {}).get("userName")
        ip = rec.get("sourceIPAddress")
        region = rec.get("awsRegion")
    except (KeyError, TypeError, ValueError):
        return None

    if name == "ConsoleLogin":
        ok = (rec.get("responseElements") or {}).get("ConsoleLogin") == "Success"
        if not ok:
            event_type = "cloud_login_failure"
        elif user == "root":
            event_type = "cloud_root_login"
        else:
            event_type = "cloud_login"
    elif name == "CreateAccessKey":
        event_type = "cloud_create_access_key"
    else:
        event_type = "cloud_other"

    return {"ts": ts, "event_type": event_type, "username": user, "source_ip": ip,
            "host": region, "source": "cloudtrail",
            "raw": json.dumps(rec, separators=(",", ":"))}


def _load_cloud(cloud_path: Path) -> tuple[list[dict], int]:
    if not cloud_path.exists():
        return [], 0
    events, skipped = [], 0
    for line in cloud_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        ev = _parse_cloud_record(rec)
        if ev is None:
            skipped += 1
            continue
        events.append(ev)
    return events, skipped


# ------------------------------------------------------------------ driver
def ingest(log_path: Path = LOG_PATH, cloud_path: Path = CLOUD_PATH) -> int:
    """Parse all telemetry sources into the events table. Returns events loaded."""
    # Rebuild the store from scratch so each pipeline run is clean and the schema
    # is current (events.db is disposable / git-ignored).
    if db.DB_PATH.exists():
        db.DB_PATH.unlink()
    conn = db.connect()
    audit.log_action(conn, actor="ingest", action="ingest_start",
                     target=str(log_path),
                     detail={"sources": [log_path.name] +
                             ([cloud_path.name] if cloud_path else [])})

    conn.execute("DELETE FROM events")  # idempotent reload
    auth_events, auth_skipped = _load_auth(log_path)
    cloud_events, cloud_skipped = _load_cloud(cloud_path) if cloud_path else ([], 0)
    events = auth_events + cloud_events
    skipped = auth_skipped + cloud_skipped

    conn.executemany(
        "INSERT INTO events (ts, event_type, username, source_ip, host, source, raw) "
        "VALUES (:ts, :event_type, :username, :source_ip, :host, :source, :raw)",
        events,
    )
    conn.commit()

    by_type = dict(conn.execute(
        "SELECT event_type, COUNT(*) FROM events GROUP BY event_type").fetchall())
    by_source = dict(conn.execute(
        "SELECT source, COUNT(*) FROM events GROUP BY source").fetchall())
    audit.log_action(conn, actor="ingest", action="ingest_complete", target=str(log_path),
                     detail={"loaded": len(events), "skipped": skipped,
                             "by_type": by_type, "by_source": by_source})

    print(f"[ingest] loaded {len(events)} events ({skipped} skipped) -> {db.DB_PATH.name}")
    for src, n in sorted(by_source.items()):
        print(f"         source={src:<11} {n}")
    for et, n in sorted(by_type.items()):
        print(f"         {et:<24} {n}")
    conn.close()
    return len(events)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Ingest telemetry into the event store.")
    ap.add_argument("--log", type=Path, default=LOG_PATH,
                    help="auth/syslog file. Real sshd logs work as-is "
                         "(e.g. loghub OpenSSH — see scripts/fetch_public_sample.py).")
    ap.add_argument("--cloud", type=Path, default=CLOUD_PATH,
                    help="CloudTrail-style JSONL file.")
    ap.add_argument("--no-cloud", action="store_true", help="skip the cloud source.")
    a = ap.parse_args()
    ingest(a.log, None if a.no_cloud else a.cloud)

