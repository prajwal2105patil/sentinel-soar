"""Tests for the SQL hunt CLI (cli/hunt.py)."""
from __future__ import annotations

import pytest

from cli import hunt
from core import db
from core.detect import detect
from core.ingest import ingest


@pytest.fixture(scope="module")
def conn():
    ingest()
    detect(verbose=False)      # populate alerts + audit_log for the cases/audit hunts
    c = db.connect()
    yield c
    c.close()


def test_top_talkers_ranks_by_failures(conn):
    cols, rows = hunt.run_hunt(conn, "top-talkers", (5,))
    assert cols[:2] == ["source_ip", "failures"]
    assert rows[0][0] == "203.0.113.44" and rows[0][1] == 8   # busiest brute-force source


def test_brute_window_excludes_low_and_slow(conn):
    # 62.4.5.9 makes 4 root failures ~90s apart -> below the 5-in-120s shape, so the
    # SQL brute hunt (like the rule) must NOT list it. That gap is the ML's job.
    cols, rows = hunt.run_hunt(conn, "brute", (5, 120, 50))
    ips = {r[0] for r in rows}
    assert "203.0.113.44" in ips
    assert "62.4.5.9" not in ips


def test_spray_respects_min_users(conn):
    cols, rows = hunt.run_hunt(conn, "spray", (4, 20))
    assert rows and all(r[1] >= 4 for r in rows)


def test_timeline_filters_by_source_ip(conn):
    params = {"src_ip": "45.133.1.88", "user": None, "since": None, "limit": 50}
    cols, rows = hunt.run_hunt(conn, "timeline", params)
    assert rows and all(r[3] == "45.133.1.88" for r in rows)


def test_audit_and_cases_populated(conn):
    _, audit_rows = hunt.run_hunt(conn, "audit", (10,))
    _, case_rows = hunt.run_hunt(conn, "cases", (10,))
    assert len(audit_rows) >= 1 and len(case_rows) >= 1


def test_sql_flag_prints_query(capsys):
    hunt.main(["top-talkers", "--sql"])
    out = capsys.readouterr().out
    assert "SELECT" in out and "GROUP BY" in out
