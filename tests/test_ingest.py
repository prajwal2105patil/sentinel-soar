"""Tests that the ingest adapter handles REAL public-log formats (loghub OpenSSH).

The line formats below are the genuine shapes found in loghub's OpenSSH_2k.log
(github.com/logpai/loghub) — the same corpus scripts/fetch_public_sample.py pulls.
Proving the parser reads them offline is the honest core of "runs on real data".
"""
from __future__ import annotations

from core import db
from core.ingest import _parse_line, ingest


def test_parses_real_openssh_invalid_user():
    e = _parse_line("Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user "
                    "webmaster from 173.234.31.186 port 38926 ssh2")
    assert e["event_type"] == "auth_failure"
    assert e["username"] == "webmaster"
    assert e["source_ip"] == "173.234.31.186"
    assert e["host"] == "LabSZ"


def test_parses_real_openssh_accepted():
    e = _parse_line("Dec 10 07:02:47 LabSZ sshd[24203]: Accepted password for fztu "
                    "from 119.137.62.142 port 49116 ssh2")
    assert e["event_type"] == "auth_success" and e["source_ip"] == "119.137.62.142"


def test_parses_real_openssh_message_repeated():
    e = _parse_line("Dec 10 06:55:48 LabSZ sshd[24200]: message repeated 2 times: "
                    "[ Failed password for root from 5.36.59.76 port 22 ssh2]")
    assert e["event_type"] == "auth_failure" and e["source_ip"] == "5.36.59.76"


def test_non_auth_line_is_other_not_a_crash():
    e = _parse_line("Dec 10 09:32:20 LabSZ sshd[24680]: Connection closed by 216.229.4.2 [preauth]")
    assert e["event_type"] == "other"


def test_ingest_real_format_file_no_cloud(tmp_path):
    log = tmp_path / "openssh.log"
    log.write_text(
        "Dec 10 06:55:46 LabSZ sshd[1]: Failed password for root from 5.36.59.76 port 22 ssh2\n"
        "Dec 10 06:56:10 LabSZ sshd[1]: Failed password for root from 5.36.59.76 port 23 ssh2\n",
        encoding="utf-8")
    assert ingest(log_path=log, cloud_path=None) == 2
    c = db.connect()
    try:
        assert c.execute("SELECT COUNT(*) FROM events WHERE source_ip='5.36.59.76'").fetchone()[0] == 2
    finally:
        c.close()
