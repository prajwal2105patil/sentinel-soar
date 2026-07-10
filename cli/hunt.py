"""SQL threat-hunting CLI over the Sentinel-SOAR event store.

An analyst runs parameterized SQL hunts against `events` / `alerts` / `audit_log`
without writing SQL by hand — but every query is real, visible (`--sql`), and safely
parameterized. Directly serves the JD line "write SQL queries to extract and analyze
security-related data from databases."

Run:
  python -m cli.hunt top-talkers --limit 10
  python -m cli.hunt spray --min-users 4
  python -m cli.hunt brute --min-failures 5 --window 120
  python -m cli.hunt users
  python -m cli.hunt timeline --src-ip 45.133.1.88
  python -m cli.hunt cases
  python -m cli.hunt audit --limit 15
  python -m cli.hunt top-talkers --sql        # print the SQL instead of running it
"""
from __future__ import annotations

import argparse
import sqlite3

from core import db

# Reusable SQL fragments (SQLite: boolean expressions evaluate to 1/0).
_FAIL = "event_type LIKE '%fail%'"
_SUCCESS = "event_type IN ('auth_success','cloud_login','cloud_root_login')"


# name -> (help, sql, build_params(args) -> tuple)
HUNTS: dict[str, tuple] = {
    "top-talkers": (
        "Source IPs ranked by failed authentications (with distinct users targeted).",
        f"""SELECT source_ip,
                   COUNT(*)                        AS failures,
                   COUNT(DISTINCT username)        AS distinct_users
              FROM events
             WHERE {_FAIL} AND source_ip IS NOT NULL
             GROUP BY source_ip
             ORDER BY failures DESC
             LIMIT ?""",
        lambda a: (a.limit,),
    ),
    "users": (
        "Per-user authentication outcome (failed vs. successful attempts).",
        f"""SELECT username,
                   SUM({_FAIL})    AS failed,
                   SUM({_SUCCESS}) AS succeeded
              FROM events
             WHERE username IS NOT NULL
             GROUP BY username
             ORDER BY failed DESC
             LIMIT ?""",
        lambda a: (a.limit,),
    ),
    "spray": (
        "Password-spray sources: one IP failing against many distinct accounts.",
        f"""SELECT source_ip,
                   COUNT(DISTINCT username) AS distinct_users,
                   COUNT(*)                 AS attempts
              FROM events
             WHERE {_FAIL} AND source_ip IS NOT NULL
             GROUP BY source_ip
            HAVING distinct_users >= ?
             ORDER BY distinct_users DESC, attempts DESC
             LIMIT ?""",
        lambda a: (a.min_users, a.limit),
    ),
    "brute": (
        "Brute-force shape in SQL: IPs with >= N failures inside a time window.",
        f"""SELECT source_ip,
                   COUNT(*) AS failures,
                   CAST(MAX(strftime('%s', ts)) - MIN(strftime('%s', ts)) AS INTEGER) AS span_seconds
              FROM events
             WHERE {_FAIL} AND source_ip IS NOT NULL
             GROUP BY source_ip
            HAVING failures >= ? AND span_seconds <= ?
             ORDER BY failures DESC
             LIMIT ?""",
        lambda a: (a.min_failures, a.window, a.limit),
    ),
    "timeline": (
        "Chronological event timeline, filtered by --src-ip and/or --user, since --since.",
        """SELECT ts, event_type, username, source_ip, host
              FROM events
             WHERE (:src_ip IS NULL OR source_ip = :src_ip)
               AND (:user   IS NULL OR username  = :user)
               AND (:since  IS NULL OR ts >= :since)
             ORDER BY ts
             LIMIT :limit""",
        lambda a: {"src_ip": a.src_ip, "user": a.user, "since": a.since, "limit": a.limit},
    ),
    "cases": (
        "Investigated alerts (populated after `python -m core.detect`).",
        """SELECT id, severity, rule_id, source_ip, verdict, escalated
              FROM alerts
             ORDER BY id DESC
             LIMIT ?""",
        lambda a: (a.limit,),
    ),
    "audit": (
        "Recent audit-log actions (append-only governance trail).",
        """SELECT ts, actor, action, target
              FROM audit_log
             ORDER BY id DESC
             LIMIT ?""",
        lambda a: (a.limit,),
    ),
}


def run_hunt(conn: sqlite3.Connection, name: str, params) -> tuple[list[str], list[tuple]]:
    """Execute a named hunt; return (column_names, rows)."""
    _, sql, _ = HUNTS[name]
    cur = conn.execute(sql, params)
    cols = [d[0] for d in cur.description]
    return cols, cur.fetchall()


def _render(cols: list[str], rows: list) -> str:
    table = [cols] + [[("" if v is None else str(v)) for v in r] for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(cols))]
    line = lambda cells: "  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))
    out = [line(cols), "  " + "  ".join("-" * w for w in widths)]
    out += [line(r) for r in table[1:]]
    out.append(f"\n  {len(rows)} row(s)")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cli.hunt", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="hunt", required=True)
    for name, (help_text, _, _) in HUNTS.items():
        sp = sub.add_parser(name, help=help_text, description=help_text)
        sp.add_argument("--limit", type=int, default=20)
        sp.add_argument("--sql", action="store_true", help="print the SQL instead of running it")
        if name == "spray":
            sp.add_argument("--min-users", type=int, default=3, dest="min_users")
        if name == "brute":
            sp.add_argument("--min-failures", type=int, default=5, dest="min_failures")
            sp.add_argument("--window", type=int, default=120, help="seconds")
        if name == "timeline":
            sp.add_argument("--src-ip", dest="src_ip", default=None)
            sp.add_argument("--user", default=None)
            sp.add_argument("--since", default=None, help="ISO timestamp lower bound")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    help_text, sql, build = HUNTS[args.hunt]
    if getattr(args, "sql", False):
        print(f"\n-- {help_text}\n{sql.strip()}\n")
        return 0
    conn = db.connect()
    try:
        cols, rows = run_hunt(conn, args.hunt, build(args))
    finally:
        conn.close()
    print(f"\n  [{args.hunt}] {help_text}")
    print(_render(cols, rows))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
