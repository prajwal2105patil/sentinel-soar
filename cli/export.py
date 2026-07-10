"""Export detections as Sigma and events as ECS — for portability into a SIEM.

Run:
  python -m cli.export sigma                 # print Sigma rules (YAML) to stdout
  python -m cli.export sigma --out sigma/    # write one .yml per rule
  python -m cli.export ecs --limit 20        # print events as ECS-normalized JSONL
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from core import db
from interop import sigma
from interop.ecs import to_ecs


def _export_sigma(args) -> int:
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for rule in sigma.all_sigma_rules():
            slug = rule["id"].lower().replace("rule-", "").replace("-", "_")
            path = args.out / f"{slug}.yml"
            path.write_text(yaml.safe_dump(rule, sort_keys=False).strip() + "\n", encoding="utf-8")
            print(f"  wrote {path}")
        return 0
    print(sigma.dumps())
    return 0


def _export_ecs(args) -> int:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT ts, event_type, username, source_ip, host, source, raw "
            "FROM events ORDER BY ts LIMIT ?", (args.limit,)).fetchall()
    finally:
        conn.close()
    for r in rows:
        print(json.dumps(to_ecs(dict(r)), separators=(",", ":")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cli.export", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="what", required=True)
    sp = sub.add_parser("sigma", help="export detections as Sigma rules")
    sp.add_argument("--out", type=Path, default=None,
                    help="directory to write one .yml per rule (default: stdout)")
    sp.set_defaults(func=_export_sigma)
    se = sub.add_parser("ecs", help="export events as ECS-normalized JSONL")
    se.add_argument("--limit", type=int, default=50)
    se.set_defaults(func=_export_ecs)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
