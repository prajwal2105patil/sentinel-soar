"""Fetch a REAL, free, public SSH log sample and stage it for ingestion.

Source: loghub (https://github.com/logpai/loghub) — a widely-cited collection of
real-world system logs used in log-analysis research. `OpenSSH_2k.log` is 2,000
lines of genuine sshd auth activity captured from a lab host (real attacker
brute-force traffic included). Sentinel-SOAR's sshd parser (core/ingest.py) reads
it as-is — no adapter changes needed.

This script needs network access and is NOT run in CI. The repo's default data
stays synthetic; this is the "prove it on messy real data" path.

Usage:
    python scripts/fetch_public_sample.py
    python -m core.ingest --log data/public/OpenSSH_2k.log --no-cloud
    python -m cli.hunt top-talkers          # hunt over REAL log data
    python -m core.detect                   # run the rules over REAL log data
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
DEST = Path(__file__).resolve().parents[1] / "data" / "public" / "OpenSSH_2k.log"


def main() -> int:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    print(f"Fetching real public SSH logs (loghub OpenSSH_2k)\n  {URL}")
    try:
        with urllib.request.urlopen(URL, timeout=30) as r:   # noqa: S310 - known https source
            data = r.read()
    except Exception as exc:  # noqa: BLE001
        print(f"  download failed: {exc}\n  (offline? the repo still runs on its synthetic data.)")
        return 1
    DEST.write_bytes(data)
    n = data.decode("utf-8", "replace").count("\n")
    print(f"  saved {len(data):,} bytes ({n} lines) -> {DEST}")
    print("\nNext:")
    print(f"  python -m core.ingest --log {DEST.as_posix()} --no-cloud")
    print("  python -m cli.hunt top-talkers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
