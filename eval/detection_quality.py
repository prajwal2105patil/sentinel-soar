"""Phase 4 — the full §5 scoreboard as a pass/fail gate.

Runs the whole pipeline (ingest -> detect -> agent investigation) on the synthetic
labeled set, prints every §5 metric next to its target with a PASS/FAIL, and exits
non-zero if any hard target is missed. This is the finish line: `python -m
eval.detection_quality` is the one command that proves the platform's claims.

Numbers are computed on a SYNTHETIC labeled set (data/labels.csv) — engineering
proof, not a real-world SOC benchmark.

Run:  python -m eval.detection_quality
"""
from __future__ import annotations

import sys

from core import detect
from core.ingest import ingest

# metric-key -> (label, formatter, predicate(value)->bool, target text)
CHECKS = [
    ("precision",       "Detection Precision", "{:.2f}",  lambda v: v >= 0.90, ">= 0.90"),
    ("recall",          "Detection Recall",    "{:.2f}",  lambda v: v >= 0.85, ">= 0.85"),
    ("f1",              "Detection F1",        "{:.2f}",  lambda v: v >= 0.87, ">= 0.87"),
    ("fpr",             "False-Pos Reduction", "{:.1f}%", lambda v: v >= 70.0, ">= 70%"),
    ("auto_rate",       "Auto-Triage Rate",    "{:.1f}%", lambda v: v >= 80.0, ">= 80%"),
    ("mttt_ms",         "Mean Time To Triage", "{:.2f} ms", lambda v: v < 5000, "< 5000 ms"),
    ("coverage_n",      "ATT&CK Coverage",     "{:d}",    lambda v: v >= 5,    ">= 5"),
    ("enrichment_rate", "Enrichment Success",  "{:.1f}%", lambda v: v >= 95.0, ">= 95%"),
    ("cage_escapes",    "Cage Containment",    "{:d}",    lambda v: v == 0,    "== 0 escapes"),
    ("audit_completeness", "Audit Completeness", "{:.1f}%", lambda v: v >= 100.0, "== 100%"),
    ("faithfulness",    "Verdict Faithfulness", "{:.1f}%", lambda v: v >= 90.0, ">= 90%"),
]


def main() -> int:
    ingest()
    m = detect.detect(verbose=False)
    m = dict(m, coverage_n=len(m["coverage"]))  # expose coverage as a count for the check

    print("\n  SENTINEL-SOAR - DETECTION QUALITY SCOREBOARD (synthetic labeled set)")
    print("  " + "=" * 66)
    print(f"  {'Metric':<22}{'Result':>12}   {'Target':<14}{'Status':>8}")
    print("  " + "-" * 66)

    all_pass = True
    for key, label, fmt, ok, target in CHECKS:
        value = m[key]
        passed = ok(value)
        all_pass &= passed
        print(f"  {label:<22}{fmt.format(value):>12}   {target:<14}"
              f"{'PASS' if passed else 'FAIL':>8}")

    print("  " + "-" * 66)
    print(f"  Analyst-Approval Rate {m['approval_rate']:.1f}%  "
          f"({m['actions_gated']}/{m['actions_total']} escalated actions gated)   [informational]")
    print("  " + "=" * 66)
    print(f"  RESULT: {'ALL TARGETS MET' if all_pass else 'TARGETS MISSED'}   "
          f"({len(m['escalated'])} escalated / {len(m['suppressed'])} suppressed, "
          f"{m['tp']} TP / {m['fp']} FP / {m['fn']} FN)")
    print()
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
