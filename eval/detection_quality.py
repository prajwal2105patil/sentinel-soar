"""The full scoreboard as a pass/fail gate.

Runs the whole pipeline (ingest -> detect -> agent investigation) on the synthetic
labeled set, prints every rule-detection metric AND the ML risk-scorer metrics next
to their targets with PASS/FAIL, demonstrates the ML recovering rule false-negatives,
and exits non-zero if any hard target is missed. `python -m eval.detection_quality`
is the one command that proves the platform's claims.

All numbers are on SYNTHETIC data (rule metrics on data/labels.csv; ML metrics on a
held-out split of ml/dataset.py) — engineering proof, not a real-world benchmark.
"""
from __future__ import annotations

import csv
import sys

from core import db, detect
from core.ingest import ingest

try:
    from ml.model import assess_ip, held_out_metrics
    HAS_ML = True
except Exception:  # pragma: no cover - sklearn/numpy absent
    HAS_ML = False

ML_HIGH = 0.70  # risk band at/above which the ML scorer would surface an IP

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

ML_CHECKS = [
    ("precision", "ML Precision (held-out)", lambda v: v >= 0.80, ">= 0.80"),
    ("recall",    "ML Recall (held-out)",    lambda v: v >= 0.80, ">= 0.80"),
    ("roc_auc",   "ML ROC-AUC (held-out)",   lambda v: v >= 0.85, ">= 0.85"),
]


def _labels() -> dict[str, str]:
    with (db.DATA_DIR / "labels.csv").open(encoding="utf-8") as f:
        return {r["source_ip"]: r["label"] for r in csv.DictReader(f)}


def _fn_recovery(escalated_ips: set[str]):
    """How the ML scorer does on what the RULES escalated vs. missed."""
    labels = _labels()
    conn = db.connect()
    all_ips = [r[0] for r in conn.execute(
        "SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL").fetchall()]
    rule_fn = [ip for ip in all_ips if labels.get(ip) == "malicious" and ip not in escalated_ips]
    recovered = [ip for ip in rule_fn if assess_ip(conn, ip)["risk_score"] >= ML_HIGH]
    benign_unflagged = [ip for ip in all_ips
                        if labels.get(ip) == "benign" and ip not in escalated_ips]
    new_fp = [ip for ip in benign_unflagged if assess_ip(conn, ip)["risk_score"] >= ML_HIGH]
    conn.close()
    return rule_fn, recovered, new_fp


def main() -> int:
    ingest()
    m = detect.detect(verbose=False)
    m = dict(m, coverage_n=len(m["coverage"]))

    print("\n  SENTINEL-SOAR - DETECTION QUALITY SCOREBOARD (synthetic labeled set)")
    print("  " + "=" * 66)
    print(f"  {'Metric':<24}{'Result':>10}   {'Target':<14}{'Status':>8}")
    print("  " + "-" * 66)

    all_pass = True
    for key, label, fmt, ok, target in CHECKS:
        value = m[key]
        passed = ok(value)
        all_pass &= passed
        print(f"  {label:<24}{fmt.format(value):>10}   {target:<14}{'PASS' if passed else 'FAIL':>8}")

    # ---- ML risk scorer (held-out metrics + false-negative recovery) ----
    if HAS_ML:
        mlm = held_out_metrics()
        print("  " + "-" * 66)
        for key, label, ok, target in ML_CHECKS:
            value = mlm[key]
            passed = ok(value)
            all_pass &= passed
            print(f"  {label:<24}{value:>10.2f}   {target:<14}{'PASS' if passed else 'FAIL':>8}")

        escalated_ips = {c["source_ip"] for c in m["escalated"]}
        rule_fn, recovered, new_fp = _fn_recovery(escalated_ips)
        print("  " + "-" * 66)
        print(f"  ML false-negative recovery: {len(recovered)}/{len(rule_fn)} malicious source(s) "
              f"the rules MISSED are flagged high-risk by ML")
        if rule_fn:
            print(f"      recovered: {recovered or 'none'}   (new benign false-alarms at high band: {len(new_fp)})")
    else:
        print("  " + "-" * 66)
        print("  ML risk scorer: SKIPPED (scikit-learn/numpy not installed)")

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
