"""Train the risk scorer and print its held-out metrics + learned coefficients.

Run:  python -m ml.train

Metrics are on a held-out split of a SYNTHETIC feature dataset (ml/dataset.py) —
an honest measure of the model, not a real-world benchmark.
"""
from __future__ import annotations

from ml.model import train


def main() -> int:
    scorer, m = train()
    print("\n  SENTINEL-SOAR - ML RISK SCORER (LogisticRegression)")
    print("  synthetic feature set | stratified held-out split")
    print("  " + "=" * 58)
    print(f"  train / test samples   {m['n_train']} / {m['n_test']}")
    print(f"  Precision (held-out)   {m['precision']:.3f}   (target >= 0.80)")
    print(f"  Recall    (held-out)   {m['recall']:.3f}   (target >= 0.80)")
    print(f"  F1        (held-out)   {m['f1']:.3f}")
    print(f"  ROC-AUC   (held-out)   {m['roc_auc']:.3f}   (target >= 0.85)")
    print("  " + "-" * 58)
    print("  learned coefficients (standardized; sign = direction of risk):")
    for name, coef in sorted(scorer.coefficients().items(), key=lambda kv: -abs(kv[1])):
        print(f"      {name:<20} {coef:+.3f}")
    print("  " + "=" * 58)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
