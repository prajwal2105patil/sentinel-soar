"""Sentinel-SOAR ML risk scorer.

A real, offline scikit-learn model (no external API, no paid keys) that scores a
source IP's *behaviour* for maliciousness — complementing the signature rules.
Its payoff: it recovers low-and-slow attacks that sit below the rule thresholds
(a genuine "where ML beats signatures" result), and it is trained + evaluated on a
held-out split of a clearly-labelled SYNTHETIC feature dataset, so the reported
metrics are honest (no circular validation against the rule-detection labels).
"""
