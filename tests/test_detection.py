"""End-to-end pipeline assertions — the funnel and the §5 scoreboard targets."""
from __future__ import annotations


def test_funnel_shape(pipeline):
    assert len(pipeline["escalated"]) == 4
    assert len(pipeline["suppressed"]) == 2


def test_detection_quality_targets(pipeline):
    assert pipeline["precision"] >= 0.90
    assert pipeline["recall"] >= 0.85
    assert pipeline["f1"] >= 0.87
    assert pipeline["fp"] == 0
    assert pipeline["fn"] == 0


def test_attack_coverage(pipeline):
    assert len(pipeline["coverage"]) >= 5
    assert "T1110" in pipeline["coverage"]
    assert "T1078" in pipeline["coverage"]


def test_enrichment_and_faithfulness(pipeline):
    assert pipeline["enrichment_rate"] >= 95.0
    assert pipeline["faithfulness"] >= 90.0


def test_false_positive_reduction(pipeline):
    assert pipeline["fpr"] >= 70.0
    assert pipeline["benign_suppressed"] == pipeline["benign_total"]


def test_cage_and_audit(pipeline):
    assert pipeline["cage_escapes"] == 0
    assert pipeline["cage_contained"] >= 5
    assert pipeline["audit_completeness"] == 100.0


def test_latency_budget(pipeline):
    assert pipeline["mttt_ms"] < 5000


def test_credential_compromise_is_critical(pipeline):
    crit = [c for c in pipeline["escalated"] if c["source_ip"] == "45.133.1.88"]
    assert crit and crit[0]["severity"] == "critical"
    # every action on the confirmed-compromise alert must be analyst-gated
    assert all(a["requires_approval"] for a in crit[0]["response"]["actions"])
