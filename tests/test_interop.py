"""Tests for ECS normalization and Sigma export (interop/)."""
from __future__ import annotations

import yaml

from interop import sigma
from interop.ecs import ecs_selection, to_ecs


# ------------------------------------------------------------------ ECS
def test_ecs_maps_auth_failure():
    doc = to_ecs({"ts": "2025-06-14T09:05:02+00:00", "event_type": "auth_failure",
                  "username": "postgres", "source_ip": "45.133.1.88", "host": "web01",
                  "source": "auth", "raw": "..."})
    assert doc["event"]["category"] == ["authentication"]
    assert doc["event"]["outcome"] == "failure"
    assert doc["source"]["ip"] == "45.133.1.88"
    assert doc["user"]["name"] == "postgres"
    assert doc["ecs"]["version"]


def test_ecs_cloud_root_login_sets_root_and_aws_action():
    doc = to_ecs({"ts": "2025-06-14T10:00:00+00:00", "event_type": "cloud_root_login",
                  "username": "root", "source_ip": "185.220.101.5", "host": "us-east-1",
                  "source": "cloudtrail", "raw": "{}"})
    assert doc["event"]["action"] == "aws_console_login"
    assert doc["event"]["outcome"] == "success"
    assert doc["user"]["name"] == "root"


def test_ecs_selection_shape():
    sel = ecs_selection("auth_failure")
    assert sel["event.action"] == "ssh_login" and sel["event.outcome"] == "failure"


# ------------------------------------------------------------------ Sigma
def test_sigma_rules_have_required_fields_and_valid_yaml():
    rules = sigma.all_sigma_rules()
    assert rules
    required = {"title", "id", "status", "logsource", "detection", "level"}
    for r in rules:
        assert required.issubset(r)
        assert "condition" in r["detection"]
    # the whole export must be valid multi-document YAML
    docs = list(yaml.safe_load_all(sigma.dumps()))
    assert len(docs) == len(rules)


def test_sigma_brute_force_is_a_count_rule_with_attack_tags():
    bf = next(r for r in sigma.all_sigma_rules() if r["id"] == "RULE-BRUTE-FORCE-001")
    assert "count() by source.ip" in bf["detection"]["condition"]
    assert "attack.t1110" in bf["tags"]
    assert bf["logsource"] == {"product": "linux", "service": "sshd"}


def test_sigma_excludes_suppression_signal():
    ids = {r["id"] for r in sigma.all_sigma_rules()}
    assert "RULE-CREDENTIAL-REVIEW-001" not in ids   # not a shippable detection


def test_sigma_cloud_rule_uses_cloudtrail_logsource():
    cloud = next(r for r in sigma.all_sigma_rules() if "CLOUD" in r["id"])
    assert cloud["logsource"] == {"product": "aws", "service": "cloudtrail"}
    assert "attack.t1078.004" in cloud["tags"]
