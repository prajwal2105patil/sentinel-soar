"""Export Sentinel-SOAR YAML detections as Sigma rules.

Sigma (https://github.com/SigmaHQ/sigma) is the open, vendor-neutral detection
format. Emitting our rules as Sigma (with ECS field names + ATT&CK tags) means they
can be converted to Splunk SPL / Elastic EQL / Sentinel KQL with `sigma convert` —
the cheapest possible "this ports into your SIEM" story.

Note: the noisy credential-review suppression signal is intentionally NOT exported —
it's an internal triage filter, not a shippable detection.
"""
from __future__ import annotations

import yaml

from core import db
from interop.ecs import ecs_selection

RULES_DIR = db.ROOT / "detections" / "rules"
_SKIP_KINDS = {"failed_then_success"}   # suppression signals, not detections


def _logsource(rule: dict, event_type: str | None) -> dict:
    if rule.get("source") == "cloudtrail" or (event_type or "").startswith("cloud"):
        return {"product": "aws", "service": "cloudtrail"}
    return {"product": "linux", "service": "sshd"}


def to_sigma(rule: dict) -> dict:
    """Map one Sentinel-SOAR rule to a Sigma rule dict."""
    event_type = (rule.get("match") or {}).get("event_type")
    detection: dict = {"selection": ecs_selection(event_type) if event_type else {}}

    kind = rule.get("kind", "threshold")
    if kind == "threshold":
        thr = rule["threshold"]
        detection["timeframe"] = f"{thr['window_seconds']}s"
        detection["condition"] = f"selection | count() by source.ip >= {thr['count']}"
    elif kind == "impossible_travel":
        # Geo-velocity correlation (see description); expressed as a per-user grouping.
        detection["condition"] = "selection | count() by user.name >= 1"
    else:
        detection["condition"] = "selection"

    return {
        "title": rule["name"],
        "id": rule["id"],
        "status": "experimental",
        "description": " ".join((rule.get("description") or "").split()),
        "author": "Sentinel-SOAR",
        "logsource": _logsource(rule, event_type),
        "detection": detection,
        "level": rule.get("severity", "medium"),
        "tags": [f"attack.{t.lower()}" for t in rule.get("mitre", [])],
    }


def all_sigma_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if rule.get("kind") in _SKIP_KINDS:
            continue
        rules.append(to_sigma(rule))
    return rules


def dumps() -> str:
    """All Sigma rules as a single multi-document YAML string."""
    return "\n---\n".join(
        yaml.safe_dump(r, sort_keys=False, default_flow_style=False).strip()
        for r in all_sigma_rules()) + "\n"
