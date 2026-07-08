"""Response playbooks -> deterministic actions with analyst-in-the-loop approval.

Loads YAML playbooks from playbooks/response/, matches one to an alert by rule_id,
and computes which actions can auto-execute vs. which require a human. This is
AiStrike's "deterministic playbooks + control" model: the agent recommends, but
critical / account-level actions are gated on analyst approval.
"""
from __future__ import annotations

import functools

import yaml

from core import db

PLAYBOOK_DIR = db.ROOT / "playbooks" / "response"

# Fallback used when no playbook matches a rule, so every escalated alert still
# yields a safe, human-gated recommendation rather than nothing.
_GENERIC = {
    "id": "PB-GENERIC-001",
    "name": "Generic Review",
    "actions": [
        {"action": "notify_analyst",
         "description": "Route to an analyst for manual review.",
         "requires_approval": True},
    ],
    "approval_policy": {"require_approval_if_severity": ["critical"]},
}


@functools.lru_cache(maxsize=1)
def _playbooks() -> dict[str, dict]:
    """rule_id -> playbook, loaded once."""
    out = {}
    for path in sorted(PLAYBOOK_DIR.glob("*.yml")):
        pb = yaml.safe_load(path.read_text(encoding="utf-8"))
        out[pb["rule_id"]] = pb
    return out


def build_response(alert: dict, verdict: str) -> dict:
    """Return the response plan for an alert given its triage verdict.

    Suppressed (benign) alerts get no actions. Otherwise the matching playbook's
    actions are returned, each marked auto vs. requires_approval, plus an overall
    `requires_analyst` flag.
    """
    if verdict == "benign":
        return {"playbook_id": None, "suppressed": True, "actions": [],
                "requires_analyst": False}

    pb = _playbooks().get(alert.get("rule_id"), _GENERIC)
    severity = (alert.get("severity") or "").lower()
    force = severity in [s.lower() for s in pb.get("approval_policy", {})
                         .get("require_approval_if_severity", [])]

    actions = []
    for a in pb["actions"]:
        needs = bool(a.get("requires_approval")) or force
        actions.append({"action": a["action"], "description": a["description"],
                        "requires_approval": needs})

    return {
        "playbook_id": pb["id"],
        "suppressed": False,
        "actions": actions,
        "requires_analyst": any(a["requires_approval"] for a in actions),
    }
