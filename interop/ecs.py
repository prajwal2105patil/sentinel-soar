"""Normalize Sentinel-SOAR events to Elastic Common Schema (ECS).

ECS (https://www.elastic.co/guide/en/ecs) is the vendor-neutral field schema behind
Elastic/Kibana and understood by Splunk, Sentinel, and most SIEMs. Mapping our raw
events to ECS is what lets the same data (and the Sigma rules in interop/sigma.py)
run outside this repo.
"""
from __future__ import annotations

ECS_VERSION = "8.11"

# event_type -> (event.category, event.action, event.outcome, extra ECS fields)
_ECS: dict[str, tuple] = {
    "auth_failure":            (["authentication"], "ssh_login", "failure", {}),
    "auth_success":            (["authentication"], "ssh_login", "success", {}),
    "cloud_login":             (["authentication"], "aws_console_login", "success", {}),
    "cloud_login_failure":     (["authentication"], "aws_console_login", "failure", {}),
    "cloud_root_login":        (["authentication"], "aws_console_login", "success", {"user.name": "root"}),
    "cloud_create_access_key": (["iam"], "aws_create_access_key", "success", {}),
}


def _lookup(event_type: str) -> tuple:
    return _ECS.get(event_type, (["process"], event_type or "unknown", "unknown", {}))


def to_ecs(event: dict) -> dict:
    """Map one event row (events table shape) into an ECS document."""
    category, action, outcome, extra = _lookup(event.get("event_type"))
    doc: dict = {
        "@timestamp": event.get("ts"),
        "ecs": {"version": ECS_VERSION},
        "event": {"category": category, "action": action,
                  "provider": event.get("source"),
                  "dataset": f"sentinel.{event.get('source', 'unknown')}"},
        "message": event.get("raw"),
    }
    if outcome != "unknown":
        doc["event"]["outcome"] = outcome
    if event.get("source_ip"):
        doc["source"] = {"ip": event["source_ip"]}
    if event.get("username"):
        doc.setdefault("user", {})["name"] = event["username"]
    if event.get("host"):
        doc["host"] = {"name": event["host"]}
    # apply any extra ECS fields (dotted keys -> nested)
    for dotted, value in extra.items():
        node = doc
        parts = dotted.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    return doc


def ecs_selection(event_type: str) -> dict:
    """A flat ECS-field selection for a Sigma rule targeting this event_type."""
    category, action, outcome, extra = _lookup(event_type)
    sel = {"event.category": category[0], "event.action": action}
    if outcome != "unknown":
        sel["event.outcome"] = outcome
    sel.update(extra)
    return sel
