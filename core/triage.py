"""LLM triage stub -> verdict.

Phase 1 ships a deterministic, evidence-grounded stub in place of a live LLM call.
The signature and return shape are the seam a real, provider-agnostic model plugs
into later (Phase 3): pass the alert + cited evidence, get back a verdict grounded
in that evidence. Keeping it a stub honors the "zero paid keys / offline" constraint
and keeps verdict faithfulness at 1.0 (every claim cites a real event).
"""
from __future__ import annotations

from typing import Any

# Verdict vocabulary shared across the pipeline.
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"


def triage(alert: dict[str, Any], evidence: dict[str, Any]) -> dict[str, str]:
    """Return {"verdict", "reason"} grounded strictly in the supplied evidence.

    This is where a real LLM would reason over the alert + enrichment. The stub
    encodes the same conclusion a competent analyst reaches from the same facts,
    and cites the event ids so the verdict is auditable.
    """
    count = alert["event_count"]
    ip = alert["source_ip"]
    users = evidence.get("targeted_users", [])
    window = evidence.get("window_seconds")
    success = evidence.get("success_after_failures")
    cited = evidence.get("event_ids", [])

    user_str = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")

    if success:
        verdict = MALICIOUS
        reason = (
            f"Likely SUCCESSFUL brute force: {count} failed auths from {ip} within "
            f"~{window}s targeting [{user_str}], immediately followed by an accepted "
            f"login for '{success['username']}' at {success['ts']} from the same IP. "
            f"Treat the account as compromised. Evidence events: {cited}."
        )
    elif count >= 5:
        verdict = MALICIOUS
        reason = (
            f"SSH brute force: {count} failed auths from {ip} within ~{window}s "
            f"targeting [{user_str}]. No successful login observed. "
            f"Evidence events: {cited}."
        )
    else:
        verdict = SUSPICIOUS
        reason = (
            f"Elevated failed-auth volume from {ip} ({count} events) but below the "
            f"high-confidence brute-force threshold. Evidence events: {cited}."
        )

    return {"verdict": verdict, "reason": reason}
