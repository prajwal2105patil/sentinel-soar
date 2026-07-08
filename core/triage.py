"""LLM triage stub -> verdict, now with full-context investigation.

Phase 1 shipped a deterministic, evidence-grounded stub in place of a live LLM.
Phase 2 feeds it enrichment (geo + reputation) so the verdict reasons over context,
and adds an impossible-travel branch. The signature/return shape stays the seam a
real, provider-agnostic model plugs into in Phase 3. Keeping it a stub honors the
"zero paid keys / offline" constraint and keeps verdict faithfulness at 1.0.
"""
from __future__ import annotations

from typing import Any

MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"


def _rep_note(enrichment: dict | None) -> str:
    """One-line reputation/geo context, grounded in enrichment, or empty string."""
    if not enrichment:
        return ""
    rep = enrichment.get("reputation") or {}
    geo = enrichment.get("geo") or {}
    bits = []
    if rep.get("category"):
        flag = " (known-bad)" if rep.get("is_known_bad") else ""
        bits.append(f"reputation={rep['category']}{flag}")
    if geo.get("city"):
        bits.append(f"geo={geo['city']}, {geo.get('country')}")
    return (" Context: " + "; ".join(bits) + ".") if bits else ""


def triage(alert: dict[str, Any], evidence: dict[str, Any],
           enrichment: dict | None = None) -> dict[str, str]:
    """Return {"verdict", "reason"} grounded strictly in evidence + enrichment.

    This is where a real LLM would reason over alert + context. The stub encodes the
    conclusion a competent analyst reaches from the same facts and cites event ids.
    """
    ip = alert["source_ip"]
    cited = evidence.get("event_ids", [])
    ctx = _rep_note(enrichment)

    # --- Credential review (low-fidelity failed-then-success signal) ---
    if evidence.get("review"):
        user = evidence.get("username")
        k = evidence.get("failure_count", 0)
        known_bad = bool((enrichment or {}).get("reputation", {}).get("is_known_bad"))
        if k >= 5 or known_bad:
            verdict = SUSPICIOUS
            reason = (
                f"Failed-then-success login for '{user}' from {ip}: {k} prior failure(s) "
                f"and/or flagged source reputation — escalating for analyst review. "
                f"Evidence events: {cited}.{ctx}"
            )
        else:
            verdict = BENIGN
            reason = (
                f"Auto-suppressed (low-fidelity): '{user}' from {ip} had {k} failed "
                f"attempt(s) then success from a known-good residential source with no "
                f"travel anomaly. Not escalated. Evidence events: {cited}.{ctx}"
            )
        return {"verdict": verdict, "reason": reason}

    # --- Impossible travel ---
    if "implied_kmh" in evidence:
        verdict = MALICIOUS
        reason = (
            f"Impossible travel / likely account takeover for '{evidence['username']}': "
            f"successful login from {evidence['from_city']} ({evidence['from_ip']}) then "
            f"{evidence['to_city']} ({evidence['to_ip']}) {evidence['minutes_apart']:.0f} min "
            f"later - {evidence['distance_km']:.0f} km apart, implied speed "
            f"{evidence['implied_kmh']:,.0f} km/h (ceiling {evidence['max_kmh']} km/h). "
            f"Evidence events: {cited}.{ctx}"
        )
        return {"verdict": verdict, "reason": reason}

    # --- Brute force ---
    count = alert["event_count"]
    users = evidence.get("targeted_users", [])
    window = evidence.get("window_seconds")
    success = evidence.get("success_after_failures")
    user_str = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")

    if success:
        verdict = MALICIOUS
        reason = (
            f"Likely SUCCESSFUL brute force: {count} failed auths from {ip} within "
            f"~{window}s targeting [{user_str}], immediately followed by an accepted "
            f"login for '{success['username']}' at {success['ts']} from the same IP. "
            f"Treat the account as compromised. Evidence events: {cited}.{ctx}"
        )
    elif count >= 5:
        verdict = MALICIOUS
        reason = (
            f"SSH brute force: {count} failed auths from {ip} within ~{window}s "
            f"targeting [{user_str}]. No successful login observed. "
            f"Evidence events: {cited}.{ctx}"
        )
    else:
        verdict = SUSPICIOUS
        reason = (
            f"Elevated failed-auth volume from {ip} ({count} events) but below the "
            f"high-confidence brute-force threshold. Evidence events: {cited}.{ctx}"
        )

    return {"verdict": verdict, "reason": reason}
