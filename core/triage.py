"""Composite-AI triage -> verdict: heuristics + knowledge-graph context + LLM seam.

Phase 1 shipped a deterministic, evidence-grounded stub in place of a live LLM.
Phase 2 fed it enrichment (geo + reputation). Phase 5 completes the composite:
the verdict now also reasons over knowledge-graph correlation (what else did this
entity touch?) and exposes a real-LLM seam behind SENTINEL_LLM. When SENTINEL_LLM
is unset — or the provider call fails for any reason — triage cleanly falls back
to the deterministic stub, so the demo stays offline-capable with zero keys.

Providers:  SENTINEL_LLM=openai   (needs OPENAI_API_KEY)
            SENTINEL_LLM=ollama   (needs a local ollama server; SENTINEL_LLM_MODEL)
"""
from __future__ import annotations

import json
import os
from typing import Any

MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
BENIGN = "benign"
_VALID_VERDICTS = {MALICIOUS, SUSPICIOUS, BENIGN}


# ------------------------------------------------------------------ context notes
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


def _graph_note(correlation: dict | None) -> str:
    """One-line knowledge-graph correlation context, or empty string."""
    if not correlation:
        return ""
    bits = []
    n_fail = len(correlation.get("ip_failed_users", []))
    if correlation.get("spray_signal"):
        bits.append(f"source failed against {n_fail} distinct accounts (spray pattern)")
    elif n_fail > 1:
        bits.append(f"source failed against {n_fail} accounts")
    n_ips = correlation.get("user_ip_count", 0)
    if n_ips > 2:
        bits.append(f"user seen from {n_ips} distinct IPs")
    hosts = correlation.get("hosts_touched", [])
    if len(hosts) > 1:
        bits.append(f"source touched {len(hosts)} hosts")
    return (" Graph: " + "; ".join(bits) + ".") if bits else ""


# ------------------------------------------------------------------ LLM seam
def _llm_verdict(alert: dict, evidence: dict, enrichment: dict | None,
                 correlation: dict | None) -> dict | None:
    """Optional real-LLM triage. Returns {"verdict","reason"} or None to signal
    fallback to the deterministic stub. NEVER raises: any provider/parse failure
    degrades silently so the pipeline stays offline-capable with zero keys."""
    provider = os.getenv("SENTINEL_LLM", "").strip().lower()
    if not provider:
        return None
    try:
        prompt = (
            "You are a SOC triage analyst. Given the alert JSON below, return ONLY a "
            'JSON object {"verdict": "malicious"|"suspicious"|"benign", "reason": "..."} '
            "grounded strictly in the provided evidence (cite the event ids).\n"
            + json.dumps({"alert": {k: v for k, v in alert.items() if k != "evidence"},
                          "evidence": evidence, "enrichment": enrichment,
                          "correlation": correlation}, default=str)
        )
        raw: str | None = None
        if provider == "openai":
            import requests
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
                json={"model": os.getenv("SENTINEL_LLM_MODEL", "gpt-4o-mini"),
                      "messages": [{"role": "user", "content": prompt}],
                      "response_format": {"type": "json_object"}, "temperature": 0},
                timeout=20)
            r.raise_for_status()
            raw = r.json()["choices"][0]["message"]["content"]
        elif provider == "ollama":
            import requests
            r = requests.post(
                os.getenv("SENTINEL_LLM_URL", "http://localhost:11434") + "/api/generate",
                json={"model": os.getenv("SENTINEL_LLM_MODEL", "llama3.1"),
                      "prompt": prompt, "format": "json", "stream": False},
                timeout=60)
            r.raise_for_status()
            raw = r.json().get("response")
        if not raw:
            return None
        out = json.loads(raw)
        verdict, reason = out.get("verdict"), out.get("reason")
        if verdict in _VALID_VERDICTS and isinstance(reason, str) and reason.strip():
            return {"verdict": verdict, "reason": f"[llm:{provider}] {reason.strip()}"}
        return None  # malformed model output -> deterministic stub
    except Exception:
        return None  # no key / no network / bad response -> deterministic stub


# ------------------------------------------------------------------ triage
def _risk_note(risk: dict | None) -> str:
    """One-line ML risk-scorer context, or empty string. This is a model signal
    (not cited evidence), so it is labelled as such and never inflates faithfulness."""
    if not risk or "risk_score" not in risk:
        return ""
    return f" ML risk={risk['risk_score']:.2f} ({risk.get('risk_band', '?')})."


def triage(alert: dict[str, Any], evidence: dict[str, Any],
           enrichment: dict | None = None,
           correlation: dict | None = None,
           risk: dict | None = None) -> dict[str, str]:
    """Return {"verdict", "reason"} grounded strictly in evidence + enrichment +
    knowledge-graph correlation, annotated with the ML behavioural risk score. If
    SENTINEL_LLM is set, a real provider renders the verdict; otherwise (or on any
    failure) the deterministic stub does."""
    llm = _llm_verdict(alert, evidence, enrichment, correlation)
    if llm:
        return llm

    ip = alert["source_ip"]
    cited = evidence.get("event_ids", [])
    ctx = _rep_note(enrichment) + _graph_note(correlation) + _risk_note(risk)

    # --- Cloud anomaly (root console login / key mint from flagged source) ---
    if evidence.get("cloud"):
        keys = evidence.get("access_keys_created", 0)
        region = evidence.get("region")
        if evidence.get("known_bad_ip"):
            verdict = MALICIOUS
            reason = (
                f"Cloud root compromise signal: root console login from known-bad "
                f"source {ip} ({evidence.get('reputation_category')}) in {region}"
                + (f", followed by {keys} new access key(s) minted (persistence)" if keys else "")
                + f". Evidence events: {cited}.{ctx}"
            )
        else:
            verdict = SUSPICIOUS
            reason = (
                f"Root console activity from {ip} in {region} — root usage is "
                f"policy-violating even from clean sources; routing to an analyst. "
                f"Evidence events: {cited}.{ctx}"
            )
        return {"verdict": verdict, "reason": reason}

    # --- Credential review (low-fidelity failed-then-success signal) ---
    if evidence.get("review"):
        user = evidence.get("username")
        k = evidence.get("failure_count", 0)
        known_bad = bool((enrichment or {}).get("reputation", {}).get("is_known_bad"))
        spray = bool((correlation or {}).get("spray_signal"))
        if k >= 5 or known_bad or spray:
            verdict = SUSPICIOUS
            reason = (
                f"Failed-then-success login for '{user}' from {ip}: {k} prior failure(s), "
                f"flagged source reputation and/or multi-account graph correlation — "
                f"escalating for analyst review. Evidence events: {cited}.{ctx}"
            )
        else:
            verdict = BENIGN
            reason = (
                f"Auto-suppressed (low-fidelity): '{user}' from {ip} had {k} failed "
                f"attempt(s) then success from a known-good residential source with no "
                f"travel anomaly and no cross-account graph signal. Not escalated. "
                f"Evidence events: {cited}.{ctx}"
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
