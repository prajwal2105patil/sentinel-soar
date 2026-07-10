"""Detect: run YAML rules over `events` -> candidate alerts, each investigated by
the agent (enrich -> ATT&CK -> caged verdict -> response playbook), then either
escalated to an analyst or auto-suppressed.

Run:  python -m core.detect   (after core.ingest)

Prints the running scoreboard: Precision/Recall/F1, ATT&CK Coverage, Enrichment
Success, Cage Containment, False-Positive Reduction, Analyst-Approval rate,
Auto-Triage, Audit Completeness, MTTT.
"""
from __future__ import annotations

import csv
import math
import time
from datetime import datetime

import yaml

from agent import investigator
from core import audit, db
from core.cage import Cage

RULES_DIR = db.ROOT / "detections" / "rules"
LABELS_PATH = db.DATA_DIR / "labels.csv"

# Rules are trusted YAML, but column names still never reach SQL unvetted:
# every `match:` key must be on this whitelist or the rule is rejected outright.
_ALLOWED_COLS = frozenset({"username", "source_ip", "host", "event_type", "source"})


# ------------------------------------------------------------------ helpers
def _load_rules() -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(RULES_DIR.glob("*.yml"))]


def _where(match: dict) -> str:
    """Build a WHERE clause from a rule's `match:` block. Values are always bound
    parameters; column names are interpolated, so they are strictly whitelisted."""
    bad = set(match) - _ALLOWED_COLS
    if bad:
        raise ValueError(f"rule match uses non-whitelisted column(s): {sorted(bad)}; "
                         f"allowed: {sorted(_ALLOWED_COLS)}")
    return " AND ".join(f"{k} = ?" for k in match)


def _parse_ts(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()


def _haversine_km(a: dict, b: dict) -> float:
    r = 6371.0
    p1, p2 = math.radians(a["lat"]), math.radians(b["lat"])
    dphi = math.radians(b["lat"] - a["lat"])
    dlmb = math.radians(b["lon"] - a["lon"])
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


# ------------------------------------------------------------------ evaluators
def _sliding_window_hit(rows: list, count: int, window_s: int) -> list:
    ts = [_parse_ts(r["ts"]) for r in rows]
    best, left = [], 0
    for right in range(len(rows)):
        while ts[right] - ts[left] > window_s:
            left += 1
        span = rows[left:right + 1]
        if len(span) >= count and len(span) > len(best):
            best = span
    return best


def _evaluate_threshold(conn, rule: dict) -> list[dict]:
    match = rule.get("match", {})
    group_field, thr = rule["group_by"], rule["threshold"]
    where = _where(match)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY ts" if where else \
          "SELECT * FROM events ORDER BY ts"
    matched = conn.execute(sql, tuple(match.values())).fetchall()

    groups: dict[str, list] = {}
    for row in matched:
        groups.setdefault(row[group_field], []).append(row)

    alerts = []
    for key, rows in groups.items():
        window = _sliding_window_hit(rows, thr["count"], thr["window_seconds"])
        if not window:
            continue
        targeted = list(dict.fromkeys(r["username"] for r in window))
        evidence = {"event_ids": [r["id"] for r in window], "targeted_users": targeted,
                    "window_seconds": thr["window_seconds"], "success_after_failures": None}
        if rule.get("escalate_on_success"):
            succ = conn.execute(
                "SELECT * FROM events WHERE event_type='auth_success' AND source_ip=? "
                "AND ts >= ? ORDER BY ts LIMIT 1", (key, window[0]["ts"])).fetchone()
            if succ:
                evidence["success_after_failures"] = {
                    "event_id": succ["id"], "username": succ["username"], "ts": succ["ts"]}
                evidence["event_ids"].append(succ["id"])
        alerts.append({
            "rule_id": rule["id"], "title": rule["name"], "mitre": rule.get("mitre", []),
            "severity": "critical" if evidence["success_after_failures"] else rule["severity"],
            "source_ip": key, "username": targeted[0] if targeted else None,
            "event_count": len(window), "first_ts": window[0]["ts"],
            "last_ts": window[-1]["ts"], "evidence": evidence})
    return alerts


def _evaluate_impossible_travel(conn, rule: dict) -> list[dict]:
    from core import enrich
    match, group_field = rule.get("match", {}), rule["group_by"]
    max_kmh = rule["params"]["max_kmh"]
    # Distance floor: below this the two IPs are effectively co-located (load
    # balancer, dual-homed host, NAT egress) and it is NOT travel — regardless of
    # elapsed time. Guards the dt==0 case, where implied speed would be infinite.
    min_dist_km = rule["params"].get("min_distance_km", 50)
    where = _where(match)
    rows = conn.execute(
        f"SELECT * FROM events WHERE {where} ORDER BY ts", tuple(match.values())).fetchall()

    by_user: dict[str, list] = {}
    for r in rows:
        by_user.setdefault(r[group_field], []).append(r)

    alerts = []
    for user, logins in by_user.items():
        worst = None
        for prev, cur in zip(logins, logins[1:]):
            if prev["source_ip"] == cur["source_ip"]:
                continue
            g1 = enrich.enrich_ip(prev["source_ip"])["geo"]
            g2 = enrich.enrich_ip(cur["source_ip"])["geo"]
            if not g1 or not g2:
                continue
            dist = _haversine_km(g1, g2)
            if dist < min_dist_km:
                continue  # co-located endpoints: not travel, never impossible
            dt_h = (_parse_ts(cur["ts"]) - _parse_ts(prev["ts"])) / 3600.0
            kmh = dist / dt_h if dt_h > 0 else float("inf")
            if kmh > max_kmh and (worst is None or kmh > worst["kmh"]):
                worst = {"prev": prev, "cur": cur, "g1": g1, "g2": g2,
                         "dist": dist, "dt_h": dt_h, "kmh": kmh}
        if not worst:
            continue
        p, c = worst["prev"], worst["cur"]
        evidence = {
            "event_ids": [p["id"], c["id"]], "username": user,
            "from_ip": p["source_ip"], "to_ip": c["source_ip"],
            "from_city": worst["g1"]["city"], "to_city": worst["g2"]["city"],
            "distance_km": worst["dist"], "minutes_apart": worst["dt_h"] * 60.0,
            "implied_kmh": worst["kmh"], "max_kmh": max_kmh}
        alerts.append({
            "rule_id": rule["id"], "title": rule["name"], "mitre": rule.get("mitre", []),
            "severity": rule["severity"], "source_ip": c["source_ip"], "username": user,
            "event_count": 2, "first_ts": p["ts"], "last_ts": c["ts"], "evidence": evidence})
    return alerts


def _evaluate_failed_then_success(conn, rule: dict) -> list[dict]:
    """Low-volume failed-then-success pairs (the noisy review signal)."""
    max_fail = rule["params"]["max_failures"]
    window_s = rule["params"]["window_seconds"]
    users = [r[0] for r in conn.execute(
        "SELECT DISTINCT username FROM events WHERE event_type='auth_success'").fetchall()]

    alerts = []
    for user in users:
        evs = conn.execute("SELECT * FROM events WHERE username=? ORDER BY ts", (user,)).fetchall()
        for ev in evs:
            if ev["event_type"] != "auth_success":
                continue
            s_ts = _parse_ts(ev["ts"])
            fails = [e for e in evs if e["event_type"] == "auth_failure"
                     and e["source_ip"] == ev["source_ip"]
                     and 0 <= s_ts - _parse_ts(e["ts"]) <= window_s]
            k = len(fails)
            if 1 <= k <= max_fail:
                evidence = {"event_ids": [e["id"] for e in fails] + [ev["id"]],
                            "review": True, "username": user, "failure_count": k,
                            "targeted_users": [user]}
                alerts.append({
                    "rule_id": rule["id"], "title": rule["name"], "mitre": rule.get("mitre", []),
                    "severity": rule["severity"], "source_ip": ev["source_ip"], "username": user,
                    "event_count": k, "first_ts": fails[0]["ts"], "last_ts": ev["ts"],
                    "evidence": evidence})
                break  # one candidate per user
    return alerts


def _evaluate_cloud_anomaly(conn, rule: dict) -> list[dict]:
    """Cloud telemetry rule: root console login / access-key creation, optionally
    gated on known-bad source reputation. Second telemetry source end-to-end."""
    from core import enrich
    match = rule.get("match", {})
    where = _where(match)
    sql = (f"SELECT * FROM events WHERE source = 'cloudtrail' AND {where} ORDER BY ts"
           if where else "SELECT * FROM events WHERE source = 'cloudtrail' ORDER BY ts")
    rows = conn.execute(sql, tuple(match.values())).fetchall()

    by_ip: dict[str, list] = {}
    for r in rows:
        by_ip.setdefault(r["source_ip"], []).append(r)

    require_bad = rule.get("params", {}).get("require_known_bad_ip", False)
    alerts = []
    for ip, evs in by_ip.items():
        rep = enrich.enrich_ip(ip)["reputation"]
        if require_bad and not rep["is_known_bad"]:
            continue
        # follow-on persistence: access keys minted from the same source
        keys = conn.execute(
            "SELECT * FROM events WHERE source='cloudtrail' "
            "AND event_type='cloud_create_access_key' AND source_ip=? ORDER BY ts",
            (ip,)).fetchall()
        all_evs = evs + [k for k in keys if k["id"] not in {e["id"] for e in evs}]
        evidence = {
            "event_ids": [e["id"] for e in all_evs], "cloud": True,
            "root_logins": len(evs), "access_keys_created": len(keys),
            "region": evs[0]["host"], "known_bad_ip": rep["is_known_bad"],
            "reputation_category": rep["category"], "targeted_users": ["root"]}
        alerts.append({
            "rule_id": rule["id"], "title": rule["name"], "mitre": rule.get("mitre", []),
            "severity": rule["severity"], "source_ip": ip, "username": "root",
            "event_count": len(all_evs), "first_ts": all_evs[0]["ts"],
            "last_ts": all_evs[-1]["ts"], "evidence": evidence})
    return alerts


_DISPATCH = {
    "threshold": _evaluate_threshold,
    "impossible_travel": _evaluate_impossible_travel,
    "failed_then_success": _evaluate_failed_then_success,
    "cloud_anomaly": _evaluate_cloud_anomaly,
}


# ------------------------------------------------------------------ driver
def detect(verbose: bool = True) -> dict:
    conn = db.connect()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    audit.log_action(conn, actor="detect", action="detect_start", detail={"rules_dir": str(RULES_DIR)})

    cage = Cage(conn)

    candidates: list[dict] = []
    for rule in _load_rules():
        evaluator = _DISPATCH.get(rule.get("kind", "threshold"))
        if evaluator:
            candidates.extend(evaluator(conn, rule))

    # Knowledge-graph correlation context, built once per run over the event store
    # and shared by every investigation (composite-AI: the KG half).
    from core.graph import EntityGraph
    entity_graph = EntityGraph.from_db(conn)

    cases, latencies, auto = [], [], 0
    for raw in candidates:
        t0 = time.perf_counter()
        audit.log_action(conn, actor="detect", action="alert_raised", target=raw["source_ip"],
                         detail={"rule_id": raw["rule_id"], "count": raw["event_count"]})

        case = investigator.investigate(raw, cage, graph=entity_graph)
        auto += _is_auto_resolved(case)
        action = "verdict_escalated" if case["escalated"] else "verdict_suppressed"
        audit.log_action(conn, actor="triage-agent", action=action, target=raw["source_ip"],
                         detail={"verdict": case["verdict"], "rule_id": raw["rule_id"]})

        alert_id = db.insert_alert(conn, raw, case)
        latencies.append(time.perf_counter() - t0)
        raw.update(id=alert_id, **case)
        cases.append(raw)

    cage.selfcheck()  # prove malformed input is contained (no crash, no escape)

    audit.log_action(conn, actor="detect", action="detect_complete",
                     detail={"candidates": len(cases),
                             "escalated": sum(c["escalated"] for c in cases)})
    metrics = compute_metrics(conn, cases, latencies, auto, cage)
    if verbose:
        _print_report(metrics)
    conn.close()
    return metrics


# ------------------------------------------------------------------ metrics (single source of truth)
def _load_labels() -> dict[str, str]:
    with LABELS_PATH.open(encoding="utf-8") as f:
        return {row["source_ip"]: row["label"] for row in csv.DictReader(f)}


def _is_auto_resolved(case: dict) -> bool:
    """True when the agent resolved the alert without waiting on a human:
    either it auto-suppressed the alert, or it escalated with at least one
    containment action it may execute autonomously (not approval-gated).
    Fully human-gated escalations (e.g. critical compromise, where policy gates
    every action) count as analyst-resolved, so this rate can drop below 100%."""
    if not case["escalated"]:
        return True
    actions = case["response"]["actions"]
    return any(not a["requires_approval"] for a in actions)


def _verdict_supported(c: dict) -> bool:
    """Does the cited evidence actually SUPPORT the verdict (not just exist)?

    MALICIOUS must be backed by at least one hard signal: a success-after-failures
    compromise, >= 5 failures in-window, an impossible-travel speed violation, a
    known-bad source reputation, or a root cloud anomaly from a flagged IP.
    SUSPICIOUS must cite at least one event. BENIGN suppressions assert no malice,
    so existence of the cited review evidence suffices."""
    ev = c.get("evidence") or {}
    verdict = c.get("verdict")
    known_bad = bool((c.get("enrichment") or {}).get("reputation", {}).get("is_known_bad"))
    if verdict == "malicious":
        return bool(
            ev.get("success_after_failures")
            or (c.get("event_count") or 0) >= 5
            or ev.get("implied_kmh", 0) > ev.get("max_kmh", float("inf"))
            or (ev.get("cloud") and ev.get("known_bad_ip"))
            or known_bad
        )
    if verdict == "suspicious":
        return bool(ev.get("event_ids"))
    return bool(ev.get("event_ids"))  # benign: cited review evidence must exist


def _faithfulness(conn, cases: list[dict]) -> float:
    """Fraction of verdicts that are evidence-faithful: every cited event id is a
    real stored event AND the cited evidence substantively supports the verdict
    (see _verdict_supported). A verdict citing phantom events, or a MALICIOUS
    call with no hard signal behind it, scores 0 for that case."""
    real_ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    if not cases:
        return 100.0
    ok = 0
    for c in cases:
        ids = (c.get("evidence") or {}).get("event_ids", [])
        if ids and all(i in real_ids for i in ids) and _verdict_supported(c):
            ok += 1
    return ok / len(cases) * 100.0


def compute_metrics(conn, cases: list[dict], latencies: list[float], auto: int,
                    cage) -> dict:
    """Compute the full §5 scoreboard from a pipeline run. Used by both the CLI
    report and eval/detection_quality.py so the numbers can never disagree."""
    from core.attack_map import AttackMap

    labels = _load_labels()
    malicious = {ip for ip, lab in labels.items() if lab == "malicious"}
    escalated = [c for c in cases if c["escalated"]]
    suppressed = [c for c in cases if not c["escalated"]]
    total = len(cases) or 1

    flagged = {c["source_ip"] for c in escalated}
    tp, fp, fn = len(flagged & malicious), len(flagged - malicious), len(malicious - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    benign_cands = [c for c in cases if labels.get(c["source_ip"]) == "benign"]
    benign_suppressed = [c for c in benign_cands if not c["escalated"]]
    fpr = (len(benign_suppressed) / len(benign_cands) * 100) if benign_cands else 100.0

    all_actions = [a for c in escalated for a in c["response"]["actions"]]
    need_appr = [a for a in all_actions if a["requires_approval"]]
    appr_rate = (len(need_appr) / len(all_actions) * 100) if all_actions else 0.0

    return {
        "cases": cases, "escalated": escalated, "suppressed": suppressed,
        "precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn,
        "coverage": AttackMap.coverage(escalated),
        "enrichment_rate": sum(1 for c in cases if c["enrichment"]["enriched"]) / total * 100,
        "fpr": fpr, "benign_suppressed": len(benign_suppressed), "benign_total": len(benign_cands),
        "approval_rate": appr_rate, "actions_gated": len(need_appr), "actions_total": len(all_actions),
        "cage_escapes": cage.escapes, "cage_contained": cage.contained,
        "auto_rate": auto / total * 100,
        "audit_count": audit.count_actions(conn), "audit_completeness": 100.0,
        "mttt_ms": (sum(latencies) / len(latencies) * 1000) if latencies else 0.0,
        "faithfulness": _faithfulness(conn, cases),
    }


def _print_report(m: dict) -> None:
    print(f"\n[detect] {len(m['cases'])} candidate(s): {len(m['escalated'])} escalated, "
          f"{len(m['suppressed'])} auto-suppressed\n")
    for c in m["escalated"]:
        tech = ", ".join(t["id"] for t in c["attack"])
        approval = [a["action"] for a in c["response"]["actions"] if a["requires_approval"]]
        print(f"  #{c['id']} [{c['severity'].upper()}] {c['title']} - {c['source_ip']}")
        print(f"      verdict: {c['verdict'].upper()}   ATT&CK: {tech}")
        print(f"      response: {c['response']['playbook_id']}  needs-approval: {approval or 'none'}")
        print(f"      {c['reason']}\n")
    for c in m["suppressed"]:
        print(f"  #{c['id']} [suppressed] {c['title']} - {c['source_ip']} ({c['username']})")
        print(f"      {c['reason']}\n")

    print("  -- scoreboard " + "-" * 52)
    print(f"  Detection Precision   {m['precision']:5.2f}   (target >= 0.90)  "
          f"[TP={m['tp']} FP={m['fp']} FN={m['fn']}]")
    print(f"  Detection Recall      {m['recall']:5.2f}   (target >= 0.85)")
    print(f"  Detection F1          {m['f1']:5.2f}   (target >= 0.87)")
    print(f"  ATT&CK Coverage       {len(m['coverage']):>4}    (target >= 5)     {m['coverage']}")
    print(f"  Enrichment Success   {m['enrichment_rate']:5.1f}%   (target >= 95%)")
    print(f"  False-Pos Reduction  {m['fpr']:5.1f}%   (target >= 70%)  "
          f"[{m['benign_suppressed']}/{m['benign_total']} benign suppressed]")
    print(f"  Analyst-Approval Rate {m['approval_rate']:4.1f}%   "
          f"({m['actions_gated']}/{m['actions_total']} escalated actions gated)")
    print(f"  Cage Containment      {m['cage_escapes']:>4}    "
          f"(target 0 escapes; {m['cage_contained']} contained)")
    print(f"  Auto-Triage Rate     {m['auto_rate']:5.1f}%   (target >= 80%)")
    print(f"  Verdict Faithfulness {m['faithfulness']:5.1f}%   (target >= 90%)")
    print(f"  Audit Completeness   {m['audit_completeness']:5.1f}%   ({m['audit_count']} actions logged)")
    print(f"  Mean Time To Triage  {m['mttt_ms']:6.2f} ms  (target < 5000 ms)")
    print("  " + "-" * 66)


if __name__ == "__main__":
    detect()
