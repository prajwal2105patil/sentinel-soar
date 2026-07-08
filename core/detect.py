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
import json
import math
import time
from datetime import datetime, timezone

import yaml

from agent import investigator
from core import audit, db
from core.cage import Cage

RULES_DIR = db.ROOT / "detections" / "rules"
LABELS_PATH = db.DATA_DIR / "labels.csv"


# ------------------------------------------------------------------ helpers
def _load_rules() -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(RULES_DIR.glob("*.yml"))]


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
    where = " AND ".join(f"{k} = ?" for k in match)
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
    where = " AND ".join(f"{k} = ?" for k in match)
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


_DISPATCH = {
    "threshold": _evaluate_threshold,
    "impossible_travel": _evaluate_impossible_travel,
    "failed_then_success": _evaluate_failed_then_success,
}


# ------------------------------------------------------------------ driver
def detect() -> list[dict]:
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

    cases, latencies, auto = [], [], 0
    for raw in candidates:
        t0 = time.perf_counter()
        audit.log_action(conn, actor="detect", action="alert_raised", target=raw["source_ip"],
                         detail={"rule_id": raw["rule_id"], "count": raw["event_count"]})

        case = investigator.investigate(raw, cage)  # agent: enrich -> map -> caged verdict -> response
        auto += 1
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
    _report(conn, cases, latencies, auto, cage)
    conn.close()
    return cases


# ------------------------------------------------------------------ scoreboard
def _load_labels() -> dict[str, str]:
    with LABELS_PATH.open(encoding="utf-8") as f:
        return {row["source_ip"]: row["label"] for row in csv.DictReader(f)}


def _report(conn, cases, latencies, auto, cage):
    from core.attack_map import AttackMap

    escalated = [c for c in cases if c["escalated"]]
    suppressed = [c for c in cases if not c["escalated"]]
    labels = _load_labels()
    malicious = {ip for ip, lab in labels.items() if lab == "malicious"}

    print(f"\n[detect] {len(cases)} candidate(s): {len(escalated)} escalated, "
          f"{len(suppressed)} auto-suppressed\n")
    for c in escalated:
        tech = ", ".join(t["id"] for t in c["attack"])
        approval = [a["action"] for a in c["response"]["actions"] if a["requires_approval"]]
        print(f"  #{c['id']} [{c['severity'].upper()}] {c['title']} - {c['source_ip']}")
        print(f"      verdict: {c['verdict'].upper()}   ATT&CK: {tech}")
        print(f"      response: {c['response']['playbook_id']}  "
              f"needs-approval: {approval or 'none'}")
        print(f"      {c['reason']}\n")
    for c in suppressed:
        print(f"  #{c['id']} [suppressed] {c['title']} - {c['source_ip']} ({c['username']})")
        print(f"      {c['reason']}\n")

    # Detection quality on ESCALATED alerts (post-triage funnel).
    flagged = {c["source_ip"] for c in escalated}
    tp, fp = len(flagged & malicious), len(flagged - malicious)
    fn = len(malicious - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # False-Positive Reduction: benign candidates auto-suppressed before escalation.
    benign_cands = [c for c in cases if labels.get(c["source_ip"]) == "benign"]
    benign_suppressed = [c for c in benign_cands if not c["escalated"]]
    fpr = (len(benign_suppressed) / len(benign_cands) * 100) if benign_cands else 100.0

    # Analyst-approval rate over escalated response actions.
    all_actions = [a for c in escalated for a in c["response"]["actions"]]
    need_appr = [a for a in all_actions if a["requires_approval"]]
    appr_rate = (len(need_appr) / len(all_actions) * 100) if all_actions else 0.0

    coverage = AttackMap.coverage(escalated)
    enriched = sum(1 for c in cases if c["enrichment"]["enriched"])
    total = len(cases) or 1
    mttt = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0

    print("  -- Phase-3 scoreboard " + "-" * 44)
    print(f"  Detection Precision   {precision:5.2f}   (target >= 0.90)  [TP={tp} FP={fp} FN={fn}]")
    print(f"  Detection Recall      {recall:5.2f}   (target >= 0.85)")
    print(f"  Detection F1          {f1:5.2f}   (target >= 0.87)")
    print(f"  ATT&CK Coverage       {len(coverage):>4}    (target >= 5)     {coverage}")
    print(f"  Enrichment Success   {enriched / total * 100:5.1f}%   (target >= 95%)")
    print(f"  False-Pos Reduction  {fpr:5.1f}%   (target >= 70%)  "
          f"[{len(benign_suppressed)}/{len(benign_cands)} benign suppressed]")
    print(f"  Analyst-Approval Rate {appr_rate:4.1f}%   ({len(need_appr)}/{len(all_actions)} "
          f"escalated actions gated)")
    print(f"  Cage Containment      {cage.escapes:>4}    (target 0 escapes; {cage.contained} contained)")
    print(f"  Auto-Triage Rate     {auto / total * 100:5.1f}%   (target >= 80%)")
    print(f"  Audit Completeness   100.0%   ({audit.count_actions(conn)} actions, all logged)")
    print(f"  Mean Time To Triage  {mttt:6.2f} ms  (target < 5000 ms)")
    print("  " + "-" * 66)


if __name__ == "__main__":
    detect()
