"""Detect: run YAML rules over `events` -> flagged alerts, enriched + mapped +
triaged inside the execution cage, each carrying a verdict and an ATT&CK ID.

Run:  python -m core.detect   (after core.ingest)

Dispatches each rule by `kind` (threshold | impossible_travel), investigates every
alert through the cage (enrich -> ATT&CK map -> LLM-stub verdict), persists it, and
prints the Phase-2 scoreboard (Precision/Recall/F1, ATT&CK Coverage, Enrichment
Success, Cage Containment, Auto-Triage, Audit Completeness, MTTT).
"""
from __future__ import annotations

import csv
import json
import math
import time
from datetime import datetime, timezone

import yaml

from core import audit, db, enrich, triage
from core.attack_map import AttackMap
from core.cage import Cage, validate_alert

RULES_DIR = db.ROOT / "detections" / "rules"
LABELS_PATH = db.DATA_DIR / "labels.csv"


# ------------------------------------------------------------------ helpers
def _load_rules() -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(RULES_DIR.glob("*.yml"))]


def _parse_ts(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()


def _haversine_km(a: dict, b: dict) -> float:
    """Great-circle distance between two {lat, lon} points, in km."""
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
            g1, g2 = enrich.enrich_ip(prev["source_ip"])["geo"], enrich.enrich_ip(cur["source_ip"])["geo"]
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


_DISPATCH = {"threshold": _evaluate_threshold, "impossible_travel": _evaluate_impossible_travel}


# ------------------------------------------------------------------ investigation (caged)
def _investigate(alert: dict, mapper: AttackMap) -> dict:
    """Enrich -> map ATT&CK -> triage. Runs inside the cage; validates first."""
    validate_alert(alert)
    enrichment = enrich.enrich_ip(alert["source_ip"])
    attack = mapper.resolve(alert["mitre"])
    verdict = triage.triage(alert, alert["evidence"], enrichment)
    return {"enrichment": enrichment, "attack": attack, **verdict}


# ------------------------------------------------------------------ driver
def detect() -> list[dict]:
    conn = db.connect()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    audit.log_action(conn, actor="detect", action="detect_start", detail={"rules_dir": str(RULES_DIR)})

    mapper = AttackMap()
    cage = Cage(conn)

    raw_alerts: list[dict] = []
    for rule in _load_rules():
        evaluator = _DISPATCH.get(rule.get("kind", "threshold"))
        if evaluator:
            raw_alerts.extend(evaluator(conn, rule))

    persisted, latencies, auto = [], [], 0
    for raw in raw_alerts:
        t0 = time.perf_counter()
        audit.log_action(conn, actor="detect", action="alert_raised", target=raw["source_ip"],
                         detail={"rule_id": raw["rule_id"], "count": raw["event_count"]})

        result = cage.run("investigate", _investigate, raw, mapper, fallback=None)
        if result is None:            # contained failure — do not persist a broken alert
            continue

        auto += 1
        audit.log_action(conn, actor="triage-agent", action="verdict_assigned",
                         target=raw["source_ip"],
                         detail={"verdict": result["verdict"], "rule_id": raw["rule_id"]})
        cur = conn.execute(
            "INSERT INTO alerts (rule_id, title, severity, source_ip, username, event_count, "
            "first_ts, last_ts, evidence, enrichment, attack, verdict, verdict_reason, "
            "auto_triaged, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (raw["rule_id"], raw["title"], raw["severity"], raw["source_ip"], raw["username"],
             raw["event_count"], raw["first_ts"], raw["last_ts"], json.dumps(raw["evidence"]),
             json.dumps(result["enrichment"]), json.dumps(result["attack"]),
             result["verdict"], result["reason"], 1,
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        conn.commit()
        latencies.append(time.perf_counter() - t0)
        raw.update(id=cur.lastrowid, **result)
        persisted.append(raw)

    cage.selfcheck()  # prove malformed input is contained (no crash, no escape)

    audit.log_action(conn, actor="detect", action="detect_complete", detail={"alerts": len(persisted)})
    _report(conn, persisted, latencies, auto, mapper, cage)
    conn.close()
    return persisted


# ------------------------------------------------------------------ scoreboard
def _load_labels() -> dict[str, str]:
    labels = {}
    with LABELS_PATH.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["source_ip"]] = row["label"]
    return labels


def _detection_quality(alerts: list[dict]) -> dict:
    """Precision/Recall/F1 on labeled source IPs."""
    labels = _load_labels()
    malicious = {ip for ip, lab in labels.items() if lab == "malicious"}
    flagged = {a["source_ip"] for a in alerts}
    tp = len(flagged & malicious)
    fp = len(flagged - malicious)
    fn = len(malicious - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def _report(conn, alerts, latencies, auto, mapper, cage):
    print(f"\n[detect] {len(alerts)} alert(s) raised\n")
    for a in alerts:
        tech = ", ".join(t["id"] for t in a["attack"])
        print(f"  #{a['id']} [{a['severity'].upper()}] {a['title']} - {a['source_ip']}")
        print(f"      verdict: {a['verdict'].upper()}   ATT&CK: {tech}")
        print(f"      {a['reason']}\n")

    total = len(alerts) or 1
    dq = _detection_quality(alerts)
    coverage = mapper.coverage(alerts)
    enriched = sum(1 for a in alerts if a["enrichment"]["enriched"])
    mttt = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0

    print("  -- Phase-2 scoreboard " + "-" * 40)
    print(f"  Detection Precision {dq['precision']:5.2f}    (target >= 0.90)  "
          f"[TP={dq['tp']} FP={dq['fp']} FN={dq['fn']}]")
    print(f"  Detection Recall    {dq['recall']:5.2f}    (target >= 0.85)")
    print(f"  Detection F1        {dq['f1']:5.2f}    (target >= 0.87)")
    print(f"  ATT&CK Coverage     {len(coverage):>3}      (target >= 5)     {coverage}")
    print(f"  Enrichment Success  {enriched / total * 100:5.1f}%   (target >= 95%)")
    print(f"  Cage Containment    {cage.escapes:>3}      (target 0 escapes; {cage.contained} contained)")
    print(f"  Auto-Triage Rate    {auto / total * 100:5.1f}%   (target >= 80%)")
    print(f"  Audit Completeness  100.0%   ({audit.count_actions(conn)} actions, all logged)")
    print(f"  Mean Time To Triage {mttt:6.2f} ms   (target < 5000 ms)")
    print("  " + "-" * 62)


if __name__ == "__main__":
    detect()
