# Sentinel-SOAR

**An AiStrike-mirroring mini SOAR** — a runnable, offline, zero-paid-key pipeline that reproduces the SOC loop **detect → triage → investigate → respond**, with a scoreboard that speaks AiStrike's metrics.

> Patterns adapted from my **DREADNOUGHT** data platform (SQL warehouse, YAML config, append-only audit log, execution cage). Sentinel-SOAR built by **Prajwal Patil**.
> Metrics below are computed on a **synthetic labeled alert set** (`data/labels.csv`) — they are engineering proof, **not** real-world SOC benchmarks.

---

## Raw alert → investigated, responded, audited

```
sample logs → INGEST(SQL) → DETECT(YAML rules) → ENRICH(API/mock)
   → MAP(MITRE ATT&CK) → EXECUTION CAGE(safe analysis) → LLM AGENT verdict
   → YAML RESPONSE PLAYBOOK(auto | analyst-in-loop) → AUDIT LOG + EVAL
```

## Module → AiStrike capability

| Module | What it does | AiStrike capability proven | Phase |
|---|---|---|---|
| `core/ingest.py` | Parse `sample_auth.log` → `events` table via SQL | SQL to extract & analyze security data | ✅ 1 |
| `detections/rules/*.yml` | Detection-as-code (thresholds, ATT&CK, escalation) | Deterministic YAML playbooks / detection engineering | ✅ 1 |
| `core/detect.py` | Interpret rules → flagged alerts | Detection + coverage | ✅ 1 |
| `core/triage.py` | LLM-stub verdict grounded in cited evidence | AI-driven triage (composite AI, provider-agnostic) | ✅ 1 |
| `core/audit.py` | Append-only audit log of every action | SOC 2 governance / audit trail | ✅ 1 |
| `detections/rules/impossible_travel.yml` | Geo/velocity detection-as-code | Detection engineering (2nd technique) | ✅ 2 |
| `core/enrich.py` | IP reputation / geo (mock + live opt-in) | Context enrichment | ✅ 2 |
| `core/attack_map.py` | Map detections → MITRE ATT&CK IDs | Map to ATT&CK attack chains | ✅ 2 |
| `core/cage.py` | Validate + sandbox the analysis step | Guardrailed / safe automation | ✅ 2 |
| `detections/rules/credential_review.yml` | Noisy review signal the agent auto-suppresses | Fewer escalations (FP reduction) | ✅ 3 |
| `agent/investigator.py` | LangGraph agent wiring the full loop | Composite-AI agent loop | ✅ 3 |
| `core/respond.py` + `playbooks/response/*.yml` | Deterministic response + analyst-in-loop approval | Response automation with control | ✅ 3 |
| `core/auth.py` | X-API-key gate (DREADNOUGHT pattern) | Access control | ✅ 3 |
| `api/app.py` | FastAPI `/ingest` `/investigate` `/cases` | Programmatic SOC surface | ✅ 3 |
| `eval/detection_quality.py` | Compute the full scoreboard on labels | True-positive / fewer-escalations — quantified | ⏳ 4 |

## Run

```bash
pip install -r requirements.txt
python -m core.ingest              # logs -> data/events.db
python -m core.detect              # rules -> agent (enrich/map/cage/verdict/response) -> scoreboard
uvicorn api.app:app --reload       # API: /ingest /investigate /cases  (X-API-Key required)
```

Investigate a single alert over the API (key defaults to `dev-sentinel-key`, override with `SENTINEL_API_KEY`):

```bash
curl -s -X POST localhost:8000/investigate -H "X-API-Key: dev-sentinel-key" \
  -H "Content-Type: application/json" \
  -d '{"rule_id":"RULE-BRUTE-FORCE-001","source_ip":"45.133.1.88","event_count":6,
       "severity":"critical","username":"postgres",
       "evidence":{"event_ids":[17,18,19],"targeted_users":["postgres"],
                   "success_after_failures":{"username":"postgres","ts":"2025-06-14T09:05:40+00:00"}}}'
# -> verdict + ATT&CK techniques + response playbook; critical actions flagged requires_approval
```

**Acceptance:** `python -m core.ingest && python -m core.detect` flags alerts each carrying a verdict (Phase 1); every alert gets enrichment + an ATT&CK ID and the cage contains malformed input with 0 escapes (Phase 2); `POST /investigate` returns verdict + ATT&CK + recommended response with critical actions gated for human approval (Phase 3).

## Scoreboard

Live metrics (run `python -m core.detect`) on the synthetic labeled set. All current-phase targets met.

| Metric | Definition | Target | Result |
|---|---|---|---|
| Detection Precision / Recall / F1 | on escalated alerts vs `data/labels.csv` | ≥ 0.90 / 0.85 / 0.87 | **1.00 / 1.00 / 1.00** |
| ATT&CK Coverage | distinct techniques mapped | ≥ 5 | **5** (T1110, T1110.001, T1021.004, T1078, T1078.003) |
| Enrichment Success | % alerts enriched with context | ≥ 95% | **100%** |
| False-Positive Reduction | % benign alerts auto-suppressed before escalation | ≥ 70% | **100%** (2/2 benign suppressed) |
| Analyst-Approval Rate | % escalated actions gated on a human | (displayed) | **55.6%** (5/9; all critical-alert actions gated) |
| Cage Containment | unhandled errors escaping the cage | 0 | **0** (5 malformed inputs contained) |
| Auto-Triage Rate | % alerts triaged by the agent, no human | ≥ 80% | **100%** |
| Audit Completeness | % actions written to `audit_log` | 100% | **100%** |
| Mean Time To Triage | avg pipeline latency per alert | < 5 s | **~19 ms** |
| Verdict Faithfulness | verdict grounded in cited evidence | ≥ 0.90 | **1.0** by construction (every claim cites events) |

## Build status

- **Phase 1 — Core loop (MVP):** ✅ ingest, one rule, detect, LLM triage stub, audit log.
- **Phase 2 — Investigation depth:** ✅ impossible-travel rule, geo/reputation enrichment, ATT&CK map, execution cage.
- **Phase 3 — Agent + response:** ✅ LangGraph investigator, response playbooks + analyst-in-loop approval, FastAPI `/ingest` `/investigate` `/cases` with X-API-key.
- **Phase 4 — Proof polish:** ⏳ `eval/detection_quality.py` full scoreboard on `labels.csv`, architecture write-up.

## Honesty & attribution

The claim is the **engineering**: guarded AI-agent automation for the SOC loop, with measured detection quality. It is **not** production SOC experience, and the metrics are computed on a **synthetic labeled set**, not real-world traffic.
