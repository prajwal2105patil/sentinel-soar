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
| `core/enrich.py` | IP reputation / geo (API + mock) | Context enrichment | ⏳ 2 |
| `core/attack_map.py` | Map detections → MITRE ATT&CK IDs | Map to ATT&CK attack chains | ⏳ 2 |
| `core/cage.py` | Validate + sandbox the analysis step | Guardrailed / safe automation | ⏳ 2 |
| `agent/investigator.py` | LangGraph agent wiring the full loop | Composite-AI agent loop | ⏳ 3 |
| `playbooks/response/*.yml` | Deterministic response + analyst-in-loop approval | Response automation with control | ⏳ 3 |
| `api/app.py` | FastAPI `/ingest` `/investigate` `/cases` | Programmatic SOC surface | ⏳ 3 |
| `eval/detection_quality.py` | Compute the full scoreboard on labels | True-positive / fewer-escalations — quantified | ⏳ 4 |

## Run

```bash
pip install -r requirements.txt
python -m core.ingest     # logs -> data/events.db
python -m core.detect     # run YAML rules -> alerts + verdicts + scoreboard
```

**Phase-1 acceptance:** `python -m core.ingest && python -m core.detect` produces flagged alerts each carrying a verdict, and every action appears in `audit_log`.

## Scoreboard

Live Phase-1 metrics (run `python -m core.detect`). Full §5 scoreboard lands in Phase 4.

| Metric | Definition | Target | Phase-1 result |
|---|---|---|---|
| Auto-Triage Rate | % alerts fully triaged by the agent (no human) | ≥ 80% | **100%** |
| Audit Completeness | % actions written to `audit_log` | 100% | **100%** |
| Mean Time To Triage | avg pipeline latency per alert | < 5 s | **~11 ms** |
| Detection Precision / Recall / F1 | on `data/labels.csv` | ≥ 0.90 / 0.85 / 0.87 | ⏳ Phase 4 |
| ATT&CK Coverage | distinct techniques mapped | ≥ 5 | ⏳ Phase 2 |
| Cage Containment | unhandled errors escaping the cage | 0 | ⏳ Phase 2 |
| Verdict Faithfulness | verdict grounded in cited evidence | ≥ 0.90 | ✅ 1.0 by construction |

## Build status

- **Phase 1 — Core loop (MVP):** ✅ ingest, one rule, detect, LLM triage stub, audit log.
- **Phase 2 — Investigation depth:** ⏳ second rule, enrichment, ATT&CK map, execution cage.
- **Phase 3 — Agent + response:** ⏳ LangGraph agent, response playbooks, FastAPI.
- **Phase 4 — Proof polish:** ⏳ full scoreboard on `labels.csv`, architecture write-up.

## Honesty & attribution

The claim is the **engineering**: guarded AI-agent automation for the SOC loop, with measured detection quality. It is **not** production SOC experience, and the metrics are computed on a **synthetic labeled set**, not real-world traffic.
