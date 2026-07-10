"""LangGraph investigator — the agentic SOC loop for a single alert.

Graph:  START -> enrich -> correlate -> attack -> verdict
                                        -(conditional)-> respond | suppress -> END

The `verdict` node runs the LLM-stub triage *inside the execution cage*, and the
conditional edge routes escalated alerts to a response playbook while auto-
suppressing benign ones. This is the one investigation code path — the batch
pipeline (core/detect.py) and the API (api/app.py) both call `investigate()`, so
they can never diverge.

If LangGraph isn't importable the same nodes run as a linear fallback, so the repo
stays runnable offline with identical results.
"""
from __future__ import annotations

import functools
from typing import Any, TypedDict

from core import db, enrich, respond, triage
from core.attack_map import AttackMap
from core.cage import Cage
from core.graph import EntityGraph

_MAPPER = AttackMap()
ESCALATE_VERDICTS = {"malicious", "suspicious"}

try:
    import warnings

    # LangChain re-installs its own warnings filters during import, so a normal
    # filterwarnings("ignore", ...) gets overridden and a cosmetic pending-
    # deprecation notice (from langgraph internals, not our code) leaks to stderr.
    # Intercept at the display layer instead — langchain doesn't touch showwarning.
    _orig_showwarning = warnings.showwarning

    def _quiet_showwarning(message, category, filename, lineno, file=None, line=None):
        if "allowed_objects" in str(message):
            return  # drop this one library notice; pass everything else through
        return _orig_showwarning(message, category, filename, lineno, file, line)

    warnings.showwarning = _quiet_showwarning

    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except Exception:  # pragma: no cover - offline / missing dep fallback
    HAS_LANGGRAPH = False

try:
    from ml import model as ml_model
    HAS_ML = True
except Exception:  # pragma: no cover - scikit-learn/numpy absent -> skip ML scoring
    HAS_ML = False


class CaseState(TypedDict, total=False):
    alert: dict
    enrichment: dict
    correlation: dict
    attack: list
    risk: dict
    verdict: str
    reason: str
    escalated: bool
    response: dict
    _cage: Any
    _graph: Any


# ------------------------------------------------------------------ nodes
def _enrich_node(state: CaseState) -> dict:
    return {"enrichment": enrich.enrich_ip(state["alert"]["source_ip"])}


def _correlate_node(state: CaseState) -> dict:
    """Knowledge-graph correlation: what else did this alert's entities touch?
    The batch pipeline passes a graph built once per run; the API path builds one
    on demand from the current event store."""
    g = state.get("_graph")
    if g is None:
        conn = db.connect()
        try:
            g = EntityGraph.from_db(conn)
        finally:
            conn.close()
    return {"correlation": g.correlate(state["alert"])}


def _attack_node(state: CaseState) -> dict:
    return {"attack": _MAPPER.resolve(state["alert"].get("mitre", []))}


def _ml_node(state: CaseState) -> dict:
    """Attach the ML behavioural risk score for the alert's source IP. Runs inside
    its own connection (mirrors the correlate node); failures degrade to no score."""
    conn = db.connect()
    try:
        return {"risk": ml_model.assess_ip(conn, state["alert"]["source_ip"])}
    finally:
        conn.close()


def _verdict_node(state: CaseState) -> dict:
    cage: Cage = state["_cage"]
    v = cage.run(
        "verdict", triage.triage,
        state["alert"], state["alert"]["evidence"], state.get("enrichment"),
        state.get("correlation"), state.get("risk"),
        fallback={"verdict": "suspicious",
                  "reason": "Triage error contained by the cage; routed to an analyst."},
    )
    return {"verdict": v["verdict"], "reason": v["reason"],
            "escalated": v["verdict"] in ESCALATE_VERDICTS}


def _route(state: CaseState) -> str:
    return "respond" if state["escalated"] else "suppress"


def _respond_node(state: CaseState) -> dict:
    return {"response": respond.build_response(state["alert"], state["verdict"])}


def _suppress_node(state: CaseState) -> dict:
    return {"response": respond.build_response(state["alert"], state["verdict"])}


# ------------------------------------------------------------------ graph / fallback
@functools.lru_cache(maxsize=1)
def _graph():
    g = StateGraph(CaseState)
    g.add_node("enrich", _enrich_node)
    g.add_node("correlate", _correlate_node)
    g.add_node("attack", _attack_node)
    g.add_node("verdict", _verdict_node)
    g.add_node("respond", _respond_node)
    g.add_node("suppress", _suppress_node)
    g.add_edge(START, "enrich")
    g.add_edge("enrich", "correlate")
    g.add_edge("correlate", "attack")
    if HAS_ML:                                  # attack -> ml -> verdict
        g.add_node("ml", _ml_node)
        g.add_edge("attack", "ml")
        g.add_edge("ml", "verdict")
    else:
        g.add_edge("attack", "verdict")
    g.add_conditional_edges("verdict", _route, {"respond": "respond", "suppress": "suppress"})
    g.add_edge("respond", END)
    g.add_edge("suppress", END)
    return g.compile()


def _run_linear(state: CaseState) -> CaseState:
    state.update(_enrich_node(state))
    state.update(_correlate_node(state))
    state.update(_attack_node(state))
    if HAS_ML:
        state.update(_ml_node(state))
    state.update(_verdict_node(state))
    node = _respond_node if _route(state) == "respond" else _suppress_node
    state.update(node(state))
    return state


def _as_case(s: CaseState) -> dict:
    keep = ("rule_id", "title", "severity", "source_ip", "username",
            "event_count", "first_ts", "last_ts", "evidence")
    return {
        "alert": {k: s["alert"].get(k) for k in keep},
        "enrichment": s["enrichment"],
        "correlation": s.get("correlation", {}),
        "attack": s["attack"],
        "risk": s.get("risk", {}),
        "verdict": s["verdict"],
        "reason": s["reason"],
        "escalated": s["escalated"],
        "response": s["response"],
    }


def investigate(alert: dict, cage: Cage, graph: EntityGraph | None = None) -> dict:
    """Run one alert through the investigation graph; return a structured case.
    `graph` is an optional pre-built EntityGraph (the batch pipeline builds one
    per run); when None the correlate node builds it from the event store."""
    state: CaseState = {"alert": alert, "_cage": cage, "_graph": graph}
    final = _graph().invoke(state) if HAS_LANGGRAPH else _run_linear(state)
    return _as_case(final)
