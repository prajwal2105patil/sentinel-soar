"""LangGraph investigator — the agentic SOC loop for a single alert.

Graph:  START -> enrich -> attack -> verdict -(conditional)-> respond | suppress -> END

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

from core import enrich, respond, triage
from core.attack_map import AttackMap
from core.cage import Cage

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


class CaseState(TypedDict, total=False):
    alert: dict
    enrichment: dict
    attack: list
    verdict: str
    reason: str
    escalated: bool
    response: dict
    _cage: Any


# ------------------------------------------------------------------ nodes
def _enrich_node(state: CaseState) -> dict:
    return {"enrichment": enrich.enrich_ip(state["alert"]["source_ip"])}


def _attack_node(state: CaseState) -> dict:
    return {"attack": _MAPPER.resolve(state["alert"].get("mitre", []))}


def _verdict_node(state: CaseState) -> dict:
    cage: Cage = state["_cage"]
    v = cage.run(
        "verdict", triage.triage,
        state["alert"], state["alert"]["evidence"], state.get("enrichment"),
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
    g.add_node("attack", _attack_node)
    g.add_node("verdict", _verdict_node)
    g.add_node("respond", _respond_node)
    g.add_node("suppress", _suppress_node)
    g.add_edge(START, "enrich")
    g.add_edge("enrich", "attack")
    g.add_edge("attack", "verdict")
    g.add_conditional_edges("verdict", _route, {"respond": "respond", "suppress": "suppress"})
    g.add_edge("respond", END)
    g.add_edge("suppress", END)
    return g.compile()


def _run_linear(state: CaseState) -> CaseState:
    state.update(_enrich_node(state))
    state.update(_attack_node(state))
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
        "attack": s["attack"],
        "verdict": s["verdict"],
        "reason": s["reason"],
        "escalated": s["escalated"],
        "response": s["response"],
    }


def investigate(alert: dict, cage: Cage) -> dict:
    """Run one alert through the investigation graph; return a structured case."""
    state: CaseState = {"alert": alert, "_cage": cage}
    final = _graph().invoke(state) if HAS_LANGGRAPH else _run_linear(state)
    return _as_case(final)
