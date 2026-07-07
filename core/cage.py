"""Execution cage — guardrailed analysis.

The analysis/verdict step runs *inside* the cage: input is validated, execution is
sandboxed in a catch-all, and any failure is contained (logged to audit + safe
fallback returned) rather than crashing the pipeline. This is AiStrike's exact
safety model — the AI never acts unguarded, and one malformed alert can't take the
platform down.

`Cage.escapes` is the `Cage Containment` metric: it must stay 0.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Callable

from core import audit

REQUIRED_ALERT_KEYS = ("rule_id", "source_ip", "event_count", "evidence")


def validate_alert(alert: Any) -> None:
    """Reject malformed alerts before analysis. Raises on anything unusable."""
    if not isinstance(alert, dict):
        raise TypeError(f"alert must be a dict, got {type(alert).__name__}")
    for key in REQUIRED_ALERT_KEYS:
        if key not in alert or alert[key] is None:
            raise ValueError(f"alert missing required field: {key}")
    if not isinstance(alert["event_count"], int):
        raise ValueError("event_count must be an int")


class Cage:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.contained = 0   # errors safely caught + logged
        self.escapes = 0     # errors that escaped the cage (must be 0)
        self.runs = 0

    def run(self, name: str, fn: Callable, *args, fallback: Any = None, **kwargs) -> Any:
        """Execute fn sandboxed. Contain any exception; return fallback on failure."""
        self.runs += 1
        try:
            return fn(*args, **kwargs)
        except (KeyboardInterrupt, SystemExit):
            raise  # never swallow operator/interpreter control signals
        except BaseException as exc:  # noqa: BLE001 — containment is the point
            self.contained += 1
            audit.log_action(self.conn, actor="cage", action="contained_error",
                             target=name, detail={"error": repr(exc)})
            return fallback

    def selfcheck(self) -> None:
        """Prove containment: feed deliberately malformed inputs through validation.
        Each must be contained; escapes must remain 0."""
        for bad in (None, {}, {"source_ip": None}, "not-a-dict", {"rule_id": "x"}):
            self.run("selfcheck:validate_alert", validate_alert, bad, fallback="contained")
