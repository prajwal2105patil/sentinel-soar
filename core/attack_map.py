"""Map detections -> MITRE ATT&CK techniques.

Each rule carries a `mitre:` list of technique IDs; this module resolves those IDs
to name + tactic from the static catalog (detections/attack_techniques.json) and
computes ATT&CK coverage across a set of alerts. No network, fully offline.
"""
from __future__ import annotations

import json

from core import db

CATALOG_PATH = db.ROOT / "detections" / "attack_techniques.json"


class AttackMap:
    def __init__(self) -> None:
        self._catalog: dict[str, dict] = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))

    def resolve(self, technique_ids: list[str]) -> list[dict]:
        """Resolve technique IDs -> [{id, name, tactic}], flagging unknowns."""
        out = []
        for tid in technique_ids or []:
            meta = self._catalog.get(tid)
            if meta:
                out.append({"id": tid, "name": meta["name"], "tactic": meta["tactic"]})
            else:
                out.append({"id": tid, "name": "UNKNOWN", "tactic": "UNKNOWN"})
        return out

    @staticmethod
    def coverage(alerts: list[dict]) -> list[str]:
        """Distinct technique IDs mapped across all raised alerts (the coverage metric)."""
        seen: set[str] = set()
        for a in alerts:
            for t in a.get("attack", []):
                seen.add(t["id"])
        return sorted(seen)
