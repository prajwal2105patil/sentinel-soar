"""Knowledge-graph-lite entity correlation (composite-AI component).

AiStrike's "Composite AI" combines ML, knowledge graphs, and LLMs. This is the
knowledge-graph half: an in-memory graph over the event store linking the three
core SOC entities — user <-> source_ip <-> host. During investigation it answers
"what else touched this entity?", giving the verdict full-context correlation
(e.g. "this IP also targeted 4 other accounts") instead of judging an alert alone.

No network, no DB writes — built on demand from the `events` table.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict


class EntityGraph:
    """Bidirectional adjacency over (user, ip, host) built from events."""

    def __init__(self) -> None:
        self.ip_users: dict[str, set[str]] = defaultdict(set)
        self.user_ips: dict[str, set[str]] = defaultdict(set)
        self.ip_hosts: dict[str, set[str]] = defaultdict(set)
        self.ip_fail_users: dict[str, set[str]] = defaultdict(set)

    @classmethod
    def from_db(cls, conn: sqlite3.Connection) -> "EntityGraph":
        g = cls()
        for r in conn.execute(
            "SELECT username, source_ip, host, event_type FROM events "
            "WHERE source_ip IS NOT NULL"
        ).fetchall():
            u, ip, host, et = r["username"], r["source_ip"], r["host"], r["event_type"]
            if u:
                g.ip_users[ip].add(u)
                g.user_ips[u].add(ip)
                if et == "auth_failure":
                    g.ip_fail_users[ip].add(u)
            if host:
                g.ip_hosts[ip].add(host)
        return g

    def correlate(self, alert: dict) -> dict:
        """Full-context view for one alert's primary entities."""
        ip = alert.get("source_ip")
        user = alert.get("username")
        ip_users = sorted(self.ip_users.get(ip, set()))
        fail_users = sorted(self.ip_fail_users.get(ip, set()))
        user_ips = sorted(self.user_ips.get(user, set())) if user else []
        return {
            "ip_targeted_users": ip_users,
            "ip_targeted_user_count": len(ip_users),
            "ip_failed_users": fail_users,
            "user_seen_from_ips": user_ips,
            "user_ip_count": len(user_ips),
            "hosts_touched": sorted(self.ip_hosts.get(ip, set())),
            # a source hitting many distinct accounts is a spray signal
            "spray_signal": len(fail_users) >= 3,
        }
