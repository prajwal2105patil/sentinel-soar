"""Enrich: IP reputation + geolocation, with a mock fallback.

Runs fully offline against a static intel table (deterministic demo). If
SENTINEL_ENRICH_LIVE=1 and `requests` + network are available, it will try a free
live lookup (ip-api.com, no key) and fall back to the mock on any failure — the
"real when keyed, offline for demo" decision from the handoff.

Returns a stable shape so downstream (triage, impossible-travel) can rely on it:
    {ip, enriched: bool, geo: {city, country, lat, lon} | None,
     reputation: {category, is_known_bad, source}}
"""
from __future__ import annotations

import ipaddress
import os

# Static intel table (mock). Keyed by IP -> geo + reputation.
_MOCK: dict[str, dict] = {
    "198.51.100.7":  {"geo": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
                      "reputation": {"category": "residential", "is_known_bad": False}},
    "198.51.100.23": {"geo": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
                      "reputation": {"category": "datacenter", "is_known_bad": False}},
    "203.0.113.9":   {"geo": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
                      "reputation": {"category": "residential", "is_known_bad": False}},
    "203.0.113.44":  {"geo": {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
                      "reputation": {"category": "hosting", "is_known_bad": True}},
    "45.133.1.88":   {"geo": {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
                      "reputation": {"category": "bulletproof-hosting", "is_known_bad": True}},
    "185.220.101.5": {"geo": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
                      "reputation": {"category": "tor-exit", "is_known_bad": True}},
    "91.203.5.10":   {"geo": {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093},
                      "reputation": {"category": "hosting", "is_known_bad": True}},
}


# Explicit private/loopback ranges. We do NOT use ipaddress.is_private: Python 3.12+
# folds the TEST-NET documentation ranges (198.51.100.0/24, 203.0.113.0/24) into
# is_private, but our mock intel uses exactly those safe-to-publish ranges as stand-ins
# for real public IPs — so they must resolve to geo, not "internal".
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in
    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7")
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def _live_lookup(ip: str) -> dict | None:
    """Best-effort free live enrichment; None on any failure. Never raises."""
    try:
        import requests  # optional dependency, only touched when opted in
        r = requests.get(f"http://ip-api.com/json/{ip}"
                         "?fields=status,city,countryCode,lat,lon,hosting,proxy", timeout=3)
        d = r.json()
        if d.get("status") != "success":
            return None
        return {
            "geo": {"city": d.get("city"), "country": d.get("countryCode"),
                    "lat": d.get("lat"), "lon": d.get("lon")},
            "reputation": {"category": "hosting" if d.get("hosting") else
                           ("proxy" if d.get("proxy") else "unknown"),
                           "is_known_bad": bool(d.get("hosting") or d.get("proxy"))},
        }
    except Exception:
        return None


def enrich_ip(ip: str | None) -> dict:
    """Enrich a single IP. Always returns the stable shape; `enriched` says if we
    found real context (geo or a non-neutral reputation)."""
    if not ip:
        return {"ip": ip, "enriched": False, "geo": None,
                "reputation": {"category": "unknown", "is_known_bad": False, "source": "none"}}

    if _is_private(ip):
        return {"ip": ip, "enriched": True, "geo": None,
                "reputation": {"category": "internal", "is_known_bad": False, "source": "rfc1918"}}

    if os.getenv("SENTINEL_ENRICH_LIVE") == "1":
        live = _live_lookup(ip)
        if live:
            live.update(ip=ip, enriched=True)
            live["reputation"]["source"] = "ip-api"
            return live

    hit = _MOCK.get(ip)
    if hit:
        rep = dict(hit["reputation"], source="mock")
        return {"ip": ip, "enriched": True, "geo": hit["geo"], "reputation": rep}

    # Unknown public IP: still a valid (neutral) result, but not "enriched".
    return {"ip": ip, "enriched": False, "geo": None,
            "reputation": {"category": "unknown", "is_known_bad": False, "source": "mock"}}
