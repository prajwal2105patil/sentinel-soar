"""X-API-key auth for the API surface (pattern adapted from DREADNOUGHT auth.py).

The expected key comes from SENTINEL_API_KEY. For a frictionless demo it falls back
to a well-known dev key — UNLESS SENTINEL_ENV=prod, in which case it fails closed
(no key configured => the service refuses to start handing out access). Constant-time
comparison avoids leaking the key via timing.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

DEV_API_KEY = "dev-sentinel-key"
API_KEY_HEADER = "X-API-Key"


def _is_prod() -> bool:
    return os.getenv("SENTINEL_ENV", "dev").lower() == "prod"


def expected_key() -> str:
    key = os.getenv("SENTINEL_API_KEY")
    if key:
        return key
    if _is_prod():
        # Fail closed: never fall back to a shared dev key in production.
        raise RuntimeError(
            "SENTINEL_API_KEY must be set when SENTINEL_ENV=prod (refusing dev-key fallback)."
        )
    return DEV_API_KEY


def require_api_key(x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER)) -> str:
    """FastAPI dependency: reject requests without a valid X-API-Key header."""
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing or invalid API key")
    return x_api_key
