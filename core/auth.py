"""X-API-key auth for the API surface (pattern adapted from DREADNOUGHT auth.py).

The expected key comes from the SENTINEL_API_KEY env var; if unset it falls back to
a well-known dev key so the demo runs from a fresh clone. Constant-time comparison
avoids leaking the key via timing.
"""
from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

DEV_API_KEY = "dev-sentinel-key"
API_KEY_HEADER = "X-API-Key"


def expected_key() -> str:
    return os.getenv("SENTINEL_API_KEY", DEV_API_KEY)


def require_api_key(x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER)) -> str:
    """FastAPI dependency: reject requests without a valid X-API-Key header."""
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing or invalid API key")
    return x_api_key
