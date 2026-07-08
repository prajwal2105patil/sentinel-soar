"""Shared fixtures. The `pipeline` fixture runs the full pipeline once per session
(ingest -> detect) and hands the metrics dict to every test that needs it."""
from __future__ import annotations

import pytest

from core import detect
from core.ingest import ingest


@pytest.fixture(scope="session")
def pipeline() -> dict:
    ingest()
    return detect.detect(verbose=False)
