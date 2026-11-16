"""Fixtures shared by all test modules."""

from __future__ import annotations

import pytest

from app.main import app
from tests import fakenet


@pytest.fixture
def net(monkeypatch) -> fakenet.FakeNet:
    """Fake DNS + HTTP; see tests/fakenet.py."""
    return fakenet.install(monkeypatch)


@pytest.fixture(autouse=True)
def _fresh_rate_limiter():
    """Every test starts with empty rate-limit buckets, otherwise the tests
    would throttle each other (they all come from the same client address)."""
    limiter = getattr(app.state, "limiter", None)
    if limiter is not None:
        limiter.reset()
