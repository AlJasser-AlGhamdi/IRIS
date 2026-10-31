"""Shared test fixtures — keep global p2c state isolated between tests.

Carried from the upstream research code with the database half removed: ``db.py`` (SQLAlchemy engine and
session factory caches) is out of scope for this toolkit, so the fixture only resets the
settings cache and uninstalls the egress guard.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from p2c.config import Settings, get_settings
from p2c.sovereignty import egress_guard


@pytest.fixture(autouse=True)
def _reset_p2c_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset cached global state so env changes never leak across tests.

    Also forces ``env_file=None`` so a developer's local ``.env`` never bleeds
    into the (supposedly hermetic) config tests.
    """
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    get_settings.cache_clear()
    yield
    egress_guard.uninstall()
    get_settings.cache_clear()
