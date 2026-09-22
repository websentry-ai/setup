import pytest

from tests.conftest import tool_module


@pytest.fixture(autouse=True)
def _no_github_seat_lookup(monkeypatch, tmp_path):
    """Keep every test off GitHub and off the developer's own seat cache."""
    unbound = tool_module("copilot/hooks")
    monkeypatch.setattr(unbound, "_github", lambda path, graphql=None: None)
    monkeypatch.setattr(unbound, "_fetch_copilot_seat", lambda: None)
    monkeypatch.setattr(unbound, "COPILOT_SEAT_CACHE_PATH", tmp_path / "copilot_seat.json")
