import pytest

from tests.conftest import tool_module


@pytest.fixture(autouse=True)
def _no_augment_plan_lookup(monkeypatch, tmp_path):
    """Keep every test off the real auggie CLI and the developer's plan cache."""
    unbound = tool_module("augment/hooks")
    monkeypatch.setattr(unbound, "_fetch_augment_plan", lambda: None)
    monkeypatch.setattr(unbound, "AUGMENT_PLAN_CACHE_PATH", tmp_path / "augment_plan.json")
