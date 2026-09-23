import pytest

from tests.conftest import tool_module


@pytest.fixture(autouse=True)
def _no_real_gateway_settings(monkeypatch, tmp_path):
    """Keep every test off this machine's ANTHROPIC_BASE_URL and settings files."""
    unbound = tool_module("claude-code/hooks")
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setattr(unbound, "MANAGED_SETTINGS_PATHS", ())
    monkeypatch.setattr(unbound, "USER_SETTINGS_PATH", tmp_path / "settings.json")
