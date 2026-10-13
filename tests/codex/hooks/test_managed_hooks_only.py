import json
import sys
from pathlib import Path

import pytest

from tests.conftest import tool_module

setup = tool_module("codex/hooks", kind="setup")
mdm = tool_module("codex/hooks/mdm", kind="setup")


@pytest.fixture
def codex(tmp_path, monkeypatch):
    system = tmp_path / "etc-codex"
    system.mkdir()
    real_path = setup.Path
    monkeypatch.setattr(setup, "Path", lambda p, *a: system if p == "/etc/codex" else real_path(p, *a))
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return system, tmp_path / "home"


def test_system_requirements_turn_it_on(codex):
    (codex[0] / "requirements.toml").write_text("allow_managed_hooks_only = true\n")
    assert setup.managed_hooks_only() == str(codex[0] / "requirements.toml")


def test_cloud_policy_cache_turns_it_on(codex):
    (codex[1] / "cloud-config-bundle-cache.json").write_text(
        json.dumps({"bundle": {"toml": "x = 1\nallow_managed_hooks_only = true\n"}}))
    assert setup.managed_hooks_only().endswith("cloud-config-bundle-cache.json")


@pytest.mark.parametrize("text", ["# allow_managed_hooks_only = true\n", "allow_managed_hooks_only = false\n"])
def test_commented_or_false_is_off(codex, text):
    (codex[0] / "requirements.toml").write_text(text)
    assert setup.managed_hooks_only() is None


def test_user_setup_refuses_before_any_write(codex, monkeypatch):
    (codex[0] / "requirements.toml").write_text("allow_managed_hooks_only = true\n")
    monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "k"])
    monkeypatch.setattr(setup, "check_enterprise_hooks_conflict", lambda: False)
    monkeypatch.setattr(setup, "install_macos_certificates", lambda: pytest.fail("wrote before refusing"))
    assert setup.main() is False


@pytest.mark.parametrize("os_name, system_wide", [("Darwin", True), ("Windows", False)])
def test_mdm_installs_system_hooks_except_on_windows(tmp_path, monkeypatch, os_name, system_wide):
    calls = []
    monkeypatch.setattr(mdm.platform, "system", lambda: os_name)
    monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "k"])
    for name, result in [("check_admin_privileges", True), ("get_device_identifier", "d"),
                         ("fetch_api_key_from_mdm", "key"), ("set_env_var_system_wide", (True, True)),
                         ("detect_install_state", None), ("get_all_user_homes", [("u", Path(tmp_path))]),
                         ("remove_env_var_from_user", ""), ("remove_gateway_artifacts_for_user", None),
                         ("write_unbound_config_for_user", None), ("enable_codex_hooks_feature_for_user", None),
                         ("notify_setup_complete", None)]:
        monkeypatch.setattr(mdm, name, lambda *a, _r=result, **k: _r)
    for name in ("setup_managed_hooks", "remove_user_level_hooks_for_user", "configure_codex_hooks_for_user"):
        monkeypatch.setattr(mdm, name, lambda *a, _n=name, **k: calls.append(_n) or True)
    assert mdm.main() is True
    if system_wide:
        assert calls == ["setup_managed_hooks", "remove_user_level_hooks_for_user"]
    else:
        assert calls == ["configure_codex_hooks_for_user"]
