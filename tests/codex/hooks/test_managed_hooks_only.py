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


def test_setting_on_the_first_line_of_the_cloud_cache_turns_it_on(codex):
    (codex[1] / "cloud-config-bundle-cache.json").write_text(json.dumps({"toml": "allow_managed_hooks_only = true\n"}))
    assert setup.managed_hooks_only().endswith("cloud-config-bundle-cache.json")


def test_mdm_keeps_foreign_hooks_and_replaces_ours(tmp_path, monkeypatch):
    monkeypatch.setattr(mdm, "get_managed_settings_dir", lambda: tmp_path)
    monkeypatch.setattr(mdm, "download_file", lambda _u, dest: Path(dest).write_text("#") or True)
    ours = str(tmp_path / "hooks" / "unbound.py")
    foreign = {"hooks": [{"type": "command", "command": "/usr/local/bin/audit"}]}
    (tmp_path / "hooks.json").write_text(json.dumps({"version": 2, "hooks": {"Stop": [
        foreign, {"hooks": [{"type": "command", "command": f'"{ours}"'}]}]}}))
    assert mdm.setup_managed_hooks() is True
    config = json.loads((tmp_path / "hooks.json").read_text())
    assert "version" not in config
    assert config["hooks"]["Stop"][0] == foreign
    assert len(config["hooks"]["Stop"]) == 2


def test_mdm_registered_hook_with_its_script_deleted_is_tampered(tmp_path, monkeypatch):
    monkeypatch.setattr(mdm, "get_managed_settings_dir", lambda: tmp_path)
    monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [])
    script = tmp_path / "hooks" / "unbound.py"
    (tmp_path / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": f'"{script}"'}]}]}}))
    assert mdm.detect_install_state() == "tampered"


def test_quoted_key_turns_it_on(codex):
    (codex[0] / "requirements.toml").write_text('"allow_managed_hooks_only" = true\n')
    assert setup.managed_hooks_only() == str(codex[0] / "requirements.toml")


def test_mdm_keeps_a_foreign_handler_that_shares_a_group_with_ours(tmp_path, monkeypatch):
    monkeypatch.setattr(mdm, "get_managed_settings_dir", lambda: tmp_path)
    monkeypatch.setattr(mdm, "download_file", lambda _u, dest: Path(dest).write_text("#") or True)
    audit = {"type": "command", "command": "/usr/local/bin/audit"}
    ours = {"type": "command", "command": f'"{tmp_path / "hooks" / "unbound.py"}"'}
    (tmp_path / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [audit, ours]}]}}))
    assert mdm.setup_managed_hooks() is True
    stop = json.loads((tmp_path / "hooks.json").read_text())["hooks"]["Stop"]
    assert stop[0] == {"hooks": [audit]}
    assert len(stop) == 2
