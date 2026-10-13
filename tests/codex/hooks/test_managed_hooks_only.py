"""A user-level codex install refuses to run where codex only runs managed hooks."""
import base64
import json
import plistlib
import sys
from pathlib import Path

import pytest

from tests.conftest import tool_module

setup = tool_module("codex/hooks", kind="setup")

MANAGED_PREFS = "/Library/Managed Preferences"
TRUE = "allow_managed_hooks_only = true\n"
FALSE = "allow_managed_hooks_only = false\n"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Every requirements layer redirected into tmp_path; no layer exists until a test writes it."""
    system = tmp_path / "system"
    system.mkdir()
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    prefs = tmp_path / "managed-prefs"
    monkeypatch.setattr(setup, "get_managed_settings_dir", lambda: system)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setenv("USER", "alice")
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")

    real_path = type(Path())

    class RedirectedPath(real_path):
        def __new__(cls, *args):
            path = real_path(*args)
            text = str(path)
            if text.startswith(MANAGED_PREFS):
                return real_path(str(prefs) + text[len(MANAGED_PREFS):])
            return path

    monkeypatch.setattr(setup, "Path", RedirectedPath)

    class Env:
        pass

    e = Env()
    e.system, e.home, e.codex_home, e.prefs = system, home, codex_home, prefs
    return e


def _requirements(env, text):
    path = env.system / "requirements.toml"
    path.write_text(text)
    return str(path)


def _cloud(directory, bundle):
    path = directory / "cloud-config-bundle-cache.json"
    path.write_text(bundle if isinstance(bundle, str) else json.dumps(bundle))
    return f"ChatGPT workspace policy ({path})"


def _plist(env, text=None, user=None, raw=None):
    directory = env.prefs / user if user else env.prefs
    directory.mkdir(parents=True, exist_ok=True)
    encoded = raw if raw is not None else base64.b64encode(text.encode()).decode()
    with open(directory / "com.openai.codex.plist", "wb") as f:
        plistlib.dump({"requirements_toml_base64": encoded}, f)


@pytest.fixture
def darwin(env, monkeypatch):
    monkeypatch.setattr(setup.platform, "system", lambda: "Darwin")
    return env


MDM_LABEL = "macOS MDM profile (com.openai.codex)"


class TestManagedHooksOnly:
    def test_no_requirements_anywhere(self, env):
        assert setup.managed_hooks_only() is None

    def test_the_system_requirements_file(self, env):
        assert setup.managed_hooks_only() is None
        label = _requirements(env, TRUE + "[features]\nx = 1\n")
        assert setup.managed_hooks_only() == label

    def test_set_to_false(self, env):
        _requirements(env, FALSE)
        assert setup.managed_hooks_only() is None

    def test_a_commented_out_setting_is_ignored(self, env):
        _requirements(env, "# allow_managed_hooks_only = true\n")
        assert setup.managed_hooks_only() is None

    def test_the_key_under_a_table_is_not_the_top_level_setting(self, env):
        _requirements(env, "[hooks]\nallow_managed_hooks_only = true\n")
        assert setup.managed_hooks_only() is None

    def test_a_bom_and_a_quoted_key_still_count(self, env):
        label = _requirements(env, '﻿"allow_managed_hooks_only" = true\n')
        assert setup.managed_hooks_only() == label

    def test_a_huge_run_of_blank_lines_resolves_quickly(self, env):
        import time
        _requirements(env, "\n" * 200000)
        start = time.monotonic()
        assert setup.managed_hooks_only() is None
        assert time.monotonic() - start < 1

    def test_a_trailing_comment_does_not_hide_the_setting(self, env):
        label = _requirements(env, "  allow_managed_hooks_only=true  # set by IT\n")
        assert setup.managed_hooks_only() == label

    def test_a_longer_key_is_not_the_setting(self, env):
        _requirements(env, "allow_managed_hooks_only_v2 = true\n")
        assert setup.managed_hooks_only() is None

    def test_any_string_in_the_cloud_bundle(self, env):
        label = _cloud(env.codex_home, {"fragments": [{"requirements": "x = 1\n" + TRUE}]})
        assert setup.managed_hooks_only() == label

    def test_the_cloud_bundle_overrides_the_system_file(self, env):
        _requirements(env, TRUE)
        _cloud(env.codex_home, {"requirements": FALSE})
        assert setup.managed_hooks_only() is None

    def test_a_cloud_bundle_that_is_silent_leaves_the_system_setting(self, env):
        label = _requirements(env, TRUE)
        _cloud(env.codex_home, {"requirements": "model = 'gpt-5'\n", "id": "abc"})
        assert setup.managed_hooks_only() == label

    def test_a_cloud_bundle_that_is_not_json_is_skipped(self, env):
        label = _requirements(env, TRUE)
        _cloud(env.codex_home, "{not json " + FALSE)
        assert setup.managed_hooks_only() == label

    def test_codex_home_is_trimmed(self, env, monkeypatch):
        monkeypatch.setenv("CODEX_HOME", f"  {env.codex_home}\n")
        label = _cloud(env.codex_home, {"r": TRUE})
        assert setup.managed_hooks_only() == label

    def test_a_blank_codex_home_falls_back_to_the_home_folder(self, env, monkeypatch):
        monkeypatch.setenv("CODEX_HOME", "   ")
        label = _cloud(env.home / ".codex", {"r": TRUE})
        assert setup.managed_hooks_only() == label

    @pytest.mark.parametrize("hooks_text", [
        '{"hooks": {"Stop": [{"hooks": [{"command": "\\"/etc/codex/hooks/unbound.py\\""}]}]}}',
        '{"hooks": {"Stop": [{"hooks": [{"command": "/opt/unbound/current/unbound-hook/unbound-hook hook codex"}]}]}}',
    ])
    def test_none_when_our_hook_is_already_managed(self, env, hooks_text):
        _requirements(env, TRUE)
        (env.system / "hooks.json").write_text(hooks_text)
        assert setup.managed_hooks_only() is None

    def test_a_foreign_managed_hook_does_not_count_as_ours(self, env):
        label = _requirements(env, TRUE)
        (env.system / "hooks.json").write_text('{"hooks": {"Stop": [{"hooks": [{"command": "/opt/unbound/other"}]}]}}')
        assert setup.managed_hooks_only() == label

    def test_none_when_a_requirements_layer_already_references_our_hook(self, env):
        _requirements(env, TRUE)
        _cloud(env.codex_home, {"hooks": "command = '/etc/codex/hooks/unbound.py'"})
        assert setup.managed_hooks_only() is None

    def test_a_layer_that_cannot_be_listed_is_skipped(self, env, monkeypatch):
        monkeypatch.setattr(setup, "get_managed_settings_dir", lambda: (_ for _ in ()).throw(OSError("no")))
        label = _cloud(env.codex_home, {"r": TRUE})
        assert setup.managed_hooks_only() == label

    def test_any_error_answers_none(self, env, monkeypatch):
        _requirements(env, TRUE)
        monkeypatch.setattr(setup, "_codex_requirements", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        assert setup.managed_hooks_only() is None

    def test_mac_profile_plists_are_ignored_off_macos(self, env):
        _plist(env, TRUE)
        assert setup.managed_hooks_only() is None


class TestMacProfile:
    def test_the_device_profile(self, darwin):
        _plist(darwin, TRUE)
        assert setup.managed_hooks_only() == MDM_LABEL

    def test_the_user_profile(self, darwin):
        _plist(darwin, TRUE, user="alice")
        assert setup.managed_hooks_only() == MDM_LABEL

    def test_another_user_s_profile_does_not_apply(self, darwin):
        _plist(darwin, TRUE, user="bob")
        assert setup.managed_hooks_only() is None

    def test_the_user_profile_overrides_the_device_profile(self, darwin):
        _plist(darwin, TRUE)
        _plist(darwin, FALSE, user="alice")
        assert setup.managed_hooks_only() is None

    def test_the_profile_overrides_the_cloud_bundle_and_system_file(self, darwin):
        _requirements(darwin, FALSE)
        _cloud(darwin.codex_home, {"r": FALSE})
        _plist(darwin, TRUE)
        assert setup.managed_hooks_only() == MDM_LABEL

    def test_a_profile_that_is_not_base64_is_skipped(self, darwin):
        label = _requirements(darwin, TRUE)
        _plist(darwin, raw="!!! not base64 !!!")
        assert setup.managed_hooks_only() == label

    def test_a_profile_without_the_key_is_skipped(self, darwin):
        label = _requirements(darwin, TRUE)
        darwin.prefs.mkdir()
        with open(darwin.prefs / "com.openai.codex.plist", "wb") as f:
            plistlib.dump({"other": "x"}, f)
        assert setup.managed_hooks_only() == label

    def test_a_profile_that_is_not_a_plist_is_skipped(self, darwin):
        label = _requirements(darwin, TRUE)
        darwin.prefs.mkdir()
        (darwin.prefs / "com.openai.codex.plist").write_bytes(b"garbage")
        assert setup.managed_hooks_only() == label


class TestUserSetupMain:
    @pytest.fixture
    def stubs(self, env, monkeypatch):
        """Every step past the gate records its call instead of touching the machine."""
        called = []

        def stub(name, result=None):
            def _fn(*_a, **_kw):
                called.append(name)
                return result
            monkeypatch.setattr(setup, name, _fn)

        for name in ("install_macos_certificates", "run_callback_server", "remove_gateway_artifacts",
                     "write_unbound_config", "notify_setup_complete", "run_backfill", "get_shell_rc_file",
                     "download_file"):
            stub(name)
        stub("detect_install_state", "fresh")
        stub("get_device_identifier", "serial-abc")
        stub("set_env_var", (True, ""))
        stub("setup_hooks", True)
        stub("configure_codex_hooks", True)
        stub("enable_codex_hooks_feature", True)
        stub("clear_setup", True)
        monkeypatch.setattr(setup, "DEBUG", False)
        return called

    def test_managed_hooks_only_stops_before_any_write_or_download(self, env, stubs, monkeypatch, capsys):
        label = _requirements(env, TRUE)
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "k"])
        assert setup.main() is False
        assert stubs == []
        out = capsys.readouterr().out
        assert f"allow_managed_hooks_only = true, set in {label}" in out
        assert "sudo unbound setup codex-subscription" in out

    def test_without_the_setting_setup_proceeds(self, env, stubs, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "k"])
        assert setup.main() is True
        assert stubs[0] == "install_macos_certificates"
        assert {"setup_hooks", "configure_codex_hooks", "write_unbound_config", "notify_setup_complete"} <= set(stubs)

    def test_clear_still_runs_under_managed_hooks_only(self, env, stubs, monkeypatch):
        _requirements(env, TRUE)
        monkeypatch.setattr(sys, "argv", ["setup.py", "--clear"])
        assert setup.main() is True
        assert stubs == ["clear_setup"]

    def test_an_mdm_install_still_exits_3_first(self, env, stubs, monkeypatch):
        _requirements(env, TRUE)
        (env.system / "hooks").mkdir()
        (env.system / "hooks" / "unbound.py").write_text("")
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "k"])
        with pytest.raises(SystemExit) as exc:
            setup.main()
        assert exc.value.code == 3
        assert stubs == []
