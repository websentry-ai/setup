"""The MDM install writes codex's system hooks.json, merged with whatever else is there."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from tests.conftest import tool_module

mdm = tool_module("codex/hooks/mdm", kind="setup")

EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart")
FOREIGN = "/usr/local/bin/org-audit --json"
BINARY = '"/opt/unbound/current/unbound-hook/unbound-hook" hook codex'


@pytest.fixture
def system(tmp_path, monkeypatch):
    managed = tmp_path / "system"
    monkeypatch.setattr(mdm, "get_managed_settings_dir", lambda: managed)
    monkeypatch.setattr(mdm.platform, "system", lambda: "Linux")
    monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [])
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "root-home")
    monkeypatch.setenv("HOME", str(tmp_path / "root-home"))

    def fake_download(_url, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("# unbound hook\n")
        return True

    monkeypatch.setattr(mdm, "download_file", fake_download)
    monkeypatch.setattr(mdm, "_run_as_user", lambda _user, fn, *a, **kw: fn(*a, **kw))
    return managed


def _script(managed):
    return managed / "hooks" / "unbound.py"


def _ours(managed):
    return f'"{_script(managed)}"'


def _hooks_json(managed):
    return json.loads((managed / "hooks.json").read_text())


def _write_hooks(managed, config):
    managed.mkdir(parents=True, exist_ok=True)
    (managed / "hooks.json").write_text(json.dumps(config))


def _commands(group):
    return [h.get("command") for h in group.get("hooks", [])]


def _our_groups(config, managed, event):
    return [g for g in config["hooks"][event] if _ours(managed) in _commands(g)]


class TestSetupManagedHooks:
    def test_registers_every_event_with_its_timeout_and_matcher(self, system):
        assert mdm.setup_managed_hooks() is True
        config = _hooks_json(system)
        assert set(config["hooks"]) == set(EVENTS)
        for event in EVENTS:
            (group,) = config["hooks"][event]
            (hook,) = group["hooks"]
            assert hook == {"type": "command", "command": _ours(system),
                            "timeout": 15000 if event == "PreToolUse" else 60}
            if event in ("PreToolUse", "PostToolUse", "SessionStart"):
                assert group["matcher"] == "*"
            else:
                assert "matcher" not in group
        assert _script(system).read_text() == "# unbound hook\n"

    def test_unix_permissions(self, system):
        assert mdm.setup_managed_hooks() is True
        assert stat.S_IMODE(system.stat().st_mode) == 0o755
        assert stat.S_IMODE((system / "hooks").stat().st_mode) == 0o755
        assert stat.S_IMODE((system / "hooks.json").stat().st_mode) == 0o644
        assert stat.S_IMODE(_script(system).stat().st_mode) == 0o755

    @pytest.mark.parametrize("has_py, launcher", [(True, "py -3"), (False, "python")])
    def test_windows_runs_the_script_through_a_python_launcher(self, system, monkeypatch, has_py, launcher):
        monkeypatch.setattr(mdm.platform, "system", lambda: "Windows")
        monkeypatch.setattr(mdm.shutil, "which", lambda name: "C:/py.exe" if has_py and name == "py" else None)
        assert mdm.setup_managed_hooks() is True
        (group,) = _hooks_json(system)["hooks"]["Stop"]
        assert _commands(group) == [f'{launcher} "{_script(system)}"']

    def test_keeps_foreign_events_groups_and_handlers(self, system):
        _write_hooks(system, {
            "version": 2,
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": FOREIGN}]}],
                "Notification": [{"hooks": [{"type": "command", "command": FOREIGN}]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": FOREIGN},
                    {"type": "command", "command": _ours(system)}]}],
            },
        })
        assert mdm.setup_managed_hooks() is True
        config = _hooks_json(system)
        # codex denies unknown top-level fields, so the key goes and the original is kept beside it
        assert "version" not in config
        assert json.loads((system / "hooks.json.unbound-bak").read_text())["version"] == 2
        assert config["hooks"]["Notification"] == [{"hooks": [{"type": "command", "command": FOREIGN}]}]
        stop = config["hooks"]["Stop"]
        assert stop[0] == {"hooks": [{"type": "command", "command": FOREIGN}]}
        assert len(_our_groups(config, system, "Stop")) == 1
        pre = config["hooks"]["PreToolUse"]
        assert pre[0] == {"matcher": "Bash", "hooks": [{"type": "command", "command": FOREIGN}]}
        assert len(_our_groups(config, system, "PreToolUse")) == 1

    @pytest.mark.parametrize("bad", [
        {"type": "command"},
        {"type": "command", "command": FOREIGN, "timeout": -1},
        {"type": "command", "command": FOREIGN, "async": "yes"},
        {"command": FOREIGN},
        "not a handler",
    ])
    def test_a_handler_codex_rejects_is_dropped_so_the_file_still_loads(self, system, bad):
        _write_hooks(system, {"hooks": {"Stop": [{"hooks": [bad, {"type": "command", "command": FOREIGN}]}]}})
        assert mdm.setup_managed_hooks() is True
        stop = _hooks_json(system)["hooks"]["Stop"]
        assert stop[0] == {"hooks": [{"type": "command", "command": FOREIGN}]}
        assert (system / "hooks.json.unbound-bak").exists()

    def test_nan_counts_as_unreadable(self, system):
        system.mkdir(parents=True)
        (system / "hooks.json").write_text('{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x", "timeout": NaN}]}]}}')
        assert mdm.setup_managed_hooks() is True
        assert "NaN" not in (system / "hooks.json").read_text()
        assert "NaN" in (system / "hooks.json.unbound-bak").read_text()

    def test_unknown_handler_types_and_events_are_kept(self, system):
        foreign = {"hooks": {"Notification": [{"x": 1}], "Stop": [{"hooks": [{"type": "future", "k": 1}]}]}}
        _write_hooks(system, foreign)
        assert mdm.setup_managed_hooks() is True
        config = _hooks_json(system)
        assert config["hooks"]["Notification"] == [{"x": 1}]
        assert config["hooks"]["Stop"][0] == {"hooks": [{"type": "future", "k": 1}]}
        assert not (system / "hooks.json.unbound-bak").exists()

    def test_a_second_run_is_byte_identical(self, system):
        _write_hooks(system, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": FOREIGN}]}]}})
        assert mdm.setup_managed_hooks() is True
        first = (system / "hooks.json").read_bytes()
        assert mdm.setup_managed_hooks() is True
        assert (system / "hooks.json").read_bytes() == first

    @pytest.mark.parametrize("old_command", [
        BINARY,
        "__managed_script__",
        "python3 __managed_script__",
    ])
    def test_replaces_an_older_unbound_handler_instead_of_adding_beside_it(self, system, old_command):
        old_command = old_command.replace("__managed_script__", str(_script(system)))
        _write_hooks(system, {"hooks": {event: [{"hooks": [{"type": "command", "command": old_command}]}]
                                        for event in EVENTS}})
        assert mdm.setup_managed_hooks() is True
        config = _hooks_json(system)
        for event in EVENTS:
            (group,) = config["hooks"][event]
            assert _commands(group) == [_ours(system)]

    def test_a_foreign_group_with_no_handlers_is_kept(self, system):
        _write_hooks(system, {"hooks": {"Stop": [{"hooks": []}, {"matcher": "x"}]}})
        assert mdm.setup_managed_hooks() is True
        stop = _hooks_json(system)["hooks"]["Stop"]
        assert stop[:2] == [{"hooks": []}, {"matcher": "x"}]
        assert len(stop) == 3

    def test_a_command_that_only_mentions_our_prefix_is_not_ours(self, system):
        _write_hooks(system, {"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "/opt/unbound/other-tool"}]}]}})
        assert mdm.setup_managed_hooks() is True
        stop = _hooks_json(system)["hooks"]["Stop"]
        assert _commands(stop[0]) == ["/opt/unbound/other-tool"]

    @pytest.mark.parametrize("content", ["not json", "[1, 2]", '"text"', "null", '{"hooks": [1]}'])
    def test_an_unusable_file_is_rebuilt_with_our_hooks(self, system, content):
        system.mkdir(parents=True)
        (system / "hooks.json").write_text(content)
        assert mdm.setup_managed_hooks() is True
        config = _hooks_json(system)
        assert set(config["hooks"]) == set(EVENTS)

    @pytest.mark.parametrize("content", ["not json", "[1, 2]", "null"])
    def test_an_unusable_file_is_kept_as_a_backup_not_lost(self, system, content):
        system.mkdir(parents=True)
        (system / "hooks.json").write_text(content)
        assert mdm.setup_managed_hooks() is True
        assert (system / "hooks.json.unbound-bak").read_text() == content

    def test_a_readable_file_leaves_no_backup(self, system):
        system.mkdir(parents=True)
        _write_hooks(system, {"hooks": {}})
        assert mdm.setup_managed_hooks() is True
        assert not (system / "hooks.json.unbound-bak").exists()

    def test_a_symlinked_hooks_json_is_replaced_and_its_target_untouched(self, system, tmp_path):
        target = tmp_path / "elsewhere.json"
        original = json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": FOREIGN}]}]}})
        target.write_text(original)
        system.mkdir(parents=True)
        (system / "hooks.json").symlink_to(target)
        assert mdm.setup_managed_hooks() is True
        assert not (system / "hooks.json").is_symlink()
        assert target.read_text() == original
        assert len(_our_groups(_hooks_json(system), system, "Stop")) == 1

    def test_no_temp_file_is_left_behind(self, system):
        assert mdm.setup_managed_hooks() is True
        assert sorted(p.name for p in system.iterdir()) == ["hooks", "hooks.json"]

    def test_a_failed_download_writes_no_hooks_json(self, system, monkeypatch):
        monkeypatch.setattr(mdm, "download_file", lambda _url, _dest: False)
        assert mdm.setup_managed_hooks() is False
        assert not (system / "hooks.json").exists()


def _install_system(managed, script=True, registered=True):
    if script:
        _script(managed).parent.mkdir(parents=True, exist_ok=True)
        _script(managed).write_text("# hook\n")
    if registered:
        _write_hooks(managed, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": _ours(managed)}]}]}})


def _user(root, name="alice", script=True, registered=True):
    home = root / name
    hooks = home / ".codex" / "hooks"
    hooks.mkdir(parents=True)
    path = hooks / "unbound.py"
    if script:
        path.write_text("# hook\n")
    if registered:
        (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [
            {"hooks": [{"type": "command", "command": str(path)}]}]}}))
    return home


class TestDetectInstallState:
    def test_managed_script_and_registration_is_persisted(self, system):
        _install_system(system)
        assert mdm.detect_install_state() == "persisted"

    def test_the_binary_registration_alone_is_tampered(self, system):
        _write_hooks(system, {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": BINARY}]}]}})
        assert mdm.detect_install_state() == "tampered"

    def test_managed_script_without_registration_is_tampered(self, system):
        _install_system(system, registered=False)
        assert mdm.detect_install_state() == "tampered"

    def test_managed_registration_without_script_is_tampered(self, system):
        _install_system(system, script=False)
        assert mdm.detect_install_state() == "tampered"

    def test_nothing_anywhere_is_fresh(self, system, tmp_path, monkeypatch):
        home = tmp_path / "homes" / "alice"
        home.mkdir(parents=True)
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm.detect_install_state() == "fresh"

    def test_a_managed_install_wins_over_a_broken_per_user_one(self, system, tmp_path, monkeypatch):
        _install_system(system)
        home = _user(tmp_path / "homes", script=False)
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm.detect_install_state() == "persisted"

    def test_without_a_managed_install_a_complete_per_user_one_is_persisted(self, system, tmp_path, monkeypatch):
        home = _user(tmp_path / "homes")
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm.detect_install_state() == "persisted"

    def test_without_a_managed_install_a_half_per_user_one_is_tampered(self, system, tmp_path, monkeypatch):
        home = _user(tmp_path / "homes", registered=False)
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm.detect_install_state() == "tampered"

    def test_a_system_hooks_json_we_refuse_to_read_is_undetermined(self, system, tmp_path):
        _install_system(system, registered=False)
        target = tmp_path / "linked.json"
        target.write_text(json.dumps({"hooks": {"Stop": [{"hooks": [{"command": _ours(system)}]}]}}))
        (system / "hooks.json").symlink_to(target)
        assert mdm.detect_install_state() is None


class TestInstalledHookScript:
    def test_prefers_the_managed_script(self, system, tmp_path, monkeypatch):
        _install_system(system)
        home = _user(tmp_path / "homes")
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm._installed_hook_script() == _script(system)

    def test_falls_back_to_a_per_user_script(self, system, tmp_path, monkeypatch):
        home = _user(tmp_path / "homes")
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: [("alice", home)])
        assert mdm._installed_hook_script() == home / ".codex" / "hooks" / "unbound.py"

    def test_none_when_nothing_is_installed(self, system):
        assert mdm._installed_hook_script() is None


class TestRemoveUserLevelHooks:
    def test_strips_our_hook_and_script_but_keeps_the_policy_cache_logs_and_foreign_hooks(self, system, tmp_path):
        home = _user(tmp_path / "homes")
        hooks_dir = home / ".codex" / "hooks"
        config = json.loads((home / ".codex" / "hooks.json").read_text())
        config["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": FOREIGN}]})
        (home / ".codex" / "hooks.json").write_text(json.dumps(config))
        for keep in (".policy_cache.json", "agent-audit.log", "error.log"):
            (hooks_dir / keep).write_text("{}")

        mdm.remove_user_level_hooks_for_user("alice", home)

        assert not (hooks_dir / "unbound.py").exists()
        for keep in (".policy_cache.json", "agent-audit.log", "error.log"):
            assert (hooks_dir / keep).read_text() == "{}"
        remaining = json.loads((home / ".codex" / "hooks.json").read_text())
        assert remaining == {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": FOREIGN}]}]}}


class TestMain:
    @pytest.fixture
    def run_main(self, system, tmp_path, monkeypatch):
        calls = []
        homes = [("alice", _user(tmp_path / "homes"))]
        monkeypatch.setattr(mdm, "get_all_user_homes", lambda: homes)
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "auth-key"])
        monkeypatch.setattr(mdm, "DEBUG", False)
        monkeypatch.setattr(mdm, "check_admin_privileges", lambda: True)
        monkeypatch.setattr(mdm, "get_device_identifier", lambda: "serial-abc")
        monkeypatch.setattr(mdm, "fetch_api_key_from_mdm", lambda *a: "codex-key")
        monkeypatch.setattr(mdm, "remove_env_var_from_user", lambda *a: "")
        monkeypatch.setattr(mdm, "set_env_var_system_wide", lambda *a: (True, True))
        monkeypatch.setattr(mdm, "run_backfill", lambda *a: calls.append(("run_backfill",)))

        real_setup = mdm.setup_managed_hooks
        real_strip = mdm.remove_user_level_hooks_for_user

        def record(name, real=None, result=None):
            def _fn(*args, **kwargs):
                calls.append((name,) + args)
                return real(*args, **kwargs) if real else result
            return _fn

        monkeypatch.setattr(mdm, "setup_managed_hooks", record("setup_managed_hooks", real_setup))
        monkeypatch.setattr(mdm, "remove_user_level_hooks_for_user", record("remove_user_level_hooks", real_strip))
        for name in ("remove_gateway_artifacts_for_user", "write_unbound_config_for_user",
                     "enable_codex_hooks_feature_for_user"):
            monkeypatch.setattr(mdm, name, record(name))
        notified = []
        monkeypatch.setattr(mdm, "notify_setup_complete", lambda *a, **kw: notified.append((a, kw)))

        def _run():
            return mdm.main(), calls, notified, homes
        return _run

    def test_writes_the_system_hooks_before_stripping_each_user_and_reports_mdm(self, system, run_main):
        ok, calls, notified, homes = run_main()
        assert ok is True
        names = [c[0] for c in calls]
        assert names == ["setup_managed_hooks", "remove_gateway_artifacts_for_user",
                         "write_unbound_config_for_user", "enable_codex_hooks_feature_for_user",
                         "remove_user_level_hooks"]
        home = homes[0][1]
        assert not (home / ".codex" / "hooks" / "unbound.py").exists()
        assert len(_our_groups(_hooks_json(system), system, "Stop")) == 1

        ((args, kwargs),) = notified
        assert args == ("codex-key", "codex")
        assert kwargs["install_mode"] == "mdm"
        assert kwargs["install_state"] == "persisted"
        assert kwargs["serial_number"] == "serial-abc"
        assert kwargs["hook_hash"] == mdm.hook_script_hash(_script(system))

    def test_windows_keeps_the_per_user_install_and_never_writes_the_system_folder(self, system, run_main, monkeypatch):
        monkeypatch.setattr(mdm.platform, "system", lambda: "Windows")
        monkeypatch.setattr(mdm, "configure_codex_hooks_for_user", lambda *a: True)
        ok, calls, notified, _homes = run_main()
        assert ok is True
        names = [c[0] for c in calls]
        assert "setup_managed_hooks" not in names
        assert "remove_user_level_hooks" not in names
        assert not (system / "hooks.json").exists()
        assert notified[0][1]["install_mode"] == "mdm"

    def test_a_failed_system_write_touches_no_user_and_notifies_nothing(self, system, run_main, monkeypatch):
        monkeypatch.setattr(mdm, "download_file", lambda _url, _dest: False)
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "auth-key", "--backfill"])
        ok, calls, notified, homes = run_main()
        assert ok is False
        assert [c[0] for c in calls] == ["setup_managed_hooks"]
        assert notified == []
        assert (homes[0][1] / ".codex" / "hooks" / "unbound.py").exists()
