"""Tests for `unbound-hook setup` / `clear` internals and the WEB-4788
migration sweep. Root-only primitives (privilege drop, MDM key fetch,
system env vars, completion notify) are stubbed on the vendored modules;
everything else — settings writers, strippers, sweep — runs for real
against sandboxed paths.
"""

import getpass
import json
from pathlib import Path

import pytest

from unbound_hook import migration, setup_cmd
from unbound_hook._loader import load_mdm_setup_module
from unbound_hook._resources import HOOK_BINARY

ME = getpass.getuser()
BIN = str(HOOK_BINARY)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Sandboxed homes + root-only stubs across all four vendored modules."""
    home = tmp_path / "home"
    home.mkdir()
    notified = []
    backfilled = []
    modules = {}
    for tool in ("claude-code", "cursor", "codex", "copilot"):
        m = load_mdm_setup_module(tool)
        modules[tool] = m
        monkeypatch.setattr(m, "_run_as_user", lambda u, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(m, "get_all_user_homes", lambda h=home: [(ME, h)])
        monkeypatch.setattr(m, "check_admin_privileges", lambda: True)
        monkeypatch.setattr(m, "get_device_identifier", lambda: "TESTSERIAL1")
        monkeypatch.setattr(m, "fetch_api_key_from_mdm",
                            lambda base, app, auth, dev: "per-device-key")
        monkeypatch.setattr(m, "notify_setup_complete",
                            lambda *a, **k: notified.append((a, k)))
        if hasattr(m, "run_backfill"):
            monkeypatch.setattr(m, "run_backfill",
                                lambda *a, **k: backfilled.append(a))
        if hasattr(m, "set_env_var_system_wide"):
            monkeypatch.setattr(m, "set_env_var_system_wide", lambda n, v: (True, False))
        if hasattr(m, "set_env_var"):
            monkeypatch.setattr(m, "set_env_var", lambda n, v: (True, False, "ok"))
        if hasattr(m, "restart_cursor"):
            monkeypatch.setattr(m, "restart_cursor", lambda: True)
    monkeypatch.setattr(modules["claude-code"], "get_managed_settings_dir",
                        lambda: tmp_path / "managed-claude")
    monkeypatch.setattr(modules["codex"], "get_managed_settings_dir",
                        lambda: tmp_path / "managed-codex")
    monkeypatch.setattr(modules["cursor"], "get_enterprise_hooks_dir",
                        lambda: tmp_path / "enterprise-cursor")
    # NEVER run real launchctl from tests — the dev machine may have live
    # agents under these labels. Record the bootout calls instead.
    bootouts = []
    monkeypatch.setattr(migration, "_bootout_legacy_agents",
                        lambda username, uid, h, log: bootouts.append((username, uid)))
    return {"tmp": tmp_path, "home": home, "modules": modules,
            "notified": notified, "backfilled": backfilled, "bootouts": bootouts}


def _cmd(tool, event):
    return f'"{BIN}" hook {tool} {event}'


def test_setup_full_run_configures_everything(env):
    rc = setup_cmd.run(["--api-key", "admin-key"])
    assert rc == 0  # discovery skipped (no key) is not a failure

    # claude-code managed settings — exact structure incl. the historical
    # PreToolUse 15000 (vs 60 elsewhere) and async flags.
    settings = json.loads((env["tmp"] / "managed-claude" / "managed-settings.json").read_text())
    assert settings["hooks"] == {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": _cmd("claude-code", "PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": _cmd("claude-code", "PostToolUse"), "async": True, "timeout": 60}]}],
        "UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": _cmd("claude-code", "UserPromptSubmit"), "timeout": 60}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": _cmd("claude-code", "Stop"), "timeout": 60}]}],
        "SessionStart": [{"matcher": "*", "hooks": [
            {"type": "command", "command": _cmd("claude-code", "SessionStart"), "async": True, "timeout": 60}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": _cmd("claude-code", "SessionEnd"), "async": True, "timeout": 60}]}],
    }

    # codex hooks.json — no async flags, no SessionEnd.
    codex = json.loads((env["tmp"] / "managed-codex" / "hooks.json").read_text())
    assert set(codex["hooks"]) == {"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart"}
    assert codex["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 15000
    assert codex["hooks"]["PostToolUse"][0]["hooks"][0] == {
        "type": "command", "command": _cmd("codex", "PostToolUse"), "timeout": 60}

    # cursor enterprise hooks.json — 12 events, 15000 on the 3 pre-execution
    # events, no timeout key on the rest (verbatim from cursor/hooks.json).
    cursor = json.loads((env["tmp"] / "enterprise-cursor" / "hooks.json").read_text())
    assert cursor["version"] == 1
    assert len(cursor["hooks"]) == 12
    for ev in ("preToolUse", "beforeShellExecution", "beforeMCPExecution"):
        assert cursor["hooks"][ev] == [{"command": _cmd("cursor", ev), "timeout": 15000}]
    for ev in ("postToolUse", "afterShellExecution", "afterMCPExecution", "afterFileEdit",
               "beforeReadFile", "beforeSubmitPrompt", "afterAgentResponse", "stop", "sessionStart"):
        assert cursor["hooks"][ev] == [{"command": _cmd("cursor", ev)}]

    # copilot per-user unbound.json — timeout/timeoutSec + command/bash/powershell.
    copilot = json.loads((env["home"] / ".copilot" / "hooks" / "unbound.json").read_text())
    assert copilot["version"] == 1
    expected_timeouts = {"SessionStart": 30, "UserPromptSubmit": 60,
                         "PreToolUse": 600, "PostToolUse": 30, "Stop": 60}
    assert set(copilot["hooks"]) == set(expected_timeouts)
    for ev, t in expected_timeouts.items():
        entry = copilot["hooks"][ev][0]
        assert entry == {"type": "command", "command": _cmd("copilot", ev),
                         "bash": _cmd("copilot", ev), "powershell": _cmd("copilot", ev),
                         "timeout": t, "timeoutSec": t}
    # no python script is installed anywhere
    assert not (env["home"] / ".copilot" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "managed-claude" / "hooks" / "unbound.py").exists()

    # per-user config written for every tool (same device key)
    cfg = json.loads((env["home"] / ".unbound" / "config.json").read_text())
    assert cfg["api_key"] == "per-device-key"
    assert cfg["base_url"] == "https://backend.getunbound.ai"

    # completion notify fired once per tool
    assert len(env["notified"]) == 4
    # backfill NOT run without --backfill
    assert env["backfilled"] == []


def test_setup_component_failure_does_not_abort_others(env, monkeypatch):
    # claude-code's key fetch fails; everything else must still configure.
    monkeypatch.setattr(env["modules"]["claude-code"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    rc = setup_cmd.run(["--api-key", "admin-key"])
    assert rc == 1  # deferred component surfaces in the exit code
    assert not (env["tmp"] / "managed-claude" / "managed-settings.json").exists()
    assert (env["tmp"] / "managed-codex" / "hooks.json").exists()
    assert (env["tmp"] / "enterprise-cursor" / "hooks.json").exists()
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").exists()


def test_setup_backfill_flag_runs_backfill_for_supporting_tools(env):
    rc = setup_cmd.run(["--api-key", "admin-key", "--backfill"])
    assert rc == 0
    # claude-code, codex, copilot have run_backfill; cursor prints unsupported.
    assert len(env["backfilled"]) == 3


def test_setup_requires_api_key(env, capsys):
    assert setup_cmd.run([]) == 2


def test_setup_is_idempotent(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    first = (env["tmp"] / "managed-claude" / "managed-settings.json").read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").read_text() == first


# ---------------------------------------------------------------------------
# WEB-4788 migration sweep fixtures: clean, half-installed, previously-binary
# ---------------------------------------------------------------------------

def _plant_python_era_artifacts(home: Path, tmp: Path):
    """A 'fully python-installed' machine."""
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    (home / "Library" / "LaunchAgents" / "ai.getunbound.scheduled.plist").write_text("<plist/>")
    (home / "Library" / "LaunchAgents" / "ai.getunbound.discovery.plist").write_text("<plist/>")
    (home / ".local" / "share" / "unbound").mkdir(parents=True)
    (home / ".local" / "share" / "unbound" / "install.sh").write_text("#!/bin/bash")
    (home / ".local" / "share" / "unbound" / "run-scheduled.sh").write_text("#!/bin/bash")
    for d in (".claude/hooks", ".cursor/hooks", ".copilot/hooks", ".codex/hooks"):
        p = home / d
        p.mkdir(parents=True)
        (p / "unbound.py").write_text("# stale hook")
        (p / ".self_update_check").write_text("")
        (p / ".self_update.lock").write_text("")
    (home / ".unbound").mkdir(exist_ok=True)
    (home / ".unbound" / "config.json").write_text(json.dumps({"api_key": "KEEP-ME"}))
    # python-era copilot registration (commands point at unbound.py)
    (home / ".copilot" / "hooks" / "unbound.json").write_text(json.dumps(
        {"version": 1, "hooks": {"PreToolUse": [
            {"command": f'"{home}/.copilot/hooks/unbound.py"'}]}}))
    # stale managed scripts — removed by the setup adapters AFTER their
    # settings rewrite succeeds (never by the sweep; see F1 in review)
    for tool in ("managed-claude", "managed-codex", "enterprise-cursor"):
        (tmp / tool / "hooks").mkdir(parents=True, exist_ok=True)
        (tmp / tool / "hooks" / "unbound.py").write_text("# stale managed hook")
    # user-level claude hook registration pointing at the python script
    (home / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": str(home / ".claude" / "hooks" / "unbound.py")}]}]},
        "model": "opus",
    }))


def _assert_swept(home: Path, tmp: Path):
    assert not (home / "Library" / "LaunchAgents" / "ai.getunbound.scheduled.plist").exists()
    assert not (home / "Library" / "LaunchAgents" / "ai.getunbound.discovery.plist").exists()
    assert not (home / ".local" / "share" / "unbound" / "install.sh").exists()
    assert not (home / ".local" / "share" / "unbound" / "run-scheduled.sh").exists()
    for d in (".claude/hooks", ".cursor/hooks", ".codex/hooks"):
        assert not (home / d / "unbound.py").exists()
    for d in (".claude/hooks", ".cursor/hooks", ".copilot/hooks", ".codex/hooks"):
        assert not (home / d / ".self_update_check").exists()
        assert not (home / d / ".self_update.lock").exists()
    # copilot's SERVING files are not the sweep's job: unbound.json is the
    # registration and unbound.py is what it points at — both replaced by
    # the copilot adapter after its write succeeds (B2)
    assert (home / ".copilot" / "hooks" / "unbound.json").exists()
    assert (home / ".copilot" / "hooks" / "unbound.py").exists()
    # managed scripts are NOT the sweep's job (adapters remove them post-write)
    for tool in ("managed-claude", "managed-codex", "enterprise-cursor"):
        assert (tmp / tool / "hooks" / "unbound.py").exists()
    # the user-authored part of settings.json survives, unbound entries don't
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    assert settings.get("model") == "opus"
    assert "hooks" not in settings
    # config.json preserved byte-for-byte
    assert json.loads((home / ".unbound" / "config.json").read_text()) == {"api_key": "KEEP-ME"}


def test_sweep_full_python_install(env):
    _plant_python_era_artifacts(env["home"], env["tmp"])
    status, reason = migration.run_sweep(log=lambda *_: None)
    assert (status, reason) == ("configured", None)
    _assert_swept(env["home"], env["tmp"])
    # legacy LaunchAgent bootout attempted for the user (stubbed in tests)
    assert env["bootouts"] == [(ME, __import__("pwd").getpwnam(ME).pw_uid)]


def test_sweep_half_installed(env):
    """Partial python install: some artifacts present, some already gone."""
    home, tmp = env["home"], env["tmp"]
    (home / ".claude" / "hooks").mkdir(parents=True)
    (home / ".claude" / "hooks" / "unbound.py").write_text("# stale")
    (home / ".local" / "share" / "unbound").mkdir(parents=True)
    (home / ".local" / "share" / "unbound" / "install.sh").write_text("#!/bin/bash")
    (home / ".unbound").mkdir()
    (home / ".unbound" / "config.json").write_text(json.dumps({"api_key": "KEEP-ME"}))
    status, reason = migration.run_sweep(log=lambda *_: None)
    assert (status, reason) == ("configured", None)
    assert not (home / ".claude" / "hooks" / "unbound.py").exists()
    assert not (home / ".local" / "share" / "unbound" / "install.sh").exists()
    assert json.loads((home / ".unbound" / "config.json").read_text()) == {"api_key": "KEEP-ME"}


def test_sweep_previously_binary_is_noop(env):
    """Second run on an already-migrated machine: nothing to do, still ok,
    and the binary-era artifacts it must NOT touch stay put."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    before = (env["tmp"] / "managed-claude" / "managed-settings.json").read_text()
    status, reason = migration.run_sweep(log=lambda *_: None)
    assert (status, reason) == ("configured", None)
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").read_text() == before
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").exists()


def test_sweep_runs_inside_setup(env):
    _plant_python_era_artifacts(env["home"], env["tmp"])
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    # swept AND freshly configured
    assert not (env["home"] / ".claude" / "hooks" / "unbound.py").exists()
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").exists()
    assert json.loads((env["home"] / ".unbound" / "config.json").read_text())["api_key"] == "per-device-key"
    # managed stale scripts removed by adapters AFTER their settings rewrite
    for tool in ("managed-claude", "managed-codex", "enterprise-cursor"):
        assert not (env["tmp"] / tool / "hooks" / "unbound.py").exists()
    # python-era copilot registration replaced by a binary-era one, and the
    # now-unreferenced python script removed by the adapter (B2)
    copilot = json.loads((env["home"] / ".copilot" / "hooks" / "unbound.json").read_text())
    assert "unbound-hook" in copilot["hooks"]["PreToolUse"][0]["command"]
    assert not (env["home"] / ".copilot" / "hooks" / "unbound.py").exists()


def test_copilot_deferred_keeps_python_era(env, monkeypatch):
    """B2 regression: a copilot deferral (MDM key fetch fails) must leave the
    python-era copilot serving path — unbound.json AND the unbound.py it
    points at — fully intact until a successful re-run replaces them."""
    _plant_python_era_artifacts(env["home"], env["tmp"])
    python_json = (env["home"] / ".copilot" / "hooks" / "unbound.json").read_text()
    monkeypatch.setattr(env["modules"]["copilot"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").read_text() == python_json
    assert (env["home"] / ".copilot" / "hooks" / "unbound.py").exists()


def test_failed_component_keeps_python_serving_path(env, monkeypatch):
    """F1 regression: when a tool's setup defers (MDM key fetch fails), its
    managed python script must survive so existing hook registrations never
    point at a deleted file."""
    _plant_python_era_artifacts(env["home"], env["tmp"])
    monkeypatch.setattr(env["modules"]["codex"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    # codex deferred -> its managed script intact; others rewritten + cleaned
    assert (env["tmp"] / "managed-codex" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "managed-claude" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "enterprise-cursor" / "hooks" / "unbound.py").exists()


def test_sweep_scoped_to_tools_leaves_other_tools_alone(env):
    _plant_python_era_artifacts(env["home"], env["tmp"])
    status, _ = migration.run_sweep(tools=["claude-code"], log=lambda *_: None)
    assert status == "configured"
    assert not (env["home"] / ".claude" / "hooks" / "unbound.py").exists()
    # other tools' user artifacts untouched
    assert (env["home"] / ".codex" / "hooks" / "unbound.py").exists()
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").exists()


def test_sweep_user_failure_is_isolated_and_loud(env, monkeypatch):
    """One user's failing stripper must not abort the sweep silently — it is
    logged, the sweep continues, and the status is deferred (retryable)."""
    _plant_python_era_artifacts(env["home"], env["tmp"])

    def _boom(username, home_dir):
        raise RuntimeError("locked home")

    monkeypatch.setattr(env["modules"]["claude-code"],
                        "remove_user_level_hooks_for_user", _boom)
    logs = []
    status, reason = migration.run_sweep(log=logs.append)
    assert status == "deferred"
    assert ME in reason
    assert any("sweep failed for user" in line for line in logs)


def test_backfill_dry_run_failure_is_loud_not_crash(env, monkeypatch, capsys):
    """P1 regression: a tool whose collection machinery is missing/broken
    must produce a clean per-tool error + exit 1, not an unhandled traceback,
    and must not stop the remaining tools."""
    from unbound_hook import backfill_cmd
    monkeypatch.delattr(env["modules"]["claude-code"], "_backfill_collect_sessions")
    rc = backfill_cmd.run(["--all", "--dry-run"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "claude-code: dry-run failed" in captured.err
    # codex still ran its dry-run after claude-code failed
    assert "tool=codex" in captured.out


def test_sweep_keeps_binary_era_copilot_registration(env):
    """Previously-binary fixture detail: a copilot unbound.json whose
    commands already point at the binary must survive the sweep."""
    hooks_dir = env["home"] / ".copilot" / "hooks"
    hooks_dir.mkdir(parents=True)
    binary_json = json.dumps({"version": 1, "hooks": {"PreToolUse": [
        {"command": '"/opt/unbound/current/unbound-hook/unbound-hook" hook copilot PreToolUse'}]}})
    (hooks_dir / "unbound.json").write_text(binary_json)
    status, _ = migration.run_sweep(log=lambda *_: None)
    assert status == "configured"
    assert (hooks_dir / "unbound.json").read_text() == binary_json
