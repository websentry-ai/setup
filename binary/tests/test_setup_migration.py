"""Tests for `unbound-hook setup` / `clear` internals and the WEB-4788
migration sweep. Root-only primitives (privilege drop, MDM key fetch,
system env vars, completion notify) are stubbed on the vendored modules;
everything else — settings writers, strippers, sweep — runs for real
against sandboxed paths.
"""

import getpass
import io
import json
import sys
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
    for tool in ("claude-code", "cursor", "codex", "copilot", "augment"):
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
    monkeypatch.setattr(modules["augment"], "get_managed_settings_dir",
                        lambda: tmp_path / "managed-augment")
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

    # codex hooks.json — codex 0.125 discovers hooks from ~/.codex/hooks.json
    # (the user layer), so every event registers the BARE wrapper PATH (no
    # quotes, no " hook codex" args leaking into the registered command), and a
    # python shim that execs the binary lives at ~/.codex/hooks/unbound.py.
    # Codex runs that file as a PYTHON program (its native hook contract — the
    # python-era file is `#!/usr/bin/env python3`), so a `#!/bin/sh` wrapper at
    # a `.py` path is invalid python and codex silently drops it (the bug this
    # replaces).
    codex_wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    codex_cmd = str(codex_wrapper)
    codex = json.loads((env["home"] / ".codex" / "hooks.json").read_text())
    assert set(codex["hooks"]) == {"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart"}
    assert codex["hooks"]["PreToolUse"][0]["hooks"][0] == {
        "type": "command", "command": codex_cmd, "timeout": 15000}
    assert codex["hooks"]["PostToolUse"][0]["hooks"][0] == {
        "type": "command", "command": codex_cmd, "timeout": 60}
    for ev in codex["hooks"]:
        c = codex["hooks"][ev][0]["hooks"][0]["command"]
        assert c == codex_cmd and " hook codex" not in c
    # the wrapper is an executable python shim that execs the binary
    assert codex_wrapper.exists() and (codex_wrapper.stat().st_mode & 0o111)
    body = codex_wrapper.read_text()
    assert body.startswith("#!/usr/bin/env python3")
    assert not body.startswith("#!/bin/sh")
    compile(body, "unbound.py", "exec")  # must be valid python — codex runs it as one
    assert "os.execv" in body and BIN in body and '"codex"' in body
    # the dead managed hooks.json location is NOT written
    assert not (env["tmp"] / "managed-codex" / "hooks.json").exists()

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
    # augment managed /etc/augment settings.json — hooks block (verbatim
    # timeouts: PreToolUse 15000, SessionStart 60000, rest 10000) + the seeded
    # toolPermissions rules. No UserPromptSubmit (Augment has no such event).
    augment = json.loads((env["tmp"] / "managed-augment" / "settings.json").read_text())
    assert augment["hooks"] == {
        "PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": _cmd("augment", "PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": _cmd("augment", "PostToolUse"), "timeout": 10000}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "Stop"), "timeout": 10000}]}],
        "SessionStart": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "SessionStart"), "timeout": 60000}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "SessionEnd"), "timeout": 10000}]}],
    }
    aug_mod = env["modules"]["augment"]
    assert augment["toolPermissions"] == aug_mod.build_tool_permissions_block()

    # no python script is installed anywhere
    assert not (env["home"] / ".copilot" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "managed-claude" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "managed-augment" / "hooks" / "unbound.py").exists()

    # per-user config written for every tool (same device key)
    cfg = json.loads((env["home"] / ".unbound" / "config.json").read_text())
    assert cfg["api_key"] == "per-device-key"
    assert cfg["base_url"] == "https://backend.getunbound.ai"

    # completion notify fired once per tool (5: claude, cursor, codex, copilot, augment)
    assert len(env["notified"]) == 5
    # backfill NOT run without --backfill
    assert env["backfilled"] == []


def test_setup_component_failure_does_not_abort_others(env, monkeypatch):
    # claude-code's key fetch fails; everything else must still configure.
    monkeypatch.setattr(env["modules"]["claude-code"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    rc = setup_cmd.run(["--api-key", "admin-key"])
    assert rc == 1  # deferred component surfaces in the exit code
    assert not (env["tmp"] / "managed-claude" / "managed-settings.json").exists()
    assert (env["home"] / ".codex" / "hooks.json").exists()
    assert (env["tmp"] / "enterprise-cursor" / "hooks.json").exists()
    assert (env["home"] / ".copilot" / "hooks" / "unbound.json").exists()


def test_setup_backfill_flag_runs_backfill_for_supporting_tools(env):
    rc = setup_cmd.run(["--api-key", "admin-key", "--backfill"])
    assert rc == 0
    # claude-code, codex, copilot have run_backfill; cursor prints unsupported.
    assert len(env["backfilled"]) == 3


def test_setup_requires_api_key(env, capsys):
    assert setup_cmd.run([]) == 2


def test_setup_survives_ascii_stdout(env, monkeypatch):
    """Regression: Jamf's recurring check-in runs onboarding from a launchd
    context with no LANG/LC_*, so Python picks the ASCII codec for stdout.
    Before the fix, the first diagnostic print containing a non-ASCII char
    (the migration banner) raised UnicodeEncodeError and aborted `setup` on
    every check-in — it crashed Salesloft's fleet while interactive
    `sudo jamf policy` runs (UTF-8 locale) passed. main() must reconfigure the
    streams to UTF-8 so diagnostic output is best-effort, never fatal."""
    from unbound_hook.main import main

    ascii_out = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
    ascii_err = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
    monkeypatch.setattr(sys, "stdout", ascii_out)
    monkeypatch.setattr(sys, "stderr", ascii_err)

    # Routed through main() (the outermost entry every install hits), this
    # raised UnicodeEncodeError before the fix; now it completes cleanly.
    rc = main(["setup", "--api-key", "admin-key"])
    assert rc == 0
    # streams were reconfigured off the crashing ASCII codec
    assert ascii_out.encoding == "utf-8"
    assert ascii_err.encoding == "utf-8"
    # the banner actually reached the (now non-fatal) log
    ascii_out.flush()
    assert "migration" in ascii_out.buffer.getvalue().decode("utf-8")


def test_setup_is_idempotent(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    first = (env["tmp"] / "managed-claude" / "managed-settings.json").read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").read_text() == first


def test_setup_codex_user_hooks_idempotent(env):
    """A second run must not duplicate the codex hook entry in ~/.codex/hooks.json
    nor clobber the per-user wrapper."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_path = env["home"] / ".codex" / "hooks.json"
    first = json.loads(hooks_path.read_text())
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    second = json.loads(hooks_path.read_text())
    assert first == second
    for ev in second["hooks"]:
        # exactly one item, one hook entry per event — no duplication
        assert len(second["hooks"][ev]) == 1
        assert len(second["hooks"][ev][0]["hooks"]) == 1


def test_codex_wrapper_is_valid_python_execing_the_binary():
    """WEB-4850 root-cause lock-in. Codex runs ~/.codex/hooks/unbound.py as a
    PYTHON program (its native hook contract). The pre-fix binary installer wrote
    a `#!/bin/sh` wrapper there — not valid python — so codex silently dropped it
    (fail-open) and was ungoverned while the shell-executed tools worked. The
    wrapper MUST be valid python that execs the binary with `hook codex`."""
    body = setup_cmd._codex_wrapper_source()

    # (a) valid python — the exact failure mode of the sh wrapper was a parse error
    compile(body, "unbound.py", "exec")
    # (b) execs the binary with `hook codex` via os.execv (event read from stdin)
    assert "os.execv" in body
    assert BIN in body
    assert '"hook"' in body and '"codex"' in body
    # (c) NOT a /bin/sh script (the regression)
    assert body.startswith("#!/usr/bin/env python3")
    assert not body.startswith("#!/bin/sh")
    # no stray shell-isms leaked from the old wrapper
    assert "exec " not in body  # the sh builtin; os.execv is the python call


def test_codex_wrapper_written_to_disk_is_valid_python(env):
    """End-to-end: the file setup_cmd.run(...) actually writes at
    ~/.codex/hooks/unbound.py is valid python execing the binary — not a sh
    wrapper, executable, registered by bare path in hooks.json."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0

    wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    body = wrapper.read_text()
    compile(body, "unbound.py", "exec")
    assert body.startswith("#!/usr/bin/env python3")
    assert not body.startswith("#!/bin/sh")
    assert "os.execv" in body and BIN in body and '"codex"' in body
    assert wrapper.stat().st_mode & 0o111  # executable

    # the registered command is the bare wrapper path — no " hook codex" args
    hooks = json.loads((env["home"] / ".codex" / "hooks.json").read_text())
    for ev in hooks["hooks"]:
        cmd = hooks["hooks"][ev][0]["hooks"][0]["command"]
        assert cmd == str(wrapper)
        assert " hook codex" not in cmd


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
    for d in (".claude/hooks", ".cursor/hooks", ".copilot/hooks", ".codex/hooks", ".augment/hooks"):
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
    for tool in ("managed-claude", "managed-codex", "enterprise-cursor", "managed-augment"):
        (tmp / tool / "hooks").mkdir(parents=True, exist_ok=True)
        (tmp / tool / "hooks" / "unbound.py").write_text("# stale managed hook")
    # user-level claude hook registration pointing at the python script
    (home / ".claude" / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": str(home / ".claude" / "hooks" / "unbound.py")}]}]},
        "model": "opus",
    }))
    # user-level augment hook registration pointing at the python script (the
    # augment stripper matches on the bare script path, not a quoted command)
    (home / ".augment" / "settings.json").write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": str(home / ".augment" / "hooks" / "unbound.py")}]}]},
        "editorSetting": "keep",
    }))


def _assert_swept(home: Path, tmp: Path):
    assert not (home / "Library" / "LaunchAgents" / "ai.getunbound.scheduled.plist").exists()
    assert not (home / "Library" / "LaunchAgents" / "ai.getunbound.discovery.plist").exists()
    assert not (home / ".local" / "share" / "unbound" / "install.sh").exists()
    assert not (home / ".local" / "share" / "unbound" / "run-scheduled.sh").exists()
    for d in (".claude/hooks", ".cursor/hooks", ".codex/hooks", ".augment/hooks"):
        assert not (home / d / "unbound.py").exists()
    for d in (".claude/hooks", ".cursor/hooks", ".copilot/hooks", ".codex/hooks", ".augment/hooks"):
        assert not (home / d / ".self_update_check").exists()
        assert not (home / d / ".self_update.lock").exists()
    # copilot's SERVING files are not the sweep's job: unbound.json is the
    # registration and unbound.py is what it points at — both replaced by
    # the copilot adapter after its write succeeds (B2)
    assert (home / ".copilot" / "hooks" / "unbound.json").exists()
    assert (home / ".copilot" / "hooks" / "unbound.py").exists()
    # managed scripts are NOT the sweep's job (adapters remove them post-write)
    for tool in ("managed-claude", "managed-codex", "enterprise-cursor", "managed-augment"):
        assert (tmp / tool / "hooks" / "unbound.py").exists()
    # the user-authored part of settings.json survives, unbound entries don't
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    assert settings.get("model") == "opus"
    assert "hooks" not in settings
    # augment: foreign top-level key survives, the unbound hook entry is stripped
    aug_settings = json.loads((home / ".augment" / "settings.json").read_text())
    assert aug_settings.get("editorSetting") == "keep"
    assert "hooks" not in aug_settings
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
    # claude/cursor remove their python-era managed script; codex instead hosts
    # a binary wrapper at the per-user ~/.codex/hooks/unbound.py (its hook target).
    for tool in ("managed-claude", "enterprise-cursor"):
        assert not (env["tmp"] / tool / "hooks" / "unbound.py").exists()
    codex_wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    assert codex_wrapper.exists()
    wrapper_body = codex_wrapper.read_text()
    compile(wrapper_body, "unbound.py", "exec")  # codex runs it as a python program
    assert "os.execv" in wrapper_body and BIN in wrapper_body and '"codex"' in wrapper_body
    assert not (env["tmp"] / "managed-codex" / "hooks.json").exists()
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
    """F1 regression: when a managed-settings tool defers (MDM key fetch fails),
    its managed python script must survive so existing hook registrations never
    point at a deleted file."""
    _plant_python_era_artifacts(env["home"], env["tmp"])
    monkeypatch.setattr(env["modules"]["claude-code"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    # claude-code deferred -> its managed script intact; others rewritten + cleaned
    assert (env["tmp"] / "managed-claude" / "hooks" / "unbound.py").exists()
    assert not (env["tmp"] / "enterprise-cursor" / "hooks" / "unbound.py").exists()
    # codex configured fine -> per-user hooks.json registered, no managed write
    assert (env["home"] / ".codex" / "hooks.json").exists()
    assert not (env["tmp"] / "managed-codex" / "hooks.json").exists()


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


# --- WEB-4975: clear strips our hooks (python + binary) surgically + drops logs ---

def test_clear_strips_binary_hook_preserves_foreign(env):
    """Managed clear strips our hook in BINARY form but preserves foreign hooks
    and other top-level keys in a shared/Enterprise managed-settings.json."""
    m = env["modules"]["claude-code"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    settings_path = managed / "managed-settings.json"
    foreign_cmd = "/usr/local/bin/org-audit-hook"
    settings_path.write_text(json.dumps({
        "permissions": {"allow": ["Bash"]},
        "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": _cmd("claude-code", "PreToolUse")},
            {"type": "command", "command": foreign_cmd},
        ]}]},
    }))
    assert m.clear_managed_hooks() == "cleared"
    result = json.loads(settings_path.read_text())
    assert result.get("permissions") == {"allow": ["Bash"]}, "foreign top-level key dropped"
    cmds = [h["command"] for grp in result.get("hooks", {}).get("PreToolUse", [])
            for h in grp.get("hooks", [])]
    assert foreign_cmd in cmds, "foreign hook was stripped"
    assert all("/opt/unbound" not in c for c in cmds), "our binary hook survived the clear"


def test_clear_removes_managed_file_when_only_ours(env):
    """A managed config holding only our hooks is removed entirely (codex)."""
    m = env["modules"]["codex"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    settings_path = managed / "hooks.json"
    settings_path.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command", "command": _cmd("codex", "PreToolUse")}]}]}}))
    assert m.clear_managed_hooks() == "cleared"
    assert not settings_path.exists(), "config left empty of our hooks should be removed"


def test_clear_matcher_recognizes_both_forms_not_foreign(env):
    """_is_unbound_hook_command matches our managed python script path + the
    binary, but NOT a foreign hook pointing at some other unbound.py or merely
    mentioning /opt/unbound/ (the path-specific tightening)."""
    m = env["modules"]["claude-code"]
    sp = m.get_managed_settings_dir() / "hooks" / "unbound.py"
    assert m._is_unbound_hook_command(_cmd("claude-code", "Stop"), sp)             # binary
    assert m._is_unbound_hook_command(f'"{sp}"', sp)                               # our managed python
    assert not m._is_unbound_hook_command('"/some/other/unbound.py"', sp)          # foreign unbound.py
    assert not m._is_unbound_hook_command("/opt/unbound/etc/logs/foreign.sh", sp)  # prefix only, no binary
    assert not m._is_unbound_hook_command("/usr/local/bin/org-hook", sp)
    assert not m._is_unbound_hook_command("", sp)


def test_clear_removes_hook_logs(env):
    """Clear deletes the per-user agent-audit.log + error.log via the clear-only
    remove_hook_logs_for_user helper, for every tool that has one."""
    for tool, sub in (("claude-code", ".claude"), ("codex", ".codex"),
                      ("augment", ".augment"), ("cursor", ".cursor")):
        m = env["modules"][tool]
        hooks_dir = env["home"] / sub / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "agent-audit.log").write_text("audit\n")
        (hooks_dir / "error.log").write_text("err\n")
        m.remove_hook_logs_for_user(ME, env["home"])
        assert not (hooks_dir / "agent-audit.log").exists(), tool
        assert not (hooks_dir / "error.log").exists(), tool
    # The Windows machine-wide placeholder (None home) must be a safe no-op.
    env["modules"]["claude-code"].remove_hook_logs_for_user(None, None)
