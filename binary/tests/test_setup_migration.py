"""Tests for `unbound-hook setup` / `clear` internals and the WEB-4788
migration sweep. Root-only primitives (privilege drop, MDM key fetch,
system env vars, completion notify) are stubbed on the vendored modules;
everything else — settings writers, strippers, sweep — runs for real
against sandboxed paths.
"""

import getpass
import io
import json
import os
import sys
from pathlib import Path

import pytest

from unbound_hook import clear_cmd, migration, setup_cmd
from unbound_hook._loader import load_mdm_setup_module
from unbound_hook._resources import HOOK_BINARY

ME = getpass.getuser()
_PYTHON_ERA_HOOK = (Path(__file__).resolve().parents[2] / "codex" / "hooks" / "unbound.py").read_text()
BIN = str(HOOK_BINARY)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Sandboxed homes + root-only stubs across all four vendored modules."""
    home = tmp_path / "home"
    home.mkdir()
    notified = []
    backfilled = []
    bounded = []
    modules = {}
    for tool in ("claude-code", "cursor", "codex", "copilot", "augment"):
        m = load_mdm_setup_module(tool)
        modules[tool] = m
        monkeypatch.setattr(m, "_run_as_user", lambda u, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(m, "get_all_user_homes", lambda h=home: [(ME, h)])
        monkeypatch.setattr(m, "check_admin_privileges", lambda: True)
        monkeypatch.setattr(m, "get_device_identifier", lambda: "TESTSERIAL1")
        monkeypatch.setattr(m, "fetch_api_key_from_mdm",
                            lambda base, app, auth, dev, app_type=None: "per-device-key")
        monkeypatch.setattr(m, "notify_setup_complete",
                            lambda *a, **k: notified.append((a, k)))
        if hasattr(m, "run_backfill"):
            monkeypatch.setattr(m, "run_backfill",
                                lambda *a, **k: backfilled.append(a))
        if hasattr(m, "_run_backfill_bounded"):
            monkeypatch.setattr(m, "_run_backfill_bounded",
                                lambda *a, t=tool, **k: (bounded.append(t), backfilled.append(a)))
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
    daemon_bootouts = []
    monkeypatch.setattr(migration, "_bootout_legacy_daemon",
                        lambda log: daemon_bootouts.append(log) or True)
    monkeypatch.setattr(migration, "LEGACY_DAEMON_PLIST", tmp_path / "coding-discovery.plist")
    monkeypatch.setattr(migration, "LEGACY_HOOK_SHIM", tmp_path / "usr-local-bin-unbound-hook")
    # Discovery needs no key any more: it resolves the device owner from the
    # serial and runs the locally installed binary. Stand in a no-op binary so
    # the step exercises that path instead of deferring on a missing file.
    discovery_bin = tmp_path / "unbound-discovery"
    discovery_bin.write_text("#!/bin/sh\nexit 0\n")
    discovery_bin.chmod(0o755)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_BINARY", discovery_bin)
    return {"tmp": tmp_path, "home": home, "modules": modules,
            "notified": notified, "backfilled": backfilled, "bounded": bounded, "bootouts": bootouts,
            "daemon_bootouts": daemon_bootouts}


def _cmd(tool, event):
    return f'"{BIN}" hook {tool} {event}'


def test_setup_full_run_configures_everything(env):
    rc = setup_cmd.run(["--api-key", "admin-key"])
    assert rc == 0  # every component configured, discovery included

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
            {"type": "command", "command": _cmd("augment", "PreToolUse"), "timeout": 15000}],
            "metadata": {"includeUserContext": True, "includeMCPMetadata": True}}],
        "PostToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": _cmd("augment", "PostToolUse"), "timeout": 10000}],
            "metadata": {"includeUserContext": True, "includeMCPMetadata": True}}],
        "Stop": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "Stop"), "timeout": 10000}],
            "metadata": {"includeConversationData": True, "includeUserContext": True}}],
        "SessionStart": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "SessionStart"), "timeout": 60000}],
            "metadata": {"includeUserContext": True}}],
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


def _user_config(env):
    return json.loads((env["home"] / ".unbound" / "config.json").read_text())


def test_setup_records_the_frontend_url_normalized_like_backend_and_gateway(env):
    rc = setup_cmd.run(["--api-key", "admin-key", "--backend-url", "tenant-backend.example.com/",
                        "--gateway-url", "tenant-api.example.com/",
                        "--frontend-url", " tenant-app.example.com/ "])
    assert rc == 0
    cfg = _user_config(env)
    assert cfg["base_url"] == "https://tenant-backend.example.com"
    assert cfg["gateway_url"] == "https://tenant-api.example.com"
    assert cfg["frontend_url"] == "https://tenant-app.example.com"


@pytest.mark.parametrize("extra", [[], ["--frontend-url", ""], ["--frontend-url", "   "]])
def test_setup_without_a_frontend_url_records_none(env, extra):
    assert setup_cmd.run(["--api-key", "admin-key", *extra]) == 0
    assert "frontend_url" not in _user_config(env)


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
    copilot_args = next(args for args in env["backfilled"] if len(args) == 4)
    assert "def read_copilot_mcp_servers" in copilot_args[3]


def test_claude_code_backfill_goes_through_the_time_bounded_wrapper(env):
    """Unbounded, a heavy Claude Code history held `unbound-hook setup` open past the
    MDM policy's own timeout; the bounded wrapper soft-stops and hard-kills in time."""
    assert setup_cmd.run(["--api-key", "admin-key", "--backfill"]) == 0
    assert env["bounded"] == ["claude-code"]


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


def test_augment_rerun_adds_user_context_to_an_existing_install(env):
    """Devices installed before the fix have our blocks with no metadata; a
    re-run must add it, and leave an org's own block alone."""
    managed = env["tmp"] / "managed-augment"
    managed.mkdir(parents=True, exist_ok=True)
    foreign = {"matcher": ".*", "hooks": [{"type": "command", "command": "/org/own.sh"}]}
    (managed / "settings.json").write_text(json.dumps({"hooks": {
        "PreToolUse": [foreign, {"matcher": ".*", "hooks": [
            {"type": "command", "command": _cmd("augment", "PreToolUse"), "timeout": 15000}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": _cmd("augment", "Stop"), "timeout": 10000}]}],
    }}))

    assert setup_cmd.run(["--api-key", "admin-key"]) == 0

    hooks = json.loads((managed / "settings.json").read_text())["hooks"]
    assert hooks["PreToolUse"][0] == foreign
    assert hooks["PreToolUse"][1]["metadata"]["includeUserContext"] is True
    assert hooks["Stop"][0]["metadata"]["includeUserContext"] is True
    assert len(hooks["PreToolUse"]) == 2


def test_augment_rerun_keeps_the_metadata_stable(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    first = (env["tmp"] / "managed-augment" / "settings.json").read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert (env["tmp"] / "managed-augment" / "settings.json").read_text() == first


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
    for d in (".claude/hooks", ".cursor/hooks", ".augment/hooks"):
        assert not (home / d / "unbound.py").exists()
    # codex's unbound.py is its hook target in both eras; the codex adapter
    # overwrites it in place, so the sweep leaves it alone
    assert (home / ".codex" / "hooks" / "unbound.py").exists()
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


def test_sweep_removes_python_era_system_daemon_and_shim(env):
    plist, shim = migration.LEGACY_DAEMON_PLIST, migration.LEGACY_HOOK_SHIM
    plist.write_text("<plist/>")
    shim.write_text("#!/bin/bash")
    status, reason = migration.run_sweep(log=lambda *_: None)
    assert (status, reason) == ("configured", None)
    assert not plist.exists() and not shim.exists()
    assert len(env["daemon_bootouts"]) == (1 if sys.platform == "darwin" else 0)


def test_sweep_keeps_a_symlinked_hook_shim(env):
    target = env["tmp"] / "real-binary"
    target.write_text("binary")
    migration.LEGACY_HOOK_SHIM.symlink_to(target)
    status, _ = migration.run_sweep(log=lambda *_: None)
    assert status == "configured"
    assert migration.LEGACY_HOOK_SHIM.is_symlink() and target.read_text() == "binary"


@pytest.mark.skipif(sys.platform != "darwin", reason="launchctl is macOS-only")
def test_sweep_defers_while_the_legacy_daemon_stays_loaded(env, monkeypatch):
    monkeypatch.setattr(migration, "_bootout_legacy_daemon", lambda log: False)
    status, reason = migration.run_sweep(log=lambda *_: None)
    assert status == "deferred" and "system" in reason


def test_bootout_reports_a_daemon_that_is_still_loaded(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv[1])
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(migration.subprocess, "run", fake_run)
    logs = []
    assert migration._bootout_legacy_daemon(logs.append) is False
    assert calls == ["bootout", "print"]
    assert any("still loaded" in line for line in logs)


@pytest.mark.parametrize("print_rc", [113, 3])
def test_bootout_succeeds_once_the_daemon_is_gone(monkeypatch, print_rc):
    monkeypatch.setattr(
        migration.subprocess, "run",
        lambda argv, **kw: type("R", (), {"returncode": print_rc if argv[1] == "print" else 0})())
    assert migration._bootout_legacy_daemon(lambda *_: None) is True


def test_bootout_error_counts_as_not_unloaded(monkeypatch):
    def boom(argv, **kw):
        raise OSError("launchctl missing")

    monkeypatch.setattr(migration.subprocess, "run", boom)
    logs = []
    assert migration._bootout_legacy_daemon(logs.append) is False
    assert any("launchctl missing" in line for line in logs)


def test_sweep_system_removal_failure_defers_but_still_sweeps_users(env, monkeypatch):
    _plant_python_era_artifacts(env["home"], env["tmp"])
    migration.LEGACY_DAEMON_PLIST.write_text("<plist/>")
    real_unlink = Path.unlink

    def failing_unlink(self, *a, **k):
        if self == migration.LEGACY_DAEMON_PLIST:
            raise PermissionError("denied")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    logs = []
    status, reason = migration.run_sweep(log=logs.append)
    assert status == "deferred" and "system" in reason
    assert any("could not remove" in line for line in logs)
    _assert_swept(env["home"], env["tmp"])


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


CODEX_EVENTS = {"PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart"}


def _plant_python_era_codex(home: Path, command: str):
    script = home / ".codex" / "hooks" / "unbound.py"
    script.parent.mkdir(parents=True)
    script.write_text(_PYTHON_ERA_HOOK)  # the real hook a python-era install downloaded
    script.chmod(0o755)
    # Every python-era installer wrote all five events, with the same matchers.
    config = setup_cmd._codex_hooks_config(command.format(script=script))
    config["Stop"].append({"hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]})
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": config}))
    return script


def _codex_states(env):
    return [k["install_state"] for a, k in env["notified"] if a[1] == "codex"]


def _codex_registrations(home: Path):
    hooks = json.loads((home / ".codex" / "hooks.json").read_text()).get("hooks", {})
    wrapper = str(home / ".codex" / "hooks" / "unbound.py")
    return {ev: [h["command"] for grp in groups for h in grp.get("hooks", [])
                 if setup_cmd._command_targets_hook(h.get("command", ""), Path(wrapper))]
            for ev, groups in hooks.items()}


def test_codex_rerun_reports_persisted_not_tampered(env):
    """The sweep runs before the codex adapter. If it strips codex's user-level
    hook, every re-run sees it missing and reports a healthy install as
    tampered, then reinstalls it."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "persisted", "persisted"]


def test_sweep_keeps_the_binary_codex_install(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    hooks_json = env["home"] / ".codex" / "hooks.json"
    before = (wrapper.read_text(), hooks_json.read_text())
    status, _ = migration.run_sweep(log=lambda *_: None)
    assert status == "configured"
    assert (wrapper.read_text(), hooks_json.read_text()) == before


@pytest.mark.parametrize("python_era_command", [
    "{script}",              # python user-level installer
    '"{script}"',            # python MDM installer
])
def test_python_era_codex_install_upgrades_in_place(env, python_era_command):
    """A python-era codex hook is the same file + hooks.json entry the binary
    writes, so setup upgrades it in place: one registration per event, the
    file becomes the binary wrapper, and the run reports persisted."""
    home = env["home"]
    script = _plant_python_era_codex(home, python_era_command)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["persisted"]
    assert "os.execv" in script.read_text()
    regs = _codex_registrations(home)
    assert set(regs) == CODEX_EVENTS
    assert all(len(cmds) == 1 for cmds in regs.values()), regs
    stop = json.loads((home / ".codex" / "hooks.json").read_text())["hooks"]["Stop"]
    assert any(h["command"] == "/usr/local/bin/other-hook"
               for grp in stop for h in grp["hooks"])


def test_codex_deferred_keeps_python_era(env, monkeypatch):
    """A codex deferral (MDM key fetch fails) must leave the python-era hook
    and its registration intact until a successful re-run replaces them."""
    home = env["home"]
    script = _plant_python_era_codex(home, '"{script}"')
    before = (script.read_text(), (home / ".codex" / "hooks.json").read_text())
    monkeypatch.setattr(env["modules"]["codex"], "fetch_api_key_from_mdm",
                        lambda *a: None)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    assert (script.read_text(), (home / ".codex" / "hooks.json").read_text()) == before


def test_codex_clear_still_removes_the_binary_install(env):
    """Uninstall doesn't rely on the sweep for codex: clear_setup strips it."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert env["modules"]["codex"].clear_setup() is True
    assert not (env["home"] / ".codex" / "hooks" / "unbound.py").exists()
    hooks_json = env["home"] / ".codex" / "hooks.json"
    if hooks_json.exists():
        assert not any(_codex_registrations(env["home"]).values())


def test_codex_replaces_a_symlink_at_its_hook_path(env):
    """The sweep used to delete a symlinked ~/.codex/hooks/unbound.py before the
    adapter's O_NOFOLLOW write; now the adapter replaces the link itself, never
    writing through it."""
    target = env["tmp"] / "elsewhere.py"
    target.write_text("# not ours\n")
    wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.symlink_to(target)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert not wrapper.is_symlink() and "os.execv" in wrapper.read_text()
    assert target.read_text() == "# not ours\n"
    assert set(_codex_registrations(env["home"])) == CODEX_EVENTS


def test_codex_replaces_a_read_only_script_at_its_hook_path(env):
    """A no-op made read-only can't be truncated in place, so it would survive every run."""
    wrapper = env["home"] / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\nexit 0\n")
    wrapper.chmod(0o555)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert "os.execv" in wrapper.read_text() and wrapper.stat().st_mode & 0o777 == 0o755
    assert set(_codex_registrations(env["home"])) == CODEX_EVENTS


@pytest.mark.parametrize("shape", ["corrupt", "symlink"])
def test_codex_defers_on_an_unusable_hooks_json(env, shape):
    """A hooks.json we can't safely merge into defers codex without touching it
    (or writing through a link), and the other tools still configure."""
    hooks_json = env["home"] / ".codex" / "hooks.json"
    hooks_json.parent.mkdir(parents=True)
    if shape == "corrupt":
        hooks_json.write_text("{not json")
        watched = hooks_json
    else:
        watched = env["tmp"] / "dotfiles-hooks.json"
        watched.write_text(json.dumps({"hooks": {}}))
        hooks_json.symlink_to(watched)
    before = watched.read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 1
    assert watched.read_text() == before
    assert not _codex_states(env)
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").exists()


def test_clear_command_removes_the_codex_install(env, monkeypatch):
    """`unbound-hook clear` runs the sweep after each clear_setup; with codex no
    longer swept, its own clear_setup must still leave nothing behind."""
    monkeypatch.setattr(env["modules"]["copilot"], "managed_settings_path",
                        lambda: env["tmp"] / "managed-copilot" / "managed-settings.json")
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert clear_cmd.run([]) == 0
    assert not (env["home"] / ".codex" / "hooks" / "unbound.py").exists()
    hooks_json = env["home"] / ".codex" / "hooks.json"
    assert not hooks_json.exists() or not any(_codex_registrations(env["home"]).values())


def _without_hanging(fn, seconds=5):
    """Run fn, failing if anything in it blocks. Setup swallows per-tool errors,
    so the alarm is recorded rather than trusted to propagate."""
    import signal
    fired = []

    def _hung(*_):
        fired.append(True)
        raise TimeoutError("setup blocked")

    old = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(seconds)
    try:
        result = fn()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    assert not fired, "setup blocked on a FIFO"
    return result


def test_a_fifo_at_hooks_json_does_not_hang_setup(env):
    fifo = env["home"] / ".codex" / "hooks.json"
    fifo.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo)
    assert _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"])) == 1
    assert __import__("stat").S_ISFIFO(fifo.lstat().st_mode)
    assert (env["tmp"] / "managed-claude" / "managed-settings.json").exists()


def test_a_fifo_at_the_codex_hook_path_is_replaced(env):
    """Opened for writing, a FIFO with a reader attached would take the wrapper and stay a FIFO."""
    fifo = env["home"] / ".codex" / "hooks" / "unbound.py"
    fifo.parent.mkdir(parents=True)
    os.mkfifo(fifo)
    assert _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"])) == 0
    assert fifo.is_file() and "os.execv" in fifo.read_text()
    assert set(_codex_registrations(env["home"])) == CODEX_EVENTS


def test_a_fifo_at_config_toml_does_not_hang_setup(env):
    fifo = env["home"] / ".codex" / "config.toml"
    fifo.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo)
    _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"]))
    _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"]))
    assert __import__("stat").S_ISFIFO(fifo.lstat().st_mode)
    assert set(_codex_registrations(env["home"])) == CODEX_EVENTS
    assert _codex_states(env)[-1] == "tampered"  # codex can read hooks = false from it


def test_a_fifo_in_one_profile_reports_tampered_from_the_others(env, monkeypatch):
    other = env["tmp"] / "other"
    other.mkdir()
    homes = [(ME, env["home"]), (ME, other)]
    for mod in env["modules"].values():
        monkeypatch.setattr(mod, "get_all_user_homes", lambda: homes)

    def _as_user(_u, fn, *a, **k):  # the real helper returns None when fn raises
        try:
            return fn(*a, **k)
        except Exception:
            return None

    monkeypatch.setattr(env["modules"]["codex"], "_run_as_user", _as_user)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = other / ".codex" / "hooks.json"
    hooks_json.unlink()
    os.mkfifo(hooks_json)
    _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"]))
    assert _codex_states(env) == ["fresh", "tampered"]
    assert set(_codex_registrations(env["home"])) == CODEX_EVENTS


@pytest.mark.parametrize("decoy_shape", ['python3 -c "{w}"', '"{w}/"'])
def test_setup_repairs_a_decoy_registration(env, decoy_shape):
    """A command that names the wrapper but skips it is not ours to the install
    either, so setup registers the real hook beside it and the next run is clean."""
    home = env["home"]
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(setup_cmd._codex_wrapper_source())
    wrapper.chmod(0o755)
    decoy = decoy_shape.format(w=wrapper)
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {
        e: [{"hooks": [{"type": "command", "command": decoy}]}] for e in CODEX_EVENTS}}))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["tampered", "persisted"]
    hooks = json.loads((home / ".codex" / "hooks.json").read_text())["hooks"]
    for event in CODEX_EVENTS:
        cmds = [h["command"] for grp in hooks[event] for h in grp["hooks"]]
        assert cmds.count(str(wrapper)) == 1 and decoy in cmds


def _only_home(env, monkeypatch, home):
    for mod in env["modules"].values():
        monkeypatch.setattr(mod, "get_all_user_homes", lambda: [(ME, home)])


def _codex_commands(home, event):
    hooks = json.loads((home / ".codex" / "hooks.json").read_text())["hooks"]
    return [h["command"] for grp in hooks[event] for h in grp["hooks"]]


def test_a_home_with_a_space_gets_one_working_entry(env, monkeypatch):
    """Codex runs the command via `$SHELL -lc`, so the path is shell-quoted; the
    old unquoted entry (split by the shell, never run) is replaced, not duplicated."""
    home = env["tmp"] / "Jane Doe"
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {
        e: [{"hooks": [{"type": "command", "command": str(wrapper)}]}] for e in CODEX_EVENTS}}))
    _only_home(env, monkeypatch, home)
    for _ in range(3):
        assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "persisted", "persisted"]
    for event in CODEX_EVENTS:
        assert _codex_commands(home, event) == [__import__("shlex").quote(str(wrapper))]


@pytest.mark.parametrize("ours", [True, False])
def test_a_symlinked_hooks_json_is_never_written_through(env, monkeypatch, ours):
    """A dotfiles link that already registers our hook needs no write, so setup
    succeeds; one that doesn't is refused rather than written through."""
    home = env["home"]
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    dotfile = env["tmp"] / "dotfiles" / "hooks.json"
    dotfile.parent.mkdir()
    command = str(wrapper) if ours else "/usr/local/bin/other-hook"
    dotfile.write_text(json.dumps({"hooks": {
        e: [{"hooks": [{"type": "command", "command": command}]}] for e in CODEX_EVENTS}}))
    (home / ".codex" / "hooks.json").symlink_to(dotfile)
    before = dotfile.read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == (0 if ours else 1)
    assert (home / ".codex" / "hooks.json").is_symlink() and dotfile.read_text() == before


def test_an_unchanged_hooks_json_is_not_rewritten(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    os.utime(hooks_json, (1_000_000_000, 1_000_000_000))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert hooks_json.stat().st_mtime == 1_000_000_000


def test_setup_repairs_a_narrowed_matcher(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["hooks"]["PreToolUse"][0]["matcher"] = "^$"
    hooks_json.write_text(json.dumps(config))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered", "persisted"]
    # The narrowed copy is ours, so it's replaced rather than kept firing beside it.
    matchers = [g.get("matcher") for g in json.loads(hooks_json.read_text())["hooks"]["PreToolUse"]]
    assert matchers == ["*"]


def test_a_working_non_ascii_entry_on_a_symlink_is_left_alone(env, monkeypatch):
    """`/Users/José/...` is one shell word unquoted, so it already runs; only a
    path the shell would split is replaced."""
    home = env["tmp"] / "José"
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(setup_cmd._codex_wrapper_source())
    wrapper.chmod(0o755)
    dotfile = env["tmp"] / "dotfiles" / "hooks.json"
    dotfile.parent.mkdir()
    dotfile.write_text(json.dumps({"hooks": setup_cmd._codex_hooks_config(str(wrapper))}))
    (home / ".codex" / "hooks.json").symlink_to(dotfile)
    before = dotfile.read_text()
    _only_home(env, monkeypatch, home)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["persisted"]
    assert dotfile.read_text() == before


def test_an_old_era_install_is_not_duplicated(env):
    """Pre-May installs carry a 10s PreToolUse timeout and async PostToolUse /
    SessionStart; they're ours, so setup must not add a second copy."""
    home = env["home"]
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(setup_cmd._codex_wrapper_source())
    wrapper.chmod(0o755)
    config = {}
    for event in CODEX_EVENTS:
        hook = {"type": "command", "command": str(wrapper),
                "timeout": 10 if event == "PreToolUse" else 60}
        if event in ("PostToolUse", "SessionStart"):
            hook["async"] = True
        config[event] = [{"matcher": "*", "hooks": [hook]}]
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": config}))
    before = (home / ".codex" / "hooks.json").read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["persisted"]
    assert (home / ".codex" / "hooks.json").read_text() == before


@pytest.mark.parametrize("bad", [{"async": True}, {"timeout": 9.5}, {"timeout": True}, {"timeout": 15000.0}])
def test_a_disqualified_entry_of_ours_is_replaced_not_doubled(env, bad):
    """Codex would still run (or fail to load) our non-qualifying entry, so it's
    removed when the real group is added: the wrapper fires once per event."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["hooks"]["PreToolUse"][0]["hooks"][0].update(bad)
    hooks_json.write_text(json.dumps(config))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered"]
    pre = json.loads(hooks_json.read_text())["hooks"]["PreToolUse"]
    assert pre == setup_cmd._codex_hooks_config(str(env["home"] / ".codex" / "hooks" / "unbound.py"))["PreToolUse"]


def test_setup_repairs_an_async_pretooluse(env):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["hooks"]["PreToolUse"][0]["hooks"][0]["async"] = True
    hooks_json.write_text(json.dumps(config))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered", "persisted"]


@pytest.mark.parametrize("blocker", ["symlink", "fifo"])
def test_a_tamper_is_reported_even_when_the_only_install_fails(env, monkeypatch, blocker):
    """One profile whose hooks.json the install can't touch: setup defers, but the
    tamper it detected still reaches the dashboard."""
    def _as_user(_u, fn, *a, **k):  # the real helper returns None when fn raises
        try:
            return fn(*a, **k)
        except Exception:
            return None

    monkeypatch.setattr(env["modules"]["codex"], "_run_as_user", _as_user)
    home = env["home"]
    wrapper = home / ".codex" / "hooks" / "unbound.py"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(setup_cmd._codex_wrapper_source())
    wrapper.chmod(0o755)
    hooks_json = home / ".codex" / "hooks.json"
    if blocker == "symlink":
        target = env["tmp"] / "dotfiles.json"
        target.write_text(json.dumps({"hooks": {}}))
        hooks_json.symlink_to(target)
    else:
        os.mkfifo(hooks_json)
    assert _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"])) == 1
    assert _codex_states(env) == ["tampered"]


def test_a_fresh_install_that_fails_reports_nothing(env, monkeypatch):
    def _as_user(_u, fn, *a, **k):
        try:
            return fn(*a, **k)
        except Exception:
            return None

    monkeypatch.setattr(env["modules"]["codex"], "_run_as_user", _as_user)
    hooks_json = env["home"] / ".codex" / "hooks.json"
    hooks_json.parent.mkdir(parents=True)
    os.mkfifo(hooks_json)
    assert _without_hanging(lambda: setup_cmd.run(["--api-key", "admin-key"])) == 1
    assert _codex_states(env) == []


def test_setup_repairs_malformed_known_content(env):
    """A malformed handler of a type codex knows makes it refuse the file, so setup
    drops just that and keeps everything codex can load."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    foreign = {"type": "command", "command": "/usr/bin/audit", "timeout": 30}
    config["hooks"]["PreToolUse"][0]["hooks"].append(foreign)
    config["hooks"]["PreToolUse"].append({"hooks": [{"type": "command", "command": "/y", "timeout": 1.5}]})
    config["hooks"]["PreToolUse"].append({"hooks": [{"type": [], "command": "/z"}]})
    hooks_json.write_text(json.dumps(config))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered", "persisted"]
    repaired = json.loads(hooks_json.read_text())
    assert setup_cmd._codex_can_load(repaired)
    assert foreign in repaired["hooks"]["PreToolUse"][0]["hooks"]


def test_setup_keeps_keys_and_handler_types_it_does_not_know(env):
    """A newer codex may define them, so they're never deleted; the profile reads
    tampered against the codex this check knows, and the file is left alone."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["futureField"] = {"x": 1}
    config["hooks"]["Stop"].append({"hooks": [{"type": "future_kind", "anything": 1}]})
    hooks_json.write_text(json.dumps(config))
    before = hooks_json.read_text()
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered"]
    assert hooks_json.read_text() == before


def test_setup_collapses_a_repeated_key(env):
    """Rewriting is what makes a file with a repeated field loadable again."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    body = json.loads(hooks_json.read_text())["hooks"]
    hooks_json.write_text('{"hooks": {}, "hooks": ' + json.dumps(body) + "}")
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env) == ["fresh", "tampered", "persisted"]
    assert hooks_json.read_text().count('"hooks"') >= 1 and setup_cmd._codex_can_load(json.loads(hooks_json.read_text()))


@pytest.mark.parametrize("spoil, repaired", [
    (lambda text: "\ufeff" + text, True),                                     # byte-order mark
    (lambda text: text.replace('"timeout": 60', '"timeout": NaN', 1), True),  # NaN in our handler
    (lambda text: text[:-1] + ', "description": "x\\ud800"}', False),        # lone surrogate
])
def test_setup_recovers_a_hooks_json_codex_rejects_at_parse_time(env, spoil, repaired):
    """Codex refuses the whole file, so nothing runs. Setup recovers what Python can
    parse and rewrites it when that loads; a value it can't write validly is left."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    hooks_json.write_text(spoil(hooks_json.read_text()), encoding="utf-8")
    setup_cmd.run(["--api-key", "admin-key"])
    setup_cmd.run(["--api-key", "admin-key"])
    assert _codex_states(env)[1] == "tampered"
    assert _codex_states(env)[-1] == ("persisted" if repaired else "tampered")


def test_a_group_without_hooks_is_left_as_is(env):
    """Codex accepts a group with no hooks field; repair must not add one and rewrite."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["hooks"]["PreToolUse"].append({"matcher": "Bash"})
    text = json.dumps(config)
    hooks_json.write_text(text)
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert hooks_json.read_text() == text
    assert _codex_states(env)[-1] == "persisted"


def test_a_rewrite_too_large_to_read_back_is_not_written(env):
    """Detection reads at most the size cap; a bigger file would read as tampered forever."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    del config["hooks"]["Stop"]  # forces a write that adds a registration
    config["description"] = ""
    pad = setup_cmd._USER_FILE_MAX_BYTES - len(json.dumps(config)) - 100
    config["description"] = "x" * pad
    text = json.dumps(config)
    hooks_json.write_text(text)
    setup_cmd.run(["--api-key", "admin-key"])
    assert hooks_json.read_text() == text


def test_a_write_that_cannot_be_encoded_leaves_hooks_json_intact(env):
    """Encoding happens before the truncating open, so a value that can't be
    written as UTF-8 never empties the user's file."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    del config["hooks"]["Stop"]  # forces a write
    text = json.dumps(config)[:-1] + ', "description": "x\\ud800"}'
    hooks_json.write_text(text, encoding="utf-8")
    setup_cmd.run(["--api-key", "admin-key"])
    assert hooks_json.read_text(encoding="utf-8") == text


def _with_mcp_nan(config):
    config["hooks"]["Interrupt"] = [{"hooks": [
        {"type": "mcp_tool", "server": "s", "tool": "t", "input": {"a": "__NAN__"}}]}]


def _with_handler_nan(config):
    config["hooks"]["Stop"][0]["hooks"][0]["note"] = "__NAN__"


def _with_overflowing_number(config):
    config["hooks"]["Stop"][0]["hooks"][0]["note"] = "__1E400__"


def _with_overflowing_integer(config):
    config["hooks"]["Stop"][0]["hooks"][0]["note"] = "__BIGINT__"


def _with_f64_max_integer(config):
    config["hooks"]["Stop"][0]["hooks"][0]["note"] = "__F64MAX__"


@pytest.mark.parametrize("plant", [_with_mcp_nan, _with_handler_nan, _with_overflowing_number,
                                   _with_overflowing_integer, _with_f64_max_integer])
def test_a_nan_anywhere_is_repaired(env, plant):
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    plant(config)
    text = (json.dumps(config).replace('"__NAN__"', "NaN").replace('"__1E400__"', "1e400")
            .replace('"__BIGINT__"', "1" + "0" * 400).replace('"__F64MAX__"', str(int(sys.float_info.max))))
    hooks_json.write_text(text)
    assert setup_cmd._codex_hook_registered(hooks_json, hooks_json.parent / "hooks" / "unbound.py") is False  # codex rejects it
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    assert _codex_states(env)[-1] == "persisted"
    assert setup_cmd._codex_can_load(setup_cmd._load_codex_json(hooks_json.read_bytes()))


def test_a_nan_on_an_unknown_top_level_key_is_dropped(env):
    """The key is kept, as any unknown key is; the NaN codex can't parse is not."""
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    hooks_json = env["home"] / ".codex" / "hooks.json"
    config = json.loads(hooks_json.read_text())
    config["x"] = {"keep": 1, "bad": "__NAN__"}
    del config["hooks"]["Stop"]  # forces a write
    hooks_json.write_text(json.dumps(config).replace('"__NAN__"', "NaN"))
    assert setup_cmd.run(["--api-key", "admin-key"]) == 0
    repaired = setup_cmd._load_codex_json(hooks_json.read_bytes())
    assert repaired["x"] == {"keep": 1} and "Stop" in repaired["hooks"]


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


# ---------------------------------------------------------------------------
# --skip-managed-settings: install the hook, let the org's remote Claude Code
# policy own the hook config, and take our entries back out of the local file.
# ---------------------------------------------------------------------------

def test_skip_managed_settings_writes_no_hook_config(env):
    """No settings file exists and none is created; the flag only ever removes."""
    m = env["modules"]["claude-code"]
    rc = setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                        "--skip-managed-settings"])
    assert rc == 0
    assert not (m.get_managed_settings_dir() / "managed-settings.json").exists()


def test_skip_managed_settings_touches_no_managed_settings_path(env, monkeypatch):
    """The contract is stronger than "does not edit it": in skip mode the file is
    the admin's and nothing may stat, open or read it. Asserted by instrumenting the
    filesystem calls for the whole run, so a new caller anywhere trips this."""
    m = env["modules"]["claude-code"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    (managed / "managed-settings.json").write_text(json.dumps({"forceLoginOrgUUID": "org"}))

    touches = []

    def record(kind, path):
        if "managed-settings" in str(path) and str(path).endswith(".json"):
            touches.append(f"{kind}({path})")

    real_open, real_stat, real_read = io.open, os.stat, Path.read_text
    monkeypatch.setattr(io, "open", lambda f, *a, **k: (record("open", f), real_open(f, *a, **k))[1])
    monkeypatch.setattr(os, "stat", lambda f, *a, **k: (record("stat", f), real_stat(f, *a, **k))[1])
    monkeypatch.setattr(Path, "read_text",
                        lambda self, *a, **k: (record("read_text", self), real_read(self, *a, **k))[1])

    rc = setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                        "--skip-managed-settings"])
    monkeypatch.undo()
    assert rc == 0
    assert touches == [], f"skip mode touched the admin's file: {touches}"


def test_skip_managed_settings_preserves_a_symlinked_config(env):
    """The reported failure: a daily Jamf run turned the admin's symlink into a
    root-owned regular file and dropped the hook entries from the live config."""
    m = env["modules"]["claude-code"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    target = managed.parent / "org-managed-settings.json"
    target.write_text(json.dumps({
        "forceLoginOrgUUID": "org-uuid",
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": _cmd("claude-code", "PreToolUse")}]}]},
    }, indent=2))
    settings_path = managed / "managed-settings.json"
    settings_path.symlink_to(target)
    before = target.read_bytes()

    assert setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                          "--skip-managed-settings"]) == 0

    assert settings_path.is_symlink(), "the admin's link must survive the run"
    assert target.read_bytes() == before
    live = json.loads(settings_path.read_text())
    assert "PreToolUse" in live["hooks"], "the live config must keep enforcing"


def test_skip_managed_settings_keeps_python_era_script(env):
    """The stale-script sweep is skipped: a remote policy may still name it."""
    m = env["modules"]["claude-code"]
    script = m.get_managed_settings_dir() / "hooks" / "unbound.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# python-era hook\n")
    assert setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                          "--skip-managed-settings"]) == 0
    assert script.is_file(), "deleting it would strand a remote policy pointing here"


def test_default_run_still_removes_python_era_script(env):
    """Without the flag the sweep is unchanged."""
    m = env["modules"]["claude-code"]
    script = m.get_managed_settings_dir() / "hooks" / "unbound.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("# python-era hook\n")
    assert setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code"]) == 0
    assert not script.exists()
    assert (m.get_managed_settings_dir() / "managed-settings.json").exists()


def test_skip_managed_settings_prints_every_remote_policy_command(env, capsys):
    """The admin needs all six commands; the binary's differ per event."""
    setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                   "--skip-managed-settings"])
    out = capsys.readouterr().out
    for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop",
                  "SessionStart", "SessionEnd"):
        assert _cmd("claude-code", event) in out, f"{event} command not printed"


def test_non_skip_install_defers_on_a_symlinked_config(env, capsys):
    """End to end: root must neither replace the admin's link nor write through it,
    so the step defers loudly instead of reporting itself configured."""
    m = env["modules"]["claude-code"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    target = managed.parent / "org-managed-settings.json"
    target.write_text('{"forceLoginOrgUUID": "org-uuid"}')
    (managed / "managed-settings.json").symlink_to(target)

    setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code"])

    assert (managed / "managed-settings.json").is_symlink()
    assert json.loads(target.read_text()) == {"forceLoginOrgUUID": "org-uuid"}
    out = capsys.readouterr().out
    assert "deferred" in out


def test_atomic_write_refuses_a_symlinked_settings_file(tmp_path):
    """Replacing the link strands the admin's target; following it writes wherever
    it points, as root. Refused, leaving both the link and its target alone."""
    target = tmp_path / "org.json"
    target.write_text('{"owner":"org"}')
    link = tmp_path / "managed-settings.json"
    link.symlink_to(target)

    with pytest.raises(OSError):
        setup_cmd._atomic_write_text(link, '{"owner":"unbound"}')

    assert link.is_symlink()
    assert json.loads(target.read_text()) == {"owner": "org"}


def test_skip_managed_settings_reports_no_install_state(env):
    """install_state is derived from a settings file we do not own in this mode, so
    it is reported as unknown. notify_setup_complete omits the field entirely, which
    leaves the backend's tamper state untouched instead of counting every run."""
    m = env["modules"]["claude-code"]
    managed = m.get_managed_settings_dir()
    managed.mkdir(parents=True, exist_ok=True)
    # A file that would read as 'tampered' if anyone looked at it.
    (managed / "managed-settings.json").write_text(
        json.dumps({"permissions": {"deny": ["Bash"]}}))

    assert setup_cmd.run(["--api-key", "admin-key", "--tools", "claude-code",
                          "--skip-managed-settings"]) == 0

    reports = [k for _, k in env["notified"] if k.get("install_mode") == "binary-skip"]
    assert len(reports) == 1
    assert reports[0]["install_state"] is None


def test_binary_and_python_agree_on_a_hook_hash(env):
    """The binary reports the hash through the same vendored module the python path
    uses, so both must return the identical digest for identical bytes."""
    from unbound_hook._resources import hook_source_path
    for tool in ("claude-code", "cursor", "copilot", "codex", "augment"):
        source = hook_source_path(tool)
        digest = env["modules"][tool].hook_script_hash(source)
        assert len(digest) == 64 and digest == digest.lower()
        copy = source.parent / ("copy-" + source.name)
        try:
            copy.write_bytes(source.read_bytes())
            assert env["modules"][tool].hook_script_hash(copy) == digest
        finally:
            copy.unlink(missing_ok=True)


def test_skip_managed_settings_flag_is_accepted_by_the_parser(env):
    """The parser rejects unknown args outright, so the flag must be declared."""
    opts = setup_cmd._parse_args(["--api-key", "k", "--skip-managed-settings"])
    assert opts is not None and opts["skip_managed_settings"] is True
    assert setup_cmd._parse_args(["--api-key", "k"])["skip_managed_settings"] is False


# The discovery key is retired. Legacy Jamf policies still pass it to the binary,
# so every form must parse and be ignored — an unknown argument exits 2 and fails
# the whole enrollment.
@pytest.mark.parametrize("argv", [
    ["--api-key", "K", "--discovery-key", "STALE"],
    ["--api-key", "K", "--discovery-key"],
    ["--discovery-key", "--api-key", "K"],
    ["--discovery-key", "", "--api-key", "K"],
    ["--discovery-key", "STALE", "--api-key", "K", "--backfill"],
])
def test_setup_parses_and_ignores_a_stale_discovery_key(argv):
    opts = setup_cmd._parse_args(argv)
    assert opts is not None, "a stale --discovery-key must never be an unknown argument"
    assert opts["api_key"] == "K"
    assert "discovery_key" not in opts


def test_every_vendored_function_setup_cmd_calls_actually_exists():
    """setup_cmd drives the vendored modules by name, so a function renamed or
    removed on one of them is an AttributeError at install time and nothing here
    fails first. Reads the call sites out of the source rather than listing them,
    or the list drifts out of date exactly when it matters.

    Checked against the module each call site actually reaches where that is knowable:
    a function that does `m = _module("copilot")` is checked against copilot alone, so
    a name another tool happens to define cannot cover for it. Helpers that receive `m`
    as a parameter name no tool, and fall back to the union.
    """
    import ast

    source = Path(setup_cmd.__file__).with_suffix(".py").read_text(encoding="utf-8")

    def called_in(node):
        return {
            n.func.attr
            for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "m"
        }

    def tool_of(node):
        """The tool a function pins itself to via _module("<tool>"), if it does."""
        for n in ast.walk(node):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "_module" and n.args
                    and isinstance(n.args[0], ast.Constant)
                    and isinstance(n.args[0].value, str)):
                return n.args[0].value
        return None

    tree = ast.parse(source)
    modules = {}
    for tool in ("claude-code", "codex", "copilot", "cursor", "augment"):
        try:
            modules[tool] = load_mdm_setup_module(tool)
        except Exception:
            continue
    assert modules, "no vendored module loaded; the harness is broken, not the code"

    pinned, unpinned = {}, set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        names = called_in(node)
        if not names:
            continue
        tool = tool_of(node)
        if tool in modules:
            pinned.setdefault(tool, set()).update(names)
        else:
            unpinned |= names
    assert pinned, "no call site could be pinned to a tool; the extraction is broken"

    problems = []
    for tool, names in sorted(pinned.items()):
        missing = sorted(n for n in names if not hasattr(modules[tool], n))
        if missing:
            problems.append(f"{tool}: {missing}")
    # A helper takes `m` as a parameter and names no tool, so the union is all we know.
    orphans = sorted(n for n in unpinned if not any(hasattr(mod, n) for mod in modules.values()))
    if orphans:
        problems.append(f"defined by no vendored module: {orphans}")
    assert not problems, "setup_cmd calls functions its module does not define -> " + "; ".join(problems)
