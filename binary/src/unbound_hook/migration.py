"""Idempotent python→binary migration sweep (WEB-4788), run inside `setup`.

Removes every artifact of the python-era serving path that the binary
replaces, so old and new never run side by side:

  - per-user remote-fetch discovery LaunchAgents (ai.getunbound.scheduled and
    the legacy ai.getunbound.discovery label) — bootout from the gui/<uid>
    domain ONLY: the new pkg-owned system LaunchDaemon reuses the
    ai.getunbound.discovery label in the system domain and must survive
  - the scheduled-scan wrapper and the GitHub-fetched install.sh under
    ~/.local/share/unbound/
  - user-mode hook registrations pointing at the python scripts (each MDM
    module's own stripper runs FIRST, so a registration is never left
    dangling at a file this sweep already deleted), then the leftover
    unbound.py + .self_update_check/.self_update.lock files as a catch-all

Deliberately NOT swept here — anything that is still the live serving path
until the per-tool setup adapter replaces it. Each adapter removes its own
python-era files immediately after its settings write succeeds, never
before, so a deferred component leaves python-era coverage intact:
  - the managed/system unbound.py copies (claude-code / codex / cursor
    adapters, after the managed-settings rewrite)
  - copilot's per-user unbound.json AND unbound.py (the copilot adapter,
    after writing the binary-era unbound.json — unbound.json IS copilot's
    registration, so sweeping it would unhook copilot on a deferral)

Never touched: ~/.unbound/config.json (api key + urls survive migration).

Every action is existence-guarded delete-or-skip, so re-running on a clean,
half-installed, or previously-binary machine is a no-op for whatever is
already gone.
"""

import subprocess
from pathlib import Path

from ._loader import load_mdm_setup_module
from ._resources import TOOLS

LEGACY_AGENT_LABELS = ("ai.getunbound.scheduled", "ai.getunbound.discovery")

# Python-era files inside each user's tool hooks dir.
TOOL_USER_HOOKS_DIR = {
    "claude-code": ".claude/hooks",
    "cursor": ".cursor/hooks",
    "copilot": ".copilot/hooks",
    "codex": ".codex/hooks",
}
STALE_HOOK_FILES = ("unbound.py", ".self_update_check", ".self_update.lock")
# Copilot's serving path (unbound.py, referenced by unbound.json) is replaced
# by its adapter post-write; the sweep only clears its self-update state.
COPILOT_SWEEP_FILES = (".self_update_check", ".self_update.lock")

# Remote-fetch artifacts under ~/.local/share/unbound/.
REMOTE_FETCH_FILES = ("install.sh", "run-scheduled.sh")


def _bootout_legacy_agents(username: str, uid: int, home: Path, log) -> None:
    """Unload the per-user remote-fetch discovery LaunchAgents (gui domain
    only). Plist removal happens privilege-dropped in _sweep_user_home."""
    for label in LEGACY_AGENT_LABELS:
        try:
            subprocess.run(
                ["launchctl", "bootout", f"gui/{uid}/{label}"],
                capture_output=True, timeout=10,
            )
        except Exception as e:
            log(f"[migration] bootout {label} for {username}: {e}")


def _sweep_user_home(home_str: str, tools) -> list:
    """Delete python-era files in one user's home. Runs privilege-dropped
    (via the MDM module's _run_as_user), so symlink games can't redirect
    deletes at root-owned paths. Returns the paths removed."""
    home = Path(home_str)
    removed = []
    candidates = []
    for label in LEGACY_AGENT_LABELS:
        candidates.append(home / "Library" / "LaunchAgents" / f"{label}.plist")
    for name in REMOTE_FETCH_FILES:
        candidates.append(home / ".local" / "share" / "unbound" / name)
    for tool in tools:
        hooks_dir = TOOL_USER_HOOKS_DIR[tool]
        names = COPILOT_SWEEP_FILES if tool == "copilot" else STALE_HOOK_FILES
        for name in names:
            candidates.append(home / hooks_dir / name)
    for path in candidates:
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
                removed.append(str(path))
        except OSError:
            continue
    return removed


def run_sweep(tools=TOOLS, log=print) -> tuple:
    """Run the full sweep for the given tools (LaunchAgents and remote-fetch
    artifacts are tool-agnostic and always swept). Returns (status, reason)
    in the setup status vocabulary: ('configured', None) on success,
    ('deferred', reason) when something went wrong and a re-run should retry."""
    try:
        import pwd
    except ImportError:  # Windows — python-era Windows installs keep the python path
        return ("skipped", "migration sweep is mac/linux only")

    tools = [t for t in tools if t in TOOL_USER_HOOKS_DIR]
    try:
        m = load_mdm_setup_module("claude-code")  # shared primitives
        strippers = {
            "claude-code": m.remove_user_level_hooks_for_user,
            "cursor": load_mdm_setup_module("cursor").remove_user_level_hooks,
            "codex": load_mdm_setup_module("codex").remove_user_level_hooks_for_user,
            # copilot has no separate user-mode registration store beyond
            # unbound.json, handled inside _sweep_user_home
        }

        for username, home in m.get_all_user_homes():
            try:
                uid = pwd.getpwnam(username).pw_uid
            except KeyError:
                continue
            _bootout_legacy_agents(username, uid, home, log)
            # Strip registrations BEFORE deleting the scripts they point at —
            # the strippers intentionally keep a script in place when the
            # settings cleanup fails, and deleting first would defeat that.
            for tool in tools:
                stripper = strippers.get(tool)
                if stripper:
                    stripper(username, home)
            removed = m._run_as_user(username, _sweep_user_home, str(home), tools)
            for path in removed or []:
                log(f"[migration] removed {path}")
            # NOTE: ~/.unbound/config.json is deliberately never touched.

        return ("configured", None)
    except Exception as e:
        return ("deferred", f"migration sweep error: {e}")
