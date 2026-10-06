"""Idempotent python→binary migration sweep (WEB-4788), run inside `setup`.

Removes every artifact of the python-era serving path that the binary
replaces, so old and new never run side by side:

  - per-user remote-fetch discovery LaunchAgents (ai.getunbound.scheduled and
    the legacy ai.getunbound.discovery label) — bootout from the gui/<uid>
    domain ONLY: the new pkg-owned system LaunchDaemon reuses the
    ai.getunbound.discovery label in the system domain and must survive
  - the scheduled-scan wrapper and the GitHub-fetched install.sh under
    ~/.local/share/unbound/
  - the system-domain ai.getunbound.coding-discovery daemon and a non-symlink
    /usr/local/bin/unbound-hook script shim
  - user-mode hook registrations pointing at the python scripts (each MDM
    module's own stripper runs FIRST, so a registration is never left
    dangling at a file this sweep already deleted), then the leftover
    unbound.py + .self_update_check/.self_update.lock files as a catch-all;
    copilot and codex are exceptions, see below

Deliberately NOT swept here — anything that is still the live serving path
until the per-tool setup adapter replaces it. Each adapter removes its own
python-era files immediately after its settings write succeeds, never
before, so a deferred component leaves python-era coverage intact:
  - the managed/system unbound.py copies (claude-code / codex / cursor
    adapters, after the managed-settings rewrite)
  - copilot's per-user unbound.json AND unbound.py (the copilot adapter,
    after writing the binary-era unbound.json — unbound.json IS copilot's
    registration, so sweeping it would unhook copilot on a deferral)
  - codex's per-user ~/.codex/hooks/unbound.py and its hooks.json entry —
    the binary install lives at the same path, so the codex adapter
    overwrites it in place; sweeping it made every run report tampered

Never touched: ~/.unbound/config.json (api key + urls survive migration).

Every action is existence-guarded delete-or-skip, so re-running on a clean,
half-installed, or previously-binary machine is a no-op for whatever is
already gone.
"""

import subprocess
import sys
from pathlib import Path

from ._loader import load_mdm_setup_module
from ._resources import TOOLS

LEGACY_AGENT_LABELS = ("ai.getunbound.scheduled", "ai.getunbound.discovery")

# Python-era system-domain discovery daemon and the script shim it replaced.
LEGACY_DAEMON_LABEL = "ai.getunbound.coding-discovery"
LEGACY_DAEMON_PLIST = Path("/Library/LaunchDaemons/ai.getunbound.coding-discovery.plist")
LEGACY_HOOK_SHIM = Path("/usr/local/bin/unbound-hook")

# Python-era files inside each user's tool hooks dir.
TOOL_USER_HOOKS_DIR = {
    "claude-code": ".claude/hooks",
    "cursor": ".cursor/hooks",
    "copilot": ".copilot/hooks",
    "codex": ".codex/hooks",
    "augment": ".augment/hooks",
}
STALE_HOOK_FILES = ("unbound.py", ".self_update_check", ".self_update.lock")
# Tools whose adapter rewrites the user-level hook in place: copilot replaces
# unbound.py after writing unbound.json, and codex's binary install IS
# ~/.codex/hooks/unbound.py + its hooks.json entry. The sweep must not strip
# either, or every setup run sees the hook missing and reports codex tampered.
IN_PLACE_TOOLS = ("copilot", "codex")
SELF_UPDATE_FILES = (".self_update_check", ".self_update.lock")

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


def _bootout_legacy_daemon(log) -> bool:
    """True once the daemon is no longer loaded; `launchctl print` exits 0 only for a loaded job."""
    target = f"system/{LEGACY_DAEMON_LABEL}"
    try:
        subprocess.run(["launchctl", "bootout", target], capture_output=True, timeout=10)
        loaded = subprocess.run(["launchctl", "print", target],
                                capture_output=True, timeout=10).returncode == 0
    except Exception as e:
        log(f"[migration] bootout {LEGACY_DAEMON_LABEL}: {e}")
        return False
    if loaded:
        log(f"[migration] {LEGACY_DAEMON_LABEL} still loaded after bootout")
    return not loaded


def _sweep_system(log) -> bool:
    """Remove python-era system-level leftovers; a symlinked shim is not ours to delete."""
    ok = sys.platform != "darwin" or _bootout_legacy_daemon(log)
    for path in (LEGACY_DAEMON_PLIST, LEGACY_HOOK_SHIM):
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
                log(f"[migration] removed {path}")
        except OSError as e:
            log(f"[migration] could not remove {path}: {e}")
            ok = False
    return ok


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
        names = SELF_UPDATE_FILES if tool in IN_PLACE_TOOLS else STALE_HOOK_FILES
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
            "augment": load_mdm_setup_module("augment").remove_user_level_hooks_for_user,
            # copilot and codex are IN_PLACE_TOOLS: their user-level hook is
            # the current install (clear_setup removes it on uninstall)
        }

        failed_users = [] if _sweep_system(log) else ["system"]
        for username, home in m.get_all_user_homes():
            try:
                uid = pwd.getpwnam(username).pw_uid
            except KeyError:
                continue
            # Isolate each user: one user's locked/corrupt home must not
            # abort the sweep for everyone after them. Failures are logged
            # loudly and surfaced via 'deferred' so a re-run retries.
            try:
                _bootout_legacy_agents(username, uid, home, log)
                # Strip registrations BEFORE deleting the scripts they point
                # at — the strippers intentionally keep a script in place
                # when the settings cleanup fails, and deleting first would
                # defeat that.
                for tool in tools:
                    stripper = strippers.get(tool)
                    if stripper:
                        stripper(username, home)
                removed = m._run_as_user(username, _sweep_user_home, str(home), tools)
                for path in removed or []:
                    log(f"[migration] removed {path}")
            except Exception as e:
                log(f"[migration] sweep failed for user {username}: {e}")
                failed_users.append(username)
            # NOTE: ~/.unbound/config.json is deliberately never touched.

        if failed_users:
            return ("deferred", f"sweep failed for user(s): {', '.join(failed_users)}")
        return ("configured", None)
    except Exception as e:
        return ("deferred", f"migration sweep error: {e}")
