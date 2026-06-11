"""Idempotent python→binary migration sweep (WEB-4788), run inside `setup`.

Removes every artifact of the python-era serving path that the binary
replaces, so old and new never run side by side:

  - per-user remote-fetch discovery LaunchAgents (ai.getunbound.scheduled and
    the legacy ai.getunbound.discovery label) — bootout from the gui/<uid>
    domain ONLY: the new pkg-owned system LaunchDaemon reuses the
    ai.getunbound.discovery label in the system domain and must survive
  - the scheduled-scan wrapper and the GitHub-fetched install.sh under
    ~/.local/share/unbound/
  - stale unbound.py copies + .self_update_check/.self_update.lock in each
    tool's user hooks dir, and the managed (system) unbound.py copies
  - user-mode hook registrations pointing at the python scripts (via each
    MDM module's own strip functions)

Never touched: ~/.unbound/config.json (api key + urls survive migration).

Every action is existence-guarded delete-or-skip, so re-running on a clean,
half-installed, or previously-binary machine is a no-op for whatever is
already gone.
"""

import subprocess
from pathlib import Path

from ._loader import load_mdm_setup_module

LEGACY_AGENT_LABELS = ("ai.getunbound.scheduled", "ai.getunbound.discovery")

# Python-era files inside each user's tool hooks dir.
USER_HOOKS_DIRS = (".claude/hooks", ".cursor/hooks", ".copilot/hooks", ".codex/hooks")
STALE_HOOK_FILES = ("unbound.py", ".self_update_check", ".self_update.lock")

# Remote-fetch artifacts under ~/.local/share/unbound/.
REMOTE_FETCH_FILES = ("install.sh", "run-scheduled.sh")

# Managed (system-scope) python hook scripts the binary obsoletes.
MANAGED_STALE_SCRIPTS = (
    Path("/Library/Application Support/ClaudeCode/hooks/unbound.py"),
    Path("/Library/Application Support/Codex/hooks/unbound.py"),
    Path("/Library/Application Support/Cursor/hooks/unbound.py"),
)


def _bootout_legacy_agents(username: str, uid: int, home: Path, log) -> None:
    """Unload + delete the per-user remote-fetch discovery LaunchAgents."""
    for label in LEGACY_AGENT_LABELS:
        try:
            subprocess.run(
                ["launchctl", "bootout", f"gui/{uid}/{label}"],
                capture_output=True, timeout=10,
            )
        except Exception as e:
            log(f"[migration] bootout {label} for {username}: {e}")
    # plist removal happens privilege-dropped in _sweep_user_home


def _sweep_user_home(home_str: str) -> list:
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
    for hooks_dir in USER_HOOKS_DIRS:
        for name in STALE_HOOK_FILES:
            candidates.append(home / hooks_dir / name)
    for path in candidates:
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
                removed.append(str(path))
        except OSError:
            continue
    return removed


def run_sweep(log=print) -> tuple:
    """Run the full sweep. Returns (status, reason) in the setup status
    vocabulary: ('configured', None) on success, ('deferred', reason) when
    something went wrong and a re-run should retry."""
    try:
        import pwd
    except ImportError:  # Windows — python-era Windows installs keep the python path
        return ("skipped", "migration sweep is mac/linux only")

    try:
        m = load_mdm_setup_module("claude-code")  # shared primitives
        cursor_m = load_mdm_setup_module("cursor")
        codex_m = load_mdm_setup_module("codex")

        for username, home in m.get_all_user_homes():
            try:
                uid = pwd.getpwnam(username).pw_uid
            except KeyError:
                continue
            _bootout_legacy_agents(username, uid, home, log)
            removed = m._run_as_user(username, _sweep_user_home, str(home))
            for path in removed or []:
                log(f"[migration] removed {path}")
            # Strip user-mode hook registrations pointing at python scripts.
            # Each module's own stripper only removes entries referencing its
            # unbound.py, so user-authored hooks survive.
            m.remove_user_level_hooks_for_user(username, home)
            cursor_m.remove_user_level_hooks(username, home)
            codex_m.remove_user_level_hooks_for_user(username, home)
            # NOTE: ~/.unbound/config.json is deliberately never touched.

        for script in MANAGED_STALE_SCRIPTS:
            try:
                if script.is_file():
                    script.unlink()
                    log(f"[migration] removed {script}")
                parent = script.parent
                if parent.name == "hooks" and parent.is_dir() and not any(parent.iterdir()):
                    parent.rmdir()
            except OSError as e:
                log(f"[migration] could not remove {script}: {e}")

        return ("configured", None)
    except Exception as e:
        return ("deferred", f"migration sweep error: {e}")
