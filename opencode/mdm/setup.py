#!/usr/bin/env python3
"""Install the Unbound plugin for opencode for EVERY user on this device.

Run as root, once per device, from an MDM (Jamf and friends):

    sudo python3 setup.py --api-key <admin key> [--backend-url <url>] [--gateway-url <url>]
    sudo python3 setup.py --clear

What lands on disk, per enumerated user: `<home>/.config/opencode/plugins/unbound.js`, mode
0644, owned by that user, plus a sibling `unbound.js.sha256` so an operator can verify it by
hand. opencode loads every `*.{js,ts}` in that directory as a plugin, so no opencode config
file is written. Per home, the same two rules as the per-user installer also run: stray
Unbound copies that would load twice (`plugin/unbound.js`, `plugins/unbound.ts`,
`plugin/unbound.ts`) are removed when recognised as Unbound's, and `plugins/package.json` =
{"type":"module"} is created only when absent and no other plugin lives there (tracked in
`plugins/.unbound-installed.json` so --clear removes only what we created). The key is placed
where the plugin looks for it: an `export UNBOUND_OPENCODE_API_KEY=...` line in that user's
shell rc files, and `api_key` in that user's `~/.unbound/config.json` -- the latter ONLY when
it is absent or is the key this installer wrote (see below).

Writing into another user's home as root is the dangerous part of this script, so every
in-home write goes through three primitives, unchanged from `pi/mdm/setup.py` (ported there
from `augment/hooks/mdm/setup.py`):

  1. `_run_as_user` -- fork, then setgroups/setgid/setuid before touching anything. After
     the drop, a symlink in the home pointing at a root-only path fails with EACCES all by
     itself instead of handing root's authority to whoever planted it.
  2. `_repair_user_ownership` -- walks the path one component at a time, each opened
     O_NOFOLLOW relative to the previous component's descriptor (openat) and anchored at the
     passwd home, so a symlinked PARENT cannot redirect the repair out of the home. It then
     fchowns the resulting DESCRIPTOR, so the inode inspected is the inode chowned. A regular
     file carrying extra hard links (st_nlink != 1) is refused outright. Directories are
     reclaimed only when root- or self-owned, and the home directory itself is never touched.
  3. The drop itself refuses a symlinked `unbound.js` and opens its temp with O_NOFOLLOW,
     and the stray/ESM rules run per home with privileges dropped.

Two deliberate divergences from the Augment analog, both called out at the code:

  * `config.json`'s `api_key` is not assigned unconditionally. That file is the shared
    identity store for unbound-cli and other tools; overwriting a key the user minted with
    `unbound login` would silently repoint all of them at this device key. It IS replaced
    when this installer is the one that wrote it -- recognised by an
    `opencode_mdm_api_key_sha256` digest recorded beside it -- or a revoked key would survive
    every later push in the one tier the GUI-launched desktop app reads.
  * an `export` line is only written after `_is_safe_env_value()` passes, because an rc file
    is a shell script and an unvalidated value in it is command injection. The rc file is
    also published with its group and other bits stripped: the line holds a plaintext key.

About the sha256 sidecar: `opencode/index.js.sha256` is fetched from the same origin, over the
same TLS, from the same ref as the artifact itself. It catches a truncated or corrupt
download and a stale-vs-fresh mismatch, and it gives the backend an honest `hook_hash`. It
is NOT a supply-chain control -- anyone who could replace the artifact could replace the
sidecar in the same commit.

LIMITATION, stated up front: opencode does have managed config, but this baseline does not
use it. `opencode --pure`, `OPENCODE_PURE=1`, or a redirected `XDG_CONFIG_HOME` /
`OPENCODE_CONFIG_DIR` / `HOME` still start opencode without any plugin, and nothing in this
script can prevent that. Root cannot read a user's `OPENCODE_CONFIG_DIR` or
`XDG_CONFIG_HOME`, so this installer covers the default `~/.config/opencode` per home only.
This is advisory control over a machine whose user may administer it, not tamper resistance.
See `opencode/mdm/README.md`.
"""

import hashlib
import json
import os
import platform
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import pwd
except ImportError:  # Windows has no pwd; every user of it below is branch-guarded.
    pwd = None


# Same host and ref as every other artifact this repo fetches (unbound-cli setup.js:14).
# The sidecar is derived from the artifact URL so the two can never point at different refs.
ARTIFACT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/opencode/index.js"
SHA_URL = ARTIFACT_URL + ".sha256"

DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

# Spreads a fleet-wide MDM push so a thousand devices' retries do not re-synchronise.
MDM_RETRY_JITTER_SECONDS = 30

# hooks-ts/packages/opencode/src/constants.ts XDG_CONFIG_DEFAULT_SEGMENTS + OPENCODE_DIR_NAME.
CONFIG_DIR_SEGMENTS = (".config", "opencode")
PLUGIN_DIRNAME = "plugins"
PLUGIN_NAME = "unbound.js"
SIDECAR_NAME = "unbound.js.sha256"
MARKER_NAME = ".unbound-installed.json"

# The plugin's tier-1 key source. opencode-specific by design: writing the generic
# UNBOUND_API_KEY instead would hand this device key to every other tool.
ENV_API_KEY = "UNBOUND_OPENCODE_API_KEY"

# How this installer remembers which `api_key` in the shared config.json is its own, so a
# rotation can replace the value it wrote without ever touching one the user manages. A
# digest, not the key. Read by nothing else -- the other tools ignore extra fields.
MDM_KEY_PROVENANCE_FIELD = "opencode_mdm_api_key_sha256"

# Home enumeration, per platform -- pi's values, lifted into constants so the test suite
# can point them at a tmp tree instead of asserting against the machine it runs on.
MACOS_HOME_PREFIX = '/Users/'
LINUX_HOME_PREFIX = '/home/'
MACOS_UID_FLOOR = 500          # first real macOS account; 0-499 are system accounts
LINUX_UID_FLOOR = 1000         # Debian/RH convention for the first human user
MACOS_SKIP_USERS = ("Shared", "Guest")
WINDOWS_USERS_DIRNAME = "Users"
WINDOWS_SKIP_PROFILES = ("Public", "Default", "Default User", "Administrator", "All Users")

# Older or hand-placed Unbound copies opencode would load BESIDE ours (it globs *.{js,ts}
# in `plugins/` and the legacy `plugin/`). Only banner-recognised regular files are removed.
STRAY_RELPATHS = (("plugin", "unbound.js"), ("plugins", "unbound.ts"), ("plugin", "unbound.ts"))
UNBOUND_BUNDLE_MARKER = b"unbound-hooks-ts"
BANNER_SCAN_BYTES = 4096
PLUGIN_SUFFIXES = (".js", ".ts")
ESM_PACKAGE_JSON = {"type": "module"}

# Shown in the closing notes until the v2 plugin line enforces (Phase 14).
V2_STATUS_NOTE = "OpenCode 2.x: the plugin loads but does not block yet."

# Exactly the files this installer always writes; package.json is added only when the
# marker says this installer created it.
INSTALLED_NAMES = (PLUGIN_NAME, SIDECAR_NAME)

# Marks a publish-by-rename temp. The full name adds a pid and random bytes -- see
# _unique_tmp_path -- so two concurrent writers can never share one temp file.
TMP_MARKER = ".unbound-tmp"

# bash reads only the FIRST of these that exists, in this order (bash(1), INVOCATION). The
# order is load-bearing: creating an earlier one shadows a later one the user relies on.
BASH_LOGIN_FILES = (".bash_profile", ".bash_login", ".profile")

# The charset an env value may contain before it is written into a shell rc file. An rc file
# is executed by the user's login shell, so anything outside this set -- a quote, a $, a
# backtick, a semicolon, a newline -- would be code rather than data. Real API keys are
# base64url/hex-ish, so this is not a restriction in practice.
SAFE_ENV_VALUE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
MAX_ENV_VALUE_LEN = 512

DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(domain: str) -> str:
    """Accept a bare host or a full URL and return a scheme-qualified, unslashed base."""
    if not domain:
        return domain
    domain = domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"
    return url.rstrip('/')


def _stdout_never_raises() -> None:
    """MDM gives this a non-console pipe, which on Windows defaults to cp1252 and raises
    UnicodeEncodeError on the first status line containing a check mark. Both streams are
    reconfigured: a traceback on stderr is as fatal to a Jamf policy as one on stdout."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def curl_with_auth(auth_headers, curl_args, *, input=None, text: bool = False,
                   timeout: int = 30):
    """Run curl with the secret auth header(s) kept OFF the argv.

    On a multi-user host the curl argv is world-readable through `ps` and
    /proc/<pid>/cmdline, so passing `Authorization: Bearer <key>` as `-H "<header>"` would
    leak it -- including the PRIVILEGED admin key this script is handed. Write the header
    line(s) to a 0600 temp file and pass `-H @<tmpfile>`, deleting it in a finally. Returns
    the CompletedProcess, or None if the header file could not be written.
    """
    fd, tmp_path = tempfile.mkstemp(prefix=".curlhdr.", suffix=".txt")
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(auth_headers) + "\n")
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return None
        cmd = ["curl", *curl_args, "-H", f"@{tmp_path}"]
        return subprocess.run(cmd, input=input, capture_output=True, text=text,
                              timeout=timeout)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _run_as_user(username, fn, *args, **kwargs):
    """Fork and execute fn(*args, **kwargs) as the unprivileged user `username`.
    Returns whatever fn returns on success, or None on failure.

    Security-critical primitive: every MDM op that writes inside a user's home must go
    through it. File ops run as root against paths the user controls invite
    symlink-following privilege escalation; after the drop, such a symlink fails with
    EACCES on its own. setgroups/setgid come BEFORE setuid -- the other order leaves the
    child in root's supplementary groups because setuid drops the ability to change them.

    On Windows (no fork, single-user MDM context) executes fn directly.
    """
    if platform.system().lower() == "windows":
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None
    if pwd is None:
        return None
    try:
        info = pwd.getpwnam(username)
    except KeyError:
        return None
    uid, gid = info.pw_uid, info.pw_gid

    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            # setuid alone leaves $HOME pointing at root's home, so a Path.home() inside fn
            # would resolve to the wrong home. Callers pass an explicit home today; this
            # keeps the env consistent with the dropped uid regardless.
            os.environ['HOME'] = info.pw_dir
            result = fn(*args, **kwargs)
            # json, and deliberately nothing that can execute on decode. This pipe crosses a
            # privilege boundary in the dangerous direction: the writer has already dropped
            # to the unprivileged user and the reader is still root, so a decoder that can
            # construct objects would turn any influence over these bytes into code
            # execution as root on every managed device. json is data-only, and every value
            # that crosses here is a status string, a bool, None, or a short list of those.
            # (The stdlib module this deliberately avoids is not named anywhere in this file:
            # naming it keeps semgrep's rule for it firing on the mitigation comment itself.
            # See PR #352 for the review thread.)
            os.write(w_fd, json.dumps(result).encode('utf-8'))
            os.close(w_fd)
            os._exit(0)
        except Exception:
            try:
                os.close(w_fd)
            except OSError:
                pass
            os._exit(1)
    else:
        os.close(w_fd)
        data = b''
        while True:
            try:
                chunk = os.read(r_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        os.close(r_fd)
        try:
            _, status = os.waitpid(pid, 0)
        except OSError:
            return None
        if os.WEXITSTATUS(status) != 0:
            return None
        if not data:
            return None
        try:
            result = json.loads(data.decode('utf-8'))
        except Exception:
            return None
        # Check the shape before use rather than trusting whatever crossed the boundary.
        # Callers return a status string, a bool, None, or a small list of those -- anything
        # else is a failure rather than something to pass along. NOTE a tuple becomes a
        # list across json; the one caller that returns a pair unpacks either identically.
        if result is None or isinstance(result, (str, bool, list)):
            return result
        debug_print(f"Unexpected result shape across the privilege drop: {type(result)}")
        return None


def check_admin_privileges() -> bool:
    """True only when this process can actually write into another user's home."""
    try:
        system = platform.system().lower()
        if system in ("darwin", "linux"):
            return os.geteuid() == 0
        if system == "windows":
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


def get_device_identifier() -> Optional[str]:
    """The device serial the backend keys this report on. None when it cannot be read."""
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IOPlatformSerialNumber' in line:
                        parts = line.split('=')
                        if len(parts) >= 2:
                            serial = parts[1].strip().strip('"').strip()
                            if serial:
                                return serial
            return None

        if system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True, text=True, timeout=10, stderr=subprocess.DEVNULL,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                debug_print("dmidecode failed, trying machine-id")
            for machine_id_path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
                try:
                    with open(machine_id_path, 'r', encoding='utf-8') as f:
                        device_id = f.read().strip()
                        if device_id:
                            return device_id
                except Exception:
                    continue
            try:
                result = subprocess.run(["hostname"], capture_output=True, text=True,
                                        timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                pass
            return None

        if system == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except Exception:
                debug_print("PowerShell BIOS query failed, trying registry MachineGuid")
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return value
            except Exception as e:
                debug_print(f"Registry MachineGuid read failed: {e}")
            return None

        return None
    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


def get_all_user_homes() -> List[Tuple[str, Path]]:
    """Every real human user on this device, as (username, home). Never raises.

    The rules are the analog's (augment/hooks/mdm/setup.py:356-398): a uid floor, a home
    prefix, and a per-platform skip list. Anything that fails -- a broken directory service,
    no `pwd` module, an unrecognised platform -- yields an empty list, because a raise here
    would abort the device run before a single home was considered.
    """
    user_homes: List[Tuple[str, Path]] = []
    system = platform.system().lower()

    try:
        if system == "darwin":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                if uid >= MACOS_UID_FLOOR and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith(MACOS_HOME_PREFIX) \
                            and username not in MACOS_SKIP_USERS:
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "linux":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                # No Shared/Guest skip here: on Linux a user with either name is a real one.
                if uid >= LINUX_UID_FLOOR and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith(LINUX_HOME_PREFIX):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "windows":
            # No pwd here, so the profile directories under %SystemDrive%\Users ARE the
            # list. os.sep rather than a literal backslash so this stays exercisable from a
            # POSIX test runner; on Windows os.sep is the backslash the analog hardcodes.
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(system_drive + os.sep + WINDOWS_USERS_DIRNAME)
            if users_dir.exists():
                try:
                    for user_dir in sorted(users_dir.iterdir()):
                        if user_dir.is_dir() and user_dir.name not in WINDOWS_SKIP_PROFILES:
                            user_homes.append((user_dir.name, user_dir))
                            debug_print(f"Found user: {user_dir.name} -> {user_dir}")
                except Exception as e:
                    debug_print(f"Error scanning the Windows users directory: {e}")

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def _unique_tmp_path(target: Path) -> Path:
    """A temp name beside `target` that belongs to this writer alone.

    One shared `<name>.unbound-tmp`, unlinked before every open, was a lost-update race with
    a silent wrong answer: writer B unlinks A's open temp, creates its own at the same name,
    and A's `os.replace` then publishes B's half-written file over the destination and
    reports success. An MDM push landing while that user runs `unbound setup opencode` is the
    reachable version -- both write `~/.unbound/config.json`. With the pid and four random
    bytes in the name, O_EXCL means what it says and the failure path unlinks only our own.
    """
    return target.with_name(f"{target.name}{TMP_MARKER}.{os.getpid()}.{os.urandom(4).hex()}")


def _unlink_legacy_tmp(target: Path) -> None:
    """Remove the pre-unique fixed-name temp an older killed run could have left behind.

    Safe to unlink unconditionally because no writer creates this exact name any more, so it
    can only be debris -- and unlike globbing the unique names, it can never take out a live
    writer's temp file.
    """
    try:
        os.unlink(str(target.with_name(target.name + TMP_MARKER)))
    except OSError:
        pass


def _relative_parts(base: Path, path) -> List[str]:
    """The path components of `path` strictly below `base`, or [] when it is not below it.

    Lexical on purpose. Resolving the path first is exactly what re-opens the escape this
    exists to close: the caller walks these components one at a time with O_NOFOLLOW, so a
    symlink among them is refused at open time rather than silently followed here.
    """
    try:
        parts = Path(path).relative_to(base).parts
    except (ValueError, TypeError):
        return []
    if any(part in ("", os.curdir, os.pardir) for part in parts):
        return []
    return list(parts)


def _open_below(base_fd: int, parts: List[str], flags: int, o_directory: int) -> Optional[int]:
    """A descriptor for `base_fd`/`parts`, opening EVERY component with O_NOFOLLOW (openat).

    Each component is opened relative to the descriptor of the one before it, so a symlink
    anywhere along the way is an ELOOP that ends the walk -- there is no path string for the
    kernel to re-resolve. Every component but the last must be a real directory, verified on
    the fstat as well as with O_DIRECTORY, because O_DIRECTORY is not guaranteed to exist.
    Returns None on any refusal, and closes every descriptor it opened except the one it
    hands back.
    """
    fd = os.dup(base_fd)  # dup so walking can close as it goes without closing the anchor
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            nxt = os.open(part, flags if last else flags | o_directory, dir_fd=fd)
            os.close(fd)
            fd = nxt
            if not last and not stat.S_ISDIR(os.fstat(fd).st_mode):
                return None
        opened, fd = fd, None
        return opened
    except OSError:
        return None  # missing, a symlink (ELOOP), a fifo, not a directory, or no access
    finally:
        if fd is not None:
            os.close(fd)


def _repair_user_ownership(username: str, base, paths: List[Path]) -> None:
    """Root-context best-effort: hand back any of `paths` a previous root run left owned by
    the wrong uid, so the upcoming privilege-dropped write does not fail EACCES.

    This runs as root against paths the user controls, so it is hardened against local
    escalation -- and the hardening is on EVERY path component, not just the last one.
    O_NOFOLLOW on a full path only ever protected the final component: with
    `~/.config/opencode` replaced by a symlink to `/etc`, opening
    `~/.config/opencode/plugins` follows that link without complaint and root hands
    `/etc/plugins` to the user. So each component is opened separately, O_NOFOLLOW, relative
    to the descriptor of the component before it, starting from `base` -- the account's home
    out of the passwd database, which is root's own configuration rather than anything the
    user can retarget. A symlink, a non-directory or a missing component anywhere along the
    way simply ends that path's repair.

    `base` itself is NEVER chowned. Home ownership is deliberately root-owned on real
    accounts (an sshd ChrootDirectory, an admin-locked kiosk account), changing it breaks
    those logins, and nothing this installer writes needs it: if `~/.config` cannot be created,
    the privilege-dropped write should just fail for that user.

    The inode inspected is the inode chowned -- fchown on the descriptor -- so there is no
    path TOCTOU. A regular file with extra hard links (st_nlink != 1) is refused: a hard link
    to a sensitive root-owned file planted at our target path would otherwise be given away.
    Directories are reclaimed ONLY when root- or self-owned; a directory owned by some other
    non-root user is left alone, because handing it over would be an over-reach rather than a
    repair. No-op on Windows or without pwd; only fires on the abnormal uid-mismatch case;
    never raises.
    """
    if platform.system().lower() == "windows" or pwd is None:
        return
    o_nofollow = getattr(os, "O_NOFOLLOW", None)
    if o_nofollow is None:
        return  # cannot open safely without the symlink guard -- skip, never degrade it
    if os.open not in getattr(os, "supports_dir_fd", ()):
        return  # no openat, so no way to pin a component to its parent -- skip
    try:
        info = pwd.getpwnam(username)
    except KeyError:
        return
    uid, gid = info.pw_uid, info.pw_gid
    base = Path(base)
    if not base.is_absolute():
        return
    o_directory = getattr(os, "O_DIRECTORY", 0)
    o_nonblock = getattr(os, "O_NONBLOCK", 0)
    walk_flags = os.O_RDONLY | o_nofollow | o_nonblock
    try:
        # The anchor is opened by path, following symlinks: it is the passwd home, which is
        # root's configuration. Nothing below it is followed.
        base_fd = os.open(str(base), os.O_RDONLY | o_nonblock | o_directory)
    except OSError as e:
        debug_print(f"_repair_user_ownership: no anchor directory at {base}: {e}")
        return
    try:
        for path in paths:
            parts = _relative_parts(base, path)
            if not parts:
                continue  # the anchor itself, or outside it -- neither is ours to repair
            fd = _open_below(base_fd, parts, walk_flags, o_directory)
            if fd is None:
                continue
            try:
                st = os.fstat(fd)
                if stat.S_ISDIR(st.st_mode):
                    if st.st_uid != uid and st.st_uid in (0, uid):
                        os.fchown(fd, uid, gid)
                elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                    if st.st_uid != uid:
                        os.fchown(fd, uid, gid)
            except OSError as e:
                debug_print(f"_repair_user_ownership: could not chown {path}: {e}")
            finally:
                os.close(fd)
    finally:
        os.close(base_fd)


# --- the artifact ------------------------------------------------------------------------


def download_file(url: str, dest_path) -> bool:
    """curl one URL to one path. Returns False on any failure and never raises."""
    dest_path = Path(dest_path)
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(["curl", "-fsSL", "-o", str(dest_path), url],
                                capture_output=True, timeout=30)
        return result.returncode == 0
    except Exception as e:
        # A missing curl or a timed-out fetch is a refusal, not a traceback.
        print(f"❌ Failed to download {url}: {e}")
        return False


def artifact_sha256(path) -> Optional[str]:
    """sha256 of the bytes on disk, or None when the file is missing or unreadable.

    Deliberately NOT named hook_script_hash: tests/test_setup_contract.py asserts exactly
    10 installers define that name, and opencode ships no unbound.py hook script -- what
    is hashed here is the plugin bundle itself.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def parse_sha256_sidecar(text) -> Optional[str]:
    """The digest out of a `shasum -a 256` line, or None if this is not one.

    Accepts a bare 64-hex line and the two-field `<digest>  <file>` form (including the `*`
    binary-mode marker). The filename column is not checked: the committed sidecar names
    `opencode/index.js` and the local one `unbound.js`. Anything else -- empty, wrong length,
    non-hex, extra fields -- returns None, which every caller turns into a refusal.
    """
    if not isinstance(text, str):
        return None
    tokens = text.strip().split()
    if not tokens or len(tokens) > 2:
        return None
    digest = tokens[0].strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return None
    return digest


def verify_artifact(path, sidecar_text) -> Tuple[bool, Optional[str], Optional[str]]:
    """(ok, computed, expected) -- both digests come back so the caller can name them."""
    expected = parse_sha256_sidecar(sidecar_text)
    computed = artifact_sha256(path)
    ok = bool(expected) and bool(computed) and expected == computed
    return ok, computed, expected


def fetch_artifact() -> Optional[Tuple[bytes, str]]:
    """Download and verify the plugin ONCE for the whole device. (payload, digest) or None.

    Once, before the home loop, deliberately: a per-home download would give a corrupt or
    mid-publish artifact N chances to reach one user and not another, and would multiply a
    fleet-wide push by the number of accounts on each device. A failure here refuses the
    whole run, so a bad artifact reaches zero homes rather than all of them.
    """
    staging = None
    try:
        # 0700 and root-owned, so a partly-downloaded artifact is never readable by the
        # users we are about to install for.
        staging = tempfile.mkdtemp(prefix=".unbound-opencode-mdm.")
        try:
            os.chmod(staging, 0o700)
        except OSError as e:
            debug_print(f"Could not tighten the staging dir: {e}")
        staged = Path(staging) / PLUGIN_NAME
        staged_sidecar = Path(staging) / SIDECAR_NAME

        if not download_file(ARTIFACT_URL, staged):
            print(f"❌ Could not download the opencode plugin from {ARTIFACT_URL}")
            return None
        if not download_file(SHA_URL, staged_sidecar):
            print(f"❌ Could not download the integrity sidecar from {SHA_URL}")
            print("   The artifact and its sidecar are committed together, so a missing")
            print("   sidecar means that ref is inconsistent. Refusing to install.")
            return None
        try:
            sidecar_text = staged_sidecar.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"❌ Could not read the downloaded sidecar: {e}")
            return None

        ok, computed, expected = verify_artifact(staged, sidecar_text)
        if not ok:
            print(f"❌ Integrity check failed for {ARTIFACT_URL}")
            if expected is None:
                # A sidecar that is not a sha256 line at all: say that, rather than
                # printing "expects None" and looking like a digest mismatch.
                print(f"   {SHA_URL} is not a sha256 sidecar: {sidecar_text.strip()[:60]!r}")
            else:
                print(f"   {SHA_URL} expects {expected[:16]}...")
            print(f"   the downloaded bytes are {str(computed)[:16]}...")
            print("   Nothing was written in any home; existing installs are untouched.")
            return None
        try:
            payload = staged.read_bytes()
        except OSError as e:
            print(f"❌ Could not read the verified artifact: {e}")
            return None
        print(f"✅ Verified the opencode plugin ({len(payload)} bytes, {computed[:16]}...)")
        return payload, computed
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


# --- where the plugin goes ---------------------------------------------------------------


def resolve_config_dir(home) -> Optional[Path]:
    """`<home>/.config/opencode`, or None when `home` is not an absolute path.

    The per-user installer also honours OPENCODE_CONFIG_DIR and XDG_CONFIG_HOME (profile.ts
    resolveOpencodeConfigDir). This one deliberately does not and takes no env seam: those
    variables live in the TARGET user's environment, which root running from an MDM cannot
    read, and reading root's own copy would install every user's plugin into one directory.
    MDM therefore covers the default config directory only, and opencode/mdm/README.md says so.
    """
    home_str = "" if home is None else str(home)
    if not home_str or not os.path.isabs(home_str):
        return None
    return Path(home_str).joinpath(*CONFIG_DIR_SEGMENTS)


def plugin_dir(config_dir) -> Path:
    """`<config dir>/plugins` -- opencode loads every *.js / *.ts in it."""
    return Path(config_dir) / PLUGIN_DIRNAME


def plugin_path(config_dir) -> Path:
    """The plugin this installer writes."""
    return plugin_dir(config_dir) / PLUGIN_NAME


def sidecar_path(config_dir) -> Path:
    """The digest written beside the plugin, so --clear can remove both."""
    return plugin_dir(config_dir) / SIDECAR_NAME


def marker_path(config_dir) -> Path:
    """Lists files this installer created that are not always ours (today: package.json)."""
    return plugin_dir(config_dir) / MARKER_NAME


def _is_unbound_bundle(path) -> bool:
    """True for a REGULAR file (lstat, never following a link) whose first 4 KiB carry the
    `unbound-hooks-ts` build banner. Anything we cannot read is not recognised."""
    try:
        st = os.lstat(str(path))
        if not stat.S_ISREG(st.st_mode):
            return False
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            head = f.read(BANNER_SCAN_BYTES)
        return UNBOUND_BUNDLE_MARKER in head
    except OSError:
        return False


def remove_stray_copies(config_dir, say=print) -> bool:
    """Delete Unbound copies opencode would load beside ours. True when none remains.

    Same rule as opencode/setup.py: a banner-recognised regular file is deleted; a symlink is
    never followed or removed; anything else is left byte-identical with a warning. Runs with
    privileges dropped, so `say` collects the messages for the parent to print.
    """
    base = Path(config_dir)
    clean = True
    for parts in STRAY_RELPATHS:
        path = base.joinpath(*parts)
        rel = "/".join(parts)
        try:
            st = os.lstat(str(path))
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            say(f"⚠️  {path} is a symlink; left in place. If it points at a copy of the")
            say("   Unbound plugin, opencode loads it as well as ours -- remove it by hand.")
            continue
        if _is_unbound_bundle(path):
            try:
                os.unlink(str(path))
                say(f"🧹 Removed a stray Unbound copy at {rel} (opencode would load it twice).")
            except OSError as e:
                clean = False
                say(f"⚠️  Could not remove the stray Unbound copy {path}: {e}")
            continue
        say(f"⚠️  {path} was left in place: it is not recognisably Unbound's,")
        say("   and opencode will load it beside the Unbound plugin.")
    return clean


def _other_plugin_files(pdir) -> list:
    """Every *.js / *.ts in plugins/ other than ours -- what opencode would also load."""
    try:
        names = os.listdir(str(pdir))
    except OSError:
        return []
    return sorted(n for n in names if n != PLUGIN_NAME and n.endswith(PLUGIN_SUFFIXES))


def _read_marker(config_dir) -> list:
    """Names the marker says this installer created. Missing/corrupt -> []."""
    try:
        if os.path.islink(str(marker_path(config_dir))):
            return []
        data = json.loads(marker_path(config_dir).read_text(encoding="utf-8"))
    except Exception:
        return []
    created = data.get("created") if isinstance(data, dict) else None
    if not isinstance(created, list):
        return []
    return [n for n in created if isinstance(n, str)]


def _is_our_package_json(path) -> bool:
    """True only for a regular file whose JSON is exactly {"type":"module"}."""
    try:
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            return False
        return json.loads(Path(path).read_text(encoding="utf-8")) == ESM_PACKAGE_JSON
    except Exception:
        return False


def ensure_esm_marker(config_dir, say=print) -> str:
    """Create `plugins/package.json` = {"type":"module"} when, and only when, it is safe.

    Same rule as opencode/setup.py (spike V1-4: plain Node refuses the ESM bundle under a
    commonjs parent): never touch an existing package.json; skip when another plugin lives
    in plugins/; otherwise record it in the marker FIRST, then create it with O_EXCL.
    Returns "exists" | "skipped" | "created" | "failed". Never raises.
    """
    pdir = plugin_dir(config_dir)
    pkg = pdir / "package.json"
    if os.path.lexists(str(pkg)):
        return "exists"
    others = _other_plugin_files(pdir)
    if others:
        say(f"ℹ️  Not creating {pkg}: other plugins live there ({', '.join(others[:3])}).")
        return "skipped"
    created = _read_marker(config_dir)
    if "package.json" not in created:
        created.append("package.json")
    if not _atomic_write_text(marker_path(config_dir), json.dumps({"created": created}) + "\n",
                              0o644):
        return "failed"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(pkg), flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(ESM_PACKAGE_JSON) + "\n")
        return "created"
    except OSError as e:
        debug_print(f"Could not create {pkg}: {e}")
        created.remove("package.json")
        if created:
            _atomic_write_text(marker_path(config_dir), json.dumps({"created": created}) + "\n",
                               0o644)
        else:
            _clear_path(marker_path(config_dir), "install marker")
        return "failed"


def _drop_in_home(config_dir: Path, payload: bytes, digest: str) -> list:
    """Write the plugin. Runs with root already dropped to the target user.

    Returns `[status, *messages]`, status being "installed", "persisted" or "failed: <reason>"
    -- data rather than a raise or a print, because this crosses a fork boundary: one user's
    bad home must not end the run, and a print in the child is lost when it _exits.
    """
    notes = []
    pdir = plugin_dir(config_dir)
    target = plugin_path(config_dir)
    sidecar = sidecar_path(config_dir)
    try:
        pdir.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError as e:
        return [f"failed: could not create {pdir} ({e})"]
    try:
        # mkdir's mode is masked by umask and does nothing for a directory that existed.
        os.chmod(pdir, 0o755)
    except OSError as e:
        debug_print(f"Could not set the mode on {pdir}: {e}")

    # Read before the write, or every run would look like a first one.
    state = "persisted" if target.exists() else "installed"

    # A symlink planted at unbound.js by the user is refused rather than written through.
    try:
        if os.path.islink(str(target)):
            return [f"failed: {target} is a symlink"]
    except OSError as e:
        return [f"failed: could not inspect {target} ({e})"]

    remove_stray_copies(config_dir, say=notes.append)
    ensure_esm_marker(config_dir, say=notes.append)

    # Write a sibling temp file and rename it in, never truncating the target in place: a
    # truncating write that then fails leaves a previously working plugin broken in that
    # user's home, with no error anywhere. os.replace is atomic within a directory.
    tmp = _unique_tmp_path(target)
    # O_EXCL belongs to the TEMP file only.
    tmp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        _unlink_legacy_tmp(target)
        fd = os.open(str(tmp), tmp_flags, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(str(tmp), 0o644)
        except OSError as e:
            debug_print(f"Could not set the mode on {tmp}: {e}")
        os.replace(str(tmp), str(target))
    except OSError as e:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        return [f"failed: could not write {target} ({e})"] + notes

    # Re-read from disk, so the hook_hash this device reports is provably the bytes in the home.
    if artifact_sha256(target) != digest:
        return ["failed: the bytes written do not match the verified artifact"] + notes

    # Atomic, and NOT O_EXCL: on every push after the first this file already exists.
    if not _atomic_write_text(sidecar, f"{digest}  {PLUGIN_NAME}\n", 0o644):
        debug_print("Could not write the local sidecar")

    return [state] + notes


def install_for_user(username: str, home_dir, payload: bytes, digest: str) -> str:
    """Drop the verified plugin into one user's home. "installed"/"persisted"/"failed: ...".

    Never raises: the caller is a loop over every account on the device, and one unwritable
    home must cost that user their coverage and nothing more.
    """
    config_dir = resolve_config_dir(home_dir)
    if config_dir is None:
        return "failed: no absolute home directory to install under"
    pdir = plugin_dir(config_dir)

    # A previous root-context run can leave these root-owned, which the dropped user then
    # cannot write. Repair first (symlink- and hardlink-guarded), then drop. The home itself
    # is the anchor, not a repaired path: see _repair_user_ownership.
    _repair_user_ownership(username, home_dir, [config_dir.parent, config_dir, pdir,
                                                plugin_path(config_dir), sidecar_path(config_dir),
                                                marker_path(config_dir)])

    result = _run_as_user(username, _drop_in_home, config_dir, payload, digest)
    if not isinstance(result, list) or not result or not isinstance(result[0], str):
        return "failed: the privilege-dropped write did not complete"
    for note in result[1:]:
        if isinstance(note, str):
            print(f"  {note}")
    return result[0]


def detect_install_state(user_homes) -> str:
    """'persisted' when any enumerated home already carries the plugin, else 'fresh'.

    Device-scope and read BEFORE the loop. 'tampered' is never reported: this baseline
    writes no managed config to compare against.
    """
    try:
        for _, home_dir in user_homes:
            config_dir = resolve_config_dir(home_dir)
            if config_dir is not None and plugin_path(config_dir).exists():
                return "persisted"
        return "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


# --- the per-application key --------------------------------------------------------------


def fetch_api_key_from_mdm(base_url: str, app_name: Optional[str], auth_api_key: str,
                           device_id: str) -> Optional[str]:
    """Exchange the admin key for this org's opencode application key. None on any failure.

    `app_type=opencode` is what makes the backend mint an opencode application key rather
    than a `default` one (it must be in device_handlers.py VALID_APP_TYPES). The params are
    urlencoded because a serial number can contain a space or an `&`, either of which would
    otherwise truncate or inject query parameters.
    """
    query = [("serial_number", device_id), ("app_type", "opencode")]
    if app_name:
        query.insert(0, ("app_name", app_name))
    params = urllib.parse.urlencode(query)
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"
    debug_print(f"Fetching the opencode application key from: {url}")

    try:
        # Jitter first: a fleet-wide push otherwise has every device retrying in lockstep.
        time.sleep(random.uniform(0, MDM_RETRY_JITTER_SECONDS))
        # The PRIVILEGED admin key goes off-argv, via curl_with_auth's 0600 header file.
        result = curl_with_auth(
            [f"Authorization: Bearer {auth_api_key}"],
            ["-fsSL", "-w", "\n%{http_code}",
             "--max-time", "30", "--retry", "7", "--retry-max-time", "180",
             "--retry-connrefused", url],
            text=True,
            timeout=300,
        )
        if result is None:
            print("❌ Failed to fetch the opencode application key")
            return None

        output_lines = (result.stdout or "").strip().split('\n')
        if len(output_lines) < 2:
            print("❌ Invalid response from the server")
            return None
        http_code = output_lines[-1]
        response_body = '\n'.join(output_lines[:-1])
        debug_print(f"HTTP status: {http_code}")

        if http_code != "200":
            print(f"❌ The API key request failed with status {http_code}")
            return None
        try:
            data = json.loads(response_body)
        except json.JSONDecodeError:
            print("❌ Invalid JSON in the server's response")
            return None
        if not isinstance(data, dict):
            print("❌ Unexpected response shape from the server")
            return None
        api_key = data.get("api_key")
        if not api_key:
            print("❌ No api_key in the response")
            return None
        print(f"Application: {data.get('email')} ({data.get('first_name')} "
              f"{data.get('last_name')})")
        return api_key
    except subprocess.TimeoutExpired:
        print("❌ The API key request timed out")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        print("❌ Failed to fetch the opencode application key")
        return None


def _is_safe_env_value(value) -> bool:
    """True when `value` is safe to interpolate into a shell rc file.

    An rc file is executed by the user's login shell, so a value containing a quote, a `$`,
    a backtick, a `;` or a newline would be COMMAND rather than data -- and this one is
    written into every account on the device. The gate is an allow-list, not an escape
    routine: escaping is easy to get subtly wrong, and a real API key needs none of those
    characters. This is an addition to the Augment analog, not a port of it.
    """
    if not isinstance(value, str) or not value:
        return False
    if len(value) > MAX_ENV_VALUE_LEN:
        return False
    return all(c in SAFE_ENV_VALUE_CHARS for c in value)


def rc_files_for(home_dir) -> List[Path]:
    """The login-shell files an `export` line has to land in, per platform.

    The bash file is CHOSEN rather than fixed, because bash reads only the FIRST of
    `.bash_profile`, `.bash_login`, `.profile` that exists. Always writing `.bash_profile`
    created it for a user who relied on one of the other two, and from that moment every new
    terminal silently stopped sourcing their PATH and environment -- a breakage this installer
    caused and `--clear` could not undo. Writing to whichever file bash already reads both
    avoids the shadowing and puts the export where it actually runs.

    zsh has no such chain -- it sources `.zshenv`, `.zprofile`, `.zshrc` and `.zlogin`, so
    `.zprofile` is unconditional -- and the Linux pair are interactive rc files, not a
    first-match login sequence.
    """
    system = platform.system().lower()
    home_dir = Path(home_dir)
    if system == "darwin":
        return [home_dir / ".zprofile", _bash_login_file(home_dir)]
    if system == "linux":
        return [home_dir / ".zshrc", home_dir / ".bashrc"]
    return []


def _bash_login_file(home_dir: Path) -> Path:
    """The bash login profile bash itself would read, or `.bash_profile` to create if none.

    Existence is checked, not followed: a broken symlink at `.bash_profile` is still the name
    bash resolves first, so it stays the target rather than being stepped over.
    """
    for name in BASH_LOGIN_FILES:
        candidate = home_dir / name
        try:
            if candidate.exists() or candidate.is_symlink():
                return candidate
        except OSError:
            continue
    return home_dir / BASH_LOGIN_FILES[0]


def append_to_file(file_path: Path, line: str, var_name: Optional[str] = None,
                   holds_secret: bool = False) -> bool:
    """Append `line` to `file_path` exactly once. With `var_name`, any previous
    `export <var_name>=` line is dropped first, so a repeated MDM push rotates the value
    rather than growing the file. `holds_secret` publishes the result owner-only.

    A plain open, not O_NOFOLLOW: this already runs as the target user (inside
    _run_as_user), where a symlink grants nothing the user does not already have -- and a
    shell rc file symlinked into a dotfiles repo is a common, legitimate setup that
    O_NOFOLLOW would break.
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if file_path.exists():
            try:
                # surrogateescape, and NEVER a fallback to an empty list. A single non-UTF-8
                # byte -- an accented name in a comment, a stray 0x80 -- used to raise here,
                # get swallowed into `lines = []`, and then the truncating write below
                # replaced the user's entire shell profile with one export line. As root,
                # for every account on the device, on every push. surrogateescape decodes
                # such bytes into lone surrogates that the matching write turns back into
                # the original bytes, so the file round-trips byte-for-byte.
                with open(file_path, "r", encoding="utf-8", errors="surrogateescape") as f:
                    lines = f.readlines()
            except OSError as e:
                # Unreadable for a real reason (permissions, EIO). Refuse rather than
                # rewrite: failing to set the variable costs this one account its
                # enforcement, while rewriting a file we could not read costs them their
                # shell profile. The caller records this as a per-user failure.
                print(f"Refusing to rewrite {file_path}, which could not be read: {e}")
                return False
        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]
        normalized_line = line.rstrip()
        if not any(l.rstrip() == normalized_line for l in lines):
            # Terminate the last retained line first. readlines() keeps terminators as they
            # are and writelines() adds none, so a profile whose final line has no newline
            # got our export CONCATENATED onto it: `export EDITOR=vim` became
            # `export EDITOR=vimexport UNBOUND_OPENCODE_API_KEY="..."`, which breaks the user's
            # setting and our own line at once -- and a final `# comment` swallows the export
            # whole, leaving the account silently unprotected. Only on the append path: a
            # no-op push must not rewrite a file it has nothing to add to.
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"{line}\n")
        return _rewrite_rc_file(file_path, lines, holds_secret=holds_secret)
    except Exception as e:
        print(f"Failed to modify {file_path}: {e}")
        return False


def _atomic_write_text(path, text: str, mode: int = 0o644) -> bool:
    """Replace one file's contents with no truncate-in-place window, refusing a symlink.

    A plain O_TRUNC open makes the destination the failure window: an interrupt, ENOSPC or
    EIO after that open leaves the file empty or half-written. For `~/.unbound/config.json`
    that means logging the user out of every tool that shares it, not just opencode.

    Unlike the user installer's equivalent, and unlike `_rewrite_rc_file`, this REFUSES a
    symlinked destination rather than following it: root is writing into someone else's
    home, where a planted link is an attack rather than a dotfiles convention. That is the
    guard O_NOFOLLOW gave us before the write went via a temp file.
    """
    try:
        target = Path(path)
        if os.path.islink(str(target)):
            debug_print(f"Refusing to write {target}: it is a symlink")
            return False
        tmp = _unique_tmp_path(target)
        try:
            # Debris from a killed pre-unique run, never another live writer's temp.
            _unlink_legacy_tmp(target)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(str(tmp), flags, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                # fsync before the rename, or a crash can publish a name whose bytes never
                # reached the disk.
                os.fsync(f.fileno())
            try:
                os.chmod(str(tmp), mode)
            except OSError as e:
                debug_print(f"Could not set the mode on {tmp}: {e}")
            os.replace(str(tmp), str(target))
            return True
        except OSError:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            raise
    except Exception as e:
        debug_print(f"Could not write {path}: {e}")
        return False


def _rewrite_rc_file(file_path: Path, lines, holds_secret: bool = False) -> bool:
    """Replace one shell rc file's contents without a truncate-in-place window.

    A plain `open(path, "w")` truncates first, so a write that then fails (ENOSPC, EIO, a
    killed MDM run) leaves the user with an empty or half-written shell profile. Writing a
    sibling temp file and renaming makes the outcome all-or-nothing.

    A shell rc file symlinked into a dotfiles repo is a common, legitimate setup, so the
    link is resolved and the REAL file is rewritten: os.replace on the link path would
    replace the link itself and silently detach the user from their dotfiles.

    `holds_secret` publishes the file with the group and other bits stripped, because the
    content we are adding is a plaintext API key. The default 0644 -- which is what a shell
    profile normally is, and what the Augment analog writes -- is world-readable, and a macOS
    home is 0755 by default, so every other local account (including the service accounts
    this installer deliberately skips) could read the key straight out of `~/.zprofile`.
    Tightening only ever REMOVES bits: a profile the user keeps at 0600 stays 0600, and the
    owner's own bits are untouched, because the login shell reading the file runs as them.
    """
    try:
        target = Path(os.path.realpath(str(file_path)))
        mode = 0o644
        try:
            if target.exists():
                # Keep whatever the user had -- an rc file is sometimes 0600 on purpose.
                mode = stat.S_IMODE(target.stat().st_mode)
        except OSError:
            pass
        if holds_secret:
            mode &= ~(stat.S_IRWXG | stat.S_IRWXO)
        tmp = _unique_tmp_path(target)
        try:
            # Debris from a killed pre-unique run, never another live writer's temp.
            _unlink_legacy_tmp(target)
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as f:
                f.writelines(lines)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(str(tmp), mode)
            except OSError as e:
                debug_print(f"Could not set the mode on {tmp}: {e}")
            os.replace(str(tmp), str(target))
            return True
        except OSError as e:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            print(f"Failed to rewrite {target}: {e}")
            return False
    except Exception as e:
        print(f"Failed to rewrite {file_path}: {e}")
        return False


def check_env_var_exists(rc_file: Path, var_name: str, value: str) -> bool:
    """True when this exact export line is already in the file, so a repeat is a no-op."""
    rc_file = Path(rc_file)
    if not rc_file.exists():
        return False
    try:
        with open(rc_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        export_line = f'export {var_name}="{value}"'
        return any(l.rstrip() == export_line for l in lines)
    except Exception:
        return False


def set_env_var_for_user(username: str, home_dir, var_name: str,
                         value: str) -> Tuple[bool, bool]:
    """Put `export <var_name>="<value>"` in one user's rc files. (success, changed).

    The charset gate comes FIRST and refuses before any file is touched: these files are
    executed by the user's shell. Privilege-drops on Unix, so the line is written by the
    user who owns the file.
    """
    if not _is_safe_env_value(value):
        print(f"❌ Refusing to write {var_name}: the value contains characters that are not")
        print("   safe in a shell rc file. Nothing was written for this user.")
        return False, False

    system = platform.system().lower()
    if system == "windows":
        try:
            # `setx /M` is machine-wide in one call -- no per-user iteration on Windows.
            subprocess.run(["setx", var_name, value, "/M"], check=False,
                           capture_output=True, timeout=10)
            return True, True
        except Exception as e:
            debug_print(f"Failed to set {var_name} on Windows: {e}")
            return False, False

    rc_files = rc_files_for(home_dir)
    if not rc_files:
        return False, False
    export_line = f'export {var_name}="{value}"'

    def _do():
        _success = False
        _changed = False
        for rc_file in rc_files:
            try:
                exists_already = check_env_var_exists(rc_file, var_name, value)
                # holds_secret: the line being added is the plaintext application key.
                if append_to_file(rc_file, export_line, var_name, holds_secret=True):
                    _success = True
                    if not exists_already:
                        _changed = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
        # A list, not a tuple: this value crosses the privilege drop as json, which has no
        # tuple type, so returning a list keeps the round trip lossless by construction.
        return [_success, _changed]

    _repair_user_ownership(username, home_dir, rc_files)
    result = _run_as_user(username, _do)
    if not isinstance(result, list) or len(result) != 2:
        debug_print(f"Could not set {var_name} for {username}")
        return False, False
    return bool(result[0]), bool(result[1])


def _warn_if_shadowing_and_empty(rc_file: Path, remaining_lines) -> None:
    """Name the one thing `--clear` cannot undo: a `.bash_profile` an OLDER version of this
    installer created, which now shadows the `.bash_login` or `.profile` the user relies on.

    Removing the export empties the file but does not un-shadow it, and bash still reads the
    empty file first. The file is NOT deleted: an empty `.bash_profile` is sometimes a
    deliberate way to suppress `.profile`, and silently removing a shell profile from someone's
    home on an uninstall path is a worse failure than the one being reported. So the operator
    is told, precisely, and decides. Current versions never create this situation --
    `rc_files_for` writes to whichever login file bash already reads.
    """
    if rc_file.name != BASH_LOGIN_FILES[0]:
        return
    if any(line.strip() for line in remaining_lines):
        return
    shadowed = [name for name in BASH_LOGIN_FILES[1:] if (rc_file.parent / name).exists()]
    if not shadowed:
        return
    print(f"⚠️  {rc_file} is now empty, and bash reads it BEFORE "
          f"{' and '.join(shadowed)}.")
    print("   An older version of this installer created it. Delete it by hand to restore")
    print(f"   {shadowed[0]}; it is left in place because an empty profile is sometimes")
    print("   deliberate, and removing a shell profile is not ours to guess at.")


def remove_env_var_from_user(username: str, home_dir, var_name: str) -> str:
    """Strip our export line from one user's rc files. "cleared"/"not_found"/"failed"."""
    system = platform.system().lower()
    if system == "windows":
        reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
        try:
            query = subprocess.run(["reg", "query", reg_path, "/V", var_name],
                                   capture_output=True, timeout=10)
            if query.returncode != 0:
                return "not_found"
            subprocess.run(["reg", "delete", reg_path, "/F", "/V", var_name],
                           check=True, capture_output=True, timeout=10)
            return "cleared"
        except Exception as e:
            debug_print(f"Failed to remove {var_name}: {e}")
            return "failed"

    rc_files = rc_files_for(home_dir)
    if not rc_files:
        return "failed"
    export_prefix = f"export {var_name}="

    def _do():
        cleared = False
        had_error = False
        for rc_file in rc_files:
            if not rc_file.exists():
                continue
            try:
                # surrogateescape so a non-UTF-8 byte anywhere in the file does not make the
                # whole removal fail (it used to leave our export in place and report
                # "failed"), and so the bytes we do not understand are written back
                # unchanged. The rewrite goes through the same atomic helper as the append.
                with open(rc_file, 'r', encoding='utf-8', errors='surrogateescape') as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if not l.strip().startswith(export_prefix)]
                if len(new_lines) < len(lines):
                    if _rewrite_rc_file(rc_file, new_lines):
                        cleared = True
                        _warn_if_shadowing_and_empty(rc_file, new_lines)
                    else:
                        had_error = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
                had_error = True
        if cleared:
            return "cleared"
        return "failed" if had_error else "not_found"

    result = _run_as_user(username, _do)
    return result if result in ("cleared", "not_found", "failed") else "failed"


def _key_provenance(api_key: str) -> str:
    """The digest this installer records beside a key it wrote, to recognise it on the next push.

    A digest rather than the key: the field exists to answer "is the value in this file still
    the one we put there?", and storing a second copy of the secret to answer that would be
    gratuitous (the first copy is two lines above it in the same 0600 file).
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def write_unbound_config_for_user(username: str, home_dir, api_key: str,
                                  urls: Optional[dict] = None) -> bool:
    """Merge the key and the tenant URLs into one user's ~/.unbound/config.json.

    An rc export is invisible to an already-open shell and to a GUI-launched opencode, so this is
    what makes the CURRENT session work -- which is also why a key this installer wrote here
    has to stay rotatable. Privilege-drops before any filesystem op.
    """
    home_dir = Path(home_dir)
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    # A previous root-context run can leave these root-owned; repair (symlink-guarded)
    # before dropping, or the write below fails EACCES.
    _repair_user_ownership(username, home_dir, [config_dir, config_file])

    def _write():
        if platform.system().lower() == "windows":
            config_dir.mkdir(parents=True, exist_ok=True)
        else:
            config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.chmod(config_dir, 0o700)
            except OSError:
                pass
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.loads(f.read())
            except json.JSONDecodeError:
                # Parsed as nothing, so there is nothing in it left to lose.
                config = {}
            except OSError as e:
                # A file we could not READ is a file we know nothing about. Publishing a fresh
                # object over it would drop this user's email, org and the api_key six tools
                # authenticate with -- and would hand them the device key in its place, which
                # is the exact clobber the ownership check above exists to prevent. Same rule
                # as append_to_file: refuse rather than rewrite what we could not read.
                debug_print(f"Refusing to rewrite {config_file}, which could not be read: {e}")
                return False
        if not isinstance(config, dict):
            config = {}
        # DELIBERATE DIVERGENCE from augment/hooks/mdm/setup.py:770, which assigns
        # config['api_key'] unconditionally. This file is the shared identity store for
        # unbound-cli and the other tools (Cursor, Claude Code, Codex, Copilot, Augment, pi):
        # on a device where the user has run `unbound login`, overwriting api_key would
        # silently repoint ALL of them at this device key.
        #
        # But a blanket "never overwrite" was the other half of the bug. The value this
        # installer wrote on the FIRST push is also an existing value, so once the org
        # revoked that key a later push updated only the rc exports and left the dead key in
        # config.json -- and config.json is precisely the tier a GUI-launched opencode, or any
        # already-open shell, reads. The plugin authenticated with a revoked key and
        # failed open, after a redeployment that reported success.
        #
        # So ownership is tracked instead of guessed: the value is replaced when it is
        # absent, when it is already the key we are about to write, or when its digest
        # matches the one we recorded the last time we wrote it. Anything else is the user's
        # own credential and is left byte-identical.
        existing = config.get("api_key")
        existing = existing.strip() if isinstance(existing, str) else ""
        if (not existing or existing == api_key
                or config.get(MDM_KEY_PROVENANCE_FIELD) == _key_provenance(existing)):
            config["api_key"] = api_key
            config[MDM_KEY_PROVENANCE_FIELD] = _key_provenance(api_key)
        if urls:
            # URLs are tenant configuration, not identity, so they DO update unconditionally.
            config.update({k: v for k, v in urls.items() if v})
        # Atomic, and still refusing a symlink: an interrupt during a truncating write would
        # leave this shared identity file empty, logging the user out of all six tools.
        if not _atomic_write_text(config_file, json.dumps(config, indent=2), 0o600):
            return False
        try:
            os.chmod(config_file, 0o600)
        except OSError:
            pass
        return True

    if _run_as_user(username, _write) is True:
        return True
    debug_print(f"Could not write the unbound config for {username}")
    return False


# --- the device report -------------------------------------------------------------------


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = DEFAULT_BACKEND_URL,
                          install_state: Optional[str] = None,
                          serial_number: Optional[str] = None,
                          hook_hash: Optional[str] = None,
                          install_mode: Optional[str] = None):
    """Tell the backend this tool is set up. Never fails the setup.

    POST /api/v1/setup/complete/ -- the same endpoint every other installer reports to, and
    the only one that carries a tool_type. (The device-level Jamf telemetry endpoint is a
    different thing entirely: it has no tool_type, it is posted by the fleet bootstrap's
    exit trap, and this installer must not post it.)

    The body is assembled BY PRESENCE and the signature is the one every other installer
    ships: tests/test_setup_contract.py calls this directly on every setup.py in the repo
    and asserts that a caller passing neither hook_hash nor install_mode sends the exact
    body it always sent. Returns True when the POST looked like it landed, else None.
    """
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = {"tool_type": tool_type}
        if install_state is not None:
            body["install_state"] = install_state
        if serial_number is not None:
            body["serial_number"] = serial_number
        if hook_hash is not None:
            body["hook_hash"] = hook_hash
        if install_mode is not None:
            body["install_mode"] = install_mode
        data = json.dumps(body)
        # X-API-KEY off-argv via a 0600 temp header file; body off-argv via stdin.
        result = curl_with_auth(
            [f"X-API-KEY: {api_key}"],
            ["-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            timeout=10,
        )
        if result is None or getattr(result, "returncode", 1) != 0:
            debug_print("Setup completion notification did not land")
            return None
        debug_print("Setup completion notification sent")
        return True
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")
        return None


# --- teardown ----------------------------------------------------------------------------


def _clear_path(path, label: str) -> str:
    """Remove one file we wrote. "cleared"/"not_found"/"failed", never raises.

    lexists, not exists: a dangling symlink at one of our names is still ours to remove.
    """
    path = Path(path)
    try:
        if not os.path.lexists(str(path)):
            return "not_found"
        path.unlink()
        return "cleared"
    except Exception as e:
        debug_print(f"Failed to clear {label}: {e}")
        return "failed"


def _clear_in_home(config_dir: Path) -> List[str]:
    """Remove our files from one plugins dir. Runs with privileges dropped.

    Returns one status per INSTALLED_NAMES entry, then the package.json status: removed only
    when the marker lists it AND it is still exactly {"type":"module"}. The marker goes last,
    and stays when our package.json could not be removed, so a retry still knows it.
    """
    pdir = plugin_dir(config_dir)
    statuses = [_clear_path(pdir / name, name) for name in INSTALLED_NAMES]
    pkg_status = "not_ours"
    if "package.json" in _read_marker(config_dir):
        pkg = pdir / "package.json"
        if not os.path.lexists(str(pkg)):
            pkg_status = "not_found"
        elif _is_our_package_json(pkg):
            pkg_status = _clear_path(pkg, "package.json")
        else:
            pkg_status = "kept (edited since install)"
    if pkg_status != "failed":
        if _clear_path(marker_path(config_dir), "install marker") == "failed":
            pkg_status = "failed"
    return statuses + [pkg_status]


def clear_setup() -> bool:
    """Undo this installer across every home: our files, and our export line.

    Never touches ~/.unbound/config.json -- its api_key is shared with other tools. Posts
    nothing: install_state is an install-time enum with no uninstall value, and no installer
    in this repo reports a clear.
    """
    print("=" * 60)
    print("OpenCode Plugin - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return False

    user_homes = get_all_user_homes()
    if platform.system().lower() == "windows" and not user_homes:
        # `reg delete HKLM\...` is machine-wide, so the env removal still has work to do
        # even when there are no profiles under the users directory.
        user_homes = [(None, None)]
    if not user_homes:
        print("No user home directories found; nothing to clear.")
        print("Clear Complete!")
        return True

    names = list(INSTALLED_NAMES) + ["package.json"]
    any_failed = False
    for username, home_dir in user_homes:
        if home_dir is not None:
            config_dir = resolve_config_dir(home_dir)
            if config_dir is None:
                print(f"  {username}: skipped (no absolute home)")
                continue
            pdir = plugin_dir(config_dir)
            _repair_user_ownership(username, home_dir, [pdir, plugin_path(config_dir),
                                                        sidecar_path(config_dir),
                                                        marker_path(config_dir)])
            statuses = _run_as_user(username, _clear_in_home, config_dir)
            if not isinstance(statuses, list) or len(statuses) != len(names):
                any_failed = True
                statuses = ["failed"] * len(names)
            elif "failed" in statuses:
                any_failed = True
            files = ", ".join(f"{n}: {s}" for n, s in zip(names, statuses))
        else:
            files = "n/a"
        env_status = remove_env_var_from_user(username, home_dir, ENV_API_KEY)
        if env_status == "failed":
            any_failed = True
        print(f"  {username}: {files}; {ENV_API_KEY}: {env_status}")

    print("\nThe plugins directories, and every other file in them, were left in place.")
    print("~/.unbound/config.json was NOT touched: its api_key is shared with the other")
    print("Unbound tools on this device.")
    print("=" * 60)
    print("Clear Complete!")
    print("=" * 60)
    return not any_failed


# --- arguments and main ------------------------------------------------------------------


def _flag_value(argv, flag: str) -> Optional[str]:
    """The token after `flag`, or None -- including when `flag` is the last token."""
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def parse_args(argv) -> dict:
    """The flags the MDM bootstrap passes, plus --clear and --debug."""
    backend = _flag_value(argv, "--backend-url")
    gateway = _flag_value(argv, "--gateway-url")
    frontend = _flag_value(argv, "--frontend-url")
    return {
        "api_key": _flag_value(argv, "--api-key"),
        "app_name": _flag_value(argv, "--app_name"),
        "backend_url": normalize_url(backend) if backend else DEFAULT_BACKEND_URL,
        "gateway_url": normalize_url(gateway) if gateway else DEFAULT_GATEWAY_URL,
        "frontend_url": normalize_url(frontend) if frontend else None,
        "clear": "--clear" in argv,
        "debug": "--debug" in argv,
    }


def _print_summary(rows) -> None:
    """One table, one line per account, so an MDM log says exactly who got what."""
    print("\n" + "=" * 60)
    print("Per-user result")
    print("-" * 60)
    width = max([len(r[0] or "?") for r in rows] + [4])
    for username, extension, key in rows:
        print(f"  {(username or '?').ljust(width)}  plugin: {extension}; key: {key}")
    print("=" * 60)


def main() -> bool:
    _stdout_never_raises()
    global DEBUG

    args = parse_args(sys.argv)
    # MDM deployments always run with debug logging enabled -- administrators need full
    # diagnostic output for troubleshooting across managed devices they cannot log into.
    DEBUG = True

    # --clear is answered first: it needs no key and makes no network call.
    if args["clear"]:
        return clear_setup()

    print("=" * 60)
    print("OpenCode Plugin - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("This script requires administrator/root privileges")
        print("   Please re-run with sudo. No user home was touched.")
        return False

    if not args["api_key"]:
        print("\nMissing required argument: --api-key <admin api key>")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>]")
        print("            [--gateway-url <url>] [--frontend-url <url>] [--app_name <name>] [--debug]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
        return False

    print("\nGetting the device identifier...")
    device_id = get_device_identifier()
    if not device_id:
        print("❌ Failed to get the device identifier; the report would not be attributable.")
        return False
    debug_print(f"Device identifier: {device_id}")

    user_homes = get_all_user_homes()
    if not user_homes:
        print("❌ No user home directories found; nothing to install.")
        return False
    print(f"Found {len(user_homes)} user(s): {', '.join(n for n, _ in user_homes)}")

    # Read the device's state BEFORE anything is written, or every run reports 'fresh'.
    install_state = detect_install_state(user_homes)

    print("\nFetching the opencode application key...")
    # Once per device, not once per home: the endpoint is keyed on (app_name,
    # serial_number) and carries no user, so a per-user fetch would return the identical
    # key while multiplying a fleet-wide push by the number of accounts on the machine.
    api_key = fetch_api_key_from_mdm(args["backend_url"], args["app_name"],
                                     args["api_key"], device_id)
    if not api_key:
        print("❌ Could not obtain the opencode application key; refusing to install a keyless")
        print("   plugin, which would be inert and would look installed.")
        return False

    print("\nFetching the plugin...")
    fetched = fetch_artifact()
    if fetched is None:
        return False
    payload, digest = fetched

    urls = {"base_url": args["backend_url"], "gateway_url": args["gateway_url"],
            "frontend_url": args["frontend_url"]}

    rows = []
    installed_any = False
    covered_any = False
    for username, home_dir in user_homes:
        print(f"\n--- {username} ---")
        extension_status = install_for_user(username, home_dir, payload, digest)
        extension_ok = extension_status in ("installed", "persisted")
        if extension_ok:
            installed_any = True
        env_ok, _ = set_env_var_for_user(username, home_dir, ENV_API_KEY, api_key)
        config_ok = write_unbound_config_for_user(username, home_dir, api_key, urls=urls)
        # An installed plugin with no key is inert (the plugin resolves no key from an
        # absent env var and an absent config), so coverage needs BOTH halves. Either key
        # location is enough on its own: the rc export serves new shells, config.json serves
        # the current one and GUI launches.
        if extension_ok and (env_ok or config_ok):
            covered_any = True
        if env_ok and config_ok:
            key_status = "rc + config.json"
        elif env_ok:
            key_status = "rc only (config.json failed)"
        elif config_ok:
            key_status = "config.json only (rc failed)"
        else:
            key_status = "failed"
        print(f"  {username}: {extension_status}; key: {key_status}")
        rows.append((username, extension_status, key_status))

    _print_summary(rows)

    # Exactly one report per device run, after the loop, with the state read before it. A
    # run where every home failed still reports -- the backend's view of the fleet would
    # otherwise silently omit the devices that need attention most.
    try:
        reported = notify_setup_complete(
            api_key, "opencode", backend_url=args["backend_url"], install_state=install_state,
            serial_number=device_id, hook_hash=digest, install_mode="mdm",
        )
    except Exception as e:
        # notify_setup_complete swallows internally, so this is belt-and-braces -- but the
        # rule is absolute: nothing about reporting may change whether the install succeeded,
        # because the plugin is on disk and enforcing either way.
        debug_print(f"The report raised out of notify_setup_complete: {e}")
        reported = None
    if reported is not True:
        print("⚠️  Could not report this install to the backend. Install-state reporting is")
        print("   best-effort and does not change the outcome above.")

    if not installed_any:
        print("❌ The plugin reached no user on this device. See the table above.")
        return False

    # Installed is not configured. An account whose rc files AND config.json both failed has
    # a plugin that loads, reads no key and enforces nothing -- and exiting zero there
    # told the MDM everything was fine, so nothing was ever remediated. The plugin stays
    # on disk (removing it would be worse), but the run is a failure.
    if not covered_any:
        print("❌ The plugin is installed, but no account has a key it can read: every")
        print(f"   {ENV_API_KEY} export and every config.json write failed. The plugin")
        print("   loads and enforces nothing. See the key column above, fix the permissions")
        print("   on those files, and re-run this push.")
        return False

    print("=" * 60)
    print("✅ Setup complete")
    print("   Each user must restart opencode (quit and relaunch the OpenCode desktop app)")
    print("   to load the plugin.")
    print("   If a user runs `opencode serve`, `opencode attach` or the desktop app's background")
    print("   service on another machine, push this to the machine where the server runs.")
    print("   Not tamper-proof: `opencode --pure`, OPENCODE_PURE=1, or a redirected")
    print("   XDG_CONFIG_HOME / OPENCODE_CONFIG_DIR starts opencode without it. This push")
    print("   covers the default ~/.config/opencode in each home. See opencode/mdm/README.md.")
    print(f"   {V2_STATUS_NOTE}")
    print("=" * 60)
    return True


if __name__ == "__main__":
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    sys.exit(0 if ok else 1)
