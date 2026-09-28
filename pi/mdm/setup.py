#!/usr/bin/env python3
"""Install the Unbound extension for the Pi Coding Agent for EVERY user on this device.

Run as root, once per device, from an MDM (Jamf and friends):

    sudo python3 setup.py --api-key <admin key> [--backend-url <url>] [--gateway-url <url>]
    sudo python3 setup.py --clear

What lands on disk, per enumerated user: one file, `<home>/.pi/agent/extensions/unbound/
index.js`, mode 0644, owned by that user, plus a sibling `index.js.sha256` so an operator
can verify it by hand. The key is placed where the extension looks for it: an
`export UNBOUND_PI_API_KEY=...` line in that user's shell rc files, and `api_key` in that
user's `~/.unbound/config.json` -- the latter ONLY when it is absent (see below).

Writing into another user's home as root is the dangerous part of this script, so every
in-home write goes through three primitives, all of them ported from
`augment/hooks/mdm/setup.py`:

  1. `_run_as_user` -- fork, then setgroups/setgid/setuid before touching anything. After
     the drop, a symlink in the home pointing at a root-only path fails with EACCES all by
     itself instead of handing root's authority to whoever planted it.
  2. `_repair_user_ownership` -- opens with O_NOFOLLOW (a symlink becomes ELOOP) and
     fchowns the resulting file DESCRIPTOR, so the inode inspected is the inode chowned and
     there is no path TOCTOU. A regular file carrying extra hard links (st_nlink != 1) is
     refused outright: a hard link to a sensitive root-owned file would otherwise be given
     away. Directories are reclaimed only when root- or self-owned.
  3. The drop itself opens `index.js` with O_NOFOLLOW too, and runs the same `index.ts`
     shadow guard the per-user installer runs -- per home, so one user's leftover cannot
     silently defeat enforcement for that user.

Two deliberate divergences from the Augment analog, both called out at the code:

  * `config.json`'s `api_key` is written with `setdefault`, not assigned. That file is the
    shared identity store for unbound-cli and five other tools; overwriting a key the user
    minted with `unbound login` would silently repoint all of them at this device key.
  * an `export` line is only written after `_is_safe_env_value()` passes, because an rc file
    is a shell script and an unvalidated value in it is command injection.

About the sha256 sidecar: `pi/index.js.sha256` is fetched from the same origin, over the
same TLS, from the same ref as the artifact itself. It catches a truncated or corrupt
download and a stale-vs-fresh mismatch, and it gives the backend an honest `hook_hash`. It
is NOT a supply-chain control -- anyone who could replace the artifact could replace the
sidecar in the same commit. Said plainly so the reader knows how much assurance this is.

LIMITATION, stated up front because it is the honest framing of what this buys you: pi has
no managed or enterprise settings file. `pi --no-extensions`, a `PI_CODING_AGENT_DIR`
pointed somewhere else, or an SDK embedder passing `noExtensions` each bypass the extension
entirely, and nothing in this script can prevent that. This is advisory control over a
machine whose user is an administrator of it, not tamper resistance. `coding-discovery-tool`
still reports that pi is INSTALLED, so a bypassing device remains visible as "has pi"; the
"has pi but no Unbound extension" finding is backlog. See `pi/mdm/README.md`.

Root cannot read the target user's `PI_CODING_AGENT_DIR`, so this installer covers the
default agent directory only. The README says so too.
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
ARTIFACT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/pi/index.js"
SHA_URL = ARTIFACT_URL + ".sha256"

DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

# Spreads a fleet-wide MDM push so a thousand devices' retries do not re-synchronise.
MDM_RETRY_JITTER_SECONDS = 30

# hooks-ts/packages/core/src/constants.ts:27 PI_AGENT_DIR_SEGMENTS -- keep in lockstep.
PI_AGENT_DIR_SEGMENTS = (".pi", "agent")

# The extension's tier-1 key source (constants.ts:8 ENV_API_KEY_PI). pi-specific by design:
# writing the generic UNBOUND_API_KEY instead would hand this device key to six other tools.
ENV_API_KEY_PI = "UNBOUND_PI_API_KEY"

# Home enumeration, per platform. These are the analog's values
# (augment/hooks/mdm/setup.py:356-398), lifted into constants so the test suite can point
# them at a tmp tree instead of asserting against the machine it runs on.
MACOS_HOME_PREFIX = '/Users/'
LINUX_HOME_PREFIX = '/home/'
MACOS_UID_FLOOR = 500          # first real macOS account; 0-499 are system accounts
LINUX_UID_FLOOR = 1000         # Debian/RH convention for the first human user
MACOS_SKIP_USERS = ("Shared", "Guest")
WINDOWS_USERS_DIRNAME = "Users"
WINDOWS_SKIP_PROFILES = ("Public", "Default", "Default User", "Administrator", "All Users")

# Files in the extension dir that pi resolves BEFORE our index.js, and files that merely
# change resolution and so only warrant a warning.
SHADOW_NAMES = ("index.ts",)
WARN_NAMES = ("package.json",)
DISABLED_SUFFIX = ".unbound-disabled"

# Exactly the files this installer writes, and so exactly what --clear may remove.
INSTALLED_NAMES = ("index.js", "index.js.sha256")

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


def _repair_user_ownership(username: str, paths: List[Path]) -> None:
    """Root-context best-effort: hand back any of `paths` a previous root run left owned by
    the wrong uid, so the upcoming privilege-dropped write does not fail EACCES.

    This runs as root against paths the user controls, so it is hardened against local
    escalation. Open with O_NOFOLLOW -- a symlink becomes ELOOP -- and fchown the resulting
    file DESCRIPTOR, so the inode inspected is the inode chowned and there is no path
    TOCTOU. A regular file with extra hard links (st_nlink != 1) is refused: a hard link to
    a sensitive root-owned file planted at our target path would otherwise be given away.
    Directories are opened with O_DIRECTORY and reclaimed ONLY when root- or self-owned; a
    directory owned by some other non-root user is left alone, because handing it over
    would be an over-reach rather than a repair. No-op on Windows or without pwd; only
    fires on the abnormal uid-mismatch case; never raises.
    """
    if platform.system().lower() == "windows" or pwd is None:
        return
    try:
        info = pwd.getpwnam(username)
    except KeyError:
        return
    uid, gid = info.pw_uid, info.pw_gid
    o_nofollow = getattr(os, "O_NOFOLLOW", None)
    if o_nofollow is None:
        return  # cannot open safely without the symlink guard -- skip, never degrade it
    o_directory = getattr(os, "O_DIRECTORY", 0)
    base_flags = os.O_RDONLY | o_nofollow | getattr(os, "O_NONBLOCK", 0)
    for path in paths:
        # The directory open first: O_DIRECTORY succeeds only for a real directory, and
        # O_NOFOLLOW refuses a symlink to one. ENOTDIR falls through to the file open.
        try:
            fd = os.open(str(path), base_flags | o_directory)
        except OSError:
            try:
                fd = os.open(str(path), base_flags)
            except OSError:
                continue  # missing, a symlink (ELOOP), a fifo, or no access
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
    10 installers define that name, and pi ships no unbound.py hook script -- what is
    hashed here is the extension bundle itself.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def parse_sha256_sidecar(text) -> Optional[str]:
    """The digest out of a `shasum -a 256` line, or None if this is not one.

    Accepts a bare 64-hex line and the two-field `<digest>  pi/index.js` form (including
    the `*` binary-mode marker). Anything else -- empty, wrong length, non-hex, or a line
    naming some other file -- returns None, which every caller turns into a refusal.
    """
    if not isinstance(text, str):
        return None
    tokens = text.strip().split()
    if not tokens or len(tokens) > 2:
        return None
    digest = tokens[0].strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return None
    if len(tokens) == 2:
        named = os.path.basename(tokens[1].lstrip("*"))
        if named != "index.js":
            return None
    return digest


def verify_artifact(path, sidecar_text) -> Tuple[bool, Optional[str], Optional[str]]:
    """(ok, computed, expected) -- both digests come back so the caller can name them."""
    expected = parse_sha256_sidecar(sidecar_text)
    computed = artifact_sha256(path)
    ok = bool(expected) and bool(computed) and expected == computed
    return ok, computed, expected


def fetch_artifact() -> Optional[Tuple[bytes, str]]:
    """Download and verify the extension ONCE for the whole device. (payload, digest) or None.

    Once, before the home loop, deliberately: a per-home download would give a corrupt or
    mid-publish artifact N chances to reach one user and not another, and would multiply a
    fleet-wide push by the number of accounts on each device. A failure here refuses the
    whole run, so a bad artifact reaches zero homes rather than all of them.
    """
    staging = None
    try:
        # 0700 and root-owned, so a partly-downloaded artifact is never readable by the
        # users we are about to install for.
        staging = tempfile.mkdtemp(prefix=".unbound-pi-mdm.")
        try:
            os.chmod(staging, 0o700)
        except OSError as e:
            debug_print(f"Could not tighten the staging dir: {e}")
        staged = Path(staging) / "index.js"
        staged_sidecar = Path(staging) / "index.js.sha256"

        if not download_file(ARTIFACT_URL, staged):
            print(f"❌ Could not download the pi extension from {ARTIFACT_URL}")
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
        print(f"✅ Verified the pi extension ({len(payload)} bytes, {computed[:16]}...)")
        return payload, computed
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


# --- where the extension goes ------------------------------------------------------------


def resolve_agent_dir(home) -> Optional[Path]:
    """`<home>/.pi/agent`, or None when `home` is not an absolute path.

    The per-user installer also honours the target user's PI_CODING_AGENT_DIR
    (hooks-ts/packages/core/src/cache.ts:68-95). This one deliberately does not and takes
    no env seam: that variable lives in the TARGET user's shell environment, which root
    running from an MDM cannot read, and reading root's own copy of it would install every
    user's extension into one attacker- or admin-chosen directory. MDM therefore covers the
    default agent directory only, and pi/mdm/README.md says so.
    """
    home_str = "" if home is None else str(home)
    if not home_str or not os.path.isabs(home_str):
        return None
    return Path(home_str).joinpath(*PI_AGENT_DIR_SEGMENTS)


def extension_dir(agent_dir) -> Path:
    """`<agent dir>/extensions/unbound` -- one directory per extension, ours is `unbound`."""
    return Path(agent_dir) / "extensions" / "unbound"


def artifact_path(agent_dir) -> Path:
    """The file this installer writes. `.js`, because the artifact is a JS bundle."""
    return extension_dir(agent_dir) / "index.js"


def sidecar_path(agent_dir) -> Path:
    """The digest written beside the artifact, so --clear can remove both."""
    return extension_dir(agent_dir) / "index.js.sha256"


def _next_free_name(path) -> Path:
    """`path`, or `path.1`, `path.2`, ... -- the first name nothing occupies."""
    path = Path(path)
    if not path.exists():
        return path
    for n in range(1, 1000):
        candidate = path.with_name(f"{path.name}.{n}")
        if not candidate.exists():
            return candidate
    return path.with_name(f"{path.name}.{os.getpid()}")


def handle_shadow_files(extdir) -> bool:
    """Move aside anything pi would resolve before our index.js. False means give up.

    pi resolves index.ts BEFORE index.js in an extension directory, so one user's leftover
    .ts wins silently for that user: pi starts, logs no load error, and no policy check
    ever fires. The developer's file is renamed, never deleted.
    """
    extdir = Path(extdir)
    for name in SHADOW_NAMES:
        candidate = extdir / name
        if not candidate.exists():
            continue
        moved_to = _next_free_name(extdir / (name + DISABLED_SUFFIX))
        try:
            candidate.rename(moved_to)
        except Exception as e:
            print(f"❌ A {name} would shadow index.js and could not be moved aside: {e}")
            return False
        print(f"⚠️  Found {name}, which would shadow index.js -- pi resolves it first.")
        print(f"   Moved it to {moved_to.name}; it was not deleted. Nothing else changed.")
    for name in WARN_NAMES:
        if (extdir / name).exists():
            print(f"⚠️  A {name} is present in {extdir}; it can change how pi resolves")
            print("   this directory. Continuing -- remove it if the extension misbehaves.")
    return True


def _drop_in_home(extdir: Path, target: Path, sidecar: Path, payload: bytes,
                  digest: str) -> str:
    """Write the extension. Runs with root already dropped to the target user.

    Returns "installed", "persisted", or "failed: <reason>" -- a string rather than a raise,
    because this crosses a fork boundary and one user's bad home must not end the run.
    """
    try:
        extdir.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError as e:
        return f"failed: could not create {extdir} ({e})"
    try:
        # mkdir's mode is masked by umask and does nothing for a directory that existed.
        os.chmod(extdir, 0o755)
    except OSError as e:
        debug_print(f"Could not set the mode on {extdir}: {e}")

    # Read before the write, or every run would look like a first one.
    state = "persisted" if target.exists() else "installed"

    if not handle_shadow_files(extdir):
        return "failed: a shadowing file could not be moved aside"

    # A symlink planted at index.js by the user is refused rather than written through --
    # the same guard O_NOFOLLOW gave us, kept explicit now that the bytes go to a temp file
    # and are renamed into place. os.replace would replace the link rather than follow it,
    # which is safe, but refusing is the behaviour this installer already promises.
    try:
        if os.path.islink(str(target)):
            return f"failed: {target} is a symlink"
    except OSError as e:
        return f"failed: could not inspect {target} ({e})"

    # Write a sibling temp file and rename it in, never O_TRUNC on the target. A truncating
    # write that then fails leaves a previously working extension truncated in that user's
    # home, and pi loads the broken file silently -- the user is unprotected with no error
    # anywhere. os.replace is atomic within a directory.
    tmp = target.with_name(target.name + ".unbound-tmp")
    # O_EXCL belongs to the TEMP file only -- it must never be reused for a destination that
    # legitimately already exists, which is how a shared `flags` variable silently turned
    # every repeat fleet push into a stale sidecar.
    tmp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        # A temp left by an earlier killed run must not fail the O_EXCL open.
        try:
            os.unlink(str(tmp))
        except FileNotFoundError:
            pass
        fd = os.open(str(tmp), tmp_flags, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            # fsync before the rename, or a crash can publish a name whose bytes never
            # reached the disk.
            os.fsync(f.fileno())
        try:
            # 0644 so pi can read it; O_CREAT's mode is masked by umask, so set it
            # explicitly before publishing the name.
            os.chmod(str(tmp), 0o644)
        except OSError as e:
            debug_print(f"Could not set the mode on {tmp}: {e}")
        os.replace(str(tmp), str(target))
    except OSError as e:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        return f"failed: could not write {target} ({e})"

    # Re-read from disk, so the hook_hash this device reports is provably the bytes in the
    # home rather than the bytes we downloaded.
    if artifact_sha256(target) != digest:
        return "failed: the bytes written do not match the verified artifact"

    # O_TRUNC, not O_EXCL: on every push after the first this file already exists, and an
    # EEXIST swallowed here would leave the previous digest next to new bytes -- so
    # `shasum -a 256 -c` would fail in every managed home and no later run could repair it.
    # O_NOFOLLOW still refuses a symlink planted in its place.
    sidecar_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(str(sidecar), sidecar_flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{digest}  index.js\n")
    except OSError as e:
        debug_print(f"Could not write the local sidecar: {e}")

    return state


def install_for_user(username: str, home_dir, payload: bytes, digest: str) -> str:
    """Drop the verified extension into one user's home. "installed"/"persisted"/"failed: …".

    Never raises: the caller is a loop over every account on the device, and one unwritable
    home must cost that user their coverage and nothing more.
    """
    agent_dir = resolve_agent_dir(home_dir)
    if agent_dir is None:
        return "failed: no absolute home directory to install under"
    extdir = extension_dir(agent_dir)
    target = artifact_path(agent_dir)
    sidecar = sidecar_path(agent_dir)

    # A previous root-context run can leave these root-owned, which the dropped user then
    # cannot write. Repair first (symlink- and hardlink-guarded), then drop.
    _repair_user_ownership(username, [Path(home_dir), agent_dir.parent, agent_dir,
                                      extdir.parent, extdir, target, sidecar])

    result = _run_as_user(username, _drop_in_home, extdir, target, sidecar, payload, digest)
    if not isinstance(result, str):
        return "failed: the privilege-dropped write did not complete"
    return result


def detect_install_state(user_homes) -> str:
    """'persisted' when any enumerated home already carries the extension, else 'fresh'.

    Device-scope and read BEFORE the loop, so "persisted" means "this device already had
    it". 'tampered', the backend's third value, is never reported: it means "managed config
    present but hook script gone", and pi has no managed config to compare against.
    """
    try:
        for _, home_dir in user_homes:
            agent_dir = resolve_agent_dir(home_dir)
            if agent_dir is not None and artifact_path(agent_dir).exists():
                return "persisted"
        return "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


# --- the per-application key --------------------------------------------------------------


def fetch_api_key_from_mdm(base_url: str, app_name: Optional[str], auth_api_key: str,
                           device_id: str) -> Optional[str]:
    """Exchange the admin key for this org's pi application key. None on any failure.

    `app_type=pi` is what makes the backend mint a PI application key rather than a
    `default` one (device_handlers.py VALID_APP_TYPES already contains it). The params are
    urlencoded because a serial number can contain a space or an `&`, either of which would
    otherwise truncate or inject query parameters.
    """
    query = [("serial_number", device_id), ("app_type", "pi")]
    if app_name:
        query.insert(0, ("app_name", app_name))
    params = urllib.parse.urlencode(query)
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"
    debug_print(f"Fetching the pi application key from: {url}")

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
            print("❌ Failed to fetch the pi application key")
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
        print("❌ Failed to fetch the pi application key")
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
    """The login-shell files an `export` line has to land in, per platform."""
    system = platform.system().lower()
    home_dir = Path(home_dir)
    if system == "darwin":
        return [home_dir / ".zprofile", home_dir / ".bash_profile"]
    if system == "linux":
        return [home_dir / ".zshrc", home_dir / ".bashrc"]
    return []


def append_to_file(file_path: Path, line: str, var_name: Optional[str] = None) -> bool:
    """Append `line` to `file_path` exactly once. With `var_name`, any previous
    `export <var_name>=` line is dropped first, so a repeated MDM push rotates the value
    rather than growing the file.

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
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                lines = []
        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]
        normalized_line = line.rstrip()
        if not any(l.rstrip() == normalized_line for l in lines):
            lines.append(f"{line}\n")
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return True
    except Exception as e:
        print(f"Failed to modify {file_path}: {e}")
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
                if append_to_file(rc_file, export_line, var_name):
                    _success = True
                    if not exists_already:
                        _changed = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
        # A list, not a tuple: this value crosses the privilege drop as json, which has no
        # tuple type, so returning a list keeps the round trip lossless by construction.
        return [_success, _changed]

    _repair_user_ownership(username, rc_files)
    result = _run_as_user(username, _do)
    if not isinstance(result, list) or len(result) != 2:
        debug_print(f"Could not set {var_name} for {username}")
        return False, False
    return bool(result[0]), bool(result[1])


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
                with open(rc_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if not l.strip().startswith(export_prefix)]
                if len(new_lines) < len(lines):
                    with open(rc_file, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
                    cleared = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")
                had_error = True
        if cleared:
            return "cleared"
        return "failed" if had_error else "not_found"

    result = _run_as_user(username, _do)
    return result if result in ("cleared", "not_found", "failed") else "failed"


def write_unbound_config_for_user(username: str, home_dir, api_key: str,
                                  urls: Optional[dict] = None) -> bool:
    """Merge the key and the tenant URLs into one user's ~/.unbound/config.json.

    An rc export is invisible to an already-open shell and to a GUI-launched pi, so this is
    what makes the CURRENT session work. Privilege-drops before any filesystem op.
    """
    home_dir = Path(home_dir)
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"

    # A previous root-context run can leave these root-owned; repair (symlink-guarded)
    # before dropping, or the write below fails EACCES.
    _repair_user_ownership(username, [config_dir, config_file])

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
            except (json.JSONDecodeError, OSError):
                config = {}
        if not isinstance(config, dict):
            config = {}
        # DELIBERATE DIVERGENCE from augment/hooks/mdm/setup.py:770, which assigns
        # config['api_key'] unconditionally. This file is the shared identity store for
        # unbound-cli and five other tools (Cursor, Claude Code, Codex, Copilot, Augment):
        # on a device where the user has run `unbound login`, overwriting api_key would
        # silently repoint ALL of them at this device key. setdefault writes it only when
        # there is nothing there to lose.
        config.setdefault("api_key", api_key)
        if urls:
            # URLs are tenant configuration, not identity, so they DO update unconditionally.
            config.update({k: v for k, v in urls.items() if v})
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(str(config_file), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
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
    """Remove one file we wrote. "cleared"/"not_found"/"failed", never raises."""
    path = Path(path)
    try:
        if not path.exists():
            return "not_found"
        path.unlink()
        return "cleared"
    except Exception as e:
        debug_print(f"Failed to clear {label}: {e}")
        return "failed"


def _clear_in_home(extdir: Path) -> List[str]:
    """Remove our two files from one extension dir. Runs with privileges dropped."""
    return [_clear_path(extdir / name, name) for name in INSTALLED_NAMES]


def clear_setup() -> bool:
    """Undo this installer across every home: our two files, and our export line.

    Never touches ~/.unbound/config.json -- its api_key is shared with five other tools, so
    removing it would log the user out of all of them. Posts nothing: install_state is an
    install-time enum with no uninstall value, and no installer in this repo reports a clear.
    """
    print("=" * 60)
    print("Pi Coding Agent Extension - Clearing MDM Setup")
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

    any_failed = False
    for username, home_dir in user_homes:
        if home_dir is not None:
            agent_dir = resolve_agent_dir(home_dir)
            if agent_dir is None:
                print(f"  {username}: skipped (no absolute home)")
                continue
            extdir = extension_dir(agent_dir)
            _repair_user_ownership(username, [extdir, artifact_path(agent_dir),
                                              sidecar_path(agent_dir)])
            statuses = _run_as_user(username, _clear_in_home, extdir)
            if statuses is None:
                any_failed = True
                statuses = ["failed"] * len(INSTALLED_NAMES)
            elif "failed" in statuses:
                any_failed = True
            files = ", ".join(f"{n}: {s}" for n, s in zip(INSTALLED_NAMES, statuses))
        else:
            files = "n/a"
        env_status = remove_env_var_from_user(username, home_dir, ENV_API_KEY_PI)
        if env_status == "failed":
            any_failed = True
        print(f"  {username}: {files}; {ENV_API_KEY_PI}: {env_status}")

    print("\nThe extension directories, and every other file in them, were left in place.")
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
        print(f"  {(username or '?').ljust(width)}  extension: {extension}; key: {key}")
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
    print("Pi Coding Agent Extension - MDM Setup")
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

    print("\nFetching the pi application key...")
    # Once per device, not once per home: the endpoint is keyed on (app_name,
    # serial_number) and carries no user, so a per-user fetch would return the identical
    # key while multiplying a fleet-wide push by the number of accounts on the machine.
    api_key = fetch_api_key_from_mdm(args["backend_url"], args["app_name"],
                                     args["api_key"], device_id)
    if not api_key:
        print("❌ Could not obtain the pi application key; refusing to install a keyless")
        print("   extension, which would be inert and would look installed.")
        return False

    print("\nFetching the extension...")
    fetched = fetch_artifact()
    if fetched is None:
        return False
    payload, digest = fetched

    urls = {"base_url": args["backend_url"], "gateway_url": args["gateway_url"],
            "frontend_url": args["frontend_url"]}

    rows = []
    installed_any = False
    for username, home_dir in user_homes:
        print(f"\n--- {username} ---")
        extension_status = install_for_user(username, home_dir, payload, digest)
        if extension_status in ("installed", "persisted"):
            installed_any = True
        env_ok, _ = set_env_var_for_user(username, home_dir, ENV_API_KEY_PI, api_key)
        config_ok = write_unbound_config_for_user(username, home_dir, api_key, urls=urls)
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
            api_key, "pi", backend_url=args["backend_url"], install_state=install_state,
            serial_number=device_id, hook_hash=digest, install_mode="mdm",
        )
    except Exception as e:
        # notify_setup_complete swallows internally, so this is belt-and-braces -- but the
        # rule is absolute: nothing about reporting may change whether the install succeeded,
        # because the extension is on disk and enforcing either way.
        debug_print(f"The report raised out of notify_setup_complete: {e}")
        reported = None
    if reported is not True:
        print("⚠️  Could not report this install to the backend. Install-state reporting is")
        print("   best-effort and does not change the outcome above.")

    if not installed_any:
        print("❌ The extension reached no user on this device. See the table above.")
        return False

    print("=" * 60)
    print("✅ Setup complete")
    print("   Each user picks the extension up the next time they start pi.")
    print("   Reminder: pi has no managed config, so --no-extensions or a redirected")
    print("   PI_CODING_AGENT_DIR bypasses it. See pi/mdm/README.md.")
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
