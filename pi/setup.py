#!/usr/bin/env python3
"""Install the Unbound extension for the Pi Coding Agent, for the current user.

What lands on disk: one file, `<agent dir>/extensions/unbound/index.js`, mode 0644,
fetched from this repo's raw GitHub URL. `<agent dir>` is `PI_CODING_AGENT_DIR` when it
names an absolute path, otherwise `~/.pi/agent` -- resolved by exactly the rules the
extension itself uses (see resolve_agent_dir).

Why the file must be `index.js` and nothing else: the artifact is a generated
dependency-free JavaScript bundle, and pi resolves `index.ts` BEFORE `index.js` in an
extension directory. A stale `index.ts` therefore wins silently -- pi starts, logs no
load error, and no policy check ever fires. So this installer moves any `index.ts` aside
before writing, rather than leaving it to shadow us.

About the sha256 sidecar: `pi/index.js.sha256` is fetched from the same origin, over the
same TLS, from the same ref as the artifact itself. It catches a truncated or corrupt
download and a stale-vs-fresh mismatch, and it gives the backend an honest `hook_hash`.
It is NOT a supply-chain control -- anyone who could replace the artifact could replace
the sidecar in the same commit. Said plainly here so the reader of the installer knows
exactly how much assurance this is.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple


# Same host and ref as every other artifact this repo fetches (setup.js:14). The sidecar
# is deliberately derived from the artifact URL so the two can never point at different refs.
ARTIFACT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/pi/index.js"
SHA_URL = ARTIFACT_URL + ".sha256"

DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

# The pi release this extension was built and smoke-tested against. Preflight warns when
# the installed pi is older; it never refuses, because an old pi still loads the bundle.
TESTED_PI_VERSION = "0.87.1"

# hooks-ts/packages/core/src/constants.ts:27 PI_AGENT_DIR_SEGMENTS -- keep in lockstep.
PI_AGENT_DIR_SEGMENTS = (".pi", "agent")
ENV_PI_AGENT_DIR = "PI_CODING_AGENT_DIR"

# Files in the extension dir that pi would resolve before our index.js, so they have to
# be moved out of the way, and files that merely change resolution, which only warn.
SHADOW_NAMES = ("index.ts",)
WARN_NAMES = ("package.json",)
DISABLED_SUFFIX = ".unbound-disabled"

# Exactly the files this installer writes, and so exactly what --clear may remove.
INSTALLED_NAMES = ("index.js", "index.js.sha256")

DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(domain: str) -> str:
    """Accept a bare host or a full URL and return a scheme-qualified, unslashed base."""
    domain = domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"
    return url.rstrip('/')


def _expand_tilde(raw, home_dir: str) -> Optional[str]:
    """Expand a leading `~` against an EXPLICIT home, never against the process env.

    Mirrors expandTilde in hooks-ts/packages/core/src/cache.ts. os.path.expanduser would
    read HOME instead, which is the wrong home the moment this runs for another user.
    """
    if not isinstance(raw, str):
        return None
    trimmed = raw.strip()
    if not trimmed:
        return None
    if trimmed == "~":
        return home_dir
    if trimmed.startswith("~/"):
        return os.path.join(home_dir, trimmed[2:])
    return trimmed


def resolve_agent_dir(home, env=None) -> Optional[Path]:
    """The pi agent directory, resolved exactly as resolveCachePath does.

    hooks-ts/packages/core/src/cache.ts:68-95 is the authority: PI_CODING_AGENT_DIR wins,
    `~` and `~/x` expand against home, and anything that is not absolute after that --
    including a RELATIVE value like `pitest` -- falls back to the home default.

    The relative case is the one that matters: resolving it against the process cwd would
    write the extension into whatever directory the CLI happened to run from, where pi
    never looks, and the install would still report success. Returns None when there is
    no safe absolute base at all, rather than guessing one.
    """
    env = os.environ if env is None else env
    home_str = "" if home is None else str(home)
    base = _expand_tilde(env.get(ENV_PI_AGENT_DIR), home_str)
    if base is None or not os.path.isabs(base):
        if not home_str or not os.path.isabs(home_str):
            return None
        base = os.path.join(home_str, *PI_AGENT_DIR_SEGMENTS)
    if not os.path.isabs(base):
        return None
    return Path(base)


def extension_dir(agent_dir) -> Path:
    """`<agent dir>/extensions/unbound` -- one directory per extension, ours is `unbound`."""
    return Path(agent_dir) / "extensions" / "unbound"


def artifact_path(agent_dir) -> Path:
    """The single file this installer writes. `.js`, because the artifact is a JS bundle."""
    return extension_dir(agent_dir) / "index.js"


def sidecar_path(agent_dir) -> Path:
    """The digest written next to the artifact, so a later --clear can remove both."""
    return extension_dir(agent_dir) / "index.js.sha256"


def _version_tuple(raw) -> Optional[tuple]:
    """(0, 87, 1) from `0.87.1`, or None for anything that is not a dotted number."""
    try:
        return tuple(int(part) for part in raw.strip().split(".")[:3])
    except (ValueError, AttributeError):
        return None


def preflight() -> bool:
    """Report on the local pi install. Always returns True -- never blocks the install.

    pi installs to ~/.local/bin rather than an npm global prefix, so there is no package
    root to probe; `pi --version` prints a bare version and that is the whole check.
    Installing the extension before pi is a supported order: pi picks it up on next start.
    """
    pi_path = shutil.which("pi")
    if not pi_path:
        print("⚠️  pi was not found on PATH. The extension will be installed anyway and")
        print("   picked up the first time pi runs; add pi to PATH to use it now.")
        return True
    debug_print(f"Found pi at {pi_path}")
    version = None
    try:
        result = subprocess.run(["pi", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout:
            tokens = result.stdout.split()
            version = tokens[0] if tokens else None
    except Exception as e:
        # A pi that cannot be run is a warning at most; the extension is inert until it can.
        debug_print(f"Could not read pi --version: {e}")
    if not version:
        print("⚠️  Could not read the pi version; continuing.")
        return True
    found = _version_tuple(version)
    tested = _version_tuple(TESTED_PI_VERSION)
    if found is not None and tested is not None and found < tested:
        print(f"⚠️  pi {version} is older than the tested {TESTED_PI_VERSION}; the extension")
        print("   should still load, but upgrade pi if policy checks do not appear.")
        return True
    print(f"✅ pi {version} detected.")
    return True


def download_file(url: str, dest_path) -> bool:
    """curl one URL to one path. Returns False on any failure and never raises."""
    dest_path = Path(dest_path)
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(
            ["curl", "-fsSL", "-o", str(dest_path), url],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            debug_print(f"File downloaded successfully: {dest_path}")
        return result.returncode == 0
    except Exception as e:
        # A missing curl or a timed-out fetch is a refusal, not a traceback.
        print(f"❌ Failed to download {url}: {e}")
        return False


def artifact_sha256(path) -> Optional[str]:
    """sha256 of the bytes on disk, or None when the file is missing or unreadable.

    Deliberately NOT named hook_script_hash: tests/test_setup_contract.py asserts that
    exactly 10 installers define that name, and pi ships no unbound.py hook script -- what
    is hashed here is the extension bundle itself.
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
        # The committed sidecar is generated from the repo root, so the path is pi/index.js;
        # a line naming anything else is a sidecar for a different artifact.
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


def _next_free_name(path) -> Path:
    """`path`, or `path.1`, `path.2`, ... -- the first name nothing occupies.

    A developer's own file is moved aside, never overwritten and never deleted, so a
    second run with a second index.ts must not land on the first one's grave.
    """
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

    pi resolves index.ts BEFORE index.js in an extension directory, so a leftover .ts
    wins silently: pi starts, logs no load error, and no policy check ever fires. A
    sibling package.json can change module resolution too, but not shadow us outright,
    so it only warns.
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


def detect_install_state(path) -> str:
    """'persisted' when the extension is already on this device, else 'fresh'.

    'tampered', the backend's third value, belongs to the managed path only -- a
    user-level install is not tamper-eligible, so it is never reported here.
    """
    try:
        return "persisted" if Path(path).exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


def install_extension(agent_dir) -> Optional[str]:
    """Fetch, verify and drop the extension. Returns the digest written, or None.

    Nothing is written until the downloaded bytes match the downloaded sidecar, so a
    truncated or stale artifact can never become an installed extension -- and the
    returned digest is of the bytes on disk, which is what gets reported as hook_hash.
    """
    if agent_dir is None:
        print("❌ Could not work out where pi keeps its agent directory; nothing installed.")
        return None

    extdir = extension_dir(agent_dir)
    target = artifact_path(agent_dir)
    staging = None
    try:
        # A 0700 staging dir, so a partly-downloaded artifact is never visible to pi and
        # is not readable by other users on a shared host.
        staging = tempfile.mkdtemp(prefix=".unbound-pi.")
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
            print(f"   {SHA_URL} expects {str(expected)[:16]}...")
            print(f"   the downloaded bytes are {str(computed)[:16]}...")
            print("   Nothing was written; the existing install, if any, is untouched.")
            return None

        if not handle_shadow_files(extdir):
            return None

        try:
            extdir.mkdir(mode=0o755, parents=True, exist_ok=True)
        except OSError as e:
            print(f"❌ Could not create {extdir}: {e}")
            return None
        try:
            # mkdir's mode is masked by umask, and does nothing for a dir that existed.
            os.chmod(extdir, 0o755)
        except OSError as e:
            debug_print(f"Could not set the mode on {extdir}: {e}")

        try:
            payload = staged.read_bytes()
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
        except OSError as e:
            print(f"❌ Could not write {target}: {e}")
            return None
        try:
            # 0644 so pi can read it and nothing else can quietly edit it; O_CREAT's mode
            # is masked by umask and is ignored entirely when the file already existed.
            os.chmod(target, 0o644)
        except OSError as e:
            debug_print(f"Could not set the mode on {target}: {e}")

        written = artifact_sha256(target)
        if written != computed:
            print(f"❌ {target} does not match what was verified; refusing to report it.")
            return None

        # Written next to the artifact so --clear can remove it and a human can check the
        # install by hand with `shasum -a 256 -c index.js.sha256`.
        try:
            fd = os.open(str(sidecar_path(agent_dir)), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"{written}  index.js\n")
        except OSError as e:
            debug_print(f"Could not write the local sidecar: {e}")

        print(f"✅ Installed the Unbound extension: {target} ({len(payload)} bytes, 0644)")
        return written
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


def _clear_path(path, label: str) -> str:
    """Remove one file we wrote. Returns "cleared"/"not_found"/"failed", never raises."""
    path = Path(path)
    if not path.exists():
        return "not_found"
    try:
        path.unlink()
        debug_print(f"Removed {path}")
        return "cleared"
    except Exception as e:
        print(f"Failed to clear {label}: {e}")
        return "failed"


def clear_setup() -> bool:
    """Undo this installer: remove the two files it wrote, and nothing else.

    Everything is derived from HOME and the env -- no API key, no network call. The shared
    contract test runs this against a pristine HOME with only HOME/PATH/SHELL set, so any
    other input would turn that into a traceback. In particular ~/.unbound/config.json is
    never opened: its api_key is shared with five other tools.
    """
    print("=" * 60)
    print("Pi Coding Agent Extension - Clearing Setup")
    print("=" * 60)

    agent_dir = resolve_agent_dir(Path.home(), os.environ)
    if agent_dir is None:
        # No absolute home means we could never have written anything under one.
        print("Could not resolve a home directory; nothing to clear.")
        return True

    extdir = extension_dir(agent_dir)
    print(f"Extension directory: {extdir}")

    any_cleared = False
    any_failed = False
    for name in INSTALLED_NAMES:
        status = _clear_path(extdir / name, f"pi extension {name}")
        print(f"  {name}: {status}")
        if status == "cleared":
            any_cleared = True
        elif status == "failed":
            any_failed = True

    if any_cleared:
        print("Cleared. The directory and any other file in it were left in place.")
    elif not any_failed:
        print("Nothing was installed here, so nothing was removed.")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)

    return not any_failed


def _flag_value(argv, flag: str) -> Optional[str]:
    """The token after `flag`, or None -- including when `flag` is the last token."""
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def parse_args(argv) -> dict:
    """The five flags unbound-cli passes (setup.js:256-267), plus --clear and --debug.

    URLs are normalized here; --domain is kept verbatim because it is also used to build
    the browser callback URL, where the raw value is what the user typed.
    """
    backend = _flag_value(argv, "--backend-url")
    gateway = _flag_value(argv, "--gateway-url")
    return {
        "api_key": _flag_value(argv, "--api-key"),
        "backend_url": normalize_url(backend) if backend else DEFAULT_BACKEND_URL,
        "gateway_url": normalize_url(gateway) if gateway else DEFAULT_GATEWAY_URL,
        "domain": _flag_value(argv, "--domain"),
        "clear": "--clear" in argv,
        "debug": "--debug" in argv,
    }


def main() -> bool:
    global DEBUG

    args = parse_args(sys.argv)
    if args["debug"]:
        DEBUG = True
        debug_print("Debug mode enabled")

    # --clear is answered before anything else: it needs no key and makes no network call.
    if args["clear"]:
        return clear_setup()

    print("=" * 60)
    print("Pi Coding Agent Setup for Unbound Gateway")
    print("=" * 60)

    preflight()

    agent_dir = resolve_agent_dir(Path.home(), os.environ)
    if agent_dir is None:
        print("❌ Could not resolve your home directory, so there is no safe place to install.")
        return False
    print(f"Agent directory: {agent_dir}")

    digest = install_extension(agent_dir)
    if not digest:
        return False

    # The key write and the backend report land in the next commit of this plan (Task 3).
    print("The API key write and the install report are not wired up yet in this commit.")
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
