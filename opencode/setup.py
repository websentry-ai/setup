#!/usr/bin/env python3
"""Install the Unbound plugin for opencode, for the current user.

What lands on disk: `<config dir>/plugins/unbound.js`, mode 0644, fetched from this
repo's raw GitHub URL, plus `unbound.js.sha256` beside it so --clear and a human can
check what was installed. `<config dir>` is resolved by exactly the rules the plugin
itself uses (resolveOpencodeConfigDir in hooks-ts/packages/opencode/src/profile.ts):
an absolute (tilde-expanded) OPENCODE_CONFIG_DIR, else an absolute XDG_CONFIG_HOME
plus `/opencode`, else `~/.config/opencode` -- on macOS too, because opencode uses
xdg-basedir, which never answers ~/Library.

opencode loads every `*.{js,ts}` in `plugins/` (and in the legacy `plugin/`), so this
installer also removes stray copies of Unbound's own plugin that would load twice, and
it writes NO opencode config file: the plugin is picked up from the directory alone.

About the sha256 sidecar: `opencode/index.js.sha256` is fetched from the same origin,
over the same TLS, from the same ref as the artifact itself. It catches a truncated or
corrupt download and a stale-vs-fresh mismatch, and it gives the backend an honest
`hook_hash`. It is NOT a supply-chain control -- anyone who could replace the artifact
could replace the sidecar in the same commit. Said plainly here so the reader of the
installer knows exactly how much assurance this is.
"""

import hashlib
import http.server
import json
import os
import platform
import shutil
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Optional, Tuple


# Same host and ref as every other artifact this repo fetches (setup.js:14). The sidecar
# is deliberately derived from the artifact URL so the two can never point at different refs.
ARTIFACT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/opencode/index.js"
SHA_URL = ARTIFACT_URL + ".sha256"

DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"

MIN_PYTHON = (3, 8)

# hooks-ts/packages/opencode/src/constants.ts -- keep in lockstep with resolveOpencodeConfigDir.
ENV_OPENCODE_CONFIG_DIR = "OPENCODE_CONFIG_DIR"
ENV_XDG_CONFIG_HOME = "XDG_CONFIG_HOME"
CONFIG_DEFAULT_SEGMENTS = (".config",)
OPENCODE_DIR_NAME = "opencode"

PLUGIN_DIRNAME = "plugins"
PLUGIN_NAME = "unbound.js"
SIDECAR_NAME = "unbound.js.sha256"
MARKER_NAME = ".unbound-installed.json"

# The first key tier the plugin reads (then UNBOUND_API_KEY, then ~/.unbound/config.json).
ENV_API_KEY = "UNBOUND_OPENCODE_API_KEY"

# Exactly the files this installer always writes; package.json is added only when the
# marker says this installer created it.
INSTALLED_NAMES = (PLUGIN_NAME, SIDECAR_NAME)

# Older or hand-placed copies of Unbound's plugin that opencode would load BESIDE ours:
# it globs `*.{js,ts}` in both `plugins/` and the legacy `plugin/` directory. Relative to
# the config dir. Only files recognised as Unbound's bundle are ever removed.
STRAY_RELPATHS = (("plugin", "unbound.js"), ("plugins", "unbound.ts"), ("plugin", "unbound.ts"))
UNBOUND_BUNDLE_MARKER = b"unbound-hooks-ts"
BANNER_SCAN_BYTES = 4096

# The file extensions opencode loads as plugins from `plugins/`.
PLUGIN_SUFFIXES = (".js", ".ts")

# The opencode config files a stale `plugin` entry could live in. Read, never written.
OPENCODE_CONFIG_NAMES = ("opencode.json", "opencode.jsonc")
MAX_CONFIG_SCAN_BYTES = 1024 * 1024

# The v2 line (OpenCode 2.x / desktop) enforces since Phase 14 (hooks-ts/docs/OPENCODE.md,
# "opencode v2"). Kept identical in both installers; the bypass notes print separately.
V2_STATUS_NOTE = ("OpenCode 2.x is enforced: tool calls, MCP, prompts and the user shell are "
                  "checked, and approvals use OpenCode's native approval prompt.")

# Marks a publish-by-rename temp. The full name adds a pid and random bytes -- see
# _unique_tmp_path -- so two concurrent writers can never share one temp file.
TMP_MARKER = ".unbound-tmp"

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


def curl_with_auth(auth_headers, curl_args, *, input=None, timeout: int = 10):
    """Run curl with the secret auth header(s) kept OFF the argv.

    The curl argv is world-readable via `ps` and /proc/<pid>/cmdline, so passing
    `X-API-KEY: <key>` as `-H "<header>"` would leak the key on a shared host. Write the
    header line(s) to a 0600 temp file and pass `-H @<tmpfile>` instead, deleting it in a
    finally. Returns the CompletedProcess, or None if the header file could not be written.
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
        return subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


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


def _absolute_or_none(value) -> Optional[str]:
    return value if isinstance(value, str) and value and os.path.isabs(value) else None


def resolve_config_dir(home, env=None) -> Optional[Path]:
    """opencode's config directory, resolved exactly as resolveOpencodeConfigDir does.

    Twin of hooks-ts/packages/opencode/src/profile.ts -- keep in lockstep:
      1. OPENCODE_CONFIG_DIR, tilde-expanded against `home`, if absolute;
      2. else XDG_CONFIG_HOME (NOT tilde-expanded) + `/opencode`, if absolute;
      3. else `<home>/.config/opencode` if home is absolute (macOS included).
    A relative value falls through to the next source and is never resolved against the
    process cwd: that would install into whatever directory the CLI ran from, where
    opencode never looks, and still report success. None when no absolute base exists.
    """
    env = os.environ if env is None else env
    home_str = "" if home is None else str(home)
    override = _absolute_or_none(_expand_tilde(env.get(ENV_OPENCODE_CONFIG_DIR), home_str))
    if override is not None:
        return Path(override)
    xdg = _absolute_or_none(env.get(ENV_XDG_CONFIG_HOME))
    if xdg is not None:
        return Path(xdg) / OPENCODE_DIR_NAME
    if _absolute_or_none(home_str) is None:
        return None
    return Path(home_str).joinpath(*CONFIG_DEFAULT_SEGMENTS, OPENCODE_DIR_NAME)


def plugin_dir(config_dir) -> Path:
    """`<config dir>/plugins` -- opencode loads every *.js / *.ts in it as a plugin."""
    return Path(config_dir) / PLUGIN_DIRNAME


def plugin_path(config_dir) -> Path:
    """The plugin this installer writes. `.js`, because the artifact is an ESM JS bundle."""
    return plugin_dir(config_dir) / PLUGIN_NAME


def sidecar_path(config_dir) -> Path:
    """The digest written next to the plugin, so a later --clear can remove both."""
    return plugin_dir(config_dir) / SIDECAR_NAME


def marker_path(config_dir) -> Path:
    """Lists files this installer created that are not always ours (today: package.json)."""
    return plugin_dir(config_dir) / MARKER_NAME


def _unique_tmp_path(target: Path) -> Path:
    """A temp name beside `target` that belongs to this writer alone.

    One shared `<name>.unbound-tmp`, unlinked before every open, was a lost-update race with
    a silent wrong answer: writer B unlinks A's open temp, creates its own at the same name,
    and A's `os.replace` then publishes B's half-written file over the destination and
    reports success. With the pid and four random bytes in the name, O_EXCL means what it
    says and the failure path unlinks only our own.
    """
    return target.with_name(f"{target.name}{TMP_MARKER}.{os.getpid()}.{os.urandom(4).hex()}")


def _unlink_legacy_tmp(target: Path) -> None:
    """Remove the fixed-name temp an older killed run could have left behind."""
    try:
        os.unlink(str(target.with_name(target.name + TMP_MARKER)))
    except OSError:
        pass


def atomic_write_text(path, text: str, mode: int = 0o644, follow_symlink: bool = True) -> bool:
    """Replace one file's contents with no truncate-in-place window.

    A plain truncating open makes the destination the failure window: an interrupt, ENOSPC
    or EIO after that open leaves the file empty or half-written. os.replace is atomic
    within a directory.

    `follow_symlink` resolves a symlinked destination and rewrites the real file, because
    os.replace on the link path would swap the link for a regular file.
    """
    try:
        target = Path(os.path.realpath(str(path))) if follow_symlink else Path(path)
        tmp = _unique_tmp_path(target)
        try:
            _unlink_legacy_tmp(target)
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                # fsync before the rename, or a crash can publish a name whose bytes never
                # reached the disk.
                os.fsync(f.fileno())
            try:
                # O_CREAT's mode is masked by umask, so set it explicitly before publishing.
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


def preflight() -> bool:
    """Check python3 >= 3.8 (refuse below it) and report whether `opencode` is on PATH.

    The binary check only warns: the OpenCode desktop app puts no CLI on PATH, and
    installing the plugin before opencode is a supported order -- opencode picks the file
    up on its next start.
    """
    if tuple(sys.version_info[:2]) < MIN_PYTHON:
        found = ".".join(str(p) for p in tuple(sys.version_info[:3]))
        print(f"❌ This installer needs python3 3.8 or newer; found {found}. Nothing was written.")
        return False
    oc_path = shutil.which("opencode")
    if not oc_path:
        print("⚠️  opencode was not found on PATH. That is expected for the OpenCode desktop")
        print("   app; the plugin is installed anyway and loads the next time opencode starts.")
        return True
    print(f"✅ opencode found at {oc_path}")
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

    Deliberately NOT named hook_script_hash: tests/test_setup_contract.py counts the
    installers that define that name, and opencode ships no unbound.py hook script --
    what is hashed here is the plugin bundle itself.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def parse_sha256_sidecar(text) -> Optional[str]:
    """The digest out of a `shasum -a 256` line, or None if this is not one.

    Accepts a bare 64-hex line and the two-field `<digest>  <file>` form (including the
    `*` binary-mode marker). The filename column is not checked: the committed sidecar
    names `opencode/index.js` and the local one names `unbound.js`. Anything else --
    empty, wrong length, non-hex, extra fields -- returns None, which callers refuse.
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


def detect_install_state(path) -> str:
    """'persisted' when the plugin is already on this device, else 'fresh'.

    'tampered', the backend's third value, belongs to the managed path only -- a
    user-level install is not tamper-eligible, so it is never reported here.
    """
    try:
        return "persisted" if Path(path).exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


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


def remove_stray_copies(config_dir) -> bool:
    """Delete Unbound copies opencode would load beside ours. True when none remains.

    For `plugin/unbound.js`, `plugins/unbound.ts` and `plugin/unbound.ts`: a regular file
    carrying Unbound's build banner is deleted and reported; a symlink is never followed or
    removed; any other file is left byte-identical with a warning that opencode will load
    it too. Our own `plugins/unbound.js` is not a stray, and no other name is ever touched.
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
            print(f"⚠️  {path} is a symlink; left in place. If it points at a copy of the")
            print("   Unbound plugin, opencode loads it as well as ours -- remove it by hand.")
            continue
        if _is_unbound_bundle(path):
            try:
                os.unlink(str(path))
                print(f"🧹 Removed a stray Unbound copy at {rel} (opencode would load it twice).")
            except OSError as e:
                clean = False
                print(f"⚠️  Could not remove the stray Unbound copy {path}: {e}")
                print("   opencode will load it beside the new plugin; remove it by hand.")
            continue
        print(f"⚠️  {path} was left in place: it is not recognisably Unbound's,")
        print("   and opencode will load it beside the Unbound plugin.")
    return clean


def _other_plugin_files(pdir) -> list:
    """Every *.js / *.ts in plugins/ other than ours -- what opencode would also load."""
    try:
        names = os.listdir(str(pdir))
    except OSError:
        return []
    return sorted(n for n in names
                  if n != PLUGIN_NAME and n.endswith(PLUGIN_SUFFIXES))


def ensure_esm_marker(config_dir) -> str:
    """Create `plugins/package.json` = {"type":"module"} when, and only when, it is safe.

    Spike V1-4: under plain Node (not Bun) the ESM bundle fails to import when the nearest
    package.json says commonjs; a nested {"type":"module"} in plugins/ fixes it. So:
      * an existing plugins/package.json is never created over or modified;
      * if plugins/ holds any other *.js / *.ts, nothing is created (a module-type flip
        could break someone else's plugin) and a note is printed;
      * otherwise it is created, and recorded in `.unbound-installed.json` FIRST, so
        --clear can remove exactly what this installer created.
    Returns "exists" | "skipped" | "created" | "failed". Never raises.
    """
    pdir = plugin_dir(config_dir)
    pkg = pdir / "package.json"
    if os.path.lexists(str(pkg)):
        return "exists"
    others = _other_plugin_files(pdir)
    if others:
        print(f"ℹ️  Not creating {pkg}: other plugins live there ({', '.join(others[:3])}).")
        print('   If opencode runs on plain Node under a "type":"commonjs" package.json and the')
        print('   plugin fails to load, add {"type":"module"} there yourself.')
        return "skipped"
    try:
        pdir.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError as e:
        debug_print(f"Could not create {pdir}: {e}")
        return "failed"
    created = _read_marker(config_dir)
    if "package.json" not in created:
        created.append("package.json")
    if not atomic_write_text(marker_path(config_dir), json.dumps({"created": created}) + "\n",
                             0o644, follow_symlink=False):
        debug_print("Could not write the install marker; not creating package.json")
        return "failed"
    try:
        # O_EXCL: if a package.json appeared since the check, it is not ours to replace.
        fd = os.open(str(pkg), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(ESM_PACKAGE_JSON) + "\n")
        return "created"
    except OSError as e:
        debug_print(f"Could not create {pkg}: {e}")
        created.remove("package.json")
        if created:
            atomic_write_text(marker_path(config_dir), json.dumps({"created": created}) + "\n",
                              0o644, follow_symlink=False)
        else:
            _clear_path(marker_path(config_dir), "install marker")
        return "failed"


def _plugin_entry_mentions_unbound(text: str) -> bool:
    """Does a `"plugin"` key's value (array or string) mention unbound? Text scan only:
    the file is JSONC (comments, trailing commas) and is never parsed-and-rewritten."""
    idx = 0
    while True:
        idx = text.find('"plugin"', idx)
        if idx < 0:
            return False
        rest = text[idx + len('"plugin"'):].lstrip()
        idx += 1
        if not rest.startswith(":"):
            continue
        value = rest[1:].lstrip()
        if value.startswith("["):
            end = value.find("]")
            chunk = value[:end] if end >= 0 else value
        elif value.startswith('"'):
            end = value.find('"', 1)
            chunk = value[:end] if end >= 0 else value
        else:
            continue
        if "unbound" in chunk.lower():
            return True


def warn_on_config_plugin_entries(config_dir) -> list:
    """Warn about a `plugin` entry naming unbound in opencode.json[c]. Read-only.

    Such an entry loads a second copy beside `plugins/unbound.js`. The installer writes no
    opencode config file, so it says so and leaves the edit to the user. Returns the paths
    warned about.
    """
    warned = []
    for name in OPENCODE_CONFIG_NAMES:
        path = Path(config_dir) / name
        try:
            if not path.is_file():
                continue
            with open(path, "rb") as f:
                text = f.read(MAX_CONFIG_SCAN_BYTES).decode("utf-8", errors="replace")
        except OSError:
            continue
        if _plugin_entry_mentions_unbound(text):
            warned.append(path)
            print(f"⚠️  {path} has a \"plugin\" entry mentioning unbound. opencode would load")
            print("   Unbound twice (that entry and plugins/unbound.js). This installer never")
            print("   edits opencode config files; remove that entry by hand.")
    return warned


def _publish_bytes(target: Path, payload: bytes, mode: int = 0o644) -> bool:
    """Sibling temp + fsync + chmod + os.replace. Never truncates the target in place."""
    tmp = _unique_tmp_path(target)
    try:
        _unlink_legacy_tmp(target)
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(str(tmp), mode)
        except OSError as e:
            debug_print(f"Could not set the mode on {tmp}: {e}")
        os.replace(str(tmp), str(target))
        return True
    except OSError as e:
        print(f"❌ Could not write {target}: {e}")
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        return False


def install_plugin(config_dir) -> Optional[str]:
    """Fetch, verify and drop the plugin. Returns the digest written, or None.

    Nothing is written until the downloaded bytes match the downloaded sidecar, so a
    truncated or stale artifact can never become an installed plugin -- and the returned
    digest is of the bytes on disk, which is what gets reported as hook_hash.
    """
    if config_dir is None:
        print("❌ Could not work out where opencode keeps its config directory; nothing installed.")
        return None

    pdir = plugin_dir(config_dir)
    target = plugin_path(config_dir)
    staging = None
    try:
        # A 0700 staging dir, so a partly-downloaded artifact is never visible to opencode
        # and is not readable by other users on a shared host.
        staging = tempfile.mkdtemp(prefix=".unbound-opencode.")
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
                print(f"   {SHA_URL} is not a sha256 sidecar: {sidecar_text.strip()[:60]!r}")
            else:
                print(f"   {SHA_URL} expects {expected[:16]}...")
            print(f"   the downloaded bytes are {str(computed)[:16]}...")
            print("   Nothing was written; the existing install, if any, is untouched.")
            return None

        try:
            pdir.mkdir(mode=0o755, parents=True, exist_ok=True)
        except OSError as e:
            print(f"❌ Could not create {pdir}: {e}")
            return None

        # Order (chosen): only after verification passed, clean up strays and settle the
        # ESM package.json BEFORE publishing ours, so a refused download touches nothing,
        # and "other plugin files" is judged without our new file in the way. A stray that
        # cannot be removed only warns: a double load is noisy, but ours still enforces.
        remove_stray_copies(config_dir)
        ensure_esm_marker(config_dir)

        payload = staged.read_bytes()
        if not _publish_bytes(target, payload, 0o644):
            return None

        written = artifact_sha256(target)
        if written != computed:
            print(f"❌ {target} does not match what was verified; refusing to report it.")
            return None

        # Written next to the plugin so --clear can remove it and a human can check the
        # install by hand. Not a *.js/*.ts name, so opencode never loads it as a plugin.
        if not atomic_write_text(sidecar_path(config_dir), f"{written}  {PLUGIN_NAME}\n", 0o644,
                                 follow_symlink=False):
            debug_print("Could not write the local sidecar")

        print(f"✅ Installed the Unbound plugin: {target} ({len(payload)} bytes, 0644)")
        return written
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


def write_unbound_config(api_key: str, urls: Optional[dict] = None) -> bool:
    """Store the key in ~/.unbound/config.json, the store unbound-cli and other tools read.

    Read-merge-write rather than truncate: this file also holds the user's email, org and
    per-tool URLs. The api_key is set unconditionally because in the user path unbound-cli
    already handed us this user's own key -- the MDM installer is the one that must only
    write it when absent.

    A SYMLINKED config.json is refused rather than followed, because the plugin's reader
    lstats the path and treats a link as absent: writing through it would install a plugin
    that reads no key and stays silently inactive.
    """
    config_dir = Path.home() / ".unbound"
    config_file = config_dir / "config.json"
    if config_file.is_symlink():
        print(f"❌ {config_file} is a symlink, and the plugin refuses a symlinked config:")
        print("   it lstats that path and treats a link as absent, so a key written through")
        print("   the link would never be read -- the plugin would install and then stay")
        print("   silently inactive. Writing it would also copy this key to wherever the link")
        print("   points, typically a dotfiles repository.")
        print("   Replace the link with a regular file, then re-run.")
        return False
    try:
        if platform.system().lower() == "windows":
            config_dir.mkdir(parents=True, exist_ok=True)
        else:
            config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(config_dir, 0o700)
        except OSError as e:
            debug_print(f"Could not tighten {config_dir}: {e}")
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.loads(f.read())
            except json.JSONDecodeError:
                # Parsed as nothing, so there is nothing in it left to lose.
                config = {}
            except OSError as e:
                # A file we could not READ is a file we know nothing about: refuse rather
                # than publish a fresh object over this user's email, org and api_key.
                print(f"❌ Refusing to rewrite {config_file}, which could not be read: {e}")
                print("   Fix the permissions on that file and re-run, or export")
                print(f"   {ENV_API_KEY} in your shell.")
                return False
        if not isinstance(config, dict):
            config = {}
        config['api_key'] = api_key
        if urls:
            config.update({k: v for k, v in urls.items() if v})
        return atomic_write_text(config_file, json.dumps(config, indent=2), 0o600)
    except Exception as e:
        print(f"⚠️  Could not write config: {e}")
        return False


def run_callback_server(frontend_url: str) -> Optional[dict]:
    """Mint a key in the browser and catch it on a loopback one-shot server.

    Reached only when unbound-cli passed --domain but no --api-key. The app type in the
    callback URL must be `opencode`, or the console mints a key of the wrong app type.
    """
    result = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code: int = 200,
                    message: bytes = b"Logged in successfully! You can close this tab.") -> None:
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)
            except Exception:
                pass

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            result["method"] = "GET"
            result["path"] = self.path
            result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
            result["headers"] = {k: v for k, v in self.headers.items()}
            query = result["query"]
            if "error" in query:
                self._finish(code=400,
                             message=f"Setup failed: {query['error'][:200]}\nPlease try again or contact support.".encode())
            else:
                self._finish()
            done_evt.set()

        def log_message(self, format: str, *args) -> None:
            return

    class _CallbackServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        # Port 0 so a second concurrent setup cannot collide, and 127.0.0.1 so nothing
        # off-box can answer the callback in our place.
        httpd = _CallbackServer(("127.0.0.1", 0), CallbackHandler)
        port = httpd.server_address[1]
        callback_url = f"http://127.0.0.1:{port}/callback"

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        encoded_callback = urllib.parse.quote(callback_url, safe="")
        target_url = (f"{frontend_url.rstrip('/')}/automations/api-key-callback"
                      f"?callback_url={encoded_callback}&app_type=opencode")
        webbrowser.open(target_url)
        print("🌐 Opening browser...")
        print("If browser doesn't open automatically, open this link:")
        print(target_url)
        print("Waiting for authentication...")

        try:
            if not done_evt.wait(timeout=300):
                print("Timed out waiting for authentication (5 minutes). Please re-run setup.")
                return None
        finally:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        return result
    except Exception as e:
        print(f"❌ Failed to run callback server: {e}")
        return None


def get_device_identifier() -> Optional[str]:
    """The hardware serial, so the backend can tell two installs by one user apart."""
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=10
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
            result = subprocess.run(
                ["cat", "/sys/class/dmi/id/product_serial"],
                capture_output=True, text=True, timeout=10
            )
            serial = result.stdout.strip() if result.returncode == 0 else ""
            return serial or None
        if system == "windows":
            result = subprocess.run(
                ["wmic", "bios", "get", "serialnumber"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = [ln.strip() for ln in result.stdout.split('\n') if ln.strip()]
                if len(lines) >= 2 and lines[1].lower() != "serialnumber":
                    return lines[1]
            return None
        return None
    except Exception as e:
        # A serial is a nice-to-have; never fail an install for the want of one.
        debug_print(f"Failed to get device identifier: {e}")
        return None


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = DEFAULT_BACKEND_URL,
                          install_state: Optional[str] = None, serial_number: Optional[str] = None,
                          hook_hash: Optional[str] = None, install_mode: Optional[str] = None):
    """Tell the backend this tool is set up. Never fails the setup.

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


def _clear_path(path, label: str) -> str:
    """Remove one file we wrote. Returns "cleared"/"not_found"/"failed", never raises.

    lexists, not exists: a dangling symlink at one of our names is still ours to remove.
    """
    path = Path(path)
    if not os.path.lexists(str(path)):
        return "not_found"
    try:
        path.unlink()
        debug_print(f"Removed {path}")
        return "cleared"
    except Exception as e:
        print(f"Failed to clear {label}: {e}")
        return "failed"


def _read_marker(config_dir) -> list:
    """Names the marker says this installer created. Missing/corrupt -> [] (remove nothing extra)."""
    try:
        data = json.loads(marker_path(config_dir).read_text(encoding="utf-8"))
    except Exception:
        return []
    created = data.get("created") if isinstance(data, dict) else None
    if not isinstance(created, list):
        return []
    return [n for n in created if isinstance(n, str)]


ESM_PACKAGE_JSON = {"type": "module"}


def _is_our_package_json(path) -> bool:
    """True only for a regular file whose JSON is exactly {"type":"module"}."""
    try:
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            return False
        return json.loads(Path(path).read_text(encoding="utf-8")) == ESM_PACKAGE_JSON
    except Exception:
        return False


def clear_setup() -> bool:
    """Undo this installer: remove the files it wrote, and nothing else.

    Everything is derived from HOME and the env -- no API key, no network call. Removes
    unbound.js and its sidecar; removes plugins/package.json ONLY when the marker lists it
    and it is still exactly {"type":"module"}; then removes the marker. The plugins/
    directory is never removed, and ~/.unbound/config.json is never opened: its api_key
    is shared with other tools.
    """
    print("=" * 60)
    print("OpenCode Plugin - Clearing Setup")
    print("=" * 60)

    config_dir = resolve_config_dir(Path.home(), os.environ)
    if config_dir is None:
        # No absolute base means we could never have written anything under one.
        print("Could not resolve a home directory; nothing to clear.")
        return True

    pdir = plugin_dir(config_dir)
    print(f"Plugin directory: {pdir}")

    any_cleared = False
    any_failed = False
    for name in INSTALLED_NAMES:
        status = _clear_path(pdir / name, f"opencode plugin {name}")
        print(f"  {name}: {status}")
        if status == "cleared":
            any_cleared = True
        elif status == "failed":
            any_failed = True

    marker_failed = False
    if "package.json" in _read_marker(config_dir):
        pkg = pdir / "package.json"
        if not os.path.lexists(str(pkg)):
            print("  package.json: not_found")
        elif _is_our_package_json(pkg):
            status = _clear_path(pkg, "plugins/package.json")
            print(f"  package.json: {status}")
            if status == "cleared":
                any_cleared = True
            elif status == "failed":
                any_failed = marker_failed = True
        else:
            print("  package.json: left in place -- it was changed after this installer")
            print("  created it, so it is no longer only ours.")

    if not marker_failed:
        # Removed last, and kept when our package.json could not be removed, so a retry
        # still knows which file it owns.
        status = _clear_path(marker_path(config_dir), "install marker")
        if status == "failed":
            any_failed = True
        elif status == "cleared":
            debug_print("Removed the install marker")

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
    """The flags unbound-cli passes (setup.js), plus --clear and --debug.

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
    print("OpenCode Setup for Unbound Gateway")
    print("=" * 60)

    if not preflight():
        return False

    # Resolve the key before touching the network or the disk, so a run with no key at all
    # leaves the machine exactly as it found it.
    api_key = args["api_key"]
    domain = args["domain"]
    if not api_key:
        if not domain:
            print("❌ No API key. Run `unbound login` first, or pass --api-key <key>.")
            print("   Nothing was written.")
            return False
        cb_response = run_callback_server(normalize_url(domain))
        if cb_response is None:
            print("❌ Failed to receive the browser callback. Nothing was written.")
            return False
        query = {}
        try:
            query = cb_response.get("query") or {}
        except Exception as e:
            debug_print(f"Malformed callback response: {e}")
        api_key = query.get("api_key")
        if not api_key:
            error_msg = query.get("error")
            if error_msg:
                print(f"❌ Login failed: {error_msg}")
            else:
                print("❌ The callback returned no API key. Nothing was written.")
            return False

    config_dir = resolve_config_dir(Path.home(), os.environ)
    if config_dir is None:
        print("❌ Could not resolve your home directory, so there is no safe place to install.")
        return False
    print(f"opencode config directory: {config_dir}")

    # Read before the write, or every install would look like a first one.
    install_state = detect_install_state(plugin_path(config_dir))

    digest = install_plugin(config_dir)
    if not digest:
        return False

    if not write_unbound_config(api_key, {
        "base_url": args["backend_url"],
        "gateway_url": args["gateway_url"],
        "frontend_url": normalize_url(domain) if domain else None,
    }):
        print(f"❌ The plugin is installed at {plugin_path(config_dir)}, but the API key")
        print(f"   could not be saved to {Path.home() / '.unbound' / 'config.json'}.")
        print("   The plugin reads no key, so it will stay inactive. Fix the permissions")
        print(f"   on that file and re-run, or export {ENV_API_KEY} in your shell.")
        return False

    reported = notify_setup_complete(
        api_key, "opencode", backend_url=args["backend_url"], install_state=install_state,
        serial_number=get_device_identifier(), hook_hash=digest, install_mode="user",
    )
    if reported is not True:
        print("⚠️  Could not report this install to the backend. Install-state reporting is")
        print("   best-effort; the plugin is installed and enforces regardless.")

    warn_on_config_plugin_entries(config_dir)

    print("=" * 60)
    print("✅ Setup complete")
    print_closing_notes(config_dir, os.environ)
    print("=" * 60)
    return True


def print_closing_notes(config_dir, env) -> None:
    """Restart, remote-server, relocation, honest-scope, v2 and proxy notes."""
    print("   Restart opencode (quit and relaunch the OpenCode desktop app) to load the plugin.")
    print("   If you use `opencode serve`, `opencode attach` or the desktop app's background")
    print("   service on another machine, run this setup on the machine where the server runs.")
    override = _absolute_or_none(_expand_tilde(env.get(ENV_OPENCODE_CONFIG_DIR), str(Path.home())))
    if override is not None:
        print(f"   The plugin went to OPENCODE_CONFIG_DIR={override}. opencode must see the")
        print("   same OPENCODE_CONFIG_DIR at run time, or it will not load the plugin.")
    elif _absolute_or_none(env.get(ENV_XDG_CONFIG_HOME)) is not None:
        print(f"   The plugin went under XDG_CONFIG_HOME ({config_dir}). opencode must see the")
        print("   same XDG_CONFIG_HOME at run time, or it will not load the plugin.")
    print("   Not tamper-proof: `opencode --pure`, OPENCODE_PURE=1, or pointing")
    print("   XDG_CONFIG_HOME / OPENCODE_CONFIG_DIR elsewhere starts opencode without it.")
    print(f"   {V2_STATUS_NOTE}")
    proxy = env.get("HTTPS_PROXY") or env.get("https_proxy")
    if proxy:
        print("   HTTPS_PROXY is set: the plugin calls Unbound through opencode's own runtime")
        print("   fetch, so a corporate proxy CA must be trusted by that runtime (for example")
        print("   NODE_EXTRA_CA_CERTS), not only by your shell tools.")


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
