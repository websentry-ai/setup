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
import http.server
import json
import os
import platform
import shutil
import socketserver
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


def atomic_write_text(path, text: str, mode: int = 0o644, follow_symlink: bool = True) -> bool:
    """Replace one file's contents with no truncate-in-place window.

    A plain O_TRUNC open makes the destination the failure window: an interrupt, ENOSPC or
    EIO after that open leaves the file empty or half-written. Every durable file either
    installer writes goes through here, so the class is closed rather than one instance of
    it. os.replace is atomic within a directory.

    `follow_symlink` resolves a symlinked destination and rewrites the real file, because
    os.replace on the link path would swap the link for a regular file -- silently detaching
    a user who deliberately symlinks their own config somewhere.
    """
    try:
        target = Path(os.path.realpath(str(path))) if follow_symlink else Path(path)
        tmp = target.with_name(target.name + ".unbound-tmp")
        try:
            # A temp left by an earlier killed run must not fail the O_EXCL open.
            try:
                os.unlink(str(tmp))
            except FileNotFoundError:
                pass
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
            if expected is None:
                # A sidecar that is not a sha256 line at all: say that, rather than
                # printing "expected None" and looking like a digest mismatch.
                print(f"   {SHA_URL} is not a sha256 sidecar: {sidecar_text.strip()[:60]!r}")
            else:
                print(f"   {SHA_URL} expects {expected[:16]}...")
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

        # Write a sibling temp file and rename it into place, never O_TRUNC on the target.
        # A truncating in-place write that then fails (ENOSPC, EIO, a killed process) leaves
        # a previously working extension truncated, and pi loads the broken file silently --
        # enforcement disappears with no error anywhere. os.replace is atomic within a
        # directory, so index.js is either the old bytes or all of the new ones.
        tmp = target.with_name(target.name + ".unbound-tmp")
        try:
            payload = staged.read_bytes()
            # A temp left by an earlier killed run must not fail the O_EXCL open below.
            try:
                os.unlink(str(tmp))
            except FileNotFoundError:
                pass
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                # fsync before the rename, or a crash can publish a name whose bytes
                # never reached the disk.
                os.fsync(f.fileno())
            try:
                # 0644 so pi can read it and nothing else can quietly edit it; O_CREAT's
                # mode is masked by umask, so set it explicitly before publishing.
                os.chmod(str(tmp), 0o644)
            except OSError as e:
                debug_print(f"Could not set the mode on {tmp}: {e}")
            os.replace(str(tmp), str(target))
        except OSError as e:
            print(f"❌ Could not write {target}: {e}")
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            return None

        written = artifact_sha256(target)
        if written != computed:
            print(f"❌ {target} does not match what was verified; refusing to report it.")
            return None

        # Written next to the artifact so --clear can remove it and a human can check the
        # install by hand with `shasum -a 256 -c index.js.sha256`.
        if not atomic_write_text(sidecar_path(agent_dir), f"{written}  index.js\n", 0o644):
            debug_print("Could not write the local sidecar")

        print(f"✅ Installed the Unbound extension: {target} ({len(payload)} bytes, 0644)")
        return written
    finally:
        if staging:
            shutil.rmtree(staging, ignore_errors=True)


def write_unbound_config(api_key: str, urls: Optional[dict] = None) -> bool:
    """Store the key in ~/.unbound/config.json, the store unbound-cli and five tools read.

    Read-merge-write rather than truncate: this file also holds the user's email, org and
    per-tool URLs, and clobbering them would log the CLI out. The api_key is set
    unconditionally because in the user path unbound-cli already handed us this user's own
    key -- the MDM installer is the one that must only write it when absent.
    """
    config_dir = Path.home() / ".unbound"
    config_file = config_dir / "config.json"
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
            except (json.JSONDecodeError, OSError):
                # A hand-edited or truncated config is replaced rather than fatal.
                config = {}
        if not isinstance(config, dict):
            config = {}
        config['api_key'] = api_key
        if urls:
            config.update({k: v for k, v in urls.items() if v})
        # Atomic: this file is the shared identity store for six tools, so an interrupt
        # during the write would log the user out of all of them, not just pi.
        return atomic_write_text(config_file, json.dumps(config, indent=2), 0o600)
    except Exception as e:
        print(f"⚠️  Could not write config: {e}")
        return False


def run_callback_server(frontend_url: str) -> Optional[dict]:
    """Mint a key in the browser and catch it on a loopback one-shot server.

    Reached only when unbound-cli passed --domain but no --api-key, which is what it does
    when nothing was logged in (setup.js:259,262). The app type in the callback URL must be
    `pi`, or the console mints a `default` key that the extension will not accept.
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
                      f"?callback_url={encoded_callback}&app_type=pi")
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

    agent_dir = resolve_agent_dir(Path.home(), os.environ)
    if agent_dir is None:
        print("❌ Could not resolve your home directory, so there is no safe place to install.")
        return False
    print(f"Agent directory: {agent_dir}")

    # Read before the write, or every install would look like a first one.
    install_state = detect_install_state(artifact_path(agent_dir))

    digest = install_extension(agent_dir)
    if not digest:
        return False

    # The key write is NOT best-effort, unlike the report below. config.json is where the
    # extension reads the key from when neither env var is set, and on the browser-callback
    # path it is the only place the freshly minted key exists at all -- so a failed write
    # means an installed extension that stays inactive. Saying "Setup complete" there would
    # be the worst outcome: silent, and indistinguishable from success.
    if not write_unbound_config(api_key, {
        "base_url": args["backend_url"],
        "gateway_url": args["gateway_url"],
        "frontend_url": normalize_url(domain) if domain else None,
    }):
        print(f"❌ The extension is installed at {artifact_path(agent_dir)}, but the API key")
        print(f"   could not be saved to {Path.home() / '.unbound' / 'config.json'}.")
        print("   The extension reads no key, so it will stay inactive. Fix the permissions")
        print("   on that file and re-run, or export UNBOUND_PI_API_KEY in your shell.")
        return False

    reported = notify_setup_complete(
        api_key, "pi", backend_url=args["backend_url"], install_state=install_state,
        serial_number=get_device_identifier(), hook_hash=digest, install_mode="user",
    )
    if reported is not True:
        print("⚠️  Could not report this install to the backend. Install-state reporting is")
        print("   best-effort; the extension is installed and enforces regardless.")

    print("=" * 60)
    print("✅ Setup complete")
    print("   Start a new pi session to pick up the extension.")
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
