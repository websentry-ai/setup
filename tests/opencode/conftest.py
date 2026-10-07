"""Fixtures for the opencode installers.

Every test under tests/opencode runs inside a throwaway HOME: the autouse
`_isolated_home` fixture points HOME and Path.home() at a tmp dir and removes every
variable that could redirect the install (OPENCODE_CONFIG_DIR, XDG_CONFIG_HOME,
XDG_DATA_HOME, UNBOUND_*), then asserts before and after the test that Path.home()
is still under tmp_path. Nothing here can resolve the developer's real
~/.config/opencode, ~/.unbound or shell rc files.

The installer is loaded by repo-relative path through `tests.conftest.load_module`:
many tools ship a module named `setup`, so a bare import would pick whichever
directory wins sys.path.
"""

import builtins
import io
import json
import os
from pathlib import Path

import pytest

from tests.conftest import load_module

# hooks-ts/packages/opencode/src/constants.ts XDG_CONFIG_DEFAULT_SEGMENTS + OPENCODE_DIR_NAME.
OC_CONFIG_SEGMENTS = (".config", "opencode")

REDIRECTING_VARS = ("OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                    "OPENCODE_PURE", "HTTPS_PROXY", "https_proxy")

# A banner the stray-copy check recognises, as the committed bundle carries it.
UNBOUND_BANNER = (b"/**\n * GENERATED FILE - DO NOT EDIT.\n"
                  b" * Built from unbound-hooks-ts (packages/core + packages/opencode)\n */\n")


class OcHome:
    """A throwaway HOME. `config_dir` is the default opencode config dir under it."""

    def __init__(self, home):
        self.home = home
        self.config_dir = home.joinpath(*OC_CONFIG_SEGMENTS)
        self.unbound_dir = home / ".unbound"
        self.config_path = self.unbound_dir / "config.json"

    def plugins(self, base=None):
        return Path(base or self.config_dir) / "plugins"

    def write_config(self, data):
        """Plants an existing ~/.unbound/config.json so a test can prove it survives."""
        self.unbound_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(data))
        return self.config_path

    def snapshot(self, base=None):
        """{relative path: bytes} for every regular file under the config dir."""
        root = Path(base or self.config_dir)
        out = {}
        if not root.exists():
            return out
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                p = Path(dirpath) / name
                if p.is_symlink():
                    out[str(p.relative_to(root))] = ("link", os.readlink(p))
                else:
                    out[str(p.relative_to(root))] = p.read_bytes()
        return out


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in REDIRECTING_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("UNBOUND_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    assert str(Path.home()).startswith(str(tmp_path)), "Path.home() escaped the tmp dir"
    yield OcHome(home)
    assert str(Path.home()).startswith(str(tmp_path)), "Path.home() escaped the tmp dir"


# opencode's system managed config dirs (packages/opencode/src/config/managed.ts). No test may
# ever write, open or remove anything under them: the MDM installer's managed-reference step is
# pointed at a tmp dir through OPENCODE_TEST_MANAGED_CONFIG_DIR, exactly as opencode honours it.
SYSTEM_MANAGED_DIRS = ("/Library/Application Support/opencode", "/etc/opencode")
_GUARDED_OS_CALLS = ("open", "mkdir", "makedirs", "replace", "rename", "unlink", "remove",
                     "rmdir", "chmod", "chown", "lchown")


def _touches_system_managed_dir(path) -> bool:
    if isinstance(path, int) or path is None:
        return False
    try:
        raw = os.fspath(path)
    except TypeError:
        return False
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    full = os.path.normpath(os.path.join(os.getcwd(), raw)) if not os.path.isabs(raw) else os.path.normpath(raw)
    return any(full == d or full.startswith(d + "/") for d in SYSTEM_MANAGED_DIRS)


def _guarded(fn):
    def wrapped(path, *args, **kwargs):
        if _touches_system_managed_dir(path):
            raise AssertionError(f"a test reached the system managed opencode dir: {path!r}")
        return fn(path, *args, **kwargs)
    wrapped.__wrapped__ = fn
    return wrapped


@pytest.fixture(autouse=True)
def _no_system_managed_dir(tmp_path, monkeypatch):
    """Every test: managed dir = tmp, and the real system managed dirs are unreachable."""
    managed = tmp_path / "managed-opencode"
    monkeypatch.setenv("OPENCODE_TEST_MANAGED_CONFIG_DIR", str(managed))
    for name in _GUARDED_OS_CALLS:
        original = getattr(os, name)
        wrapper = _guarded(original)
        monkeypatch.setattr(os, name, wrapper)
        # Capability sets are keyed on function identity (`os.open in os.supports_dir_fd`);
        # the wrapper must keep every capability the original has.
        for cap in ("supports_dir_fd", "supports_fd", "supports_follow_symlinks",
                    "supports_effective_ids"):
            caps = getattr(os, cap, None)
            if isinstance(caps, set) and original in caps:
                monkeypatch.setattr(os, cap, caps | {wrapper})
    monkeypatch.setattr(builtins, "open", _guarded(builtins.open))
    monkeypatch.setattr(io, "open", _guarded(io.open))
    yield managed


@pytest.fixture
def oc_home(_isolated_home):
    return _isolated_home


@pytest.fixture
def oc_setup():
    """opencode/setup.py, loaded by repo-relative path."""
    return load_module("opencode/setup.py")


class CapturedReports(list):
    """Parsed setup_complete bodies, captured at the curl boundary (no backend)."""

    def __init__(self, monkeypatch):
        super().__init__()
        self._monkeypatch = monkeypatch
        self.fail = False

    def poster(self):
        def fake_run(cmd, **kw):
            payload = kw.get("input")
            if payload is not None:
                if isinstance(payload, bytes):
                    payload = payload.decode()
                try:
                    self.append(json.loads(payload))
                except ValueError:
                    self.append(payload)
            return _CompletedRun(1 if self.fail else 0)

        return fake_run

    def attach(self, module):
        self._monkeypatch.setattr(module.subprocess, "run", self.poster())
        return self


class _CompletedRun:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


@pytest.fixture
def captured_reports(monkeypatch):
    return CapturedReports(monkeypatch)


@pytest.fixture
def oc_mdm_setup():
    """opencode/mdm/setup.py, loaded by repo-relative path."""
    return load_module("opencode/mdm/setup.py")


# --- MDM fakes: no real root, no real /Users or /home ------------------------------------


def pw_row(name, uid, home):
    """A pwd.getpwall() row, shaped exactly like the real thing."""
    import pwd as real_pwd
    return real_pwd.struct_passwd((name, "*", uid, uid, "", str(home), "/bin/zsh"))


class FakePwd:
    """Stands in for the `pwd` module so a test controls the machine's user list."""

    def __init__(self, entries=(), raises=None):
        self._entries = list(entries)
        self._raises = raises

    def getpwall(self):
        if self._raises is not None:
            raise self._raises
        return list(self._entries)

    def getpwnam(self, name):
        for entry in self._entries:
            if entry.pw_name == name:
                return entry
        raise KeyError(name)


@pytest.fixture
def fake_homes(tmp_path):
    """Two user homes under a tmp `Users/` tree, shaped like an enumerated device."""
    made = []
    for name in ("alice", "bob"):
        home = tmp_path / "Users" / name
        home.mkdir(parents=True)
        made.append((name, home))
    return made


@pytest.fixture
def passthrough(oc_mdm_setup, monkeypatch):
    """Run the in-home function in-process instead of behind a real privilege drop,
    recording who it would have run as. That the drop happens at all is asserted
    separately; a real fork+setuid needs root."""
    calls = []

    def _fake(username, fn, *args, **kwargs):
        calls.append(username)
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None

    monkeypatch.setattr(oc_mdm_setup, "_run_as_user", _fake)
    return calls


@pytest.fixture
def fake_fetch(monkeypatch):
    """Answers the artifact + sidecar fetch offline, keyed on the full URL. An unmapped
    URL is a 404: download_file returns False, never raises."""

    def _install(mapping, module=None):
        calls = []

        def _download_file(url, dest, *args, **kwargs):
            calls.append(url)
            payload = mapping.get(url)
            if payload is None:
                return False
            dest = Path(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(payload, str):
                payload = payload.encode()
            dest.write_bytes(payload)
            return True

        _download_file.calls = calls
        if module is not None:
            monkeypatch.setattr(module, "download_file", _download_file)
        return _download_file

    return _install
