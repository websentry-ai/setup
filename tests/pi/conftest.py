"""Fixtures for the pi installers.

The pi installers land in later waves; this file must collect cleanly before they
exist, so nothing here imports `pi/setup.py` at module scope. Loading happens inside
the `pi_setup` / `pi_mdm_setup` fixtures, by repo-relative path through
`tests.conftest.load_module` -- six tools ship a module of this basename, so a bare
`import setup` resolves to whichever directory wins sys.path.
"""

import json
from pathlib import Path

import pytest

from tests.conftest import REPO, load_module

# The three variables tests/test_setup_contract.py's pristine-HOME clear run allows.
# Anything else in the env would let a developer's own shell leak into an assertion.
MINIMAL_ENV_KEYS = ("HOME", "PATH", "SHELL")

# hooks-ts/packages/core/src/constants.ts:27 PI_AGENT_DIR_SEGMENTS.
PI_AGENT_SEGMENTS = (".pi", "agent")


class PiHome:
    """A throwaway HOME that looks like a machine with pi installed and unbound logged in."""

    def __init__(self, home):
        self.home = home
        self.agent_dir = home.joinpath(*PI_AGENT_SEGMENTS)
        self.unbound_dir = home / ".unbound"
        self.config_path = self.unbound_dir / "config.json"
        # Only the three keys the shared contract test allows, so a pi test cannot
        # accidentally depend on the developer's real environment.
        self.env = {
            "HOME": str(home),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "SHELL": "/bin/zsh",
        }

    def extension_dir(self, base=None):
        """`<base>/extensions/unbound` -- where index.js is dropped (RESEARCH B5)."""
        return Path(base or self.agent_dir) / "extensions" / "unbound"

    def write_config(self, data):
        """Plants an existing ~/.unbound/config.json so a test can prove it is not clobbered."""
        self.unbound_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(data))
        return self.config_path


class AgentDirCase:
    """One PI_CODING_AGENT_DIR state and the base the extension would resolve for it."""

    def __init__(self, name, env_value, expected_base):
        self.name = name
        self.env_value = env_value
        self.expected_base = Path(expected_base)

    def env(self, base_env):
        """The env dict to run an installer under; unset means the key is absent, not empty."""
        env = dict(base_env)
        env.pop("PI_CODING_AGENT_DIR", None)
        if self.env_value is not None:
            env["PI_CODING_AGENT_DIR"] = self.env_value
        return env

    def __repr__(self):
        return "AgentDirCase(%s)" % self.name


class CapturedReports(list):
    """A list of parsed setup_complete bodies that can attach itself to an installer."""

    def __init__(self, monkeypatch):
        super().__init__()
        self._monkeypatch = monkeypatch

    def poster(self):
        """The subprocess.run stand-in: curl gets the JSON body on stdin, never on argv."""

        def fake_run(cmd, **kw):
            payload = kw.get("input")
            if payload is not None:
                if isinstance(payload, bytes):
                    payload = payload.decode()
                try:
                    self.append(json.loads(payload))
                except ValueError:
                    # A non-JSON stdin write is some other curl call; record it verbatim.
                    self.append(payload)
            return _CompletedRun()

        return fake_run

    def attach(self, module):
        """Waves 1-2 call this to capture a real installer's report with no backend."""
        self._monkeypatch.setattr(module.subprocess, "run", self.poster())
        return self


class _CompletedRun:
    """Just enough of subprocess.CompletedProcess for an installer's success check."""

    returncode = 0
    stdout = ""
    stderr = ""


@pytest.fixture
def pi_home(tmp_path):
    """A fake HOME with ~/.pi/agent and ~/.unbound already present, plus a minimal env."""
    home = tmp_path / "home"
    home.joinpath(*PI_AGENT_SEGMENTS).mkdir(parents=True)
    (home / ".unbound").mkdir(parents=True)
    return PiHome(home)


@pytest.fixture
def agent_dir_cases(pi_home):
    """The four PI_CODING_AGENT_DIR states cache.ts:68-95 distinguishes.

    A relative value falls back to the home default -- it is never resolved against
    cwd, which is the one case an installer is most likely to get wrong (RESEARCH E2).
    """
    default = pi_home.agent_dir
    return [
        AgentDirCase("unset", None, default),
        AgentDirCase("absolute", str(pi_home.home / "abs-agent"), pi_home.home / "abs-agent"),
        AgentDirCase("tilde", "~/tilde-agent", pi_home.home / "tilde-agent"),
        AgentDirCase("relative", "relative-agent", default),
    ]


@pytest.fixture
def plant_shadow():
    """Plants the index.ts (or package.json) that pi resolves BEFORE index.js -- the
    silent-wrong-file-load the installer has to notice (RESEARCH B4)."""

    def _plant(extdir, name="index.ts", body="// a developer's own extension\n"):
        extdir = Path(extdir)
        extdir.mkdir(parents=True, exist_ok=True)
        path = extdir / name
        path.write_text(body)
        return path

    return _plant


@pytest.fixture
def fake_fetch(monkeypatch):
    """Answers the raw-GitHub artifact + sidecar fetch offline, keyed on the full URL,
    so a test can map pi/index.js and deliberately leave pi/index.js.sha256 unmapped."""

    def _install(mapping, module=None):
        calls = []

        def _download_file(url, dest, *args, **kwargs):
            calls.append(url)
            payload = mapping.get(url)
            if payload is None:
                # An unmapped URL is a 404: download_file returns False, never raises.
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


@pytest.fixture
def captured_reports(monkeypatch):
    """Captures the setup_complete body at the curl boundary -- the same trick
    test_setup_contract.py::_notify_body uses -- so a report is assertable with no backend."""
    return CapturedReports(monkeypatch)


@pytest.fixture
def pi_setup():
    """Loads pi/setup.py by repo-relative path; skips until the wave that writes it."""
    if not (REPO / "pi" / "setup.py").exists():
        pytest.skip("pi/setup.py lands in 10-01")
    return load_module("pi/setup.py")


@pytest.fixture
def pi_mdm_setup():
    """Loads pi/mdm/setup.py by repo-relative path; skips until the wave that writes it."""
    if not (REPO / "pi" / "mdm" / "setup.py").exists():
        pytest.skip("pi/mdm/setup.py lands in 10-02")
    return load_module("pi/mdm/setup.py")
