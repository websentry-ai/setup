"""Hermetic tests for setup_cmd._write_discovery_config (WEB-4808).

This is the WRITER side of the discovery-credential contract; its READER side
(the daemon entry point) is covered by test_discovery_entry.py. Together they
guard the only credential channel the scheduled root LaunchDaemon has.

What's asserted here:

  * the persisted file round-trips api_key + domain
  * the file is mode 0600 (it holds a credential)
  * the leaf `etc` dir is created 0750, NOT the umask-default world-traversable
    0755 (the directory-level barrier the 0600 file relies on — M1 hardening)
  * a missing grandparent (/opt/unbound absent) returns a reason string rather
    than silently building the whole tree, and never raises
  * a non-writable parent returns a reason string rather than raising
    (fail-open: a persist failure must never abort onboarding)

Hermetic: DISCOVERY_CONFIG_PATH is redirected into a tmp dir; nothing touches
/opt. The module is imported from binary/src without a built bundle.
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "binary" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from unbound_hook import setup_cmd  # noqa: E402


def _opts(discovery_key="disc-key", backend_url="https://backend.example.com"):
    # _write_discovery_config only reads these two keys.
    return {"discovery_key": discovery_key, "backend_url": backend_url}


def _provisioned_cfg_path(tmp_path):
    """A tmp analog of /opt/unbound/etc/discovery.json where the grandparent
    (the pkg-provisioned /opt/unbound) already exists but `etc` does not — the
    real production precondition."""
    opt_unbound = tmp_path / "opt" / "unbound"
    opt_unbound.mkdir(parents=True)
    return opt_unbound / "etc" / "discovery.json"


# --- happy path: round-trip, file mode, dir mode -----------------------------

def test_writes_creds_and_roundtrips(tmp_path, monkeypatch):
    cfg = _provisioned_cfg_path(tmp_path)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_CONFIG_PATH", cfg)

    err = setup_cmd._write_discovery_config(_opts())

    assert err is None, f"expected success, got reason: {err}"
    assert cfg.is_file()
    data = json.loads(cfg.read_text())
    assert data == {"api_key": "disc-key", "domain": "https://backend.example.com"}


def test_credential_file_is_0600(tmp_path, monkeypatch):
    cfg = _provisioned_cfg_path(tmp_path)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_CONFIG_PATH", cfg)

    assert setup_cmd._write_discovery_config(_opts()) is None

    mode = stat.S_IMODE(os.stat(cfg).st_mode)
    assert mode == 0o600, f"credential file mode {oct(mode)} != 0600"


def test_leaf_dir_created_0750_not_world_traversable(tmp_path, monkeypatch):
    cfg = _provisioned_cfg_path(tmp_path)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_CONFIG_PATH", cfg)

    assert setup_cmd._write_discovery_config(_opts()) is None

    mode = stat.S_IMODE(os.stat(cfg.parent).st_mode)
    # The leaf etc dir must not be world-traversable (no o+x); 0750 is the
    # target. (Root chmod-enforces 0750 exactly; non-root relies on makedirs'
    # mode arg, which umask may tighten further but never loosen the o-bits.)
    assert not (mode & stat.S_IXOTH), f"etc dir {oct(mode)} is world-traversable"
    assert not (mode & stat.S_IROTH), f"etc dir {oct(mode)} is world-readable"


# --- fail-open: a persist failure returns a reason, never raises -------------

def test_missing_grandparent_returns_reason(tmp_path, monkeypatch):
    """If /opt/unbound is absent, refuse (return reason) instead of building
    the whole tree world-readable — and do NOT raise."""
    # grandparent (the "/opt/unbound" analog) intentionally NOT created
    cfg = tmp_path / "opt" / "unbound" / "etc" / "discovery.json"
    monkeypatch.setattr(setup_cmd, "DISCOVERY_CONFIG_PATH", cfg)

    err = setup_cmd._write_discovery_config(_opts())

    assert isinstance(err, str) and err, "expected a reason string"
    assert not cfg.exists()
    assert not cfg.parent.exists(), "should not have created the etc tree"


def test_non_writable_parent_returns_reason(tmp_path, monkeypatch):
    """A pre-existing but non-writable etc dir yields a reason, not a crash."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory write permissions")
    etc = tmp_path / "opt" / "unbound" / "etc"
    etc.mkdir(parents=True)
    etc.chmod(0o500)  # r-x: cannot create the temp file inside
    monkeypatch.setattr(setup_cmd, "DISCOVERY_CONFIG_PATH", etc / "discovery.json")

    try:
        err = setup_cmd._write_discovery_config(_opts())
    finally:
        etc.chmod(0o700)  # restore so tmp_path cleanup can proceed

    assert isinstance(err, str) and err, "expected a reason string on write failure"
