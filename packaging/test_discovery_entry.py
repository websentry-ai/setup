"""Boundary tests for the unbound-discovery entry point's config resolution.

Exercises packaging/unbound_discovery_entry.py at its outermost in-process
seams — `main()` and the config resolver it delegates to — without needing a
built PyInstaller bundle or the upstream `coding_discovery_tools` package
(which is fetched only at build time from packaging/discovery.lock).

The behavior under test is WEB-4808: the scheduled root LaunchDaemon runs
`unbound-discovery scan` with NO --api-key/--domain flags and NO shell env, so
it must instead pick up credentials from the persisted root-only config file
/opt/unbound/etc/discovery.json. The two anchors:

  * config file present  -> resolves creds, proceeds to the real sweep
  * config file absent   -> idles fail-open and exits 0 (unchanged contract)

The upstream sweep is stubbed so we can assert main() reached it (the
credentialed path) and observe the creds it would run with, while keeping the
test hermetic.
"""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ENTRY_PATH = Path(__file__).resolve().parent / "unbound_discovery_entry.py"


def _load_entry():
    """Import the entry module fresh from source (it is not a package member)."""
    spec = importlib.util.spec_from_file_location("unbound_discovery_entry", ENTRY_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def entry(tmp_path, monkeypatch):
    """Entry module with the config path redirected into a temp dir and a
    stubbed `coding_discovery_tools.ai_tools_discovery` so the credentialed
    path is observable without the real upstream package."""
    mod = _load_entry()
    cfg_path = tmp_path / "discovery.json"
    monkeypatch.setattr(mod, "DISCOVERY_CONFIG_PATH", str(cfg_path))

    calls = {"sweep": 0}

    def fake_sweep():
        calls["sweep"] += 1
        # Capture what the sweep would actually run with: the entry feeds the
        # key via UNBOUND_API_KEY env and the domain via --domain argv.
        import argparse
        import os

        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("--domain")
        ns, _ = p.parse_known_args(sys.argv[1:])
        calls["api_key"] = os.environ.get("UNBOUND_API_KEY", "")
        calls["domain"] = ns.domain or ""
        return 0

    pkg = types.ModuleType("coding_discovery_tools")
    sub = types.ModuleType("coding_discovery_tools.ai_tools_discovery")
    sub.main = fake_sweep
    pkg.ai_tools_discovery = sub
    monkeypatch.setitem(sys.modules, "coding_discovery_tools", pkg)
    monkeypatch.setitem(sys.modules, "coding_discovery_tools.ai_tools_discovery", sub)

    # Default to a clean env so flags/env never leak across cases.
    monkeypatch.delenv("UNBOUND_API_KEY", raising=False)

    mod._test_cfg_path = cfg_path
    mod._test_calls = calls
    return mod


def _run(mod, argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["unbound-discovery", *argv])
    return mod.main()


# --- config file present: the daemon's `scan` invocation now proceeds ---------

def test_config_file_supplies_creds_for_daemon_scan(entry, monkeypatch):
    """The production case: `scan` with no flags/env, creds only in the file.
    main() must strip `scan`, resolve creds from the file, and run the sweep."""
    entry._test_cfg_path.write_text(
        '{"api_key": "file-key", "domain": "https://backend.example.com"}'
    )
    rc = _run(entry, ["scan"], monkeypatch)
    assert rc == 0
    assert entry._test_calls["sweep"] == 1, "credentialed sweep did not run"
    assert entry._test_calls["api_key"] == "file-key"
    assert entry._test_calls["domain"] == "https://backend.example.com"


def test_config_file_resolves_without_scan_token(entry, monkeypatch):
    """Bare invocation (no `scan`) with file-only creds also proceeds."""
    entry._test_cfg_path.write_text(
        '{"api_key": "file-key", "domain": "https://backend.example.com"}'
    )
    assert entry._missing_required_config([]) == []
    rc = _run(entry, [], monkeypatch)
    assert rc == 0
    assert entry._test_calls["sweep"] == 1


def test_flags_win_over_config_file(entry, monkeypatch):
    """Explicit flags/env take precedence; the file only fills absent fields."""
    entry._test_cfg_path.write_text(
        '{"api_key": "file-key", "domain": "https://file.example.com"}'
    )
    rc = _run(
        entry,
        ["--api-key", "flag-key", "--domain", "https://flag.example.com"],
        monkeypatch,
    )
    assert rc == 0
    assert entry._test_calls["api_key"] == "flag-key"
    assert entry._test_calls["domain"] == "https://flag.example.com"


def test_config_file_fills_only_missing_domain(entry, monkeypatch):
    """Key from env, domain from file -> both resolve, sweep runs."""
    entry._test_cfg_path.write_text('{"domain": "https://file.example.com"}')
    monkeypatch.setenv("UNBOUND_API_KEY", "env-key")
    rc = _run(entry, ["scan"], monkeypatch)
    assert rc == 0
    assert entry._test_calls["api_key"] == "env-key"
    assert entry._test_calls["domain"] == "https://file.example.com"


# --- config file absent / broken: fail-open idle must hold (exit 0) ----------

def test_no_config_file_idles_exit_0(entry, monkeypatch, caplog):
    """No file, no flags, no env: idle fail-open, exit 0, never touch sweep."""
    assert not entry._test_cfg_path.exists()
    rc = _run(entry, ["scan"], monkeypatch)
    assert rc == 0
    assert entry._test_calls["sweep"] == 0, "sweep ran without any config (should idle)"


def test_partial_config_file_idles_when_key_missing(entry, monkeypatch):
    """Domain-only file, no env key: still missing the key -> idle, exit 0."""
    entry._test_cfg_path.write_text('{"domain": "https://file.example.com"}')
    rc = _run(entry, ["scan"], monkeypatch)
    assert rc == 0
    assert entry._test_calls["sweep"] == 0


@pytest.mark.parametrize(
    "contents",
    ["not json at all", "[1, 2, 3]", '{"api_key": 123, "domain": 456}', ""],
)
def test_unreadable_or_malformed_config_idles(entry, monkeypatch, contents):
    """A corrupt/empty/wrong-typed file must not crash; it idles fail-open."""
    entry._test_cfg_path.write_text(contents)
    rc = _run(entry, ["scan"], monkeypatch)
    assert rc == 0
    assert entry._test_calls["sweep"] == 0


def test_load_discovery_config_never_raises_on_missing(entry):
    """The loader returns {} (not an exception) for a path that does not exist."""
    assert entry._load_discovery_config("/no/such/path/discovery.json") == {}


# --- the `scan` token strip must not disturb other routing -------------------

def test_version_short_circuits_before_config(entry, monkeypatch, capsys):
    """--version prints and exits 0 even with a config file present (WEB-4802)."""
    entry._test_cfg_path.write_text('{"api_key": "k", "domain": "d"}')
    rc = _run(entry, ["--version"], monkeypatch)
    assert rc == 0
    assert "unbound-discovery" in capsys.readouterr().out
    assert entry._test_calls["sweep"] == 0
