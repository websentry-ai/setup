"""The contract every installer must honour, for every setup.py in the repo.

These are deliberately shallow and total: they cover every tool rather than
every branch of one tool, so a new tool cannot ship without the basics. Deeper
per-tool behaviour lives beside the tool it belongs to.
"""

import json
import subprocess
import sys

import pytest

from tests.conftest import REPO, load_module

# Every installer, keyed by the path a reader would name it by.
SETUPS = sorted(
    str(p.relative_to(REPO))
    for p in REPO.glob("*/**/setup.py")
    if "node_modules" not in p.parts and "binary" not in p.parts
    and "tests" not in p.parts
)

# Installers that offer a teardown. Read off the source so a tool that gains one
# is covered the day it does.
def _has(relpath, name):
    return ("def %s(" % name) in (REPO / relpath).read_text()


CLEARABLE = [s for s in SETUPS if _has(s, "clear_setup")]


def test_the_inventory_is_not_empty():
    """A glob that silently matched nothing would make this whole file vacuous."""
    assert len(SETUPS) >= 15, SETUPS
    assert CLEARABLE, "no installer exposes clear_setup"


def test_every_installer_offering_clear_is_actually_covered():
    """CLEARABLE is derived by reading source, so a rename would quietly shrink the
    teardown coverage instead of failing. Tie it to the flag the installer advertises."""
    advertises = [s for s in SETUPS if '"--clear"' in (REPO / s).read_text()
                  or "'--clear'" in (REPO / s).read_text()]
    missing = sorted(set(advertises) - set(CLEARABLE))
    assert not missing, "advertise --clear but expose no clear_setup: %s" % missing


@pytest.mark.parametrize("relpath", SETUPS)
class TestEveryInstaller:
    def test_it_imports_without_side_effects(self, relpath):
        """Importing must not touch the machine: everything happens under main()."""
        mod = load_module(relpath)
        assert hasattr(mod, "main"), "%s: no main()" % relpath

    def test_it_compiles(self, relpath):
        r = subprocess.run([sys.executable, "-m", "py_compile", str(REPO / relpath)],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr

    def test_it_declares_the_gateway_it_defaults_to(self, relpath):
        """Every installer routes somewhere; the default must be ours and explicit."""
        src = (REPO / relpath).read_text()
        if "gateway" not in relpath and "GATEWAY" not in src:
            pytest.skip("hooks-only installer with no gateway default")
        assert "getunbound.ai" in src, relpath


@pytest.mark.parametrize("relpath", CLEARABLE)
class TestEveryTeardown:
    def test_clearing_a_pristine_machine_is_a_no_op(self, relpath, tmp_path):
        """Nothing installed means nothing to remove, and no traceback."""
        home = tmp_path / "home"
        home.mkdir()
        r = subprocess.run(
            [sys.executable, str(REPO / relpath), "--clear"],
            capture_output=True, text=True, timeout=120,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "SHELL": "/bin/zsh"},
        )
        assert "Traceback" not in r.stderr, r.stderr[-600:]
        # An MDM installer refuses without root rather than clearing; both are fine.
        assert r.returncode in (0, 1), "exit %d\n%s" % (r.returncode, r.stderr[-400:])

    def test_clearing_leaves_a_foreign_config_alone(self, relpath, tmp_path):
        """The rule the whole repo turns on: remove only what we installed."""
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        rc = home / ".zprofile"
        rc.write_text('export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n'
                      'export CLAUDE_CODE_USE_BEDROCK=1\n')
        settings = home / ".claude" / "settings.json"
        settings.write_text(json.dumps({"model": "opus", "permissions": {"allow": []}}))
        subprocess.run(
            [sys.executable, str(REPO / relpath), "--clear"],
            capture_output=True, text=True, timeout=120,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "SHELL": "/bin/zsh"},
        )
        assert "llm.acme-corp.internal" in rc.read_text(), \
            "%s cleared somebody else's endpoint" % relpath
        assert "CLAUDE_CODE_USE_BEDROCK" in rc.read_text(), relpath
        assert json.loads(settings.read_text())["model"] == "opus", relpath


@pytest.mark.parametrize("relpath", SETUPS)
def test_no_installer_hardcodes_a_developer_home(relpath):
    """A path baked in from somebody's laptop is a bug that only shows in the field."""
    src = (REPO / relpath).read_text()
    for needle in ("/Users/", "/home/runner", "C:\\\\Users\\\\"):
        for line in src.splitlines():
            if needle in line and not line.lstrip().startswith("#"):
                assert '"' not in line.split(needle)[0][-2:], \
                    "%s hardcodes a home: %s" % (relpath, line.strip()[:80])


# Installers that walk history. The force request is org-wide on the backend, with no
# tool in it, so every one of these must ask for it or an admin's request is silently
# honoured by some tools and ignored by others.
BACKFILLERS = [s for s in SETUPS if _has(s, "run_backfill")]


def test_the_backfiller_inventory_is_not_empty():
    """Derived by reading source, so a rename would quietly empty this and pass."""
    assert len(BACKFILLERS) >= 6, BACKFILLERS


@pytest.mark.parametrize("relpath", BACKFILLERS)
def test_every_backfiller_asks_for_the_force_request(relpath):
    """The backend stores one timestamp for the organization and does not scope it to a
    tool, so a backfiller that never asks makes the request a lie for that tool."""
    assert _has(relpath, "_backfill_force_config"), (
        "%s walks history but never asks whether the org requested a re-walk" % relpath)


def test_every_installer_reads_the_force_request_the_same_way():
    """Six copies of one function. Byte-identical or a fix lands in one tool only."""
    import ast

    bodies = {}
    for relpath in BACKFILLERS:
        tree = ast.parse((REPO / relpath).read_text())
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_backfill_force_config"), None)
        assert fn is not None, relpath
        bodies.setdefault(ast.dump(fn), []).append(relpath)
    assert len(bodies) == 1, "copies have drifted: %s" % list(bodies.values())


@pytest.mark.parametrize("relpath", BACKFILLERS)
class TestEveryForceRequestReader:
    """Each installer carries its own copy, so a bad copy has to fail on its own."""

    @staticmethod
    def _read(module, payload, code=200):
        from unittest.mock import patch
        body = json.dumps(payload).encode("utf-8")
        with patch.object(module, "_backfill_http_request", lambda *a, **k: (code, body)):
            return module._backfill_force_config("key", "https://backend")

    def test_it_reads_a_request_and_its_window(self, relpath):
        module = load_module(relpath)
        assert self._read(module, {"force_backfill_requested_epoch": 1787893680,
                                   "force_backfill_days": 45}) == (1787893680.0, 45)

    def test_no_request_means_no_window(self, relpath):
        module = load_module(relpath)
        assert self._read(module, {}) == (None, None)
        assert self._read(module, {"force_backfill_days": 45}) == (None, None)

    def test_an_unusable_window_falls_back_to_the_installer_default(self, relpath):
        # None, not 30: the caller owns the default. bool is an int subclass, and 0 or a
        # negative would reach back to the epoch.
        module = load_module(relpath)
        for bad in (True, False, 0, -5, "45", 45.5, [45], {"d": 45}):
            assert self._read(module, {"force_backfill_requested_epoch": 1787893680,
                                       "force_backfill_days": bad})[1] is None, bad

    def test_a_failed_call_never_forces(self, relpath):
        module = load_module(relpath)
        assert self._read(module, {"force_backfill_requested_epoch": 1787893680},
                          code=500) == (None, None)
