"""The contract every installer must honour, for every setup.py in the repo.

These are deliberately shallow and total: they cover every tool rather than
every branch of one tool, so a new tool cannot ship without the basics. Deeper
per-tool behaviour lives beside the tool it belongs to.
"""

import hashlib
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

# Every tool's hook script, keyed by the path a reader would name it by.
HOOKS = sorted(
    str(p.relative_to(REPO))
    for p in REPO.glob("*/**/unbound.py")
    if "node_modules" not in p.parts and "binary" not in p.parts
    and "tests" not in p.parts and "packaging" not in p.parts
)


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


MDM_BACKFILLERS = [s for s in BACKFILLERS if "/mdm/" in s]


class TestCollectorShapeMatchesEveryUnpacker:
    """The managed collector is unpacked by the installer AND by the packaged
    `unbound-hook backfill --dry-run`. Both must agree on how many values it
    returns, or the odd one out raises ValueError at runtime."""

    @staticmethod
    def _return_arities(path, fn_name):
        import ast
        tree = ast.parse((REPO / path).read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == fn_name)
        return {len(n.value.elts) if isinstance(n.value, ast.Tuple) else 1
                for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None}

    @pytest.mark.parametrize("relpath", MDM_BACKFILLERS)
    def test_every_exit_returns_the_same_number_of_values(self, relpath):
        # An early return that is one value short is invisible until a device hits
        # exactly that path, and its ValueError aborts the whole run.
        arities = self._return_arities(relpath, "_backfill_collect_sessions")
        assert arities == {3}, f"{relpath}: mixed arities {sorted(arities)}"

    def test_the_packaged_dry_run_unpacks_what_the_collectors_return(self):
        import ast
        path = "binary/src/unbound_hook/backfill_cmd.py"
        src = (REPO / path).read_text(encoding="utf-8")
        targets = [n.targets[0] for n in ast.walk(ast.parse(src))
                   if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Tuple)
                   and isinstance(n.value, ast.Name) and n.value.id == "result"]
        assert targets, f"{path}: no `<tuple> = result` unpack found — did it get renamed?"
        for t in targets:
            assert len(t.elts) == 3, f"{path}: unpacks {len(t.elts)}, collectors return 3"


def test_every_hook_is_in_the_inventory():
    """A glob that silently matched nothing would make the check below vacuous."""
    assert len(HOOKS) == 5, HOOKS


@pytest.mark.parametrize("relpath", HOOKS)
def test_no_hook_fetches_its_own_source(relpath):
    # A hook is replaced by re-running its installer, never by rewriting itself:
    # naming this repo's raw URL is how an in-script updater comes back.
    assert "raw.githubusercontent.com/websentry-ai/setup" not in (
        REPO / relpath).read_text(encoding="utf-8")


# Installers that ship an unbound.py, and so can report which version is deployed.
# Gateway-mode and openclaw write no hook script and are deliberately excluded.
HOOK_NOTIFIERS = sorted(s for s in SETUPS if _has(s, "hook_script_hash"))
NOTIFIERS = sorted(s for s in SETUPS if _has(s, "notify_setup_complete"))


def _notify_body(relpath, **kwargs):
    """The JSON body an installer would POST, captured at the curl boundary."""
    module = load_module(relpath)
    captured = {}

    def fake_run(cmd, **kw):
        captured["body"] = json.loads(kw["input"].decode())

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(module.subprocess, "run", fake_run)
        module.notify_setup_complete("k", "claude-code", backend_url="https://b", **kwargs)
    return captured["body"]


def test_the_hook_notifier_inventory_is_the_five_tools_twice():
    """Five tools, each with a user-level and an MDM installer. A drop here means
    a tool silently stopped reporting its hook version."""
    assert len(HOOK_NOTIFIERS) == 10, HOOK_NOTIFIERS


@pytest.mark.parametrize("relpath", NOTIFIERS)
def test_notify_body_is_unchanged_when_the_new_fields_are_absent(relpath):
    # A caller passing neither field must send the exact body it always sent, so
    # old installers keep working against the new backend and vice versa.
    body = _notify_body(relpath)
    assert "hook_hash" not in body
    assert "install_mode" not in body


@pytest.mark.parametrize("relpath", HOOK_NOTIFIERS)
def test_every_hook_installer_forwards_hash_and_mode(relpath):
    body = _notify_body(relpath, hook_hash="d" * 64, install_mode="mdm")
    assert body["hook_hash"] == "d" * 64
    assert body["install_mode"] == "mdm"


@pytest.mark.parametrize("relpath", HOOK_NOTIFIERS)
def test_hook_script_hash_is_sha256_and_survives_a_missing_file(relpath, tmp_path):
    module = load_module(relpath)
    script = tmp_path / "unbound.py"
    script.write_bytes(b"print('hook')\n")
    assert module.hook_script_hash(script) == hashlib.sha256(b"print('hook')\n").hexdigest()
    # A hash is never worth failing an install over.
    assert module.hook_script_hash(tmp_path / "gone.py") is None
    assert module.hook_script_hash(None) is None
