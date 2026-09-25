"""The Nuitka entry shim must hand the hooks the same sys.executable
contract PyInstaller does: sys.executable IS the unbound-hook binary.

The hooks re-exec `[sys.executable, 'sync-skills', <tool>]` and
`[sys.executable, 'mcp-diagnostic', <tool>]` in frozen mode. Nuitka sets
sys.executable to <dist>/python, which on case-insensitive APFS opens the
bundled libpython dylib `Python` (0644) -> EACCES, so skills sync never ran
on Nuitka runtimes (Sentry AI-GATEWAY-19H). These tests run the real shim
inside a fake onedir bundle, the way the compiled binary runs it.
"""

import os
import runpy
import shutil
import stat
import sys
import types

import pytest

from conftest import REPO

SHIM = REPO / "packaging" / "nuitka" / "unbound_hook_entry.py"


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    """A dist/unbound-hook/ dir holding the shim and a libpython stand-in,
    with the sys attributes the shim writes restored afterwards."""
    dist = tmp_path / "unbound-hook"
    dist.mkdir()
    shutil.copy(SHIM, dist / "unbound_hook_entry.py")
    # The dylib that `.../python` resolves to on APFS: present, not executable.
    (dist / "Python").write_bytes(b"\xcf\xfa\xed\xfe")
    (dist / "Python").chmod(0o644)

    monkeypatch.setattr(sys, "executable", str(dist / "python"))
    # The shim SETS these; monkeypatch.delattr records no undo for an
    # attribute that is absent, so snapshot and restore them by hand or
    # sys.frozen leaks into every later test.
    saved = {a: getattr(sys, a) for a in ("frozen", "_MEIPASS") if hasattr(sys, a)}
    for attr in ("frozen", "_MEIPASS"):
        if hasattr(sys, attr):
            delattr(sys, attr)
    # The shim imports unbound_hook.main at module level; the real package
    # is not what is under test here.
    pkg = types.ModuleType("unbound_hook")
    main = types.ModuleType("unbound_hook.main")
    main.main = lambda: 0
    monkeypatch.setitem(sys.modules, "unbound_hook", pkg)
    monkeypatch.setitem(sys.modules, "unbound_hook.main", main)
    yield dist
    for attr in ("frozen", "_MEIPASS"):
        if hasattr(sys, attr):
            delattr(sys, attr)
    for attr, value in saved.items():
        setattr(sys, attr, value)


def run_compiled_shim(dist):
    # `__compiled__` is the global Nuitka injects into a compiled module.
    runpy.run_path(
        str(dist / "unbound_hook_entry.py"),
        init_globals={"__compiled__": object()},
        run_name="unbound_hook_entry",
    )


def test_repoints_sys_executable_at_the_binary(bundle):
    binary = bundle / "unbound-hook"
    binary.write_bytes(b"")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

    run_compiled_shim(bundle)

    assert sys.executable == str(binary)
    assert os.access(sys.executable, os.X_OK)
    assert sys.frozen is True
    assert sys._MEIPASS == str(bundle)


def test_leaves_sys_executable_alone_without_an_executable_binary(bundle):
    before = sys.executable
    (bundle / "unbound-hook").write_bytes(b"")  # present, not executable

    run_compiled_shim(bundle)

    assert sys.executable == before
    assert sys.frozen is True
