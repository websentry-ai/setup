#!/usr/bin/env python3
"""Nuitka entry script for the unbound-hook binary (WEB-4804 EDR bake-off).

The PyInstaller build (binary/src/entry.py + binary/unbound-hook.spec) stays
canonical and untouched; this shim exists only so the Nuitka --standalone
artifact runs the EXACT same unbound_hook package and vendored module bytes
with zero source changes.

PyInstaller's bootloader sets sys.frozen and sys._MEIPASS, which
unbound_hook._resources.resource_root() uses to locate the vendored hook /
MDM setup sources. Nuitka 2.8 sets neither, so this shim provides both
before unbound_hook is imported:

  * sys.frozen = True  -> the vendored modules' frozen-mode gates engage
    (no self-update fetch, discovery via the local binary), identical to the
    PyInstaller artifact.
  * sys._MEIPASS = <dist dir>  -> resource_root() resolves to
    <dist>/vendored/, where build-nuitka.sh places the same data files the
    .spec's VENDORED list places under PyInstaller's _MEIPASS.

Under Nuitka --standalone the main module's __file__ lives in the dist
folder, so its dirname IS the bundle root. Run directly with python for a
dev sanity check (the shim then changes nothing: not compiled => attributes
untouched => _resources falls back to the repo-checkout path).
"""

import os
import sys

if "__compiled__" in globals():  # Nuitka build only; inert under plain python
    sys.frozen = True
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))
else:
    # Dev fallback mirrors binary/src/entry.py: make unbound_hook importable
    # from a plain repo checkout.
    sys.path.insert(
        0,
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "binary", "src"
        ),
    )

from unbound_hook.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
