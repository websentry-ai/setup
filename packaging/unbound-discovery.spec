# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the unbound-discovery onedir bundle (WEB-4787, Stream B).
#
# Build via build-discovery.sh, which pins the source SHA (discovery.lock),
# verifies the build Python is a universal2 python.org CPython 3.12, and
# lipo-gates every Mach-O in the output. Do not invoke pyinstaller directly
# unless you replicate those checks.
#
# UNBOUND_DISCOVERY_SRC must point to a coding-discovery-tool checkout at the
# locked SHA. The detection code is bundled as-is — no logic changes here.
# Codesigning is intentionally absent (certs pending); PyInstaller applies its
# default ad-hoc signature on arm64.

import os
import sys

src = os.environ.get("UNBOUND_DISCOVERY_SRC")
if not src or not os.path.isdir(src):
    raise SystemExit(
        "UNBOUND_DISCOVERY_SRC must point to a coding-discovery-tool checkout "
        "(use build-discovery.sh)"
    )

# scripts/ has no __init__.py, so the importable package is coding_discovery_tools
pkg_root = os.path.join(src, "scripts")
sys.path.insert(0, pkg_root)

from PyInstaller.utils.hooks import collect_submodules

# The OS-specific tool detectors are all statically imported by
# coding_tool_factory, but collect explicitly so a future move to dynamic
# imports cannot silently produce a binary with missing detectors.
hidden = collect_submodules("coding_discovery_tools")

a = Analysis(
    ["unbound_discovery_entry.py"],
    pathex=[pkg_root],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc_data"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="unbound-discovery",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    target_arch="universal2",
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="unbound-discovery",
)
