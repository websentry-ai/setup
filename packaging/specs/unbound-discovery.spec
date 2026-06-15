# -*- mode: python ; coding: utf-8 -*-
# DRY-RUN-ONLY fallback spec for `unbound-discovery`. The CANONICAL spec is
# packaging/unbound-discovery.spec (WEB-4787), which builds from the pinned
# coding-discovery-tool checkout via UNBOUND_DISCOVERY_SRC. CI uses this
# fallback only on tokenless workflow_dispatch dry-runs; tag releases
# hard-require the real checkout, and the install-test version assert
# rejects the placeholder binary. Bundle name, onedir COLLECT layout, and
# target_arch are the pipeline contract — see unbound-hook.spec for the
# rationale on onedir / no-MERGE / universal2 / no in-spec signing.

import os

a = Analysis(
    ["../placeholder/unbound_discovery_main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    disable_windowed_traceback=False,
    argv_emulation=False,
    # Defaults to universal2 (macOS); the Linux dry-run lane sets
    # UNBOUND_TARGET_ARCH="" -> None to build native (matches the two real
    # specs). Without this the tokenless Linux dry-run can't build.
    target_arch=os.environ.get("UNBOUND_TARGET_ARCH", "universal2") or None,
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
