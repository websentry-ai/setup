# -*- mode: python ; coding: utf-8 -*-
# PLACEHOLDER spec for the `unbound-discovery` bundle (real spec lands with
# Stream B / WEB-4787). The real Analysis points into the
# websentry-ai/coding-discovery-tool checkout that CI places at
# ./discovery-src (pinned by packaging/discovery.lock). Bundle name, onedir
# COLLECT layout, and target_arch are the pipeline contract — see
# unbound-hook.spec for the rationale on onedir / no-MERGE / universal2 /
# no in-spec signing.

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
