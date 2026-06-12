# -*- mode: python ; coding: utf-8 -*-
# PLACEHOLDER spec for the `unbound-hook` bundle (real spec lands with
# Stream A / WEB-4786 and replaces the Analysis inputs below; the bundle
# name, onedir COLLECT layout, and target_arch are the pipeline contract
# and must not change).
#
# Deliberate choices (apply to the real spec too):
#   * onedir (COLLECT), NOT onefile — every nested Mach-O stays a real file
#     on disk so CI can sign each one individually (deep signing is
#     deprecated) and Gatekeeper pre-warm in postinstall hits real inodes.
#   * two separate bundles, no MERGE — hook and discovery ship as
#     independent bundles per WEB-4789.
#   * target_arch='universal2' — requires the pinned python.org universal2
#     CPython; CI's lipo gate fails the build if any Mach-O is thin.
#   * no codesign_identity here — signing is a dedicated, gated CI step.

a = Analysis(
    ["../placeholder/unbound_hook_main.py"],
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
    name="unbound-hook",
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
    name="unbound-hook",
)
