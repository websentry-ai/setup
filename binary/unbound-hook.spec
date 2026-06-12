# -*- mode: python ; coding: utf-8 -*-
# unbound-hook — onedir universal2 bundle (WEB-4786).
#
# The four tools' hook modules and MDM setup modules ship as SOURCE data
# files under vendored/ — the binary executes the exact same bytes as the
# python serving path. Because data files aren't import-analyzed, every
# stdlib module they use is listed as a hidden import; build.sh re-derives
# that set from the sources and fails the build on drift.

VENDORED = [
    ("../claude-code/hooks/unbound.py", "vendored/claude-code/hooks"),
    ("../cursor/unbound.py", "vendored/cursor"),
    ("../copilot/hooks/unbound.py", "vendored/copilot/hooks"),
    ("../codex/hooks/unbound.py", "vendored/codex/hooks"),
    ("../claude-code/hooks/mdm/setup.py", "vendored/claude-code/hooks/mdm"),
    ("../cursor/mdm/setup.py", "vendored/cursor/mdm"),
    ("../copilot/hooks/mdm/setup.py", "vendored/copilot/hooks/mdm"),
    ("../codex/hooks/mdm/setup.py", "vendored/codex/hooks/mdm"),
]

# Union of stdlib imports across the vendored modules (mac/linux relevant;
# winreg/ctypes guarded by platform checks at runtime and excluded on mac).
HIDDEN = [
    "base64", "collections", "ctypes", "datetime", "hashlib", "json",
    "pathlib", "pickle", "platform", "pwd", "re", "shutil", "socket",
    "sqlite3", "subprocess", "tempfile", "time", "tomllib", "typing",
    "urllib", "urllib.request", "urllib.error", "importlib.util",
]

a = Analysis(
    ["src/entry.py"],
    pathex=["src"],
    binaries=[],
    datas=VENDORED,
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
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
    upx_exclude=[],
    name="unbound-hook",
)
