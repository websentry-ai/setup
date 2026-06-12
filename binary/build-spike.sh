#!/usr/bin/env bash
# WEB-4785 spike build. Requires:
#  - python.org CPython 3.12.x universal2 (framework install)
#  - pip install pyinstaller (inside a venv created from that interpreter)
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${UNBOUND_BUILD_PYTHON:-/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12}"
"$PYTHON" -c 'import platform,sys; assert sys.version_info[:2]==(3,12), sys.version'
lipo -archs "$PYTHON" | grep -q x86_64 || { echo "ERROR: $PYTHON is not universal2"; exit 1; }
"$PYTHON" -m PyInstaller unbound-hook-spike.spec --noconfirm
echo "--- verifying universal2 on every Mach-O ---"
bad=0
while IFS= read -r -d '' f; do
  file "$f" | grep -q Mach-O || continue
  archs=$(lipo -archs "$f" 2>/dev/null)
  case "$archs" in *x86_64*arm64*|*arm64*x86_64*) ;; *) echo "NOT-UNIVERSAL: $f -> $archs"; bad=1;; esac
done < <(find dist/unbound-hook-spike -type f -print0)
[ "$bad" = 0 ] && echo "OK: all Mach-O universal2"
exit "$bad"
