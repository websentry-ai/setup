#!/usr/bin/env bash
# Build the unbound-hook onedir universal2 bundle (WEB-4786).
# Requires python.org CPython 3.12.x universal2 with PyInstaller installed.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${UNBOUND_BUILD_PYTHON:-/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12}"
"$PYTHON" -c 'import sys; assert sys.version_info[:2]==(3,12), sys.version'
lipo -archs "$PYTHON" | grep -q x86_64 || { echo "ERROR: $PYTHON is not universal2"; exit 1; }

# Drift guard: the spec hardcodes the vendored modules' stdlib imports as
# hidden imports (data files aren't import-analyzed). Fail if a new import
# appears in the sources that the spec doesn't know about.
"$PYTHON" - <<'EOF'
import ast, re, sys
files = ["../claude-code/hooks/unbound.py", "../cursor/unbound.py",
         "../copilot/hooks/unbound.py", "../codex/hooks/unbound.py",
         "../augment/hooks/unbound.py",
         "../claude-code/hooks/mdm/setup.py", "../cursor/mdm/setup.py",
         "../copilot/hooks/mdm/setup.py", "../codex/hooks/mdm/setup.py",
         "../augment/hooks/mdm/setup.py"]
need = set()
for f in files:
    for node in ast.walk(ast.parse(open(f).read())):
        if isinstance(node, ast.Import):
            need.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            need.add(node.module.split(".")[0])
spec = open("unbound-hook.spec").read()
hidden = set(re.findall(r'"([a-z0-9_.]+)"', spec.split("HIDDEN = [")[1].split("]")[0]))
hidden.update({"os", "sys"})  # always present
missing = {m for m in need if m not in hidden and m not in ("os", "sys", "winreg")}
if missing:
    sys.exit(f"ERROR: vendored modules import {sorted(missing)} but unbound-hook.spec "
             f"HIDDEN list doesn't include them — update the spec.")
print("hidden-import drift check OK")
EOF

"$PYTHON" -m PyInstaller unbound-hook.spec --noconfirm

echo "--- verifying universal2 on every Mach-O ---"
bad=0
while IFS= read -r -d '' f; do
  file "$f" | grep -q Mach-O || continue
  archs=$(lipo -archs "$f" 2>/dev/null)
  case "$archs" in
    *x86_64*arm64*|*arm64*x86_64*) ;;
    *) echo "NOT-UNIVERSAL: $f -> $archs"; bad=1 ;;
  esac
done < <(find dist/unbound-hook -type f -print0)
[ "$bad" = 0 ] && echo "OK: all Mach-O universal2"

echo "--- smoke ---"
./dist/unbound-hook/unbound-hook --version
echo '{}' | ./dist/unbound-hook/unbound-hook hook claude-code PreToolUse
exit "$bad"
