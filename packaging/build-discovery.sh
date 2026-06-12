#!/bin/bash
# Build the unbound-discovery PyInstaller onedir bundle (macOS universal2).
#
# The binary IS the distribution: target machines never git-clone the source
# or run install.sh. Source is pinned by SHA in discovery.lock.
#
# Requirements on the build machine:
#   - python.org CPython matching PYTHON_VERSION in discovery.lock (universal2
#     framework build). Point UNBOUND_DISCOVERY_PYTHON at it if it is not
#     /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12.
#   - git, curl (for the source fetch), Xcode CLT (lipo, file).
#
# Optional env:
#   UNBOUND_DISCOVERY_PYTHON  build interpreter (must be universal2 CPython 3.12)
#   UNBOUND_DISCOVERY_SRC     existing source checkout to build from; its HEAD
#                             must match SOURCE_SHA from discovery.lock
#
# Output: packaging/dist/unbound-discovery/  (onedir bundle)
#         packaging/dist/unbound-discovery-macos-universal2.tar.gz + .sha256
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$HERE/discovery.lock"
BUILD="$HERE/build"
DIST="$HERE/dist"

log() { echo "[build-discovery] $*"; }
die() { echo "[build-discovery] ERROR: $*" >&2; exit 1; }

# --- 1. Read the lock file -------------------------------------------------
[ -f "$LOCK" ] || die "missing $LOCK"
# Direct per-key assignment — never eval/re-interpret lock values as shell.
while IFS='=' read -r key value; do
    case "$key" in
        SOURCE_REPO)         SOURCE_REPO="$value" ;;
        SOURCE_SHA)          SOURCE_SHA="$value" ;;
        SOURCE_ENTRYPOINT)   SOURCE_ENTRYPOINT="$value" ;;
        PYTHON_VERSION)      PYTHON_VERSION="$value" ;;
        PYINSTALLER_VERSION) PYINSTALLER_VERSION="$value" ;;
        TARGET_ARCH)         TARGET_ARCH="$value" ;;
    esac
done < "$LOCK"
for var in SOURCE_REPO SOURCE_SHA SOURCE_ENTRYPOINT PYTHON_VERSION PYINSTALLER_VERSION TARGET_ARCH; do
    [ -n "${!var:-}" ] || die "$var not set in discovery.lock"
done
log "source: $SOURCE_REPO @ $SOURCE_SHA"

# --- 2. Verify the build interpreter is universal2 CPython 3.12 ------------
PYTHON="${UNBOUND_DISCOVERY_PYTHON:-/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12}"
command -v "$PYTHON" >/dev/null || die "build python not found: $PYTHON"

PY_ACTUAL="$("$PYTHON" -c 'import platform; print(platform.python_version())')"
if [ "$PY_ACTUAL" != "$PYTHON_VERSION" ] && [ "${ALLOW_PYTHON_MISMATCH:-0}" != "1" ]; then
    die "build python is $PY_ACTUAL, lock pins $PYTHON_VERSION (set ALLOW_PYTHON_MISMATCH=1 to override)"
fi
case "$PY_ACTUAL" in 3.12.*) ;; *) die "build python must be CPython 3.12.x, got $PY_ACTUAL";; esac

PY_REAL="$("$PYTHON" -c 'import os, sys; print(os.path.realpath(sys.executable))')"
PY_ARCHS="$(lipo -archs "$PY_REAL" 2>/dev/null || true)"
if [[ "$PY_ARCHS" != *x86_64* || "$PY_ARCHS" != *arm64* ]]; then
    die "build python is not universal2 (archs: '$PY_ARCHS'): $PY_REAL — install the python.org universal2 build"
fi
log "build python OK: $PY_REAL ($PY_ARCHS)"

# --- 3. Fetch source at the locked SHA -------------------------------------
if [ -n "${UNBOUND_DISCOVERY_SRC:-}" ]; then
    SRC="$UNBOUND_DISCOVERY_SRC"
    HEAD_SHA="$(git -C "$SRC" rev-parse HEAD)"
    [ "$HEAD_SHA" = "$SOURCE_SHA" ] || \
        die "UNBOUND_DISCOVERY_SRC HEAD ($HEAD_SHA) != locked SOURCE_SHA ($SOURCE_SHA)"
    log "using existing source checkout: $SRC"
else
    SRC="$BUILD/src"
    rm -rf "$SRC" && mkdir -p "$SRC"
    git -C "$SRC" init -q
    git -C "$SRC" remote add origin "$SOURCE_REPO"
    git -C "$SRC" fetch -q --depth 1 origin "$SOURCE_SHA"
    git -C "$SRC" checkout -q FETCH_HEAD
    log "fetched source into $SRC"
fi
[ -f "$SRC/$SOURCE_ENTRYPOINT" ] || \
    die "source checkout missing $SOURCE_ENTRYPOINT"

# --- 4. Build venv with hash-pinned PyInstaller toolchain --------------------
# requirements-build.txt pins every wheel by sha256 (--require-hashes) so the
# toolchain that produces a fleet-wide root-daemon binary cannot be swapped
# out by a compromised PyPI artifact.
VENV="$BUILD/venv"
VENV_STAMP="$VENV/.base-interpreter"
WANT_STAMP="$PY_REAL $PY_ACTUAL pyinstaller==$PYINSTALLER_VERSION"
if [ ! -x "$VENV/bin/pyinstaller" ] || \
   [ "$(cat "$VENV_STAMP" 2>/dev/null)" != "$WANT_STAMP" ]; then
    rm -rf "$VENV"
    "$PYTHON" -m venv "$VENV"
    "$VENV/bin/python" -m pip -q install --require-hashes --no-deps \
        -r "$HERE/requirements-build.txt"
    echo "$WANT_STAMP" > "$VENV_STAMP"
fi
BUILT_PYI="$("$VENV/bin/pyinstaller" --version)"
[ "$BUILT_PYI" = "$PYINSTALLER_VERSION" ] || \
    die "venv pyinstaller is $BUILT_PYI, lock pins $PYINSTALLER_VERSION (update requirements-build.txt + discovery.lock together)"
log "pyinstaller $BUILT_PYI (hash-pinned toolchain)"

# --- 5. Build ----------------------------------------------------------------
rm -rf "$DIST/unbound-discovery"
UNBOUND_DISCOVERY_SRC="$SRC" "$VENV/bin/pyinstaller" \
    --noconfirm --clean \
    --distpath "$DIST" \
    --workpath "$BUILD/work" \
    "$HERE/unbound-discovery.spec"

BUNDLE="$DIST/unbound-discovery"
[ -x "$BUNDLE/unbound-discovery" ] || die "build produced no executable"

# --- 6. lipo gate: every Mach-O in the bundle must be universal2 -------------
log "lipo gate: checking every Mach-O is $TARGET_ARCH (x86_64 + arm64)..."
FAILED=0
CHECKED=0
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q "Mach-O" || continue
    CHECKED=$((CHECKED + 1))
    ARCHS="$(lipo -archs "$f" 2>/dev/null || echo none)"
    if [[ "$ARCHS" != *x86_64* || "$ARCHS" != *arm64* ]]; then
        echo "[build-discovery]   NOT universal2 ($ARCHS): $f" >&2
        FAILED=$((FAILED + 1))
    fi
done < <(find "$BUNDLE" -type f -print0)
[ "$CHECKED" -gt 0 ] || die "lipo gate found no Mach-O files — bad bundle"
[ "$FAILED" -eq 0 ] || die "lipo gate failed: $FAILED/$CHECKED Mach-O files are not universal2"
log "lipo gate passed: $CHECKED/$CHECKED Mach-O files universal2"

# --- 7. Smoke test: no-config state must idle cleanly and exit 0 -------------
set +e
NOCONF_OUT="$("$BUNDLE/unbound-discovery" 2>&1)"
NOCONF_RC=$?
set -e
[ "$NOCONF_RC" -eq 0 ] || die "no-config run exited $NOCONF_RC (want 0). Output: $NOCONF_OUT"
echo "$NOCONF_OUT" | grep -q "No configuration provided" || \
    die "no-config run missing idle log line. Output: $NOCONF_OUT"
log "no-config smoke test passed (exit 0, idle log line present)"

if arch -x86_64 /usr/bin/true 2>/dev/null; then
    set +e
    X86_OUT="$(arch -x86_64 "$BUNDLE/unbound-discovery" 2>&1)"
    X86_RC=$?
    set -e
    [ "$X86_RC" -eq 0 ] || die "x86_64 no-config run exited $X86_RC. Output: $X86_OUT"
    log "x86_64 slice smoke test passed"
else
    log "Rosetta not available — skipping x86_64 slice smoke test"
fi

# --- 8. Tarball + checksum ----------------------------------------------------
TARBALL="$DIST/unbound-discovery-macos-universal2.tar.gz"
tar -czf "$TARBALL" -C "$DIST" unbound-discovery
(cd "$DIST" && shasum -a 256 "$(basename "$TARBALL")" | tee "$(basename "$TARBALL").sha256")
log "done: $BUNDLE"
log "artifact: $TARBALL"
