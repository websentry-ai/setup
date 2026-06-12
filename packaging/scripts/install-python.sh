#!/bin/bash
# Install the pinned python.org universal2 CPython on the CI runner.
# Usage: install-python.sh  (expects to run from the repo root)
set -euo pipefail

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../versions.env
source "$(dirname "$0")/../versions.env"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

pkg="$workdir/python.pkg"
echo "Downloading pinned CPython: $PYTHON_PKG_URL"
curl -fsSL --retry 3 --retry-delay 2 -o "$pkg" "$PYTHON_PKG_URL"

echo "$PYTHON_PKG_SHA256  $pkg" | shasum -a 256 -c -

sudo installer -pkg "$pkg" -target /

[[ -x "$PYTHON_BIN" ]] || { echo "ERROR: $PYTHON_BIN missing after install" >&2; exit 1; }

# The whole point of the python.org build is universal2 — fail fast if the
# interpreter itself is thin (a thin interpreter silently produces thin
# PyInstaller bundles, which the lipo gate would only catch much later).
archs="$(lipo -archs "$PYTHON_BIN")"
echo "Interpreter archs: $archs"
case "$archs" in
  *x86_64*arm64*|*arm64*x86_64*) ;;
  *) echo "ERROR: pinned CPython is not universal2 (archs: $archs)" >&2; exit 1 ;;
esac

"$PYTHON_BIN" --version
