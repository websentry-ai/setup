#!/usr/bin/env bash
# Build the unbound-hook Go universal2 binary (WEB-4809).
# Requires Go 1.22+ and macOS lipo. UNBOUND_BUILD_GO overrides the toolchain.
set -euo pipefail
cd "$(dirname "$0")"

GO="${UNBOUND_BUILD_GO:-go}"
command -v "$GO" >/dev/null 2>&1 || { echo "ERROR: go toolchain not found (set UNBOUND_BUILD_GO)"; exit 1; }
command -v lipo >/dev/null 2>&1 || { echo "ERROR: lipo not found (macOS required)"; exit 1; }

# packaging/README.md "Version contract": --version must self-identify with
# the release version as a whitespace-delimited token.
VERSION="${UNBOUND_HOOK_VERSION:-0.0.0-dev}"
LDFLAGS="-s -w -X main.Version=${VERSION}"

OUT=dist/unbound-hook
mkdir -p "$OUT"

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 "$GO" build -trimpath -ldflags "$LDFLAGS" \
  -o "$OUT/unbound-hook.arm64" ./cmd/unbound-hook
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 "$GO" build -trimpath -ldflags "$LDFLAGS" \
  -o "$OUT/unbound-hook.amd64" ./cmd/unbound-hook
lipo -create -output "$OUT/unbound-hook" "$OUT/unbound-hook.arm64" "$OUT/unbound-hook.amd64"
rm "$OUT/unbound-hook.arm64" "$OUT/unbound-hook.amd64"

echo "--- verifying universal2 ---"
archs=$(lipo -archs "$OUT/unbound-hook")
case "$archs" in
  *x86_64*arm64*|*arm64*x86_64*) echo "OK: universal2 ($archs)" ;;
  *) echo "NOT-UNIVERSAL: $archs"; exit 1 ;;
esac

echo "--- smoke ---"
"./$OUT/unbound-hook" --version
echo '{}' | "./$OUT/unbound-hook" hook claude-code PreToolUse
