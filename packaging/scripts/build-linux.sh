#!/bin/bash
# Build the Linux runtime tarball (Linux analog of build-pkg.sh, which makes
# the macOS .pkg). Linux ships a self-contained tar.gz — no distro package
# manager assumed — with the SAME layout the macOS pkg installs:
#   <out>/unbound-runtime-<version>-linux-<arch>.tar.gz
#     └─ unbound-hook/unbound-hook  +  unbound-discovery/unbound-discovery
# onboard.sh extracts it to /opt/unbound/<version>/ and `unbound-hook
# install-daemon` registers the systemd timer.
#
# Usage: build-linux.sh <version> <arch> <out-dir>
#   arch is amd64|arm64 (used only in the tarball name; the build itself is
#   native — the runner's arch must match).
#
# Env:
#   PYINSTALLER            path to the pinned pyinstaller (required)
#   UNBOUND_DISCOVERY_SRC  coding-discovery-tool checkout at the locked SHA.
#                          When set, the canonical discovery spec is built;
#                          when unset, the placeholder spec (dry-run only).
#   UNBOUND_TARGET_ARCH    forwarded to the specs; MUST be "" on Linux so the
#                          shared (universal2-default) specs build native.
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <version> <arch> <out-dir>" >&2; exit 2; }
version="$1"; arch="$2"; out="$3"
case "$arch" in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 2 ;; esac

[[ -n "${PYINSTALLER:-}" && -x "$PYINSTALLER" ]] \
  || { echo "PYINSTALLER must point at the pinned pyinstaller binary" >&2; exit 2; }

# Native, single-arch on Linux: empty -> None in the specs (vs universal2).
export UNBOUND_TARGET_ARCH=""

setup_dir="$(cd "$(dirname "$0")/../.." && pwd)"   # .../setup
mkdir -p "$out" dist build

# Hook bundle: single source of truth spec (same file the macOS lane builds).
"$PYINSTALLER" --noconfirm --distpath dist --workpath build \
  "$setup_dir/binary/unbound-hook.spec"

# Discovery bundle: canonical spec from the pinned checkout, else placeholder
# (dry-run only — a tag release wires UNBOUND_DISCOVERY_SRC and the onboard
# version assert rejects placeholders).
if [[ -n "${UNBOUND_DISCOVERY_SRC:-}" ]]; then
  "$PYINSTALLER" --noconfirm --distpath dist --workpath build \
    "$setup_dir/packaging/unbound-discovery.spec"
else
  echo "::warning::building PLACEHOLDER unbound-discovery (no UNBOUND_DISCOVERY_SRC) — dry-run only"
  "$PYINSTALLER" --noconfirm --distpath dist --workpath build \
    "$setup_dir/packaging/specs/unbound-discovery.spec"
fi

for b in unbound-hook unbound-discovery; do
  [[ -x "dist/$b/$b" ]] || { echo "ERROR: missing bundle dist/$b/$b" >&2; exit 1; }
  echo "smoke: $b --version -> $("dist/$b/$b" --version)"
done

tar_name="unbound-runtime-${version}-linux-${arch}.tar.gz"
tar -czf "$out/$tar_name" -C dist unbound-hook unbound-discovery
( cd "$out" && sha256sum "$tar_name" > "$tar_name.sha256" )
echo "built $out/$tar_name"
sha256sum "$out/$tar_name" | awk '{print $1}'
