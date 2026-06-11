#!/bin/bash
# Assemble the pkg root (WEB-4792 layout) and run pkgbuild.
# Usage: build-pkg.sh <version> <dist-dir> <out-pkg>
#   <dist-dir> must contain unbound-hook/ and unbound-discovery/ onedir
#   bundles (already signed when signing is enabled — pkgbuild must run
#   AFTER signing so the payload hashes match the signatures).
#
# Payload:
#   /opt/unbound/<version>/{unbound-hook/,unbound-discovery/,share/}
#   /Library/LaunchDaemons/ai.getunbound.discovery.plist
# Everything else (current symlink, /var/log/unbound, newsyslog conf,
# daemon bootstrap, version GC) happens in postinstall — the `current`
# symlink especially must NOT be payload, because postinstall pre-warms the
# new binaries before flipping it.
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <version> <dist-dir> <out-pkg>" >&2; exit 2; }
version="$1"; dist="$2"; out="$3"

pkgdir="$(cd "$(dirname "$0")/.." && pwd)/pkg"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../versions.env
source "$(dirname "$0")/../versions.env"

for b in unbound-hook unbound-discovery; do
  [[ -x "$dist/$b/$b" ]] || { echo "ERROR: missing bundle $dist/$b/$b" >&2; exit 1; }
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
root="$stage/root"
verdir="$root$INSTALL_PREFIX/$version"

mkdir -p "$verdir" "$root/Library/LaunchDaemons"
cp -R "$dist/unbound-hook" "$dist/unbound-discovery" "$verdir/"

# Canonical entry points are the bundle executables themselves:
#   /opt/unbound/current/unbound-hook/unbound-hook
#   /opt/unbound/current/unbound-discovery/unbound-discovery
# (aligned with the unbound-hook binary work in WEB-4786 — no bin/ shim dir,
# one path for LaunchDaemon, onboard.sh, and tool-hook commands alike).

# Shipped inside the version dir; postinstall copies it to /etc/newsyslog.d
# (payload writing straight into /private/etc is avoidable churn).
mkdir -p "$verdir/share"
cp "$pkgdir/newsyslog-ai.getunbound.conf" "$verdir/share/"

cp "$pkgdir/ai.getunbound.discovery.plist" "$root/Library/LaunchDaemons/"
chmod 644 "$root/Library/LaunchDaemons/ai.getunbound.discovery.plist"

scripts="$stage/scripts"
mkdir -p "$scripts"
sed "s/@VERSION@/$version/g" "$pkgdir/postinstall" > "$scripts/postinstall"
chmod 755 "$scripts/postinstall"

pkgbuild \
  --root "$root" \
  --scripts "$scripts" \
  --identifier "$PKG_IDENTIFIER" \
  --version "$version" \
  --install-location / \
  --ownership recommended \
  "$out"

echo "Built $out (identifier=$PKG_IDENTIFIER version=$version)"
