#!/usr/bin/env bash
# devcontainer Feature installer. Runs at image-build time as root. Places:
#   /unbound/unbound.py                      — the canonical, self-contained hook
#   /etc/claude-code/managed-settings.json   — managed hook settings (highest tier)
#
# The hook is the canonical copy from this repo's claude-code/hooks/unbound.py (CI copies
# it into this feature dir before publish — see .github/workflows/publish-feature.yml), so
# there is no vendored/drifting duplicate.
#
# python3 (the hook's only dependency) is installed best-effort across common package
# managers (apt/apk/dnf/microdnf/yum) so the Feature stays OS-agnostic — no external
# feature dependency. The hook reads credentials directly: UNBOUND_CLAUDE_API_KEY in
# the env, or a mounted ~/.unbound/config.json. No shell env-export bridge is installed —
# the hook resolves config.json itself.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# The hook requires python3. Install it best-effort across common package managers, the
# same way curl is handled below. Guarded with `|| true` so a failed install never aborts
# the build under `set -e` — the safety-net warning below fires only if it truly failed.
if ! command -v python3 >/dev/null 2>&1; then
  if   command -v apt-get  >/dev/null 2>&1; then apt-get update 2>&1 && apt-get install -y --no-install-recommends python3 2>&1 || true
  elif command -v apk      >/dev/null 2>&1; then apk add --no-cache python3 2>&1 || true
  elif command -v dnf      >/dev/null 2>&1; then dnf install -y python3 2>&1 || true
  elif command -v microdnf >/dev/null 2>&1; then microdnf install -y python3 2>&1 || true
  elif command -v yum      >/dev/null 2>&1; then yum install -y python3 2>&1 || true
  fi
fi

# Safety net: warn (don't fail) if python3 still isn't available after the best-effort install.
if ! command -v python3 >/dev/null 2>&1; then
  echo "unbound-hooks: WARNING — python3 not found on PATH and could not be installed;" >&2
  echo "unbound-hooks: hooks will fail open (no enforcement) until python3 is available." >&2
fi

# The hook shells out to curl for gateway calls. Most dev base images have it; install
# it best-effort across common package managers, and warn (don't fail) if we can't.
if ! command -v curl >/dev/null 2>&1; then
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq curl 2>&1 || true
  elif command -v apk     >/dev/null 2>&1; then apk add --no-cache curl 2>&1 || true
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y curl 2>&1 || true
  elif command -v microdnf>/dev/null 2>&1; then microdnf install -y curl 2>&1 || true
  elif command -v yum     >/dev/null 2>&1; then yum install -y curl 2>&1 || true
  fi
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "unbound-hooks: WARNING — curl not found and could not be installed; the hook uses curl" >&2
  echo "unbound-hooks: for gateway calls and will fail open (no enforcement) without it." >&2
fi

install -D -m 0755 "$HERE/unbound.py" /unbound/unbound.py
install -D -m 0644 "$HERE/managed-settings.json" /etc/claude-code/managed-settings.json

# Symlink helper: links a mounted config (/usr/local/share/unbound/config.json) into every
# user's ~/.unbound/config.json so the hook works as ANY user (incl. after su/sudo). Run at
# container start via the Feature's postStartCommand (see devcontainer-feature.json).
install -D -m 0755 "$HERE/link-unbound.sh" /usr/local/share/unbound/link-unbound.sh

echo "unbound-hooks: installed hook + managed settings"
echo "unbound-hooks: mount ~/.unbound/config.json (or set UNBOUND_CLAUDE_API_KEY) to supply creds"
