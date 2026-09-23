#!/usr/bin/env bash
# devcontainer Feature installer. Runs at image-build time as root. Places:
#   /unbound/unbound.py                      — the canonical Claude Code hook
#   /etc/claude-code/managed-settings.json   — Claude Code managed hook settings (highest tier)
#   /etc/cursor/hooks/unbound.py             — the canonical Cursor hook
#   /etc/cursor/hooks.json                   — Cursor enterprise-managed hooks config
#
# Both hooks are the canonical copies from this repo (claude-code/hooks/unbound.py and
# cursor/unbound.py + cursor/hooks.json); CI vendors them into this feature dir before
# publish — see .github/workflows/publish-feature.yml — so there is no drifting duplicate.
#
# The Cursor enterprise path (/etc/cursor) and layout are exactly what cursor/mdm/setup.py
# installs on Linux (get_enterprise_hooks_dir + setup_hooks): hooks.json at the root, the
# script under hooks/, and hooks.json referencing it by the relative "./hooks/unbound.py".
#
# python3 (the hooks' only dependency) is installed automatically via the dependsOn the
# official python feature. Both hooks read credentials the same way: an env key
# (UNBOUND_CLAUDE_API_KEY / UNBOUND_CURSOR_API_KEY) or a mounted ~/.unbound/config.json,
# which link-unbound.sh already links into every home — so Cursor needs no extra plumbing.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Safety net: dependsOn should have provided python3 already.
if ! command -v python3 >/dev/null 2>&1; then
  echo "unbound-hooks: WARNING — python3 not found on PATH despite the python dependency;" >&2
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

# Cursor: mirror cursor/mdm/setup.py's Linux layout under /etc/cursor so Cursor's
# enterprise-managed hooks fire in the container. The script is executable (hooks.json
# invokes it as the relative "./hooks/unbound.py", which resolves from /etc/cursor).
install -D -m 0755 "$HERE/cursor-unbound.py" /etc/cursor/hooks/unbound.py
install -D -m 0644 "$HERE/cursor-hooks.json" /etc/cursor/hooks.json

# Symlink helper: links a mounted config (/usr/local/share/unbound/config.json) into every
# user's ~/.unbound/config.json so the hook works as ANY user (incl. after su/sudo). Run at
# container start via the Feature's postStartCommand (see devcontainer-feature.json).
install -D -m 0755 "$HERE/link-unbound.sh" /usr/local/share/unbound/link-unbound.sh

echo "unbound-hooks: installed Claude Code + Cursor hooks and managed settings"
echo "unbound-hooks: mount ~/.unbound/config.json (or set UNBOUND_CLAUDE_API_KEY / UNBOUND_CURSOR_API_KEY) to supply creds"
