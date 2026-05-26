#!/usr/bin/env bash
# Triggers TTL-gated re-install via the local Python setup script.
# Fired by Codex SessionStart. Fail-open; never blocks host-app session.
set +e

SETUP_SCRIPT="$(dirname "$0")/unbound-setup.py"
[ -f "$SETUP_SCRIPT" ] || exit 0

# Source API key from unbound-cli config or env. No creds = silent skip.
API_KEY=""
if [ -f "$HOME/.unbound/config.json" ]; then
  API_KEY=$(python3 -c "
import json
try: print(json.load(open('$HOME/.unbound/config.json')).get('api_key',''))
except Exception: pass
" 2>/dev/null)
fi
[ -z "$API_KEY" ] && API_KEY="${UNBOUND_API_KEY:-}"
[ -z "$API_KEY" ] && exit 0

python3 "$SETUP_SCRIPT" --if-stale --background --api-key "$API_KEY" >/dev/null 2>&1
exit 0
