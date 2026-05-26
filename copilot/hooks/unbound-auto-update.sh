#!/usr/bin/env bash
# TTL-gated auto-update fired from host-app SessionStart.
set +e

SETUP_SCRIPT="$(dirname "$0")/unbound-setup.py"
[ -f "$SETUP_SCRIPT" ] || exit 0

# Path passed via env to skip shell interpolation in the Python literal.
API_KEY=""
UNBOUND_CONFIG_PATH="$HOME/.unbound/config.json"
if [ -f "$UNBOUND_CONFIG_PATH" ]; then
  API_KEY=$(UNBOUND_CONFIG_PATH="$UNBOUND_CONFIG_PATH" python3 -c '
import json, os
try: print(json.load(open(os.environ["UNBOUND_CONFIG_PATH"])).get("api_key",""))
except Exception: pass
' 2>/dev/null)
fi
[ -z "$API_KEY" ] && API_KEY="${UNBOUND_API_KEY:-}"
[ -z "$API_KEY" ] && exit 0

python3 "$SETUP_SCRIPT" --if-stale --background --api-key "$API_KEY" >/dev/null 2>&1
exit 0
