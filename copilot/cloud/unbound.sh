#!/usr/bin/env bash
# Fetches the Unbound hook into the sandbox and runs it. Printing {} on every
# failure path keeps a fetch problem from denying a tool call.

HOOK=/tmp/unbound-hook.py
SRC="${UNBOUND_HOOK_URL:-https://raw.githubusercontent.com/websentry-ai/setup/main/copilot/hooks/unbound.py}"

# Machines with the agent installed already report through their own hook; this
# config is read by Copilot CLI there too, and both would send the same turn.
if [ -f "$HOME/.copilot/hooks/unbound.py" ]; then
  echo '{}'
  exit 0
fi

if [ ! -s "$HOOK" ]; then
  curl -fsSL -m 20 "$SRC" -o "$HOOK" || {
    echo "unbound: hook fetch failed from $SRC" >&2
    echo '{}'
    exit 0
  }
fi

exec python3 "$HOOK"
