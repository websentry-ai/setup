#!/usr/bin/env bash
# Fetches the Unbound hook into the sandbox and runs it.
#
# The hook is pinned to an immutable commit and its digest checked before it
# runs: this process holds the organization API key, so unverified bytes from a
# mutable ref must never reach python3.
#
# A fetch that fails leaves policy unevaluated. preToolUse is the one event
# where that silently permits an action the organization may have denied, so it
# denies instead; every other event only loses telemetry, so it stays out of the
# agent's way.

EVENT="${1:-unknown}"
HOOK=/tmp/unbound-hook.py
# Stamped with a release commit when this file is installed into a repository.
# Deliberately not defaulted to a branch: a mutable ref would let unreviewed
# code run in a sandbox holding the organization API key.
REF="__UNBOUND_HOOK_REF__"
SRC="${UNBOUND_HOOK_URL:-https://raw.githubusercontent.com/websentry-ai/setup/$REF/copilot/hooks/unbound.py}"

fail() {
  echo "unbound: $1" >&2
  if [ "$EVENT" = "preToolUse" ]; then
    printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' \
      "Unbound policy checks are unavailable in this sandbox, so this action cannot be approved. Stop and report it in the pull request."
  else
    echo '{}'
  fi
  exit 0
}

# Machines with the agent installed already report through their own hook; this
# config is read by Copilot CLI there too, and both would send the same turn.
if [ -f "$HOME/.copilot/hooks/unbound.py" ]; then
  echo '{}'
  exit 0
fi

case "$SRC" in
  *__UNBOUND_HOOK_REF__*) fail "hook ref was never stamped; reinstall from copilot/cloud" ;;
esac

if [ ! -s "$HOOK" ]; then
  curl -fsSL -m 20 "$SRC" -o "$HOOK" || fail "hook fetch failed from $SRC"

  if [ -n "${UNBOUND_HOOK_SHA256:-}" ]; then
    actual=$(sha256sum "$HOOK" 2>/dev/null | cut -d' ' -f1)
    if [ "$actual" != "$UNBOUND_HOOK_SHA256" ]; then
      rm -f "$HOOK"
      fail "hook digest mismatch: expected $UNBOUND_HOOK_SHA256, got ${actual:-none}"
    fi
  fi
fi

exec python3 "$HOOK"
