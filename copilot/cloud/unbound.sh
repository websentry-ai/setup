#!/usr/bin/env bash
# Fetches the Unbound hook into the cloud agent sandbox and runs it.
#
# Pinned to an immutable commit and digest-checked before it runs: this process holds the
# organization API key, so unverified bytes from a mutable ref must never reach python3.
#
# A fetch that fails leaves policy unevaluated. preToolUse is the one event where that
# silently permits an action the organization may have denied, so it denies instead.

EVENT="${1:-unknown}"
HOOK=/tmp/unbound-hook.py
# Stamped with a release commit at install time; never defaulted to a branch.
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

# Machines with the agent installed already report through their own hook, and Copilot CLI
# reads this config there too. Never in a sandbox: the agent can create that path itself.
if [ -z "${COPILOT_AGENT_SESSION_ID:-}" ] && [ -f "$HOME/.copilot/hooks/unbound.py" ]; then
  echo '{}'
  exit 0
fi

# Checks the ref's shape, not the placeholder text: a guard written as a literal
# placeholder is itself rewritten by the install step and then matches every stamped URL.
if [ -z "${UNBOUND_HOOK_URL:-}" ]; then
  case "$REF" in
    '' | *[!0-9a-f]*) fail "hook ref is not a commit sha; reinstall from copilot/cloud" ;;
  esac
fi

# The cache sits in /tmp, which the agent can write. Without a digest we cannot tell a
# planted hook from ours, so it is not reused at all and every event refetches.
if [ -z "${UNBOUND_HOOK_SHA256:-}" ] || [ ! -s "$HOOK" ]; then
  # -m 8, not 20: this fetch is spent before the hook's own 2x8s of gateway retries, and
  # the total has to clear the preToolUse timeout, which defaults to 30s. Overrunning it
  # gets the hook killed, and a killed preToolUse fails OPEN.
  # A dropped transfer leaves a partial file that a later event would happily run.
  curl -fsSL -m 8 "$SRC" -o "$HOOK" || { rm -f "$HOOK"; fail "hook fetch failed from $SRC"; }
fi

# Every event, not just the one that fetched.
if [ -n "${UNBOUND_HOOK_SHA256:-}" ]; then
  actual=$(sha256sum "$HOOK" 2>/dev/null | cut -d' ' -f1)
  if [ "$actual" != "$UNBOUND_HOOK_SHA256" ]; then
    rm -f "$HOOK"
    fail "hook digest mismatch: expected $UNBOUND_HOOK_SHA256, got ${actual:-none}"
  fi
fi

UNBOUND_HOOK_EVENT="$EVENT" exec python3 "$HOOK"
