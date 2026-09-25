#!/usr/bin/env bash
# Fetches the Unbound hook into the cloud agent sandbox and runs it.
#
# Pinned to an immutable commit and digest-checked before it runs: this process holds the
# organization API key, so unverified bytes from a mutable ref must never reach python3.
#
# A fetch that fails leaves policy unevaluated. preToolUse is the one event where that
# silently permits an action the organization may have denied, so it denies instead.

# System paths first: every integrity check below is a bare command name, and one
# shadowed by an agent-writable directory earlier in PATH would verify nothing.
PATH=/usr/bin:/bin:$PATH

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

# Cloud sessions only. Copilot CLI reads this config on laptops too, where the managed
# hook already reports the turn -- and where an install may be the binary rather than
# ~/.copilot/hooks/unbound.py, so presence of that file is the wrong thing to test. On a
# laptop with no install at all, running anyway would have a repository turn telemetry on,
# and a blocked raw.githubusercontent.com would deny every preToolUse.
if [ -z "${COPILOT_AGENT_SESSION_ID:-}" ]; then
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
  # Downloaded beside the target and renamed: overlapping events share this path, and a
  # reader must never see a half-written file.
  TMP="$HOOK.$$"
  curl -fsSL -m 8 "$SRC" -o "$TMP" || { rm -f "$TMP"; fail "hook fetch failed from $SRC"; }
  mv -f "$TMP" "$HOOK" || { rm -f "$TMP"; fail "could not stage the hook at $HOOK"; }
fi

# Every event, not just the one that fetched.
if [ -n "${UNBOUND_HOOK_SHA256:-}" ]; then
  actual=$(sha256sum "$HOOK" 2>/dev/null | cut -d' ' -f1)
  if [ "$actual" != "$UNBOUND_HOOK_SHA256" ]; then
    rm -f "$HOOK"
    fail "hook digest mismatch: expected $UNBOUND_HOOK_SHA256, got ${actual:-none}"
  fi
fi

# -I is load-bearing, not hygiene. Running a script puts its own directory on sys.path
# ahead of the standard library, and that directory is /tmp: a planted /tmp/json.py would
# be imported by the verified hook, which makes the digest chain above prove nothing.
# Isolated mode drops the script directory, PYTHONPATH and user site-packages.
UNBOUND_HOOK_EVENT="$EVENT" exec python3 -I "$HOOK"
