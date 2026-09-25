#!/usr/bin/env bash
# Fetches the Unbound hook into the cloud agent sandbox and runs it.

# System paths first: the checks below are bare command names, and one shadowed by an
# agent-writable directory would verify nothing.
PATH=/usr/bin:/bin:$PATH

EVENT="${1:-unknown}"
# Stamped with a release commit at install time; never defaulted to a branch.
REF="__UNBOUND_HOOK_REF__"
SRC="${UNBOUND_HOOK_URL:-https://raw.githubusercontent.com/websentry-ai/setup/$REF/copilot/hooks/unbound.py}"

# preToolUse is the one event where saying nothing permits the action, so it denies.
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

# Cloud only. Copilot CLI reads this config on laptops, where the managed hook already
# reports the turn and a blocked raw.githubusercontent.com would deny every preToolUse.
if [ -z "${COPILOT_AGENT_SESSION_ID:-}" ]; then
  echo '{}'
  exit 0
fi

# The bytes have to be pinned by one of the two. The default URL names a commit, so the
# ref only has to be shaped like one; an override names anything, so it needs the digest.
if [ -z "${UNBOUND_HOOK_URL:-}" ]; then
  # Shape, not the placeholder text: a literal guard is rewritten by the install step too.
  case "$REF" in
    *[!0-9a-f]*) fail "hook ref is not a commit sha; reinstall from copilot/cloud" ;;
  esac
  # Full 40: a short sha or an all-hex branch name is not pinned.
  [ "${#REF}" -eq 40 ] || fail "hook ref is not a full 40-character commit sha; reinstall from copilot/cloud"
elif [ -z "${UNBOUND_HOOK_SHA256:-}" ]; then
  fail "UNBOUND_HOOK_URL requires UNBOUND_HOOK_SHA256: an override is not pinned to a commit"
fi

# -q ignores ~/.curlrc, which the agent could point at a proxy of its own; --proto '=https'
# refuses a redirect off TLS; -m 8 leaves room for the hook's own retries inside the 30s
# preToolUse timeout, past which the hook is killed and preToolUse fails OPEN.
fetch() { curl -q --proto '=https' -fsSL -m 8 "$SRC"; }

# Held in a variable, never on disk: a path the agent can write is unbounded work — a huge
# file or a FIFO with no writer stalls the read until the hook is killed, which fails OPEN.
# A shell variable is the one thing it cannot reach, so the bytes verified are the bytes run.
CODE=$(fetch) || fail "hook fetch failed from $SRC"
[ -n "$CODE" ] || fail "hook fetch returned nothing from $SRC"

# $(...) strips trailing newlines and printf restores exactly one, so the digest stays the
# plain sha256 of the published file.
if [ -n "${UNBOUND_HOOK_SHA256:-}" ]; then
  actual=$(printf '%s\n' "$CODE" | sha256sum | cut -d' ' -f1)
  if [ "$actual" != "$UNBOUND_HOOK_SHA256" ]; then
    fail "hook digest mismatch: expected $UNBOUND_HOOK_SHA256, got ${actual:-none}"
  fi
fi

# -I drops the script directory, PYTHONPATH and user site-packages: without it a module
# planted beside the script is imported by the verified hook and the digest proves nothing.
# fd 3 keeps stdin free for the event payload, and -c cannot carry a ~320KB hook past the
# 128KB argument cap.
UNBOUND_HOOK_EVENT="$EVENT" exec python3 -I /dev/fd/3 3< <(printf '%s\n' "$CODE")
