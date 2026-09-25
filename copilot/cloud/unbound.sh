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

# One of the two has to pin the bytes. The default URL is pinned by construction, because
# it names a commit -- so the ref only has to be shaped like one. An override names
# whatever it names, and a mirror's content can change under us, so there the digest is the
# only thing left and it stops being optional.
if [ -z "${UNBOUND_HOOK_URL:-}" ]; then
  # Checks the ref's shape, not the placeholder text: a guard written as a literal
  # placeholder is itself rewritten by the install step and then matches every stamped URL.
  case "$REF" in
    '' | *[!0-9a-f]*) fail "hook ref is not a commit sha; reinstall from copilot/cloud" ;;
  esac
elif [ -z "${UNBOUND_HOOK_SHA256:-}" ]; then
  fail "UNBOUND_HOOK_URL requires UNBOUND_HOOK_SHA256: an override is not pinned to a commit"
fi

# -q ignores ~/.curlrc, which the agent shares a uid with and could point at a proxy of
# its own; --proto '=https' refuses any redirect off TLS. -m 8, not 20: this fetch is spent
# before the hook's own 2x8s of gateway retries, and the total has to clear the preToolUse
# timeout, which defaults to 30s. Overrunning it gets the hook killed, and a killed
# preToolUse fails OPEN.
fetch() { curl -q --proto '=https' -fsSL -m 8 "$SRC"; }

# The hook is never written to disk. It was cached under /tmp when a digest was set, but
# that cache was the only reason this script ever read a path back -- and reading an
# agent-writable path is unbounded work: a multi-gigabyte file, or a FIFO with no writer,
# stalls the read until the hook is killed, and a killed preToolUse fails OPEN. Fetching
# every event costs one request already inside the pre-tool budget and removes the file,
# the staging rename, the symlink target and the read entirely.
#
# What is left is a snapshot in this process. A shell variable is the one thing the agent
# cannot reach, so the bytes verified below are provably the bytes executed.
CODE=$(fetch) || fail "hook fetch failed from $SRC"
[ -n "$CODE" ] || fail "hook fetch returned nothing from $SRC"

# `$(...)` strips trailing newlines and `printf '%s\n'` restores exactly one, which
# round-trips a file ending in a single newline byte-for-byte -- so UNBOUND_HOOK_SHA256
# stays the plain sha256 of the published file.
if [ -n "${UNBOUND_HOOK_SHA256:-}" ]; then
  actual=$(printf '%s\n' "$CODE" | sha256sum | cut -d' ' -f1)
  if [ "$actual" != "$UNBOUND_HOOK_SHA256" ]; then
    fail "hook digest mismatch: expected $UNBOUND_HOOK_SHA256, got ${actual:-none}"
  fi
fi

# -I is load-bearing, not hygiene. Running a script puts its own directory on sys.path
# ahead of the standard library: without it a planted module next to the script is
# imported by the verified hook, and the digest proves nothing. Isolated mode drops the
# script directory, PYTHONPATH and user site-packages.
# The script arrives on fd 3 rather than as a path, which keeps stdin free for the event
# payload. `-c` is not an option: the hook is ~320KB and Linux caps a single argument at
# 128KB. The hook's three `__file__` uses are re-invocation paths guarded by
# os.path.isfile, so they no-op here instead of misfiring.
UNBOUND_HOOK_EVENT="$EVENT" exec python3 -I /dev/fd/3 3< <(printf '%s\n' "$CODE")
