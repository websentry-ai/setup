#!/bin/bash
# Smoke-run both freshly built bundles on the runner (WEB-4789):
#   * --version on each binary
#   * a REAL tool+event hook dispatch that proves a vendored module loaded
#   * if Rosetta is available, repeat --version under forced x86_64 so the
#     Intel slice is proven to EXECUTE, not just exist in lipo output.
# Usage: smoke-test.sh <dist-dir>
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <dist-dir>" >&2; exit 2; }
dist="$1"
hook="$dist/unbound-hook/unbound-hook"
discovery="$dist/unbound-discovery/unbound-discovery"

echo "--- unbound-hook --version"
"$hook" --version

echo "--- unbound-discovery --version"
"$discovery" --version

# Real vendored-module dispatch — NOT just dispatcher boot.
#
# Why a full tool+event (claude-code PreToolUse), not bare `hook`: with no
# tool arg the dispatcher short-circuits at hook_cmd.py ("args[0] not in
# TOOLS" -> print {} exit 0) WITHOUT loading any vendored module, so a bundle
# with a missing/corrupt _internal/vendored/ tree would still pass. We must
# force a vendored import.
#
# Why exit 0 is NOT a sufficient assertion: the hook fails OPEN by design.
# A failed vendored import is caught at hook_cmd.py and prints the neutral
# `{}` with exit 0 — invisible to a returncode check. The hooks run as root
# on the fleet and a silently-non-enforcing hook is exactly the regression
# CI must catch (the fleet never will). So we assert on OUTPUT, not status:
# the claude-code PreToolUse module, gateway unreachable, fails open to the
# literal `{"suppressOutput": true}` (claude-code/hooks/unbound.py). A bundle
# whose vendored module failed to import emits `{}` instead — no
# "suppressOutput" token. That token is the proof the module actually ran.
echo "--- unbound-hook hook claude-code PreToolUse (vendored-module dispatch)"
sample='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"ci-smoke"}'
# Dead local port so the module fails open instead of hanging on / reaching a
# real gateway; HOME is the runner's, which has no ~/.unbound config.
out="$(printf '%s' "$sample" | UNBOUND_GATEWAY_URL="http://127.0.0.1:9" "$hook" hook claude-code PreToolUse)"
echo "$out"

# (a) JSON sanity, pure shell (plutil -lint mis-parses bare JSON from stdin).
case "$out" in
  "{"*"}"|"["*"]") ;;
  *) echo "FAIL: hook output is not JSON: [$out]" >&2; exit 1 ;;
esac
# (b) Load-bearing: the vendored claude-code module MUST have run. The
# fail-open neutral `{}` (missing/corrupt vendored module) lacks this token.
case "$out" in
  *'"suppressOutput": true'*|*'"suppressOutput":true'*) ;;
  *) echo "FAIL: hook claude-code PreToolUse returned '$out', not the vendored module's fail-open response — the vendored module did not load (missing/corrupt _internal/vendored/). The bundle would silently STOP enforcing on the fleet." >&2
     exit 1 ;;
esac

if arch -x86_64 /usr/bin/true 2>/dev/null; then
  echo "--- Rosetta present: re-running --version under x86_64"
  arch -x86_64 "$hook" --version
  arch -x86_64 "$discovery" --version
else
  echo "--- Rosetta not available; skipping forced-x86_64 execution check"
fi

echo "Smoke test passed."
