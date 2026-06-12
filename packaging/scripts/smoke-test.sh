#!/bin/bash
# Smoke-run both freshly built bundles on the runner (WEB-4789):
#   * --version on each binary
#   * `hook` with a sample stdin event
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

echo "--- unbound-hook hook (sample stdin event)"
sample='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"ci-smoke"}'
out="$(printf '%s' "$sample" | "$hook" hook)"
echo "$out"

if arch -x86_64 /usr/bin/true 2>/dev/null; then
  echo "--- Rosetta present: re-running --version under x86_64"
  arch -x86_64 "$hook" --version
  arch -x86_64 "$discovery" --version
else
  echo "--- Rosetta not available; skipping forced-x86_64 execution check"
fi

echo "Smoke test passed."
