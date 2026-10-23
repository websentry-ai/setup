#!/bin/bash
# Drive ONE signed+notarized runtime artifact through the full lifecycle on an
# EC2 Mac fixture (WEB-4805), so S1 sees exactly what the fleet will do:
#
#   1. pkg install            (installer -pkg, via the released onboard.sh path)
#   2. onboard.sh             (setup: writes config, bootstraps the daemon)
#   3. ALL hook events        (PreToolUse, PostToolUse, UserPromptSubmit,
#                              Stop, SessionStart) for claude-code
#   4. discovery daemon run   (kickstart the ai.getunbound.discovery daemon)
#   5. --clear                (teardown via onboard.sh --clear)
#
# Both artifacts (pyinstaller default, nuitka -nuitka suffix) are installed via
# the SAME signed onboard.sh; --artifact only selects which pkg URL to fetch so
# the install path stays identical to production.
#
# Our own logs (install/hook/discovery/clear) are captured to a results dir,
# tagged {artifact, allowlist-state, run-id}, for capture-telemetry.sh to merge
# with the S1 side.
#
# DRY-RUN BY DEFAULT. --execute runs the lifecycle on the fixture over SSH.
# This NEVER runs against the local machine — --host is the fixture.
#
# Usage:
#   run-rehearsal.sh --host <ip> --artifact pyinstaller|nuitka \
#       --allowlist none|team-id [--run-id <id>] [--execute] [--yes]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

TARGET_HOST=""
ARTIFACT=""
ALLOWLIST=""
RUN_ID=""
EXECUTE=0
ASSUME_YES=0
SSH_USER="${SSH_USER:-ec2-user}"

# Onboarding keys: rehearsal-only, supplied via env so they never hit argv or
# the results dir. Required only on --execute.
ONBOARD_API_KEY="${ONBOARD_API_KEY:-}"
ONBOARD_DISCOVERY_KEY="${ONBOARD_DISCOVERY_KEY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)      TARGET_HOST="${2:-}"; shift 2 ;;
    --artifact)  ARTIFACT="${2:-}"; shift 2 ;;
    --allowlist) ALLOWLIST="${2:-}"; shift 2 ;;
    --run-id)    RUN_ID="${2:-}"; shift 2 ;;
    --execute)   EXECUTE=1; shift ;;
    --yes)       ASSUME_YES=1; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ -n "$TARGET_HOST" ]] || die "--host <fixture-ip> is required"
case "$ARTIFACT" in
  pyinstaller|nuitka) ;;
  *) die "--artifact must be pyinstaller or nuitka (got: '$ARTIFACT')" ;;
esac
case "$ALLOWLIST" in
  none|team-id) ;;
  *) die "--allowlist must be none or team-id (got: '$ALLOWLIST')" ;;
esac
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

# Artifact -> pkg URL. The default (pyinstaller) is the canonical released pkg.
# Nuitka artifacts carry a -nuitka suffix (packaging/README.md "Cutting a
# release"). If a separate Nuitka pkg URL is published, override via
# NUITKA_PKG_URL.
artifact_pkg_url() {
  case "$1" in
    pyinstaller) echo "$PKG_URL" ;;
    nuitka)      echo "${NUITKA_PKG_URL:-${ARTIFACT_BASE}/unbound-runtime-${RELEASE_VERSION}-nuitka.pkg}" ;;
  esac
}

TAG="${ARTIFACT}_${ALLOWLIST}_${RUN_ID}"
RUN_RESULTS="$RESULTS_DIR/$TAG"

# remote: echo the command; in --execute run it over SSH, tee'ing remote output
# into a per-stage local log under the run results dir.
remote_stage() {
  local stage="$1"; shift
  log "[$stage] $*"
  emit_cmd "ssh $SSH_USER@$TARGET_HOST -- $*"
  if [[ $EXECUTE -eq 1 ]]; then
    require_tool ssh
    mkdir -p "$RUN_RESULTS"
    ssh -o StrictHostKeyChecking=accept-new "$SSH_USER@$TARGET_HOST" -- "$@" \
      > "$RUN_RESULTS/${stage}.log" 2>&1 \
      || warn "[$stage] returned non-zero — captured to ${stage}.log (NOT fatal: continue the matrix and record it)"
  fi
}

# A representative event payload per hook event. Identical shape to
# packaging/scripts/smoke-test.sh, so S1 sees a real vendored-module dispatch.
hook_payload() {
  case "$1" in
    PreToolUse)       echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"edr-rehearsal"}' ;;
    PostToolUse)      echo '{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"tool_response":{"stdout":"ok"},"session_id":"edr-rehearsal"}' ;;
    UserPromptSubmit) echo '{"hook_event_name":"UserPromptSubmit","prompt":"hello","session_id":"edr-rehearsal"}' ;;
    Stop)             echo '{"hook_event_name":"Stop","session_id":"edr-rehearsal"}' ;;
    SessionStart)     echo '{"hook_event_name":"SessionStart","session_id":"edr-rehearsal"}' ;;
  esac
}

run_hook_events() {
  local ev payload
  for ev in PreToolUse PostToolUse UserPromptSubmit Stop SessionStart; do
    payload="$(hook_payload "$ev")"
    # The hook runs as the user; sudo -u keeps it off root and closer to the
    # real claude-code invocation. Output is the fail-open JSON — captured so
    # the matrix can confirm the binary actually executed under S1.
    remote_stage "hook_${ev}" \
      "printf '%s' '$payload' | $HOOK_BIN hook claude-code $ev"
  done
}

main() {
  section "EDR rehearsal — artifact=$ARTIFACT allowlist=$ALLOWLIST run=$RUN_ID"
  log "Fixture : $TARGET_HOST"
  log "pkg URL : $(artifact_pkg_url "$ARTIFACT")"
  log "Results : $RUN_RESULTS"

  if [[ $EXECUTE -eq 1 ]]; then
    [[ -n "$ONBOARD_API_KEY" && -n "$ONBOARD_DISCOVERY_KEY" ]] \
      || die "ONBOARD_API_KEY and ONBOARD_DISCOVERY_KEY env vars are required on --execute (rehearsal keys; never argv)"
    warn "EXECUTE MODE: installs + runs the runtime on fixture $TARGET_HOST."
    warn "Confirm the S1 console allowlist state is set to '$ALLOWLIST' BEFORE proceeding."
    confirm_or_die "Run $ARTIFACT through the full lifecycle on $TARGET_HOST (allowlist=$ALLOWLIST)? Type 'yes': "
    mkdir -p "$RUN_RESULTS"
  else
    section "DRY RUN — no SSH/install will run. Re-run with --execute."
  fi

  # 1) + 2) Install + onboard via the SIGNED released onboard.sh (production
  # path). onboard.sh downloads the pkg, verifies sha256 + Team ID, installs,
  # and runs `unbound-hook setup`. We point ARTIFACT_URL at the chosen pkg.
  section "Stage 1+2: pkg install + onboard.sh"
  remote_stage "install_onboard" \
    "curl -fSL -o /tmp/onboard.sh '$ONBOARD_URL' && sudo ARTIFACT_URL='$(artifact_pkg_url "$ARTIFACT")' bash /tmp/onboard.sh --api-key \"\$ONBOARD_API_KEY\" --discovery-key \"\$ONBOARD_DISCOVERY_KEY\""

  # 3) All hook events.
  section "Stage 3: all hook events (claude-code)"
  run_hook_events

  # 4) Discovery daemon — kickstart the installed LaunchDaemon so S1 sees the
  # scheduled scan behavior (multi-user /Users iteration, MCP scans) under a
  # root daemon, which is what S1 Storyline tends to flag (-> /opt/unbound/*
  # path exclusion).
  section "Stage 4: discovery daemon scheduled run"
  remote_stage "discovery_daemon" \
    "sudo launchctl kickstart -k system/$DAEMON_LABEL && sleep 60 && sudo tail -n 50 /var/log/unbound/discovery.log"

  # 5) --clear teardown via onboard.sh (binary clear + system sweep).
  section "Stage 5: --clear"
  remote_stage "clear" \
    "curl -fSL -o /tmp/onboard.sh '$ONBOARD_URL' && sudo bash /tmp/onboard.sh --clear"

  section "Done"
  log "Our-side logs: $RUN_RESULTS/*.log"
  log "Now run: capture-telemetry.sh --host $TARGET_HOST --artifact $ARTIFACT --allowlist $ALLOWLIST --run-id $RUN_ID"
  log "Then RE-IMAGE the fixture before the next allowlist/artifact cell (rehearsal must not pollute fixtures)."
  if [[ $EXECUTE -eq 0 ]]; then
    section "DRY RUN complete. Nothing was installed or run."
  fi
}

main
