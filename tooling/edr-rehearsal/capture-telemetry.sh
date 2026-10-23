#!/bin/bash
# Collect the evidence for one rehearsal cell (WEB-4805): S1 detections/threats
# + Storyline export from the S1 console API, plus our own install/hook/
# discovery logs pulled off the fixture. Everything lands in a results dir
# tagged {artifact, allowlist-state, run-id} so matrix.md can be filled from
# files, not memory.
#
# The run-id is a PARAMETER (--run-id) so a capture is reproducible and matches
# the run-rehearsal.sh tag exactly. If omitted, it defaults to a UTC timestamp
# (fine for an interactive one-off; pass --run-id to pair with a specific run).
#
# DRY-RUN BY DEFAULT. --execute performs the S1 API queries + SSH log pulls.
# Reads only — capture never changes the fixture or the S1 tenant.
#
# Usage:
#   S1_API_TOKEN=... capture-telemetry.sh --host <ip> --artifact pyinstaller|nuitka \
#       --allowlist none|team-id [--run-id <id>] [--since <iso8601>] [--execute]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

TARGET_HOST=""
ARTIFACT=""
ALLOWLIST=""
RUN_ID=""
SINCE=""
EXECUTE=0
SSH_USER="${SSH_USER:-ec2-user}"

# S1 console (mgmt) base URL + read API token. Pending WEB-4805 vendor decision.
S1_CONSOLE_URL="${S1_CONSOLE_URL:-<S1_CONSOLE_URL>}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)      TARGET_HOST="${2:-}"; shift 2 ;;
    --artifact)  ARTIFACT="${2:-}"; shift 2 ;;
    --allowlist) ALLOWLIST="${2:-}"; shift 2 ;;
    --run-id)    RUN_ID="${2:-}"; shift 2 ;;
    --since)     SINCE="${2:-}"; shift 2 ;;
    --execute)   EXECUTE=1; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ -n "$TARGET_HOST" ]] || die "--host <fixture-ip> is required"
case "$ARTIFACT" in
  pyinstaller|nuitka) ;;
  *) die "--artifact must be pyinstaller or nuitka" ;;
esac
case "$ALLOWLIST" in
  none|team-id) ;;
  *) die "--allowlist must be none or team-id" ;;
esac
# Default run-id is a timestamp; pass --run-id to pair with a specific
# run-rehearsal.sh cell. (Default kept out of the inline command paths so the
# value is stable for the whole invocation.)
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

TAG="${ARTIFACT}_${ALLOWLIST}_${RUN_ID}"
OUT="$RESULTS_DIR/$TAG"

s1_get() { # path -> prints curl command; runs it on --execute into a named file
  local desc="$1" path="$2" outfile="$3"
  log "$desc"
  emit_cmd "curl -fsS -H 'Authorization: ApiToken \$S1_API_TOKEN' '$S1_CONSOLE_URL$path' > $OUT/$outfile"
  if [[ $EXECUTE -eq 1 ]]; then
    require_tool curl
    [[ -n "${S1_API_TOKEN:-}" ]] || die "S1_API_TOKEN unset (read token from the S1 console; do not pass on argv)"
    curl -fsS -H "Authorization: ApiToken ${S1_API_TOKEN}" "$S1_CONSOLE_URL$path" > "$OUT/$outfile" \
      || warn "S1 query failed: $desc (left $OUT/$outfile possibly empty)"
  fi
}

pull_log() { # remote-path local-name
  local remote="$1" local_name="$2"
  log "pull $remote"
  emit_cmd "scp $SSH_USER@$TARGET_HOST:$remote $OUT/$local_name"
  if [[ $EXECUTE -eq 1 ]]; then
    require_tool scp
    scp -o StrictHostKeyChecking=accept-new "$SSH_USER@$TARGET_HOST:$remote" "$OUT/$local_name" 2>/dev/null \
      || warn "could not pull $remote (may not exist for this stage — ok)"
  fi
}

main() {
  section "Capture telemetry — $TAG"
  log "Results dir: $OUT"
  if [[ $EXECUTE -eq 1 ]]; then
    mkdir -p "$OUT"
  else
    section "DRY RUN — no API/SSH calls. Re-run with --execute."
  fi

  section "1) SentinelOne console: threats + Storyline for this fixture"
  # The agent UUID/endpoint name for $TARGET_HOST is looked up first so the
  # threat/Storyline queries scope to THIS fixture only. computerName filter
  # keeps the query tenant-safe.
  s1_get "agent record for fixture" \
    "/web/api/v2.1/agents?computerName__contains=${FIXTURE_TAG}" \
    "s1_agents.json"
  local since_q=""
  [[ -n "$SINCE" ]] && since_q="&createdAt__gte=${SINCE}"
  s1_get "threats/detections for fixture" \
    "/web/api/v2.1/threats?computerName__contains=${FIXTURE_TAG}${since_q}" \
    "s1_threats.json"
  s1_get "activities (Storyline-adjacent events)" \
    "/web/api/v2.1/activities?computerName__contains=${FIXTURE_TAG}${since_q}" \
    "s1_activities.json"
  log "NOTE: full Storyline (process-tree) export is per-threat — for each threat id in"
  log "      s1_threats.json, also fetch /web/api/v2.1/threats/<id>/explore/* or export"
  log "      the Deep Visibility query from the console UI into $OUT/storyline/."

  section "2) Our-side logs off the fixture"
  pull_log "/var/log/unbound/discovery.log"     "unbound-discovery.log"
  pull_log "/var/log/unbound/discovery.err.log" "unbound-discovery.err.log"
  # run-rehearsal.sh already captured per-stage logs locally under the matching
  # tag; copy them in so each cell's evidence is self-contained.
  if [[ $EXECUTE -eq 1 && -d "$RESULTS_DIR/$TAG" && "$RESULTS_DIR/$TAG" != "$OUT" ]]; then
    cp "$RESULTS_DIR/$TAG"/*.log "$OUT/" 2>/dev/null || true
  fi

  section "3) Provenance stamp"
  emit_cmd "write $OUT/metadata.txt (artifact, allowlist, run-id, host, team-id, captured-at)"
  if [[ $EXECUTE -eq 1 ]]; then
    {
      printf 'artifact=%s\n'   "$ARTIFACT"
      printf 'allowlist=%s\n'  "$ALLOWLIST"
      printf 'run_id=%s\n'     "$RUN_ID"
      printf 'fixture_host=%s\n' "$TARGET_HOST"
      printf 'team_id=%s\n'    "$TEAM_ID"
      printf 'release_version=%s\n' "$RELEASE_VERSION"
      printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$OUT/metadata.txt"
    log "wrote $OUT/metadata.txt"
  fi

  section "Done"
  log "Fill the matching row in matrix.md from the files in $OUT."
  if [[ $EXECUTE -eq 0 ]]; then
    section "DRY RUN complete. Nothing was captured."
  fi
}

main
