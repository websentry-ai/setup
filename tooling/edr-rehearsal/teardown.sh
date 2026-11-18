#!/bin/bash
# Tear down the EC2 Mac rehearsal fixture(s) (WEB-4805): terminate the
# instance and RELEASE the dedicated host so billing stops (subject to the
# unavoidable 24h host minimum). The rehearsal must not pollute the Stream V
# fixtures, so the canonical "re-image" is: terminate + release, then re-run
# provision-fixture.sh for any further runs (a fresh host = a clean macOS AMI,
# no S1/runtime residue).
#
# Reads HostId/InstanceId from $RESULTS_DIR/fixtures-<chip>.env (written by
# provision-fixture.sh) or from explicit flags.
#
# DRY-RUN BY DEFAULT: prints the teardown commands and exits 0. --execute
# performs the termination + release. There is NO path here that can affect a
# real developer machine.
#
# Usage:
#   teardown.sh [--chip arm64|intel|both] [--instance-id i-..] [--host-id h-..] [--execute] [--yes]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

CHIP="both"
INSTANCE_ID=""
HOST_ID=""
EXECUTE=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chip)        CHIP="${2:-}"; shift 2 ;;
    --instance-id) INSTANCE_ID="${2:-}"; shift 2 ;;
    --host-id)     HOST_ID="${2:-}"; shift 2 ;;
    --execute)     EXECUTE=1; shift ;;
    --yes)         ASSUME_YES=1; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$CHIP" in
  arm64|intel|both) ;;
  *) die "--chip must be arm64, intel, or both" ;;
esac

# run_cmd: echo always; on --execute, run it.
run_cmd() {
  emit_cmd "$*"
  if [[ $EXECUTE -eq 1 ]]; then
    require_tool aws
    eval "$*" || warn "command returned non-zero: $*"
  fi
}

teardown_one() {
  local chip="$1"
  local iid="$INSTANCE_ID" hid="$HOST_ID"
  local envfile="$RESULTS_DIR/fixtures-$chip.env"

  # Prefer explicit flags; otherwise read the env file provision-fixture wrote.
  if [[ -z "$iid" || -z "$hid" ]] && [[ -f "$envfile" ]]; then
    log "reading ids from $envfile"
    # shellcheck disable=SC1090  # KEY=VALUE file written by provision-fixture.sh
    source "$envfile"
    iid="${iid:-${INSTANCE_ID:-}}"
    hid="${hid:-${HOST_ID:-}}"
  fi

  section "Teardown: $chip"
  if [[ -z "$iid" || -z "$hid" ]]; then
    warn "no instance/host id for $chip (no $envfile and no --instance-id/--host-id). Skipping."
    log "Find them manually:"
    emit_cmd "aws ec2 describe-instances $(aws_common_args) --filters 'Name=tag:$TAG_KEY,Values=$TAG_VALUE' --query 'Reservations[].Instances[].[InstanceId,Placement.HostId]' --output text"
    return 0
  fi

  log "instance: $iid   host: $hid"
  log "1) Terminate the instance"
  run_cmd "aws ec2 terminate-instances $(aws_common_args) --instance-ids $iid"
  log "2) Wait for termination (a host cannot be released while it has a running instance)"
  run_cmd "aws ec2 wait instance-terminated $(aws_common_args) --instance-ids $iid"
  log "3) Release the dedicated host (stops billing beyond the 24h minimum)"
  run_cmd "aws ec2 release-hosts $(aws_common_args) --host-ids $hid"

  if [[ $EXECUTE -eq 1 ]]; then
    rm -f "$envfile"
    log "removed $envfile"
  fi
}

main() {
  preflight_aws_profile_guard

  if [[ $EXECUTE -eq 1 ]]; then
    warn "EXECUTE MODE: this TERMINATES instances and RELEASES dedicated hosts."
    confirm_or_die "Tear down rehearsal fixture(s) for chip='$CHIP'? Type 'yes': "
  else
    section "DRY RUN — no AWS calls. Re-run with --execute to tear down."
  fi

  case "$CHIP" in
    arm64) teardown_one arm64 ;;
    intel) teardown_one intel ;;
    both)  teardown_one arm64; teardown_one intel ;;
  esac

  section "Re-image reminder"
  log "For another rehearsal cell, re-run provision-fixture.sh for a FRESH host."
  log "A fresh host boots a clean macOS AMI — no S1 agent, no runtime residue."
  if [[ $EXECUTE -eq 0 ]]; then
    section "DRY RUN complete. Nothing was torn down."
  fi
}

main
