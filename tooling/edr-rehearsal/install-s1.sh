#!/bin/bash
# Install the SentinelOne (S1) agent on an EC2 Mac fixture for the EDR
# rehearsal (WEB-4805). Parameterized: the S1 site token comes from the
# S1_SITE_TOKEN env var (never argv — tokens leak via ps/cmdline) and the
# signed agent pkg path/URL via --pkg.
#
# TODO(WEB-4805 / WEB-4784): The S1 tenant + site token are PENDING the vendor
# sourcing decision (Salesloft's actual EDR is confirmed SentinelOne; the
# tenant we rehearse against — Salesloft-supplied vs an Unbound trial — is the
# open WEB-4805 question). This script is fully parameterized so dropping the
# real token + pkg in later requires no edits.
#
# DRY-RUN BY DEFAULT: prints the install commands and exits 0. --execute runs
# the install on the fixture over SSH. install-s1 never touches the local
# machine — TARGET_HOST is the fixture.
#
# Usage:
#   S1_SITE_TOKEN=... install-s1.sh --host <fixture-ip> --pkg <s1-agent.pkg|url> [--execute] [--yes]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

TARGET_HOST=""
S1_PKG=""
EXECUTE=0
ASSUME_YES=0
SSH_USER="${SSH_USER:-ec2-user}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)    TARGET_HOST="${2:-}"; shift 2 ;;
    --pkg)     S1_PKG="${2:-}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    --yes)     ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ -n "$TARGET_HOST" ]] || die "--host <fixture-ip> is required (the EC2 Mac fixture, never your laptop)"
[[ -n "$S1_PKG" ]]      || die "--pkg <s1-agent.pkg|url> is required (the Salesloft/S1-supplied signed agent)"

# The token is the one secret we refuse to default or print. Its absence is a
# hard stop on --execute; in dry-run we only note that it must be set.
if [[ -z "${S1_SITE_TOKEN:-}" ]]; then
  if [[ $EXECUTE -eq 1 ]]; then
    die "S1_SITE_TOKEN is unset. Source it from the S1 console; do NOT pass it on argv. (Pending WEB-4805 vendor decision.)"
  fi
  warn "S1_SITE_TOKEN unset — fine for dry-run, but --execute requires it."
fi

# remote: emit the command, and in --execute actually run it over SSH.
remote() {
  local desc="$1"; shift
  log "$desc"
  emit_cmd "ssh $SSH_USER@$TARGET_HOST -- $*"
  if [[ $EXECUTE -eq 1 ]]; then
    require_tool ssh
    ssh -o StrictHostKeyChecking=accept-new "$SSH_USER@$TARGET_HOST" -- "$@" \
      || die "remote step failed: $desc"
  fi
}

main() {
  section "SentinelOne agent install -> fixture $TARGET_HOST"
  log "Site token: \$S1_SITE_TOKEN (env, not printed)"
  log "Agent pkg : $S1_PKG"

  if [[ $EXECUTE -eq 1 ]]; then
    warn "EXECUTE MODE: this installs an EDR agent on $TARGET_HOST."
    confirm_or_die "Install SentinelOne on fixture $TARGET_HOST? Type 'yes': "
  else
    section "DRY RUN — no SSH/install will run. Re-run with --execute."
  fi

  # S1 macOS install is a standard pkg install; the site token is supplied via
  # the registration token file S1 reads at first boot (com.sentinelone.*).
  # Exact mechanism is vendor-version-specific — confirm against the S1 console
  # install instructions for the tenant chosen in WEB-4805.
  remote "1) Stage the S1 agent pkg on the fixture" \
    "curl -fSL -o /tmp/s1-agent.pkg '$S1_PKG'"

  remote "2) Drop the registration (site) token where the agent reads it" \
    "sudo /bin/sh -c 'umask 077; printf %s \"\$S1_SITE_TOKEN\" > /tmp/com.sentinelone.registration-token'"

  remote "3) Install the agent" \
    "sudo installer -pkg /tmp/s1-agent.pkg -target /"

  remote "4) Verify the agent is registered + online" \
    "sudo /usr/local/bin/sentinelctl management status || true"

  remote "5) Scrub the staged token + pkg" \
    "sudo rm -f /tmp/com.sentinelone.registration-token /tmp/s1-agent.pkg"

  section "Allowlist note"
  log "The ZMA55FTA8W signer exclusion + /opt/unbound/* path exclusion are configured"
  log "in the S1 CONSOLE/policy, not on the endpoint. run-rehearsal.sh exercises BOTH"
  log "allowlist states; toggle the console policy between runs and tag captures"
  log "with --allowlist none|team-id accordingly (see matrix.md)."

  if [[ $EXECUTE -eq 0 ]]; then
    section "DRY RUN complete. Nothing was installed."
  fi
}

main
