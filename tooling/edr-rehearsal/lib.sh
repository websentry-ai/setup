#!/bin/bash
# Shared config + helpers for the EDR (SentinelOne) rehearsal harness
# (WEB-4805). Sourced by every script in this directory so the AWS-profile
# guard, dry-run/confirm gate, and result-dir conventions are identical
# everywhere. Not executable on its own.
#
# IMPORTANT (fail-open is sacred): nothing in this harness installs or runs
# the unbound runtime against a developer's daily machine. Every live action
# targets a throwaway EC2 Mac fixture and is gated behind --execute. There is
# no code path here that can BLOCK dev work.

# --- Coordinates (source of truth: WEB-4805 + packaging/README.md) -----------
# These config vars are consumed by the scripts that SOURCE this file, not by
# lib.sh itself; shellcheck can't see cross-file use, so silence SC2034 for the
# config block below.
# shellcheck disable=SC2034
AWS_REGION="${AWS_REGION:-us-west-2}"
AWS_AZ="${AWS_AZ:-us-west-2a}"
# The DEFAULT profile only. NEVER benchling (that account is single-tenant for
# the Benchling POV). Overridable for an operator's own non-default sandbox,
# but the guard below hard-refuses anything matching /benchling/.
AWS_PROFILE_NAME="${AWS_PROFILE_NAME:-default}"

# Apple Team ID for the signer/cert allowlist under test ("Websentry Inc").
TEAM_ID="ZMA55FTA8W"

# Released, signed+notarized artifacts (runtime-v0.1.0).
RELEASE_VERSION="${RELEASE_VERSION:-0.1.0}"
ARTIFACT_BASE="https://unbound-release-artifacts.s3.us-west-2.amazonaws.com/macos/${RELEASE_VERSION}"
PKG_URL="${ARTIFACT_BASE}/unbound-runtime-${RELEASE_VERSION}.pkg"
ONBOARD_URL="${ARTIFACT_BASE}/onboard.sh"

# On-disk install layout (packaging/README.md).
INSTALL_PREFIX="/opt/unbound"
HOOK_BIN="${INSTALL_PREFIX}/current/unbound-hook/unbound-hook"
DISCOVERY_BIN="${INSTALL_PREFIX}/current/unbound-discovery/unbound-discovery"
DAEMON_LABEL="ai.getunbound.discovery"

# EC2 plumbing — placeholders an operator fills in for their VPC/subnet/SG/key.
# Left as <...> so a dry-run reads clearly and an accidental --execute with
# unset plumbing fails loudly at the aws boundary rather than launching into a
# default VPC.
EC2_KEY_NAME="${EC2_KEY_NAME:-<EC2_KEY_NAME>}"
EC2_SUBNET_ID="${EC2_SUBNET_ID:-<EC2_SUBNET_ID>}"
EC2_SECURITY_GROUP_ID="${EC2_SECURITY_GROUP_ID:-<EC2_SECURITY_GROUP_ID>}"
EC2_MACOS_AMI_OWNER="${EC2_MACOS_AMI_OWNER:-amazon}"

# Tagging so every rehearsal resource is findable + teardownable.
FIXTURE_TAG="${FIXTURE_TAG:-unbound-edr-rehearsal}"
TAG_KEY="unbound:purpose"
TAG_VALUE="web-4805-edr-rehearsal"

# Results land beside the scripts by default.
RESULTS_DIR="${RESULTS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results}"

# --- Output helpers ----------------------------------------------------------
log()     { printf '  %s\n' "$*"; }
warn()    { printf 'WARNING: %s\n' "$*" >&2; }
die()     { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
section() { printf '\n=== %s ===\n' "$*"; }

# emit_cmd: in dry-run, this is the ONLY way a "live" command surfaces — it is
# printed, never run. In --execute the caller runs the real aws/ssh command
# itself; emit_cmd is still used to echo it for the operator's audit log.
emit_cmd() { printf '    $ %s\n' "$*"; }

# Common aws args every call shares: region + the (guarded) profile.
aws_common_args() { printf -- '--region %s --profile %s' "$AWS_REGION" "$AWS_PROFILE_NAME"; }

# Hard refusal of the benchling profile (and any non-default unless the
# operator opted in via AWS_PROFILE_NAME). This is the one guard that must
# never be removed.
preflight_aws_profile_guard() {
  case "$AWS_PROFILE_NAME" in
    *benchling*) die "refusing to use a benchling AWS profile ('$AWS_PROFILE_NAME'). The rehearsal runs in the DEFAULT account only." ;;
  esac
  log "AWS profile: $AWS_PROFILE_NAME, region: $AWS_REGION (benchling profile is hard-refused)"
}

# confirm_or_die: interactive gate for --execute paths. Honors --yes via the
# ASSUME_YES the caller sets. Reads from the terminal, not stdin, so it works
# even when stdin is a pipe.
confirm_or_die() {
  local prompt="$1" reply=""
  if [[ "${ASSUME_YES:-0}" -eq 1 ]]; then
    log "(--yes given; skipping interactive confirmation)"
    return 0
  fi
  if [[ ! -t 0 ]] && [[ ! -r /dev/tty ]]; then
    die "refusing to proceed without confirmation (no TTY). Re-run with --yes if you are certain."
  fi
  printf '%s' "$prompt" > /dev/tty
  read -r reply < /dev/tty
  [[ "$reply" == "yes" ]] || die "not confirmed (got '$reply'); aborting."
}

# require_tool: friendly failure if a CLI the --execute path needs is absent.
require_tool() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }
