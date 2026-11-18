#!/bin/bash
# Provision a FRESH EC2 Mac fixture for the EDR (SentinelOne) rehearsal
# (WEB-4805). Mac instances require a dedicated host, so this allocates a
# dedicated host AND launches one instance on it, for one or both chip types:
#
#   arm64 -> mac2.metal  (Apple silicon; default macOS AMI is arm64)
#   intel -> mac1.metal  (x86_64; proves the universal2 Intel slice on real HW)
#
# us-west-2, the DEFAULT aws profile. NEVER the benchling profile (that account
# is single-tenant for the Benchling POV — see project_benchling_single_tenant).
#
# DRY-RUN BY DEFAULT: prints every aws command it WOULD run and exits 0 without
# touching AWS. Pass --execute to actually allocate. Even with --execute it
# prints a cost warning and waits for confirmation, because Mac dedicated hosts
# bill a NON-NEGOTIABLE 24-hour minimum per allocation.
#
# Usage:
#   provision-fixture.sh [--chip arm64|intel|both] [--execute] [--yes]
#
# Nothing here installs SentinelOne or runs the rehearsal — see install-s1.sh
# and run-rehearsal.sh. Tear down with teardown.sh when finished.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

CHIP="both"
EXECUTE=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chip)    CHIP="${2:-}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    --yes)     ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case "$CHIP" in
  arm64|intel|both) ;;
  *) die "--chip must be arm64, intel, or both (got: $CHIP)" ;;
esac

# instance type + AMI-name pattern per chip. The AMI ID is resolved at
# provision time (it changes with every macOS point release) rather than
# pinned here — a stale baked AMI ID is a silent provisioning failure.
chip_instance_type() {
  case "$1" in
    arm64) echo "mac2.metal" ;;
    intel) echo "mac1.metal" ;;
  esac
}
chip_ami_pattern() {
  # Canonical Apple-provided macOS AMIs (owner 100343932686 = "Amazon").
  case "$1" in
    arm64) echo "amzn-ec2-macos-*-arm64" ;;
    intel) echo "amzn-ec2-macos-*-x86_64" ;;
  esac
}

# Resolve the newest matching macOS AMI for a chip. In dry-run we only PRINT
# the query (no credentials assumed); --execute actually resolves it so the
# run-instances command is concrete.
resolve_ami_cmd() {
  local pattern="$1"
  printf 'aws ec2 describe-images %s \\\n' "$(aws_common_args)"
  printf '  --owners %s \\\n' "$EC2_MACOS_AMI_OWNER"
  printf '  --filters "Name=name,Values=%s" "Name=state,Values=available" \\\n' "$pattern"
  printf '  --query "sort_by(Images,&CreationDate)[-1].ImageId" --output text\n'
}

provision_one() {
  local chip="$1"
  local itype ami_pattern
  itype="$(chip_instance_type "$chip")"
  ami_pattern="$(chip_ami_pattern "$chip")"

  section "Fixture: $chip ($itype)"

  log "1) Allocate a dedicated host for $itype in $AWS_REGION/$AWS_AZ"
  emit_cmd "$(cat <<EOF
aws ec2 allocate-hosts $(aws_common_args) \\
  --instance-type $itype \\
  --availability-zone $AWS_AZ \\
  --quantity 1 \\
  --auto-placement on \\
  --tag-specifications 'ResourceType=dedicated-host,Tags=[{Key=Name,Value=$FIXTURE_TAG-$chip},{Key=$TAG_KEY,Value=$TAG_VALUE},{Key=Chip,Value=$chip}]' \\
  --query 'HostIds[0]' --output text
EOF
)"
  warn "Dedicated Mac hosts bill a 24h MINIMUM from this moment. teardown.sh releases them."

  log "2) Resolve newest macOS AMI for $chip"
  if [[ $EXECUTE -eq 1 ]]; then
    local ami
    ami="$(eval "$(resolve_ami_cmd "$ami_pattern" | tr -d '\\\n')")" \
      || die "AMI resolution failed for $chip ($ami_pattern)"
    [[ -n "$ami" && "$ami" != "None" ]] || die "no available macOS AMI matched $ami_pattern"
    log "   resolved AMI: $ami"
  else
    emit_cmd "$(resolve_ami_cmd "$ami_pattern")"
    local ami='<AMI_ID resolved above>'
  fi

  log "3) Launch one instance onto the dedicated host"
  emit_cmd "$(cat <<EOF
aws ec2 run-instances $(aws_common_args) \\
  --image-id $ami \\
  --instance-type $itype \\
  --placement 'Tenancy=host' \\
  --key-name $EC2_KEY_NAME \\
  --security-group-ids $EC2_SECURITY_GROUP_ID \\
  --subnet-id $EC2_SUBNET_ID \\
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=200,VolumeType=gp3,DeleteOnTermination=true}' \\
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=$FIXTURE_TAG-$chip},{Key=$TAG_KEY,Value=$TAG_VALUE},{Key=Chip,Value=$chip},{Key=Purpose,Value=edr-rehearsal}]' \\
  --query 'Instances[0].InstanceId' --output text
EOF
)"

  log "4) Wait until the instance is running + status-ok, then read its address"
  emit_cmd 'aws ec2 wait instance-status-ok '"$(aws_common_args)"' --instance-ids <INSTANCE_ID>'
  emit_cmd "aws ec2 describe-instances $(aws_common_args) --instance-ids <INSTANCE_ID> --query 'Reservations[0].Instances[0].PublicIpAddress' --output text"

  log "Record HostId + InstanceId in $RESULTS_DIR/fixtures-$chip.env for teardown.sh:"
  emit_cmd "printf 'CHIP=%s\\nHOST_ID=%s\\nINSTANCE_ID=%s\\n' $chip <HOST_ID> <INSTANCE_ID> > $RESULTS_DIR/fixtures-$chip.env"
}

main() {
  preflight_aws_profile_guard

  if [[ $EXECUTE -eq 1 ]]; then
    warn "EXECUTE MODE: this WILL allocate billable AWS resources."
    warn "Mac dedicated hosts have a 24-HOUR minimum charge per host (~\$25-40/host/day)."
    confirm_or_die "Allocate EC2 Mac fixture(s) for chip='$CHIP' in $AWS_REGION? Type 'yes' to proceed: "
  else
    section "DRY RUN — no AWS calls will be made. Re-run with --execute to provision."
  fi

  case "$CHIP" in
    arm64) provision_one arm64 ;;
    intel) provision_one intel ;;
    both)  provision_one arm64; provision_one intel ;;
  esac

  section "Next steps"
  log "  1. install-s1.sh   — install the SentinelOne agent on each fixture"
  log "  2. run-rehearsal.sh --artifact pyinstaller|nuitka  — drive the lifecycle"
  log "  3. capture-telemetry.sh  — collect detections + our logs"
  log "  4. teardown.sh --execute — release the dedicated host(s) when done"
  if [[ $EXECUTE -eq 0 ]]; then
    section "DRY RUN complete. Nothing was provisioned."
  fi
}

main
