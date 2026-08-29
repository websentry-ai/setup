# tooling/edr-rehearsal — push-button EDR (SentinelOne) rehearsal harness

Rehearse the signed+notarized macOS runtime against Salesloft's EDR
(SentinelOne) on a throwaway EC2 Mac fixture, pick the surviving artifact by
evidence, and re-image. Authoring/operator tooling — distinct from the build
steps in `packaging/`. Ticket: **WEB-4805**.

Start with **[RUNBOOK.md](RUNBOOK.md)**.

| File | What |
|---|---|
| `RUNBOOK.md` | Operator-facing, step-by-step end-to-end procedure |
| `matrix.md` | 2 artifacts × 2 allowlist states × 5 stages, with a results column |
| `lib.sh` | Shared config + the AWS-profile guard + dry-run/confirm gate (sourced, not run) |
| `provision-fixture.sh` | Allocate a fresh dedicated host + instance per chip (`mac2.metal` arm64, `mac1.metal` intel), us-west-2, default profile |
| `install-s1.sh` | Install the SentinelOne agent on a fixture (site token via `S1_SITE_TOKEN`) |
| `run-rehearsal.sh` | Drive one artifact (`--artifact pyinstaller\|nuitka`) through install → onboard → all hook events → discovery daemon → `--clear` |
| `capture-telemetry.sh` | Collect S1 detections + Storyline + our logs, tagged `{artifact, allowlist, run-id}` |
| `teardown.sh` | Terminate the instance + release the dedicated host (the re-image) |
| `results/` | Per-cell evidence dirs (gitignored) |

## Safety

Every live-action script **defaults to dry-run** (prints the exact commands,
touches nothing) and requires `--execute` to do anything real. AWS-touching
scripts also warn about the **24-hour dedicated-host minimum** and require an
interactive `yes`. The **benchling AWS profile is hard-refused**. Nothing here
can block a developer's daily machine — fail-open is sacred.

All scripts pass `shellcheck` and follow the `set -euo pipefail` / `HERE` /
heredoc conventions used in `packaging/scripts/`.
