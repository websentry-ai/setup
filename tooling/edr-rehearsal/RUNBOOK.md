# EDR (SentinelOne) rehearsal — operator runbook (WEB-4805)

> One shot. We rehearse the signed+notarized macOS runtime against Salesloft's
> actual EDR (SentinelOne) on a throwaway EC2 Mac fixture **before** the
> customer ever sees it, pick the artifact that survives by evidence, and
> re-image so the rehearsal never pollutes the real fixtures.

Ticket: https://linear.app/unboundsec/issue/WEB-4805
Project: Non-Python MDM Rollout (Mac fleet) — customer Salesloft (~1,150-Mac
Jamf fleet).

## What we are deciding

Two signed artifacts ship from the same pipeline; we run BOTH end-to-end
against S1 and keep the one that stays clean:

| Artifact | Source | pkg |
|---|---|---|
| PyInstaller (default) | WEB-4786 / WEB-4787 | `unbound-runtime-0.1.0.pkg` |
| Nuitka | WEB-4804 (PR #132) | `unbound-runtime-0.1.0-nuitka.pkg` (`-nuitka` suffix; `workflow_dispatch builder=nuitka`) |

**Winner = clears S1 AND notarizes AND passes the bare-Mac universal2 gate**
(`packaging/scripts/lipo-gate.sh`). Pre-allowlisting with Mike (WEB-4784) may
settle it for either artifact even at `allowlist=none`.

## Coordinates (source of truth — do not re-derive)

| Thing | Value |
|---|---|
| Apple Team ID (signer/cert allowlist) | `ZMA55FTA8W` ("Websentry Inc") |
| Released pkg | `https://unbound-release-artifacts.s3.us-west-2.amazonaws.com/macos/0.1.0/unbound-runtime-0.1.0.pkg` |
| onboard.sh | `https://unbound-release-artifacts.s3.us-west-2.amazonaws.com/macos/0.1.0/onboard.sh` |
| Install layout | `/opt/unbound/current/{unbound-hook,unbound-discovery}/` ; LaunchDaemon `ai.getunbound.discovery` |
| AWS | `us-west-2`, **default** profile only (NEVER the benchling profile) |

## Open dependency — DO NOT BLOCK on it

The S1 **tenant + site token** are pending the WEB-4805 sourcing decision
(Salesloft's EDR is confirmed SentinelOne; the tenant we rehearse against —
Salesloft-supplied vs an Unbound S1 trial — is the open question, tracked
against WEB-4784). The harness is fully parameterized: when the token + agent
pkg land, drop them into the env vars below — no script edits required.

This runbook and all scripts can be exercised in **dry-run today** (they print
every command and touch nothing).

## Allowlist strategy under test

| State | S1 console configuration |
|---|---|
| `none` | No exclusions. Baseline. |
| `team-id` | Signer/cert exclusion on **ZMA55FTA8W**, scope **Suppress Alerts** (NOT Interop) **+** path exclusion `/opt/unbound/*` for the LaunchDaemon. |

Set the console policy to the matching state **before** each run; the scripts
only tag captures with the state, they do not configure S1's console.

---

## Prerequisites

- `aws` CLI authenticated to the **default** profile (the org payer / dev
  account — see `project_unbound_aws_org`). The harness hard-refuses any
  profile name containing `benchling`.
- An SSH keypair registered in EC2 (`EC2_KEY_NAME`), plus a subnet + security
  group that allows SSH from your egress IP. Export them so the scripts emit
  concrete commands:
  ```
  export EC2_KEY_NAME=...           EC2_SUBNET_ID=subnet-...
  export EC2_SECURITY_GROUP_ID=sg-...
  ```
- `shellcheck` (CI runs it; scripts are clean).
- The S1 agent pkg URL + site token + console API token (pending; see above):
  ```
  export S1_SITE_TOKEN=...          # registration token, never on argv
  export S1_API_TOKEN=...           # console read token (capture only)
  export S1_CONSOLE_URL=https://<tenant>.sentinelone.net
  ```
- Rehearsal onboarding keys (a scoped, throwaway tenant — never a prod admin
  key):
  ```
  export ONBOARD_API_KEY=...        ONBOARD_DISCOVERY_KEY=...
  ```

> **Every live-action script defaults to DRY-RUN.** Run it once without
> `--execute` to read the exact commands, then add `--execute` when you mean
> it. AWS-touching scripts also print a cost warning and require typing `yes`
> (or `--yes`). Mac dedicated hosts bill a **24-hour minimum** per host.

---

## Step 1 — Provision fresh fixtures (both chips)

```
./provision-fixture.sh --chip both            # dry-run: prints every aws call
./provision-fixture.sh --chip both --execute  # allocates host + instance per chip
```

- arm64 → `mac2.metal`, intel → `mac1.metal` (the Intel slice must be proven on
  real x86_64 hardware, not just present in `lipo` output).
- The script resolves the newest Apple macOS AMI per chip, launches one
  instance onto a dedicated host, waits for `instance-status-ok`, and tells you
  to record `HOST_ID`/`INSTANCE_ID` into `results/fixtures-<chip>.env` (consumed
  by `teardown.sh`).
- Note each fixture's public IP for the next steps.

## Step 2 — Install the SentinelOne agent

```
S1_SITE_TOKEN=... ./install-s1.sh --host <fixture-ip> --pkg <s1-agent.pkg|url>            # dry-run
S1_SITE_TOKEN=... ./install-s1.sh --host <fixture-ip> --pkg <s1-agent.pkg|url> --execute  # installs
```

Repeat per fixture. Confirm in the S1 console that each fixture is registered
and online before rehearsing. The site token is read from env, never argv (it
would otherwise leak via `ps`).

## Step 3 — Run the full matrix

For each cell — **2 artifacts × 2 allowlist states** — set the S1 console
allowlist to the matching state, then drive the lifecycle. Use a stable
`--run-id` so the capture pairs with the run.

```
# allowlist = none
./run-rehearsal.sh --host <ip> --artifact pyinstaller --allowlist none    --run-id r1 --execute
./run-rehearsal.sh --host <ip> --artifact nuitka      --allowlist none    --run-id r1 --execute
# allowlist = team-id (set ZMA55FTA8W suppress + /opt/unbound/* path excl. in S1 first)
./run-rehearsal.sh --host <ip> --artifact pyinstaller --allowlist team-id --run-id r1 --execute
./run-rehearsal.sh --host <ip> --artifact nuitka      --allowlist team-id --run-id r1 --execute
```

Each run drives, in order: **pkg install → onboard.sh → all 5 hook events
(PreToolUse, PostToolUse, UserPromptSubmit, Stop, SessionStart) → discovery
daemon scheduled run → `--clear`**, and captures our own per-stage logs to
`results/<artifact>_<allowlist>_<run-id>/`.

> A non-zero stage does **not** abort the run — it is logged and the matrix
> continues. We are measuring what S1 does, and fail-open is sacred: a hook
> that fails open is expected behavior, not a stop condition.

**Re-image between cells that share a fixture.** The cleanest re-image is
terminate + release the host (Step 5) and re-provision (Step 1) — a fresh host
boots a clean AMI with no S1/runtime residue. At minimum, run the artifact's
`--clear` (the rehearsal does this as Stage 5) and confirm `/opt/unbound` is
gone before the next install.

## Step 4 — Capture telemetry per cell

```
S1_API_TOKEN=... S1_CONSOLE_URL=... \
  ./capture-telemetry.sh --host <ip> --artifact pyinstaller --allowlist none --run-id r1            # dry-run
S1_API_TOKEN=... S1_CONSOLE_URL=... \
  ./capture-telemetry.sh --host <ip> --artifact pyinstaller --allowlist none --run-id r1 --execute  # collects
```

Collects, into `results/<artifact>_<allowlist>_<run-id>/`:
- S1 console: agent record, threats/detections, activities (Storyline-adjacent)
  scoped to the fixture. For each threat id, also export the full Storyline
  (process tree) from the console — see the note the script prints.
- Our-side logs pulled off the fixture (`/var/log/unbound/discovery*.log`) plus
  the per-stage logs `run-rehearsal.sh` captured.
- `metadata.txt` provenance stamp (artifact, allowlist, run-id, host, team-id,
  captured-at).

Pass `--since <iso8601>` to scope S1 queries to the rehearsal window.

## Step 5 — Pick the winner, then teardown

1. Fill `matrix.md` from the evidence dirs.
2. Apply the decision rule: **clears S1 (ideally even at `allowlist=none`, and
   certainly at `team-id`) AND notarizes AND passes the bare-Mac lipo gate**.
   0.1.0 already notarizes; the lipo gate is `packaging/scripts/lipo-gate.sh`
   over each artifact's `dist/`.
3. Release the fixtures so billing stops:
   ```
   ./teardown.sh --chip both            # dry-run
   ./teardown.sh --chip both --execute  # terminate instances + release hosts
   ```
   `teardown.sh` reads ids from `results/fixtures-<chip>.env`, or pass
   `--instance-id`/`--host-id`. If you lost the ids, the script prints the
   `describe-instances` query that finds them by the `unbound:purpose` tag.

> **Re-imaging is the teardown.** The rehearsal must not pollute the Stream V
> fixtures: terminate + release, and provision fresh for any further runs.

---

## Safety invariants (do not weaken)

- Nothing here can block a developer's daily machine. Every live action targets
  a throwaway EC2 Mac fixture and is `--execute`-gated; the runtime fails open
  by design.
- The benchling AWS profile is hard-refused (`lib.sh`).
- Secrets (S1 site/API tokens, onboarding keys) come from env, never argv, and
  are never written to the results dir except as the literal name in echoed
  commands.
- Captured results may contain endpoint/host data — `results/` is gitignored.
