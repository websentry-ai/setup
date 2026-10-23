# EDR (SentinelOne) rehearsal test matrix — WEB-4805

2 artifacts × 2 allowlist states × 5 lifecycle stages. Fill the **Result**
column from the captured evidence (`capture-telemetry.sh` writes one results
dir per cell, tagged `{artifact}_{allowlist}_{run-id}`). A cell "passes" when
S1 raised **no blocking/quarantine action** AND our binary still ran
fail-open (the hook stage output must contain the vendored module's
`"suppressOutput": true`, exactly as `packaging/scripts/smoke-test.sh`
asserts — proof the binary executed, not that S1 merely stayed quiet because
nothing ran).

Ticket: https://linear.app/unboundsec/issue/WEB-4805

## Allowlist states

| State | S1 console config under test |
|---|---|
| `none` | No Unbound exclusions. Baseline — what S1 does to an un-allowlisted fleet. |
| `team-id` | Signer/cert exclusion on Team ID **ZMA55FTA8W** ("Websentry Inc"), scope **Suppress Alerts** (NOT broad Interop mode) **+** path exclusion `/opt/unbound/*` for the LaunchDaemon. |

## Matrix

### Artifact: PyInstaller (default; WEB-4786 / WEB-4787)

| Allowlist | Stage | What S1 sees | Result (detections / verdict) | Evidence dir |
|---|---|---|---|---|
| none    | install (pkg)        | `installer -pkg` of signed/notarized pkg, postinstall pre-warm + LaunchDaemon bootstrap | | |
| none    | onboard.sh           | `unbound-hook setup` writes config, bootstraps daemon | | |
| none    | hook events          | 5 events (PreToolUse, PostToolUse, UserPromptSubmit, Stop, SessionStart) | | |
| none    | discovery daemon     | root LaunchDaemon scan, multi-user `/Users/*` iteration, MCP scans | | |
| none    | --clear              | binary clear + system sweep (bootout, rm) | | |
| team-id | install (pkg)        | same, with ZMA55FTA8W suppress + `/opt/unbound/*` excl. | | |
| team-id | onboard.sh           | | | |
| team-id | hook events          | | | |
| team-id | discovery daemon     | | | |
| team-id | --clear              | | | |

### Artifact: Nuitka (WEB-4804; merged via PR #132)

| Allowlist | Stage | What S1 sees | Result (detections / verdict) | Evidence dir |
|---|---|---|---|---|
| none    | install (pkg)        | `-nuitka` pkg install | | |
| none    | onboard.sh           | | | |
| none    | hook events          | | | |
| none    | discovery daemon     | | | |
| none    | --clear              | | | |
| team-id | install (pkg)        | | | |
| team-id | onboard.sh           | | | |
| team-id | hook events          | | | |
| team-id | discovery daemon     | | | |
| team-id | --clear              | | | |

## Decision (fill after the runs)

Winner is the artifact that **clears S1** (ideally even at `allowlist=none`,
and certainly at `allowlist=team-id`) **AND** notarizes **AND** passes the
bare-Mac universal2 gate (`packaging/scripts/lipo-gate.sh`).

| Criterion | PyInstaller | Nuitka |
|---|---|---|
| Clears S1 @ allowlist=none | | |
| Clears S1 @ allowlist=team-id | | |
| Notarizes (already true for shipped 0.1.0) | yes | |
| Passes bare-Mac lipo gate | | |
| **Winner** | | |

**Chosen artifact:** _____   **Rationale:** _____
