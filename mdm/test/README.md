# onboard.ps1 exit-code battery (WEB-5890 / PR #321)

Guards the fix that stops the Intune remediation reporting **success on a failed
run**. `Main` piped the python child's stdout into its own success stream, so
`$exitCode = Main` captured an `object[]` instead of an int and `exit $exitCode`
reported the wrong code. The fix routes the child's stdout through `| Out-Host`.

This is Windows PowerShell 5.1 stream behaviour, so the battery **only runs on a
Windows VM**. It was written and staged on macOS; nothing here has been executed.

## Requirements (on the Windows VM)

- Windows PowerShell 5.1.
- An **elevated** shell — `onboard.ps1` requires Administrator and exits early
  otherwise.
- `python` / `python3` / `py` on `PATH` (the stub child is a python script).
- No network and no LLM: the python download and the installer download are both
  intercepted by an in-process proxy `Invoke-WebRequest`; the real shipped
  `mdm/onboard.ps1` is run verbatim (copied per run; its self-destruct only
  removes the copy).

## Run

From an elevated PowerShell, in this repo checked out at the PR head:

```powershell
# Main battery: T1-T5, T7 (Intune), T8 (Scheduled Task), T9 (stress)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\mdm\test\Invoke-OnboardTests.ps1

# Proven-to-fail: T6 (parent masks failure, head reports it)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\mdm\test\Invoke-ProvenToFail.ps1
```

Each script prints a per-assertion PASS/FAIL line and exits non-zero if any
assertion fails.

## Files

| File | Role |
| --- | --- |
| `stub_onboard.py` | Stand-in child; exit code and stdout volume chosen via `UNBOUND_TEST_CHILD_EXIT` / `UNBOUND_TEST_STDOUT_LINES`. |
| `common.ps1` | Proxy `Invoke-WebRequest`, `Invoke-OnboardRun` (spawns each run as its own `powershell.exe` so `exit` sets the real process code), parent-artifact synthesis. |
| `Invoke-OnboardTests.ps1` | Single entry for T1-T5, T7-T9. |
| `Invoke-ProvenToFail.ps1` | T6 parent-vs-head demonstration. |

## Cases and assertions

| ID | Front door | Child | Assertion |
| --- | --- | --- | --- |
| T1 | direct | exit 0 | process exit == 0 |
| T2 | direct | exit 0 | child stdout visible on the process stdout (Out-Host) |
| T3 | direct | exit 1, 3 | process exit == child code (headline guard) |
| T4 | direct | exit 0/1/3/42 | process exit == child code (LASTEXITCODE fidelity) |
| T5 | direct | exit 0, 200 stdout lines | process exit == 0 (scalar, not object[]/line count) |
| T6 | direct | exit 3 | **parent** masks (exit != 3, ideally 0); **head** reports 3 |
| T7 | Intune remediation wrapper | exit 0 / 1 | success -> exit 0; failure -> non-zero and no `last-success.txt` |
| T8 | Scheduled Task runner | exit 0 / 1 | success -> exit 0; failure -> non-zero and no `last-success.txt` |
| T9 | direct | exit 0 / 1, 5000 stdout lines | exit == child code (no NativeCommandError abort, no masking) |

T10 lives in `unbound-integration-tests`
(`tests/connect/discovery/test_discovery_key_backcompat_e2e.py`): the existing
Windows `onboard.ps1` tests are repointed from `refs/heads/main` to this PR's
commit so the UIT Windows job exercises the PR artifact. Run it there, not here.

Nothing in this directory has been run. All results are pending the Windows-VM
pass.
