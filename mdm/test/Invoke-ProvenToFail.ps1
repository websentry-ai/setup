<#
.SYNOPSIS
    Proven-to-fail harness for WEB-5890 / PR #321 (T6). Windows PowerShell 5.1,
    elevated, python 3 on PATH.

.DESCRIPTION
    Demonstrates the guard is not vacuous:
      1. Synthesize the PRE-change onboard.ps1 (bare `& $pythonCmd @pythonArgs`,
         no Out-Host) and run it with a FAILING child (exit 3). Expect the bug:
         the object[] capture masks the failure, so the process does NOT report 3
         (a 0 is a confirmed false success - the exact WEB-5890 defect).
      2. Run the HEAD artifact (with `| Out-Host`) against the same failing child.
         Expect the fix: the process reports exit 3.

    Exit 0 only if the fix changes behaviour in the correct direction.
#>
[CmdletBinding()]
param([int]$ChildExit = 3)

. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Test-IsAdmin)) {
    Write-Warning "Not elevated. onboard.ps1 requires Administrator; results will be invalid. Re-run from an elevated shell."
}

Write-Host "== proven-to-fail (T6): failing child exit=$ChildExit =="

$parent = Invoke-OnboardRun -Mode parent -ChildExit $ChildExit
$head   = Invoke-OnboardRun -Mode direct -ChildExit $ChildExit

Write-Host ("  PARENT (pre-change) ProcExit = {0}" -f $parent.ProcExit)
Write-Host ("  HEAD   (fixed)      ProcExit = {0}" -f $head.ProcExit)

$falseOk = ($parent.ProcExit -eq 0)              # the WEB-5890 defect: false success
$fixed   = ($head.ProcExit -eq $ChildExit)       # head passes the real code through

if ($falseOk) {
    Write-Host "  -> PARENT reported SUCCESS (exit 0) on a FAILED child: WEB-5890 reproduced." -ForegroundColor Yellow
} elseif ($parent.ProcExit -ne $ChildExit) {
    Write-Host "  -> PARENT masked the failure (exit $($parent.ProcExit) != $ChildExit) but did not report the false success this guard pins." -ForegroundColor Yellow
}

# The defect is specifically a FALSE SUCCESS - the pre-change wrapper reported
# exit 0 on a failed child, so Intune/Task Scheduler recorded the run as good.
# Requiring parent==0 (not merely parent!=child) ties the guard to that exact
# symptom; a parent that surfaced some other non-zero code was never the bug.
$pass = ($falseOk -and $fixed)
Write-Host ""
if ($pass) {
    Write-Host "== T6 PASS: parent falsely reports success (0), head reports the real code =="
    exit 0
}
Write-Host "== T6 FAIL: falseOk=$falseOk fixed=$fixed (parent=$($parent.ProcExit) head=$($head.ProcExit)) =="
exit 1
