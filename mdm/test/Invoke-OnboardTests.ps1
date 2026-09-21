<#
.SYNOPSIS
    Test battery for mdm/onboard.ps1 exit-code fidelity (WEB-5890 / PR #321).

.DESCRIPTION
    Runs the real shipped onboard.ps1 with a controllable stub python child and
    asserts the process exit code that Intune / Task Scheduler read. Windows
    PowerShell 5.1 only. Must run in an ELEVATED shell (onboard.ps1 requires
    Administrator) with python 3 on PATH.

    Covers T1-T5 (direct), T7 (Intune remediation front door), T8 (Scheduled
    Task front door), T9 (stress). T6 (proven-to-fail) is a separate script,
    Invoke-ProvenToFail.ps1. Exits 0 only if every assertion passes.
#>
[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'common.ps1')

$results = New-Object System.Collections.ArrayList
function Assert {
    param([string]$Id, [string]$Desc, [bool]$Cond, [string]$Detail)
    [void]$results.Add([pscustomobject]@{ ID = $Id; Pass = $Cond; Desc = $Desc; Detail = $Detail })
    $tag = if ($Cond) { 'PASS' } else { 'FAIL' }
    Write-Host ("  [{0}] {1,-10} {2}  ({3})" -f $tag, $Id, $Desc, $Detail)
}

Write-Host "== onboard.ps1 exit-code battery =="
if (-not (Test-IsAdmin)) {
    Write-Warning "Not elevated. onboard.ps1 requires Administrator; results will be invalid. Re-run from an elevated shell."
}

# T1 - success run exits 0
$r = Invoke-OnboardRun -Mode direct -ChildExit 0
Assert 'T1' 'success run exits 0' ($r.ProcExit -eq 0) "ProcExit=$($r.ProcExit)"

# T2 - child stdout is visible on the host (Out-Host), captured on the process stdout
Assert 'T2' 'child stdout visible via host' (($r.Stdout -match '\[stub\] stdout line 5')) "stdoutHasChildLines=$([bool]($r.Stdout -match '\[stub\] stdout line 5'))"

# T3 - failing child makes the script exit non-zero (headline guard)
foreach ($c in 1, 3) {
    $r = Invoke-OnboardRun -Mode direct -ChildExit $c
    Assert "T3-$c" "failing child exits non-zero (==$c)" ($r.ProcExit -eq $c) "ProcExit=$($r.ProcExit)"
}

# T4 - $LASTEXITCODE carries python's real code across a matrix
foreach ($c in 0, 1, 3, 42) {
    $r = Invoke-OnboardRun -Mode direct -ChildExit $c
    Assert "T4-$c" "exit code == child code $c" ($r.ProcExit -eq $c) "ProcExit=$($r.ProcExit)"
}

# T5 - scalar int under heavy multi-line stdout (not object[]/line count).
# On the pre-change artifact those 200 lines join the object[] that masks the
# code; the direct object[]-vs-int contrast is proven by Invoke-ProvenToFail.ps1.
$r = Invoke-OnboardRun -Mode direct -ChildExit 0 -StdoutLines 200
Assert 'T5' 'scalar exit under 200-line stdout (==0)' ($r.ProcExit -eq 0) "ProcExit=$($r.ProcExit)"

# T7 - Intune remediation front door
$r = Invoke-OnboardRun -Mode intune -ChildExit 0
Assert 'T7-ok'   'intune success -> exit 0 + marker written' (($r.ProcExit -eq 0) -and $r.MarkerWritten) "ProcExit=$($r.ProcExit) marker=$($r.MarkerWritten)"
$r = Invoke-OnboardRun -Mode intune -ChildExit 1
Assert 'T7-fail' 'intune failure -> non-zero, no marker' (($r.ProcExit -ne 0) -and (-not $r.MarkerWritten)) "ProcExit=$($r.ProcExit) marker=$($r.MarkerWritten)"

# T8 - Scheduled Task front door
$r = Invoke-OnboardRun -Mode task -ChildExit 0
Assert 'T8-ok'   'task success -> exit 0 + marker written' (($r.ProcExit -eq 0) -and $r.MarkerWritten) "ProcExit=$($r.ProcExit) marker=$($r.MarkerWritten)"
$r = Invoke-OnboardRun -Mode task -ChildExit 1
Assert 'T8-fail' 'task failure -> non-zero, no marker' (($r.ProcExit -ne 0) -and (-not $r.MarkerWritten)) "ProcExit=$($r.ProcExit) marker=$($r.MarkerWritten)"

# T9 - stress: 5000-line stdout + stderr under $ErrorActionPreference='Continue'
$r = Invoke-OnboardRun -Mode direct -ChildExit 0 -StdoutLines 5000
Assert 'T9-ok'   'stress success -> exit 0' ($r.ProcExit -eq 0) "ProcExit=$($r.ProcExit)"
$r = Invoke-OnboardRun -Mode direct -ChildExit 1 -StdoutLines 5000
Assert 'T9-fail' 'stress failure -> exit 1' ($r.ProcExit -eq 1) "ProcExit=$($r.ProcExit)"

Write-Host ""
$fail = @($results | Where-Object { -not $_.Pass })
Write-Host ("== {0}/{1} passed ==" -f ($results.Count - $fail.Count), $results.Count)
if ($fail.Count -gt 0) {
    Write-Host "FAILURES:"
    $fail | ForEach-Object { Write-Host ("  {0}: {1} ({2})" -f $_.ID, $_.Desc, $_.Detail) }
    exit 1
}
exit 0
