# Shared helpers for the onboard.ps1 test battery (Windows PowerShell 5.1).
#
# The real shipped mdm/onboard.ps1 is run verbatim. Two things are intercepted
# from outside the artifact, without editing it:
#   1. A proxy Invoke-WebRequest function (defined in each child runner) so the
#      onboard.py download returns the local stub, and the Intune/Task wrappers'
#      -OutFile download drops the real head onboard.ps1 in place.
#   2. The child's exit code and stdout volume, chosen via env vars.
#
# Each run is executed in its own powershell.exe child process so that
# onboard.ps1's terminating `exit $exitCode` sets THAT process's exit code,
# which the harness reads back as the artifact's real result - exactly what
# Intune and Task Scheduler read.

$script:TestRoot   = $PSScriptRoot
$script:HeadPs1    = (Resolve-Path (Join-Path $PSScriptRoot '..\onboard.ps1')).Path
$script:StubPy     = (Resolve-Path (Join-Path $PSScriptRoot 'stub_onboard.py')).Path

# The proxy is emitted into each runner script verbatim.
$script:ProxyIwr = @'
function Invoke-WebRequest {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Uri,
        [string]$OutFile,
        [int]$TimeoutSec,
        [switch]$UseBasicParsing,
        [Parameter(ValueFromRemainingArguments = $true)]$Extra
    )
    if ($OutFile) {
        # The Intune/Task wrapper's installer download: hand back the real head onboard.ps1.
        Copy-Item -LiteralPath $env:UNBOUND_TEST_ONBOARD_PS1 -Destination $OutFile -Force
        return
    }
    # onboard.ps1's own onboard.py download: hand back the stub child.
    $content = Get-Content -Raw -LiteralPath $env:UNBOUND_TEST_STUB_PY
    return [pscustomobject]@{ Content = $content }
}
'@

function New-ParentArtifact {
    # Synthesize the PRE-change onboard.ps1 (bare native invocation, no Out-Host)
    # from the head artifact by removing the one-line fix. Deterministic on the
    # VM regardless of git state; throws if the head line is not found.
    param([string]$Destination)
    $head = Get-Content -Raw -LiteralPath $script:HeadPs1
    $fixed  = '& $pythonCmd @pythonArgs | Out-Host'
    $before = '& $pythonCmd @pythonArgs'
    if ($head.IndexOf($fixed) -lt 0) {
        throw "Head onboard.ps1 no longer contains the '$fixed' line; update New-ParentArtifact."
    }
    $parent = $head.Replace($fixed, $before)
    Set-Content -LiteralPath $Destination -Value $parent -Encoding UTF8
}

function Invoke-OnboardRun {
    <#
      Mode:
        direct  - run the artifact directly (T1-T5, T9)
        parent  - run the synthesized pre-change artifact (T6)
        intune  - run through the documented Intune remediation wrapper (T7)
        task    - run through the documented Scheduled Task runner (T8)
      Returns ProcExit (the real process exit code), captured Stdout/Stderr, and
      whether the wrapper's last-success.txt marker was written.
    #>
    param(
        [ValidateSet('direct', 'parent', 'intune', 'task')][string]$Mode = 'direct',
        [int]$ChildExit = 0,
        [int]$StdoutLines = 5
    )

    $work = Join-Path $env:TEMP ("unbound-onboard-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    # Resolve the artifact under test.
    if ($Mode -eq 'parent') {
        $artifact = Join-Path $work 'onboard_parent.ps1'
        New-ParentArtifact -Destination $artifact
    } else {
        $artifact = Join-Path $work 'onboard_head.ps1'
        Copy-Item -LiteralPath $script:HeadPs1 -Destination $artifact -Force
    }

    # Build the per-run runner script (child process top scope).
    switch ($Mode) {
        { $_ -in 'direct', 'parent' } {
            $body = @"
$script:ProxyIwr
& '$artifact' -ApiKey 'test-key'
exit `$LASTEXITCODE
"@
        }
        'intune' {
            # Documented Intune remediation body (intune.mdx), minus the ACL
            # hardening that is Intune packaging, not under test. The proxy's
            # -OutFile branch drops the head onboard.ps1 at `$installer.
            $body = @"
$script:ProxyIwr
`$base = `$env:UNBOUND_TEST_BASEDIR
`$installer = Join-Path `$base 'onboard.ps1'
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/windows/onboard' -OutFile `$installer -UseBasicParsing -ErrorAction Stop
& `$installer -ApiKey 'test-key' -Backfill
`$code = `$LASTEXITCODE
if (`$code -eq 0) {
    try { Set-Content -Path (Join-Path `$base 'last-success.txt') -Value (Get-Date -Format 'o') -ErrorAction Stop }
    catch { Write-Output "Installed, but could not write the marker. `$_"; `$code = 1 }
}
exit `$code
"@
        }
        'task' {
            # Documented Scheduled Task run-unbound.ps1 body (intune.mdx).
            $body = @"
$script:ProxyIwr
`$installer = Join-Path `$env:UNBOUND_TEST_BASEDIR 'onboard.ps1'
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/windows/onboard' -OutFile `$installer -UseBasicParsing -ErrorAction Stop
& `$installer -ApiKey 'test-key' -Backfill
`$code = `$LASTEXITCODE
if (`$code -eq 0) {
    try { Set-Content -Path (Join-Path `$env:UNBOUND_TEST_BASEDIR 'last-success.txt') -Value (Get-Date -Format 'o') -ErrorAction Stop }
    catch { Write-Output "Installed, but could not write the marker. `$_"; `$code = 1 }
}
exit `$code
"@
        }
    }

    $runner = Join-Path $work 'runner.ps1'
    Set-Content -LiteralPath $runner -Value $body -Encoding UTF8

    $out = Join-Path $work 'stdout.txt'
    $err = Join-Path $work 'stderr.txt'

    $env:UNBOUND_TEST_STUB_PY      = $script:StubPy
    $env:UNBOUND_TEST_ONBOARD_PS1  = $script:HeadPs1
    $env:UNBOUND_TEST_CHILD_EXIT   = "$ChildExit"
    $env:UNBOUND_TEST_STDOUT_LINES = "$StdoutLines"
    $env:UNBOUND_TEST_BASEDIR      = $work

    $p = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runner) `
        -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err

    [pscustomobject]@{
        Mode          = $Mode
        ChildExit     = $ChildExit
        StdoutLines   = $StdoutLines
        ProcExit      = $p.ExitCode
        Stdout        = (Get-Content -Raw -LiteralPath $out -ErrorAction SilentlyContinue)
        Stderr        = (Get-Content -Raw -LiteralPath $err -ErrorAction SilentlyContinue)
        MarkerWritten = (Test-Path (Join-Path $work 'last-success.txt'))
        Work          = $work
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
