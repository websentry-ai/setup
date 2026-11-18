<#
.SYNOPSIS
    Unbound MDM onboarding PowerShell wrapper for Windows

.DESCRIPTION
    Downloads and executes the Python-based MDM onboarding script (onboard.py)
    that performs all five setup steps:

      1. Claude Code MDM setup
      2. Cursor MDM setup
      3. Codex MDM setup
      4. GitHub Copilot MDM setup
      5. Coding-discovery scan

    Use -Backfill to seed historical transcripts for Claude Code, Codex and GitHub Copilot.

    This PowerShell wrapper:
    - Checks for Python availability (py, python3, python)
    - Downloads the onboard.py script from GitHub
    - Executes it with all provided parameters
    - Provides clear errors if Python is missing
    - Reports the result to the Unbound backend, naming the step that failed

    The report is best-effort: a failed report never changes this script's exit code.
    -Clear runs send no report.

    Python 3 is required because the underlying MDM setup scripts are Python-based.

.PARAMETER ApiKey
    The MDM admin API key (required unless -Clear is specified)

.PARAMETER DiscoveryKey
    Deprecated and ignored. The discovery scan authenticates as the device's owner,
    resolved from the hardware serial. Still accepted so existing MDM policies keep working.

.PARAMETER BackendUrl
    Backend URL override for tenant deployments (default: https://backend.getunbound.ai)

.PARAMETER GatewayUrl
    Gateway URL override for MDM tools (default: https://api.getunbound.ai)

.PARAMETER FrontendUrl
    Frontend URL override (default: https://gateway.getunbound.ai). Persisted into
    each user's ~/.unbound/config.json so unbound-cli works without further setup.

.PARAMETER Backfill
    Enable backfill of historical transcripts for Claude Code, Codex and GitHub Copilot (opt-in, disabled by default)

.PARAMETER SkipManagedSettings
    Claude Code only: install the hook script but leave managed-settings.json alone,
    for orgs whose Claude Code policy is managed remotely from the Anthropic admin console

.PARAMETER Clear
    Remove MDM configuration for all four tools (no discovery scan, no backfill)

.EXAMPLE
    # Standard onboarding
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY

.EXAMPLE
    # With backfill of historical transcripts (opt-in)
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY -Backfill

.EXAMPLE
    # Tenant deployment with custom URLs
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY -BackendUrl "https://backend.example.com" -GatewayUrl "https://api.example.com"

.EXAMPLE
    # Clear MDM setup
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -Clear

.NOTES
    Requires: Python 3, Administrator privileges
    URL: https://raw.githubusercontent.com/websentry-ai/setup/main/mdm/onboard.py
#>

param(
    [string]$ApiKey,
    [string]$DiscoveryKey,
    [string]$BackendUrl,
    [string]$GatewayUrl,
    [string]$FrontendUrl,
    [switch]$Backfill,
    [switch]$SkipManagedSettings,
    [switch]$Clear
)

$ErrorActionPreference = "Stop"

# Constants
$ONBOARD_PY_URL = "https://raw.githubusercontent.com/websentry-ai/setup/main/mdm/onboard.py"
$DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"
$INSTALL_REPORT_PATH = "/api/v1/automations/mdm/install-report/"
$INSTALLER_VERSION = "onboard.ps1/1"
$MAX_REPORT_STEP_LENGTH = 64

# What the install report says if this script stops here.
$script:CurrentStep = "check_admin"
$script:FailureExitCode = 1

# Output helpers
function Exit-WithError {
    param([string]$Message, [int]$Code = 1)
    $script:FailureExitCode = $Code
    Write-Error $Message
    exit $Code
}

# Hardware serial, resolved in the same order as get_device_identifier in onboard.py.
# The backend keys install reports on it, so it must match what the tool setups enroll.
function Get-DeviceSerial {
    try {
        $serial = (Get-CimInstance -ClassName Win32_BIOS -OperationTimeoutSec 10 -ErrorAction Stop).SerialNumber
        if (-not [string]::IsNullOrWhiteSpace($serial)) { return $serial.Trim() }
    } catch {
        # Fall through to the next identifier
    }
    try {
        $guid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        if (-not [string]::IsNullOrWhiteSpace($guid)) { return $guid.Trim() }
    } catch {
        # Fall through to the next identifier
    }
    return [System.Net.Dns]::GetHostName()
}

# Same rule as normalize_url in each tool's setup.py: default to https, no trailing slash.
function Get-InstallReportUri {
    $base = if ([string]::IsNullOrWhiteSpace($BackendUrl)) { $DEFAULT_BACKEND_URL } else { $BackendUrl.Trim() }
    if ($base -notmatch '^https?://') { $base = "https://$base" }
    return $base.TrimEnd('/') + $INSTALL_REPORT_PATH
}

# Names the tools onboard.py reported as failed, for example setup:cursor,discovery.
# Plain "setup" when it named none, such as when it crashed before writing the file.
function Get-FailedSetupStep {
    param($ResultFile)
    try {
        $result = Get-Content -Raw -LiteralPath $ResultFile -ErrorAction Stop | ConvertFrom-Json
        $names = @($result.failed_steps | ForEach-Object { ([string]$_).ToLowerInvariant() -replace '[^a-z0-9]+', '_' } | Where-Object { $_ })
        if ($names.Count -eq 0) { return "setup" }
        $step = "setup:" + ($names -join ",")
        if ($step.Length -gt $MAX_REPORT_STEP_LENGTH) { $step = $step.Substring(0, $MAX_REPORT_STEP_LENGTH) }
        return $step
    } catch {
        return "setup"
    }
}

# Best-effort POST of the result, in the shape onboard.sh sends: step=setup with
# exit_code=0 is the success report. Nothing here may change the onboarding result, so
# every failure ends as one line on stderr. That line carries only a status or an
# exception type, because the API key must never reach MDM logs.
function Send-InstallReport {
    param($Step, $ExitCode)

    # -Clear has no key to authenticate with, and a run without a key has nothing to send.
    if ($Clear -or [string]::IsNullOrWhiteSpace($ApiKey)) { return }

    try {
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        $body = [ordered]@{
            serial_number     = Get-DeviceSerial
            step              = [string]$Step
            exit_code         = [int]$ExitCode
            installer_version = $INSTALLER_VERSION
            hostname          = [System.Net.Dns]::GetHostName()
            os_version        = [Environment]::OSVersion.Version.ToString()
            arch              = [string]$env:PROCESSOR_ARCHITECTURE
            ts                = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        } | ConvertTo-Json -Compress

        # Redirects are refused so the key header is never replayed to another host.
        $response = Invoke-WebRequest -Uri (Get-InstallReportUri) -Method Post -UseBasicParsing `
            -Headers @{ 'X-API-KEY' = $ApiKey } -ContentType 'application/json' `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 10 -MaximumRedirection 0

        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            [Console]::Error.WriteLine("::install-report POST failed: HTTP $($response.StatusCode) (step=$Step)")
        }
    } catch {
        try {
            $status = $_.Exception.Response.StatusCode.value__
            $reason = if ($status) { "HTTP $status" } else { $_.Exception.GetType().Name }
            [Console]::Error.WriteLine("::install-report POST failed: $reason (step=$Step)")
        } catch {
            # Telemetry stays silent rather than affect the onboarding result
        }
    }
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find Python executable
function Find-Python {
    $pythonCommands = @("py", "python3", "python")

    foreach ($cmd in $pythonCommands) {
        try {
            $null = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                return $cmd
            }
        } catch {
            # Command not found, continue to next candidate
            continue
        }
    }

    return $null
}

# Download the Python onboard script
function Get-OnboardScript {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30

        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            Exit-WithError "Failed to download onboard.py: empty response"
        }

        return $response.Content
    } catch {
        Exit-WithError "Failed to download onboard.py: $_"
    }
}

# Main execution
function Main {
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Exit-WithError "This script requires administrator privileges. Right-click PowerShell -> Run as Administrator, then rerun."
    }

    # Validate parameters (unless -Clear is specified)
    if (-not $Clear) {
        if ([string]::IsNullOrWhiteSpace($ApiKey)) {
            Exit-WithError "-ApiKey is required. Usage: & ([scriptblock]::Create((iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing).Content)) -ApiKey YOUR_KEY"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($DiscoveryKey)) {
        Write-Warning "-DiscoveryKey is deprecated and ignored - the scan uses the device owner's key, resolved from the hardware serial."
    }

    # Find Python
    $script:CurrentStep = "find_python"
    $pythonCmd = Find-Python
    if ($null -eq $pythonCmd) {
        Exit-WithError "Python 3 is required but not found in PATH. Install from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked."
    }

    # Download the Python script
    $script:CurrentStep = "download_onboard_py"
    $scriptContent = Get-OnboardScript -Url $ONBOARD_PY_URL

    # Create a temporary file for the Python script
    $script:CurrentStep = "prepare_onboard_py"
    $tempFile = [System.IO.Path]::GetTempFileName()
    $tempPyFile = [System.IO.Path]::ChangeExtension($tempFile, ".py")

    # onboard.py lists the tools that failed here. Only the report reads it, so a
    # problem creating it must not stop onboarding.
    $resultFile = $null
    try {
        $resultFile = [System.IO.Path]::GetTempFileName()
        $env:UNBOUND_ONBOARD_RESULT_FILE = $resultFile
    } catch {
        $resultFile = $null
    }

    try {
        # Write the Python script to temp file
        [System.IO.File]::WriteAllText($tempPyFile, $scriptContent, [System.Text.Encoding]::UTF8)

        # Build arguments for the Python script
        $pythonArgs = @($tempPyFile)

        if ($Clear) {
            $pythonArgs += "--clear"
        } else {
            $pythonArgs += "--api-key"
            $pythonArgs += $ApiKey
        }

        # URL overrides apply to both normal and clear modes
        if (-not [string]::IsNullOrWhiteSpace($BackendUrl)) {
            $pythonArgs += "--backend-url"
            $pythonArgs += $BackendUrl
        }

        if (-not [string]::IsNullOrWhiteSpace($GatewayUrl)) {
            $pythonArgs += "--gateway-url"
            $pythonArgs += $GatewayUrl
        }

        if (-not [string]::IsNullOrWhiteSpace($FrontendUrl)) {
            $pythonArgs += "--frontend-url"
            $pythonArgs += $FrontendUrl
        }

        # Add backfill flag if explicitly requested (has no effect with -Clear)
        if ($Backfill -and -not $Clear) {
            $pythonArgs += "--backfill"
        }

        # Claude Code only; onboard.py routes it to that tool alone
        if ($SkipManagedSettings -and -not $Clear) {
            $pythonArgs += "--skip-managed-settings"
        }

        # Execute the Python script and capture exit code.
        # Windows PowerShell 5.1 turns each stderr line of a native command into a
        # NativeCommandError when the output is redirected into a pipeline, which is
        # terminating under the Stop preference set above. onboard.py logs to stderr,
        # so the first log line would abort onboarding for any caller that pipes us.
        # Pipe the child's stdout to the host so it reaches the console but never
        # enters this function's output stream. Otherwise every stdout line would be
        # returned by Main alongside the status, and `$exitCode = Main` would capture
        # an object array instead of the integer - making a failed run exit 0.
        $script:CurrentStep = "setup"
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $pythonCmd @pythonArgs | Out-Host
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }

        if ($exitCode -ne 0) {
            $script:CurrentStep = Get-FailedSetupStep -ResultFile $resultFile
        }

    } finally {
        # Clean up temporary files
        Remove-Item Env:\UNBOUND_ONBOARD_RESULT_FILE -ErrorAction SilentlyContinue
        if ($resultFile -and (Test-Path $resultFile)) {
            Remove-Item $resultFile -ErrorAction SilentlyContinue
        }
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
        if (Test-Path $tempPyFile) {
            Remove-Item $tempPyFile -ErrorAction SilentlyContinue
        }
    }

    # Return the exit code
    return $exitCode
}

# Entry point - capture exit code from Main. A terminating error is reported and then
# rethrown, so the caller sees the same failure it would have seen without the report.
try {
    $exitCode = Main
} catch {
    Send-InstallReport -Step $script:CurrentStep -ExitCode $script:FailureExitCode
    throw
}
Send-InstallReport -Step $script:CurrentStep -ExitCode $exitCode

# Self-destruct: Remove this script file after execution completes
# This allows users to run without manual cleanup: Invoke-WebRequest ... -OutFile onboard.ps1; .\onboard.ps1 -ApiKey ...
if ($MyInvocation.MyCommand.Path) {
    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
}

# Exit with the Python script's exit code
exit $exitCode
