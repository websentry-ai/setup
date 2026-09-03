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

    Use -Backfill to seed historical transcripts for Claude Code and Codex.

    This PowerShell wrapper:
    - Checks for Python availability (py, python3, python)
    - Downloads the onboard.py script from GitHub
    - Executes it with all provided parameters
    - Provides clear errors if Python is missing

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
    Enable backfill of historical transcripts for Claude Code and Codex (opt-in, disabled by default)

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

# Output helpers
function Exit-WithError { param([string]$Message, [int]$Code = 1) Write-Error $Message; exit $Code }

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
    $pythonCmd = Find-Python
    if ($null -eq $pythonCmd) {
        Exit-WithError "Python 3 is required but not found in PATH. Install from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked."
    }

    # Download the Python script
    $scriptContent = Get-OnboardScript -Url $ONBOARD_PY_URL

    # Create a temporary file for the Python script
    $tempFile = [System.IO.Path]::GetTempFileName()
    $tempPyFile = [System.IO.Path]::ChangeExtension($tempFile, ".py")

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
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $pythonCmd @pythonArgs
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }

    } finally {
        # Clean up temporary files
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

# Entry point - capture exit code from Main
$exitCode = Main

# Self-destruct: Remove this script file after execution completes
# This allows users to run without manual cleanup: Invoke-WebRequest ... -OutFile onboard.ps1; .\onboard.ps1 -ApiKey ...
if ($MyInvocation.MyCommand.Path) {
    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
}

# Exit with the Python script's exit code
exit $exitCode
