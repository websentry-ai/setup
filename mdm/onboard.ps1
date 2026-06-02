<#
.SYNOPSIS
    Unbound MDM onboarding PowerShell wrapper for Windows

.DESCRIPTION
    Downloads and executes the Python-based MDM onboarding script (onboard.py)
    that performs all five setup steps:

      1. Claude Code MDM setup (with backfill of historical transcripts)
      2. Cursor MDM setup
      3. Codex MDM setup (with backfill of historical transcripts)
      4. GitHub Copilot MDM setup
      5. Coding-discovery scan

    This PowerShell wrapper:
    - Checks for Python availability (py, python3, python)
    - Downloads the onboard.py script from GitHub
    - Executes it with all provided parameters
    - Provides clear errors if Python is missing

    Python 3 is required because the underlying MDM setup scripts are Python-based.

.PARAMETER ApiKey
    The MDM admin API key (required unless -Clear is specified)

.PARAMETER DiscoveryKey
    The discovery-specific API key, separate from ApiKey (required unless -Clear is specified)

.PARAMETER BackendUrl
    Backend URL override for tenant deployments (default: https://backend.getunbound.ai)

.PARAMETER GatewayUrl
    Gateway URL override for MDM tools (default: https://api.getunbound.ai)

.PARAMETER Backfill
    Enable backfill of historical transcripts for Claude Code and Codex (enabled by default, can be explicitly set for clarity)

.PARAMETER Clear
    Remove MDM configuration for all four tools (no discovery scan, no backfill)

.EXAMPLE
    # Standard onboarding with both keys
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY -DiscoveryKey YOUR_DISCOVERY_KEY

.EXAMPLE
    # Explicit backfill (already enabled by default)
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY -DiscoveryKey YOUR_DISCOVERY_KEY -Backfill

.EXAMPLE
    # Tenant deployment with custom URLs
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_KEY -DiscoveryKey YOUR_DISCOVERY_KEY -BackendUrl "https://backend.example.com" -GatewayUrl "https://api.example.com"

.EXAMPLE
    # Clear MDM setup
    Invoke-WebRequest -Uri "https://getunbound.ai/setup/mdm/onboard.ps1" -OutFile onboard.ps1; .\onboard.ps1 -Clear

.NOTES
    Requires: Python 3, Administrator privileges
    URL: https://raw.githubusercontent.com/websentry-ai/setup/42c7b5535aaee4bfd65f5ca77ad91ba88b4a23b2/mdm/onboard.py
#>

param(
    [string]$ApiKey,
    [string]$DiscoveryKey,
    [string]$BackendUrl,
    [string]$GatewayUrl,
    [switch]$Backfill,
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
            Exit-WithError "-ApiKey is required. Usage: & ([scriptblock]::Create((iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing).Content)) -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY"
        }

        if ([string]::IsNullOrWhiteSpace($DiscoveryKey)) {
            Exit-WithError "-DiscoveryKey is required. Usage: & ([scriptblock]::Create((iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing).Content)) -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY"
        }
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
            $pythonArgs += "--discovery-key"
            $pythonArgs += $DiscoveryKey
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

        # Add backfill flag if explicitly requested
        if ($Backfill) {
            $pythonArgs += "--backfill"
        }

        # Execute the Python script and capture exit code
        & $pythonCmd @pythonArgs
        $exitCode = $LASTEXITCODE

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
