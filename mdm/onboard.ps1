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
    - Checks for Python availability (python, python3, py)
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

.PARAMETER Clear
    Remove MDM configuration for all four tools (no discovery scan, no backfill)

.EXAMPLE
    # Standard onboarding with both keys
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing).Content)" -ApiKey YOUR_ADMIN_KEY -DiscoveryKey YOUR_DISCOVERY_KEY

.EXAMPLE
    # Clear MDM setup
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing).Content)" -Clear

.NOTES
    Requires: Python 3, Administrator privileges
    URL: https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py
#>

param(
    [string]$ApiKey,
    [string]$DiscoveryKey,
    [string]$BackendUrl,
    [string]$GatewayUrl,
    [switch]$Clear
)

$ErrorActionPreference = "Stop"

# Constants
$ONBOARD_PY_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py"
$SCRIPT_NAME = "Unbound MDM Onboarding"

# Output helpers
function Write-Error-Exit { param([string]$Message, [int]$Code = 1) Write-Error $Message; exit $Code }

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find Python executable
function Find-Python {
    $pythonCommands = @("python", "python3", "py")

    foreach ($cmd in $pythonCommands) {
        try {
            $null = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                return $cmd
            }
        } catch {
            # Command not found, continue to next
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
            Write-Error-Exit "Failed to download onboard.py: empty response"
        }

        return $response.Content
    } catch {
        Write-Error-Exit "Failed to download onboard.py: $_"
    }
}

# Main execution
function Main {
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error-Exit "This script requires administrator privileges. Right-click PowerShell -> Run as Administrator, then rerun."
    }

    # Validate parameters (unless -Clear is specified)
    if (-not $Clear) {
        if ([string]::IsNullOrWhiteSpace($ApiKey)) {
            Write-Error-Exit "-ApiKey is required. Usage: iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing | Select -ExpandProperty Content | iex -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY"
        }

        if ([string]::IsNullOrWhiteSpace($DiscoveryKey)) {
            Write-Error-Exit "-DiscoveryKey is required. Usage: iwr 'https://getunbound.ai/setup/mdm/onboard.ps1' -UseBasicParsing | Select -ExpandProperty Content | iex -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY"
        }
    }

    # Find Python
    $pythonCmd = Find-Python
    if ($null -eq $pythonCmd) {
        Write-Error-Exit "Python 3 is required but not found in PATH. Install from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked."
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

            if (-not [string]::IsNullOrWhiteSpace($BackendUrl)) {
                $pythonArgs += "--backend-url"
                $pythonArgs += $BackendUrl
            }

            if (-not [string]::IsNullOrWhiteSpace($GatewayUrl)) {
                $pythonArgs += "--gateway-url"
                $pythonArgs += $GatewayUrl
            }
        }

        # Execute the Python script and capture exit code
        & $pythonCmd @pythonArgs
        exit $LASTEXITCODE

    } finally {
        # Clean up temporary files
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
        if (Test-Path $tempPyFile) {
            Remove-Item $tempPyFile -ErrorAction SilentlyContinue
        }
    }
}

# Entry point
Main
