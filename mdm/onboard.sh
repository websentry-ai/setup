#!/usr/bin/env bash
#
# Unbound MDM onboarding bash wrapper for macOS/Linux
#
# Downloads and executes the Python-based MDM onboarding script (onboard.py)
# that performs all five setup steps:
#
#   1. Claude Code MDM setup (with backfill of historical transcripts)
#   2. Cursor MDM setup
#   3. Codex MDM setup (with backfill of historical transcripts)
#   4. GitHub Copilot MDM setup
#   5. Coding-discovery scan
#
# This bash wrapper:
# - Checks for Python availability (python3, python)
# - Downloads the onboard.py script from GitHub
# - Executes it with all provided parameters
# - Provides clear errors if Python is missing
#
# Python 3 is required because the underlying MDM setup scripts are Python-based.
#
# Usage:
#   curl -fsSL https://getunbound.ai/setup/mdm/onboard.sh | bash -s -- --api-key YOUR_ADMIN_KEY --discovery-key YOUR_DISCOVERY_KEY
#
#   Or with URL overrides:
#   curl -fsSL https://getunbound.ai/setup/mdm/onboard.sh | bash -s -- --api-key YOUR_KEY --discovery-key YOUR_KEY --backend-url https://backend.example.com --gateway-url https://api.example.com
#
#   To clear MDM setup:
#   curl -fsSL https://getunbound.ai/setup/mdm/onboard.sh | bash -s -- --clear
#
# Requires: Python 3, sudo privileges

set -euo pipefail

# Constants
# Pinned to commit 42c7b55 to ensure reproducible deployments and prevent supply-chain attacks
ONBOARD_PY_URL="https://raw.githubusercontent.com/websentry-ai/setup/42c7b5535aaee4bfd65f5ca77ad91ba88b4a23b2/mdm/onboard.py"

# Variables
API_KEY=""
DISCOVERY_KEY=""
BACKEND_URL=""
GATEWAY_URL=""
CLEAR_MODE=false

# Output helpers
error_exit() {
    echo "Error: $1" >&2
    exit "${2:-1}"
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --discovery-key)
                DISCOVERY_KEY="$2"
                shift 2
                ;;
            --backend-url)
                BACKEND_URL="$2"
                shift 2
                ;;
            --gateway-url)
                GATEWAY_URL="$2"
                shift 2
                ;;
            --clear)
                CLEAR_MODE=true
                shift
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
}

# Find Python executable
find_python() {
    local python_commands=("python3" "python")

    for cmd in "${python_commands[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            # Verify it's Python 3
            if "$cmd" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
                echo "$cmd"
                return 0
            fi
        fi
    done

    return 1
}

# Download the Python onboard script
download_onboard_script() {
    local url="$1"
    local content
    local curl_stderr

    # Capture stderr separately to avoid mixing warnings into script content
    curl_stderr=$(mktemp)
    trap "rm -f '$curl_stderr'" RETURN

    if ! content=$(curl -fsSL "$url" 2>"$curl_stderr"); then
        local error_msg
        error_msg=$(cat "$curl_stderr" 2>/dev/null || echo "unknown error")
        error_exit "Failed to download onboard.py: $error_msg"
    fi

    if [[ -z "$content" ]]; then
        error_exit "Failed to download onboard.py: empty response"
    fi

    echo "$content"
}

# Main execution
main() {
    # Parse arguments
    parse_args "$@"

    # Validate parameters (unless --clear is specified)
    if [[ "$CLEAR_MODE" == false ]]; then
        if [[ -z "$API_KEY" ]]; then
            error_exit "--api-key is required. Usage: curl -fsSL https://getunbound.ai/setup/mdm/onboard.sh | bash -s -- --api-key YOUR_KEY --discovery-key YOUR_KEY"
        fi

        if [[ -z "$DISCOVERY_KEY" ]]; then
            error_exit "--discovery-key is required. Usage: curl -fsSL https://getunbound.ai/setup/mdm/onboard.sh | bash -s -- --api-key YOUR_KEY --discovery-key YOUR_KEY"
        fi
    fi

    # Find Python
    if ! python_cmd=$(find_python); then
        error_exit "Python 3 is required but not found in PATH. Install Python 3 from https://www.python.org/downloads/ or via your package manager (brew install python3, apt install python3, etc.)"
    fi

    # Download the Python script
    script_content=$(download_onboard_script "$ONBOARD_PY_URL")

    # Create a temporary file for the Python script
    temp_file=$(mktemp)
    temp_py_file="${temp_file}.py"

    # Cleanup on exit
    trap 'rm -f "$temp_file" "$temp_py_file"' EXIT

    # Write the Python script to temp file
    echo "$script_content" > "$temp_py_file"

    # Build arguments for the Python script
    python_args=("$temp_py_file")

    if [[ "$CLEAR_MODE" == true ]]; then
        python_args+=(--clear)
    else
        python_args+=(--api-key "$API_KEY" --discovery-key "$DISCOVERY_KEY")

        if [[ -n "$BACKEND_URL" ]]; then
            python_args+=(--backend-url "$BACKEND_URL")
        fi

        if [[ -n "$GATEWAY_URL" ]]; then
            python_args+=(--gateway-url "$GATEWAY_URL")
        fi
    fi

    # Execute the Python script
    "$python_cmd" "${python_args[@]}"
    return $?
}

# Entry point
main "$@"
exit_code=$?

# Self-destruct: Remove this script file after execution completes
# This allows users to run without manual cleanup when downloaded first
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    rm -f "${BASH_SOURCE[0]}" 2>/dev/null || true
fi

# Exit with the Python script's exit code
exit $exit_code
