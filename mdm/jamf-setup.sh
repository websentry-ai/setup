#!/bin/bash
# Unbound setup for a pkg deployed from your own Jamf. Downloads nothing; its only
# network call is the install report POST to your backend. Run it After the pkg.
# Parameters: $4 api key, $5 discovery key (ignored), $6 backend url, $7 gateway url,
# $8 clear, $9 backfill, $10 skip-managed-settings, $11 frontend url.
set -euo pipefail

PREFIX="/opt/unbound"
PKG_ID="ai.getunbound.runtime"
DAEMON_LABEL="ai.getunbound.discovery"
HOOK="$PREFIX/current/unbound-hook/unbound-hook"

API_KEY="${4:-}"
BACKEND_URL="${6:-https://backend.getunbound.ai}"
GATEWAY_URL="${7:-https://api.getunbound.ai}"
FRONTEND_URL="${11:-}"
CURRENT_STEP="preflight"
install_succeeded=0

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/[[:cntrl:]]//g'; }

# Same rule as normalize_url in each tool's setup.py: default to https, no trailing slash.
normalize_url() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  [[ -n "$v" ]] || return 0
  [[ "$v" == http://* || "$v" == https://* ]] || v="https://$v"
  while [[ "$v" == */ ]]; do v="${v%/}"; done
  printf '%s' "$v"
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
report() {
  local serial version body http_code
  serial="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')" || serial=""
  version="$(pkgutil --pkg-info "$PKG_ID" 2>/dev/null | awk '/^version:/{print $2}')" || version=""
  body="$(printf '{"serial_number":"%s","step":"%s","exit_code":%d,"installer_version":"%s","hostname":"%s","os_version":"%s","ts":%d}' \
    "$(json_escape "$serial")" "$(json_escape "$CURRENT_STEP")" "$1" \
    "$(json_escape "$version")" "$(json_escape "$(hostname)")" \
    "$(json_escape "$(sw_vers -productVersion)")" "$(date +%s)")"
  http_code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' \
    -X POST "$(normalize_url "$BACKEND_URL")/api/v1/automations/mdm/install-report/" \
    -H 'Content-Type: application/json' \
    -H "X-API-KEY: ${API_KEY}" \
    -d "$body" 2>/dev/null)" || http_code="000"
  case "$http_code" in
    2??) ;;
    *) echo "::install-report POST failed: HTTP ${http_code} (step=${CURRENT_STEP})" >&2 ;;
  esac
}

# shellcheck disable=SC2329  # invoked from the EXIT trap
on_exit() {
  local code=$1
  if [[ $code -ne 0 ]]; then
    echo "UNBOUND_INSTALL_FAILED step=${CURRENT_STEP} code=${code}" >&2
  fi
  if [[ -n "$API_KEY" && ( $code -ne 0 || $install_succeeded -eq 1 ) ]]; then
    report "$code" || true
  fi
}
trap 'on_exit $?' EXIT

# macOS has no `timeout`.
run_with_timeout() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs" && kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 & local watchdog=$!
  local rc=0
  wait "$pid" 2>/dev/null || rc=$?
  pkill -P "$watchdog" 2>/dev/null || true
  kill "$watchdog" 2>/dev/null || true; wait "$watchdog" 2>/dev/null || true
  return "$rc"
}

# Each slot accepts generic booleans plus only its own token.
is_clear_token()        { case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|clear|--clear) return 0;; *) return 1;; esac; }
is_backfill_token()     { case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|backfill|--backfill) return 0;; *) return 1;; esac; }
is_skip_managed_token() { case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|skip-managed-settings|--skip-managed-settings) return 0;; *) return 1;; esac; }

[[ $EUID -eq 0 ]] || { echo "must run as root (Jamf runs scripts as root)" >&2; exit 1; }

if is_clear_token "${8:-}"; then
  CURRENT_STEP="clear"
  if [[ -x "$HOOK" ]] && run_with_timeout 300 "$HOOK" clear; then
    echo "binary teardown complete"
  else
    echo "binary unavailable or failed; removing runtime files only"
  fi
  launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || true
  rm -f "/Library/LaunchDaemons/${DAEMON_LABEL}.plist" /etc/newsyslog.d/ai.getunbound.conf
  rm -rf "$PREFIX"
  pkgutil --forget "$PKG_ID" >/dev/null 2>&1 || true
  echo "UNBOUND_CLEAR_OK"
  exit 0
fi

[[ -n "$API_KEY" ]] || { echo "API key (parameter 4) is required" >&2; exit 2; }
args=(setup --api-key "$API_KEY" --backend-url "$BACKEND_URL" --gateway-url "$GATEWAY_URL")
compact_frontend="${FRONTEND_URL//[[:space:]]/}"
if [[ -n "$compact_frontend" ]]; then
  [[ "$compact_frontend" != -* ]] || { echo "frontend url (parameter 11) must be a URL" >&2; exit 2; }
  args+=(--frontend-url "$FRONTEND_URL")
fi
if is_backfill_token "${9:-}"; then args+=(--backfill); fi
if is_skip_managed_token "${10:-}"; then args+=(--skip-managed-settings); fi

CURRENT_STEP="runtime_check"
[[ -x "$HOOK" ]] || { echo "Unbound runtime not installed: add the pkg to this policy and run this script After it" >&2; exit 1; }

CURRENT_STEP="setup"
"$HOOK" "${args[@]}"

install_succeeded=1
exit 0
