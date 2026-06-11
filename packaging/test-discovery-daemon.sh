#!/bin/bash
# LaunchDaemon integration test for the unbound-discovery bundle.
#
# Verifies the binary works in its real production context: a root LaunchDaemon
# bootstrapped via `launchctl bootstrap system` (NOT a sudo shell — launchd
# strips the session environment) with HOME pinned to /var/empty, reproducing
# the daemon environment where ambient HOME is meaningless. Asserts:
#   1. the daemon exits 0 and a discovery report payload reaches a local sink
#   2. multi-user /Users/* iteration ran as root (log says "Users to process: N",
#      N >= 1, and the console user's home was explored)
#   3. the no-config variant (HOME entirely unset — the other daemon reality)
#      idles with a log line and exit 0
#
# Must be run as root:  sudo bash packaging/test-discovery-daemon.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${UNBOUND_DISCOVERY_BIN:-$HERE/dist/unbound-discovery/unbound-discovery}"
[ -x "$BIN" ] || { echo "bundle not built: $BIN (run build-discovery.sh)" >&2; exit 1; }

LABEL="ai.unbound.discovery.daemontest"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SINK_DIR="$(mktemp -d /var/tmp/$LABEL.sink.XXXX)"
STAGE="/var/tmp/$LABEL.bin"
PORT="${SINK_PORT:-18924}"
TIMEOUT_S="${DAEMON_TEST_TIMEOUT:-900}"
FAIL=0

cleanup() {
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    rm -rf "$STAGE"
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Stage the bundle to a TCC-free, root-owned path. A root LaunchDaemon has no
# TCC grants, so a bundle inside ~/Documents (or any TCC-protected dir) makes
# the PyInstaller bootloader unable to read its own archive (PYI-ERROR:
# "Could not load PyInstaller's embedded PKG archive"). Production installs
# to a system path, so this staging also matches deployment semantics.
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -R "$(cd "$(dirname "$BIN")" && pwd)" "$STAGE/"
DAEMON_BIN="$STAGE/$(basename "$(dirname "$BIN")")/$(basename "$BIN")"
chown -R root:wheel "$STAGE"
[ -x "$DAEMON_BIN" ] || { echo "staging failed: $DAEMON_BIN" >&2; exit 1; }

xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# write_plist <log-path> <home-mode: varempty|unset> [program args...]
write_plist() {
    local log_path="$1" home_mode="$2"
    shift 2
    log_path="$(xml_escape "$log_path")"
    local args_xml=""
    local a
    for a in "$DAEMON_BIN" "$@"; do
        args_xml="$args_xml        <string>$(xml_escape "$a")</string>
"
    done
    local env_xml=""
    if [ "$home_mode" = "varempty" ]; then
        env_xml="    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key><string>/var/empty</string>
        <key>AI_DISCOVERY_SENTRY_DSN</key><string></string>
        <key>AI_DISCOVERY_SENTRY_ENV</key><string>test</string>
    </dict>"
    else
        # HOME deliberately absent — launchd daemons get no HOME by default
        env_xml="    <key>EnvironmentVariables</key>
    <dict>
        <key>AI_DISCOVERY_SENTRY_DSN</key><string></string>
        <key>AI_DISCOVERY_SENTRY_ENV</key><string>test</string>
    </dict>"
    fi
    cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
$args_xml    </array>
$env_xml
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>$log_path</string>
    <key>StandardErrorPath</key><string>$log_path</string>
</dict>
</plist>
PLISTEOF
    chown root:wheel "$PLIST" && chmod 644 "$PLIST"
}

# wait_for_daemon_exit <timeout-seconds>  → sets DAEMON_EXIT (code or "unknown")
# Handles the spawn race: first waits for the job to have run at all (state
# running, or a recorded exit), then waits for it to stop running.
wait_for_daemon_exit() {
    local timeout_s="$1" elapsed=0 started=0 info
    DAEMON_EXIT="unknown"
    while [ "$elapsed" -lt "$timeout_s" ]; do
        info="$(launchctl print "system/$LABEL" 2>/dev/null || true)"
        if echo "$info" | grep -q "state = running"; then
            started=1
        elif [ "$started" -eq 1 ] || \
             { echo "$info" | grep -q "last exit code" && \
               ! echo "$info" | grep -q "never exited"; }; then
            DAEMON_EXIT="$(echo "$info" | awk '/last exit code/ {print $NF}')"
            [ -n "$DAEMON_EXIT" ] || DAEMON_EXIT="unknown"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "TIMEOUT: daemon still running after ${timeout_s}s"
    return 1
}

# --- local HTTP sink ----------------------------------------------------------
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    echo "FAIL: sink port $PORT already in use (set SINK_PORT to override)" >&2
    exit 1
fi
python3 - "$PORT" "$SINK_DIR" <<'PYEOF' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, outdir = int(sys.argv[1]), sys.argv[2]
n = 0
class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.rstrip("/") == "/api/v1/ai-tools/report":
            n += 1
            with open(f"{outdir}/report_{n}.json", "wb") as f:
                f.write(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", port), Sink).serve_forever()
PYEOF
SINK_PID=$!
sleep 1

# --- variant 1: full discovery, HOME=/var/empty (incident repro) ---------------
LOG="/var/tmp/$LABEL.log"
rm -f "$LOG"
write_plist "$LOG" varempty \
    --api-key daemon-test-key --domain "http://127.0.0.1:$PORT"
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo "daemon bootstrapped (system/$LABEL, HOME=/var/empty); waiting (timeout ${TIMEOUT_S}s)..."
wait_for_daemon_exit "$TIMEOUT_S" || { tail -20 "$LOG" 2>/dev/null; exit 1; }

REPORTS=$(ls "$SINK_DIR"/report_*.json 2>/dev/null | wc -l | tr -d ' ')
echo "--- variant 1 results ---------------------------------------"
echo "daemon exit code: $DAEMON_EXIT; report payloads received: $REPORTS"
[ "$DAEMON_EXIT" = "0" ] || { echo "FAIL: daemon exit code != 0"; FAIL=1; }
[ "$REPORTS" -gt 0 ] || { echo "FAIL: no report payload reached the sink"; FAIL=1; }

# Multi-user /Users/* iteration must actually have run (AC: WEB-4787).
USERS_LINE="$(grep -m1 "Users to process:" "$LOG" 2>/dev/null || true)"
USERS_N="$(echo "$USERS_LINE" | awk -F': ' '{print $NF}' | tr -dc 0-9)"
CONSOLE_USER="$(stat -f %Su /dev/console 2>/dev/null || echo "")"
if [ -n "$USERS_N" ] && [ "$USERS_N" -ge 1 ]; then
    echo "PASS: multi-user iteration ran ($USERS_LINE)"
else
    echo "FAIL: log has no 'Users to process: N' with N >= 1 — /Users/* enumeration did not run"
    FAIL=1
fi
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    if grep -q "Detecting tools for user: $CONSOLE_USER" "$LOG" 2>/dev/null; then
        echo "PASS: console user '$CONSOLE_USER' explored under /Users"
    else
        echo "FAIL: console user '$CONSOLE_USER' not explored — iteration incomplete"
        FAIL=1
    fi
fi

# --- variant 2: no config, HOME unset — must idle cleanly, exit 0 --------------
launchctl bootout "system/$LABEL" 2>/dev/null || true
NOCONF_LOG="/var/tmp/$LABEL.noconf.log"
rm -f "$NOCONF_LOG"
write_plist "$NOCONF_LOG" unset
launchctl bootstrap system "$PLIST"
wait_for_daemon_exit 120 || { tail -5 "$NOCONF_LOG" 2>/dev/null; exit 1; }
if [ "$DAEMON_EXIT" = "0" ] && grep -q "No configuration provided" "$NOCONF_LOG" 2>/dev/null; then
    echo "PASS: no-config daemon (HOME unset) idled with log line, exit 0"
else
    echo "FAIL: no-config daemon — exit $DAEMON_EXIT, log:"
    head -5 "$NOCONF_LOG" 2>/dev/null
    FAIL=1
fi

echo "daemon logs: $LOG, $NOCONF_LOG; sink artifacts: $SINK_DIR"
if [ "$FAIL" -eq 0 ]; then
    echo "DAEMON TEST PASSED"
else
    echo "DAEMON TEST FAILED"
    exit 1
fi
