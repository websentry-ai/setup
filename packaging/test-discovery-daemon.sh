#!/bin/bash
# LaunchDaemon integration test for the unbound-discovery bundle.
#
# Verifies the binary works in its real production context: a root LaunchDaemon
# bootstrapped via `launchctl bootstrap system` (NOT a sudo shell — launchd
# strips the session environment) with HOME pinned to /var/empty, reproducing
# the daemon environment where ambient HOME is meaningless. Asserts a
# discovery report payload is POSTed to a local HTTP sink and that the
# no-config variant idles with exit 0.
#
# Must be run as root:  sudo bash packaging/test-discovery-daemon.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${UNBOUND_DISCOVERY_BIN:-$HERE/dist/unbound-discovery/unbound-discovery}"
[ -x "$BIN" ] || { echo "bundle not built: $BIN (run build-discovery.sh)" >&2; exit 1; }

LABEL="ai.unbound.discovery.daemontest"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LOG="/var/tmp/$LABEL.log"
SINK_DIR="$(mktemp -d /var/tmp/$LABEL.sink.XXXX)"
PORT="${SINK_PORT:-18924}"
TIMEOUT_S="${DAEMON_TEST_TIMEOUT:-900}"

cleanup() {
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- local HTTP sink ---------------------------------------------------------
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

# --- bootstrap the daemon ------------------------------------------------------
rm -f "$LOG"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN</string>
        <string>--api-key</string><string>daemon-test-key</string>
        <string>--domain</string><string>http://127.0.0.1:$PORT</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <!-- reproduce the incident environment: HOME is meaningless for a root daemon -->
        <key>HOME</key><string>/var/empty</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>$LOG</string>
    <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
PLISTEOF
chown root:wheel "$PLIST" && chmod 644 "$PLIST"

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo "daemon bootstrapped (system/$LABEL); waiting for discovery to finish (timeout ${TIMEOUT_S}s)..."

# --- wait for the run to complete ---------------------------------------------
ELAPSED=0
while launchctl print "system/$LABEL" 2>/dev/null | grep -q "state = running"; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    [ "$ELAPSED" -lt "$TIMEOUT_S" ] || { echo "TIMEOUT after ${TIMEOUT_S}s"; tail -20 "$LOG" 2>/dev/null; exit 1; }
done
sleep 2

EXIT_STATUS="$(launchctl print "system/$LABEL" 2>/dev/null | awk '/last exit code/ {print $NF}')"
REPORTS=$(ls "$SINK_DIR"/report_*.json 2>/dev/null | wc -l | tr -d ' ')

echo "--- results -------------------------------------------------"
echo "daemon last exit code: ${EXIT_STATUS:-unknown}"
echo "report payloads received: $REPORTS"
echo "daemon log: $LOG ($(wc -l < "$LOG" 2>/dev/null || echo 0) lines)"
grep -m1 "Users to process" "$LOG" 2>/dev/null || true
grep -c "report.*sent successfully" "$LOG" 2>/dev/null | sed 's/^/reports logged as sent: /' || true

FAIL=0
[ "${EXIT_STATUS:-1}" = "0" ] || { echo "FAIL: daemon exit code != 0"; FAIL=1; }
[ "$REPORTS" -gt 0 ] || { echo "FAIL: no report payload reached the sink"; FAIL=1; }

# --- no-config variant: must idle cleanly, exit 0 ------------------------------
launchctl bootout "system/$LABEL" 2>/dev/null || true
NOCONF_LOG="/var/tmp/$LABEL.noconf.log"
rm -f "$NOCONF_LOG"
/usr/bin/sed -i '' \
    -e 's|<string>--api-key</string><string>daemon-test-key</string>||' \
    -e 's|<string>--domain</string><string>http://127.0.0.1:'"$PORT"'</string>||' \
    -e "s|$LABEL.log|$LABEL.noconf.log|g" "$PLIST"
launchctl bootstrap system "$PLIST"
sleep 5
NOCONF_EXIT="$(launchctl print "system/$LABEL" 2>/dev/null | awk '/last exit code/ {print $NF}')"
if [ "${NOCONF_EXIT:-1}" = "0" ] && grep -q "No configuration provided" "$NOCONF_LOG" 2>/dev/null; then
    echo "PASS: no-config daemon idled with log line, exit 0"
else
    echo "FAIL: no-config daemon — exit ${NOCONF_EXIT:-unknown}, log:"
    cat "$NOCONF_LOG" 2>/dev/null | head -5
    FAIL=1
fi

echo "sink artifacts kept at: $SINK_DIR"
if [ "$FAIL" -eq 0 ]; then
    echo "DAEMON TEST PASSED"
else
    echo "DAEMON TEST FAILED"
    exit 1
fi
