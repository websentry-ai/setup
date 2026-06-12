#!/bin/bash
# CLI-boundary tests for the unbound-discovery onedir bundle.
#
# Fast checks (default) exercise the binary's argument boundary: the no-config
# state must idle with a log line and exit 0 (fail-open — the bundle is
# installed fleet-wide before per-tenant config exists), --help must print
# usage, and malformed values must not crash the daemon.
#
# RUN_FULL=1 additionally runs a real discovery against a local HTTP sink and
# asserts at least one report payload is POSTed to /api/v1/ai-tools/report/.
# This scans the build machine and can take several minutes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${UNBOUND_DISCOVERY_BIN:-$HERE/dist/unbound-discovery/unbound-discovery}"
[ -x "$BIN" ] || { echo "bundle not built: $BIN (run build-discovery.sh)" >&2; exit 1; }

PASS=0
FAIL=0
check() { # name expected_rc grep_pattern args...
    local name="$1" want_rc="$2" pattern="$3"; shift 3
    local out rc
    set +e
    out="$("$BIN" "$@" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -ne "$want_rc" ]; then
        echo "FAIL: $name — exit $rc (want $want_rc)"; echo "$out" | head -3
        FAIL=$((FAIL + 1)); return
    fi
    if [ -n "$pattern" ] && ! echo "$out" | grep -q "$pattern"; then
        echo "FAIL: $name — output missing /$pattern/"; echo "$out" | head -3
        FAIL=$((FAIL + 1)); return
    fi
    echo "PASS: $name"
    PASS=$((PASS + 1))
}

check "no args idles, exit 0"            0 "No configuration provided"
check "missing --domain idles, exit 0"   0 "missing: --domain"        --api-key k
check "missing --api-key idles, exit 0"  0 "missing: --api-key"       --domain example.com
check "empty values idle, exit 0"        0 "No configuration provided" --api-key "" --domain ""
check "key=value form recognized"        0 "missing: --domain"        --api-key=k
check "--help prints usage, exit 0"      0 "usage:"                   --help

# mcp-scan subcommand must route to scan_single_mcp_server (mirrors upstream
# install.sh routing — the agent hooks invoke `unbound-discovery mcp-scan ...`).
# Without an api key that module exits 2 with its distinctive error; if routing
# were broken, the sweep's argparse would exit 2 with "unrecognized arguments".
set +e
MCP_OUT="$("$BIN" mcp-scan --name testsrv --domain example.com 2>&1)"
MCP_RC=$?
set -e
if [ "$MCP_RC" -eq 2 ] && echo "$MCP_OUT" | grep -q "no api key"; then
    echo "PASS: mcp-scan routes to scan_single_mcp_server"
    PASS=$((PASS + 1))
else
    echo "FAIL: mcp-scan routing (exit $MCP_RC)"; echo "$MCP_OUT" | head -3
    FAIL=$((FAIL + 1))
fi

# UNBOUND_API_KEY env must satisfy --api-key (the argv-free channel that keeps
# the key out of ps/cmdline) — only --domain may be reported missing then.
set +e
ENV_OUT="$(UNBOUND_API_KEY=env-key "$BIN" 2>&1)"
ENV_RC=$?
set -e
if [ "$ENV_RC" -eq 0 ] && echo "$ENV_OUT" | grep -q "missing: --domain" \
   && ! echo "$ENV_OUT" | grep -q "api-key"; then
    echo "PASS: UNBOUND_API_KEY env satisfies --api-key"
    PASS=$((PASS + 1))
else
    echo "FAIL: UNBOUND_API_KEY env not honored (exit $ENV_RC)"; echo "$ENV_OUT" | head -3
    FAIL=$((FAIL + 1))
fi

if [ "${RUN_FULL:-0}" = "1" ]; then
    SINK_DIR="$(mktemp -d)"
    PORT="${SINK_PORT:-18923}"
    if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
        echo "FAIL: sink port $PORT already in use (set SINK_PORT to override)"
        exit 1
    fi
    python3 - "$PORT" "$SINK_DIR" <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, outdir = int(sys.argv[1]), sys.argv[2]
n = 0
class Sink(BaseHTTPRequestHandler):
    def _store(self, prefix, body):
        global n
        n += 1
        with open(f"{outdir}/{prefix}_{n}.json", "wb") as f:
            f.write(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        path = self.path.rstrip("/")
        if path == "/api/v1/ai-tools/report":
            self._store("report", body)
        elif path == "/api/v1/ai-tools/mcp-server-scan":
            self._store("mcpscan", body)
        else:  # S3 upload-url etc. — 404 forces the legacy POST fallback
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", port), Sink).serve_forever()
PYEOF
    SINK_PID=$!
    trap 'kill $SINK_PID 2>/dev/null || true' EXIT
    sleep 1

    # The tool short-circuits uploads when its local cache shows no change
    # since the last successful upload (~/.unbound/discovery-cache.json, with
    # a per-uid /var/tmp/unbound-$UID fallback). Clear it so this run
    # deterministically re-uploads everything for the sink assertion.
    # Harmless beyond the test: the backend dedups by payload_hash anyway.
    rm -f "$HOME/.unbound/discovery-cache.json" "/var/tmp/unbound-$(id -u)/discovery-cache.json"

    echo "running full discovery against local sink (this scans the machine)..."
    set +e
    # Empty DSN disables the tool's raw-HTTP Sentry reporting so synthetic
    # sink 404s (the S3 path we deliberately fail) don't pollute production.
    AI_DISCOVERY_SENTRY_DSN="" AI_DISCOVERY_SENTRY_ENV="test" \
        "$BIN" --api-key test-key --domain "http://127.0.0.1:$PORT" > "$SINK_DIR/run.log" 2>&1
    RC=$?
    set -e
    REPORTS=$(ls "$SINK_DIR"/report_*.json 2>/dev/null | wc -l | tr -d ' ')
    if [ "$RC" -eq 0 ] && [ "$REPORTS" -gt 0 ]; then
        echo "PASS: full run — exit 0, $REPORTS report payload(s) received"
        # Lifecycle scan-event payloads carry no tools; require at least one
        # data payload with device_id + a non-empty tools list.
        if python3 -c "
import json, glob, sys
ok = any(
    'device_id' in r and r.get('tools')
    for r in (json.load(open(p)) for p in glob.glob('$SINK_DIR/report_*.json'))
)
sys.exit(0 if ok else 1)
"; then
            echo "PASS: payload schema sanity (>=1 payload with device_id + tools)"
            PASS=$((PASS + 1))
        else
            echo "FAIL: payload schema sanity — no payload carried a tools list"
            FAIL=$((FAIL + 1))
        fi
        PASS=$((PASS + 1))
    else
        echo "FAIL: full run — exit $RC, $REPORTS report(s). Log tail:"
        tail -5 "$SINK_DIR/run.log"
        FAIL=$((FAIL + 1))
    fi
    # End-to-end mcp-scan: the frozen binary scans a fake stdio MCP server
    # (newline-delimited JSON-RPC: initialize + tools/list) and must POST the
    # result to /api/v1/ai-tools/mcp-server-scan/.
    cat > "$SINK_DIR/fake_mcp_server.py" <<'FAKEEOF'
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if "id" not in msg:
        continue  # notification (e.g. notifications/initialized)
    if msg.get("method") == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-mcp", "version": "1.0"}}
    elif msg.get("method") == "tools/list":
        result = {"tools": [{"name": "echo", "description": "echo a string",
                             "inputSchema": {"type": "object"}}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
FAKEEOF
    set +e
    MCP_FULL_OUT="$(UNBOUND_API_KEY=test-key \
        UNBOUND_MCP_SERVER_JSON="{\"command\":\"python3\",\"args\":[\"$SINK_DIR/fake_mcp_server.py\"]}" \
        "$BIN" mcp-scan --name fake-test-server --domain "http://127.0.0.1:$PORT" 2>&1)"
    MCP_FULL_RC=$?
    set -e
    MCP_REPORTS=$(ls "$SINK_DIR"/mcpscan_*.json 2>/dev/null | wc -l | tr -d ' ')
    if [ "$MCP_FULL_RC" -eq 0 ] && [ "$MCP_REPORTS" -gt 0 ] && python3 -c "
import json, glob, sys
p = sorted(glob.glob('$SINK_DIR/mcpscan_*.json'))[0]
s = json.load(open(p)).get('mcp_server') or {}
ok = s.get('name') == 'fake-test-server' and ((s.get('scan') or {}).get('tools'))
sys.exit(0 if ok else 1)
"; then
        echo "PASS: mcp-scan end-to-end (scanned fake server, POSTed to mcp-server-scan endpoint)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: mcp-scan end-to-end — exit $MCP_FULL_RC, $MCP_REPORTS payload(s)"
        echo "$MCP_FULL_OUT" | head -3
        FAIL=$((FAIL + 1))
    fi

    echo "sink artifacts: $SINK_DIR"
fi

echo "---"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
