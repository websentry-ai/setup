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

if [ "${RUN_FULL:-0}" = "1" ]; then
    SINK_DIR="$(mktemp -d)"
    PORT="${SINK_PORT:-18923}"
    python3 - "$PORT" "$SINK_DIR" <<'PYEOF' &
import json, sys
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

    echo "running full discovery against local sink (this scans the machine)..."
    set +e
    "$BIN" --api-key test-key --domain "http://127.0.0.1:$PORT" > "$SINK_DIR/run.log" 2>&1
    RC=$?
    set -e
    REPORTS=$(ls "$SINK_DIR"/report_*.json 2>/dev/null | wc -l | tr -d ' ')
    if [ "$RC" -eq 0 ] && [ "$REPORTS" -gt 0 ]; then
        echo "PASS: full run — exit 0, $REPORTS report payload(s) received"
        python3 -c "
import json, glob, sys
p = sorted(glob.glob('$SINK_DIR/report_*.json'))[0]
r = json.load(open(p))
missing = [k for k in ('device_id', 'tools') if k not in r]
sys.exit('payload missing keys: %s' % missing if missing else 0)
" && echo "PASS: payload schema sanity (device_id, tools present)" \
  || { echo "FAIL: payload schema sanity"; FAIL=$((FAIL + 1)); }
        PASS=$((PASS + 1))
    else
        echo "FAIL: full run — exit $RC, $REPORTS report(s). Log tail:"
        tail -5 "$SINK_DIR/run.log"
        FAIL=$((FAIL + 1))
    fi
    echo "sink artifacts: $SINK_DIR"
fi

echo "---"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
