package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newReporter(t *testing.T) (*Reporter, string) {
	t.Helper()
	dir := t.TempDir()
	return &Reporter{
		GatewayURL:     "https://gw.example.com",
		HookSource:     "claude-code",
		ErrorLog:       filepath.Join(dir, "error.log"),
		LastReportFile: filepath.Join(dir, ".last_error_report"),
	}, dir
}

// installFakeCurl captures the detached error-report POST.
func installFakeCurl(t *testing.T) (argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")
	script := `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > "$CURL_ARGS_FILE"
cat > "$CURL_STDIN_FILE"
`
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CURL_ARGS_FILE", argsFile)
	t.Setenv("CURL_STDIN_FILE", stdinFile)
	return argsFile, stdinFile
}

func waitForFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		if time.Now().After(deadline) {
			t.Fatalf("file %s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUTCTimestampMatchesPythonIsoformat(t *testing.T) {
	ts := time.Date(2026, 6, 12, 1, 2, 3, 456789000, time.UTC)
	if got := UTCTimestamp(ts); got != "2026-06-12T01:02:03.456789Z" {
		t.Errorf("UTCTimestamp = %q", got)
	}
	// python isoformat omits microseconds entirely when zero
	zero := time.Date(2026, 6, 12, 1, 2, 3, 0, time.UTC)
	if got := UTCTimestamp(zero); got != "2026-06-12T01:02:03Z" {
		t.Errorf("UTCTimestamp = %q", got)
	}
}

func TestLocalTimestampOffsetFormat(t *testing.T) {
	loc := time.FixedZone("IST", 5*3600+30*60)
	ts := time.Date(2026, 6, 12, 1, 2, 3, 0, loc)
	defer func(orig *time.Location) { time.Local = orig }(time.Local)
	time.Local = loc
	if got := LocalTimestamp(ts); got != "2026-06-12T01:02:03+05:30" {
		t.Errorf("LocalTimestamp = %q", got)
	}
	time.Local = time.FixedZone("UTC", 0) // python replaces "+00:00" with "Z"
	if got := LocalTimestamp(ts.UTC()); !strings.HasSuffix(got, "Z") {
		t.Errorf("LocalTimestamp = %q, want Z suffix", got)
	}
}

func TestLogErrorAppendsTimestampedLine(t *testing.T) {
	r, _ := newReporter(t)
	r.now = func() time.Time { return time.Date(2026, 6, 12, 1, 2, 3, 0, time.UTC) }
	r.LogError("boom happened", "general")
	data, err := os.ReadFile(r.ErrorLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "2026-06-12T01:02:03Z: boom happened\n" {
		t.Errorf("error.log = %q", got)
	}
}

func TestLogErrorTrimsToLast25Lines(t *testing.T) {
	r, _ := newReporter(t)
	for i := 0; i < 30; i++ {
		r.LogError(fmt.Sprintf("err %d", i), "general")
	}
	data, err := os.ReadFile(r.ErrorLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 25 {
		t.Fatalf("got %d lines, want 25", len(lines))
	}
	if !strings.HasSuffix(lines[0], ": err 5") || !strings.HasSuffix(lines[24], ": err 29") {
		t.Errorf("window wrong: first %q last %q", lines[0], lines[24])
	}
}

func TestReportToGatewayPayloadMatchesPython(t *testing.T) {
	argsFile, stdinFile := installFakeCurl(t)
	r, _ := newReporter(t)
	r.now = func() time.Time { return time.Date(2026, 6, 12, 1, 2, 3, 456789000, time.UTC) }

	r.ReportToGateway("it broke", "api_call", "sk-9")

	// python: json.dumps({'errors': [{'message': ..., 'timestamp': ..., 'category': ...}], 'hook_source': 'claude-code'})
	wantBody := `{"errors": [{"message": "it broke", "timestamp": "2026-06-12T01:02:03.456789Z", "category": "api_call"}], "hook_source": "claude-code"}`
	if got := waitForFile(t, stdinFile); got != wantBody {
		t.Errorf("payload:\n got %s\nwant %s", got, wantBody)
	}

	wantArgs := []string{"-fsSL", "-X", "POST",
		"-H", "Authorization: Bearer sk-9",
		"-H", "Content-Type: application/json",
		"--data-binary", "@-",
		"https://gw.example.com/v1/hooks/errors"}
	got := strings.Split(strings.TrimRight(waitForFile(t, argsFile), "\n"), "\n")
	if strings.Join(got, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Errorf("argv = %q, want %q", got, wantArgs)
	}
}

func TestReportToGatewayRateLimited(t *testing.T) {
	_, stdinFile := installFakeCurl(t)
	r, _ := newReporter(t)

	r.ReportToGateway("first", "general", "sk-9")
	waitForFile(t, stdinFile)
	if err := os.Remove(stdinFile); err != nil {
		t.Fatal(err)
	}
	r.ReportToGateway("second", "general", "sk-9") // inside the 60s window
	time.Sleep(200 * time.Millisecond)
	if _, err := os.ReadFile(stdinFile); err == nil {
		t.Error("second report within 60s must be suppressed")
	}
}

func TestReportToGatewayNoAPIKeyIsNoop(t *testing.T) {
	_, stdinFile := installFakeCurl(t)
	r, _ := newReporter(t)
	r.ReportToGateway("msg", "general", "")
	time.Sleep(100 * time.Millisecond)
	if _, err := os.ReadFile(stdinFile); err == nil {
		t.Error("no api key must mean no report")
	}
	if _, err := os.Stat(r.LastReportFile); err == nil {
		t.Error("rate-limit marker must not be touched before the key check")
	}
}

func TestShouldReportFailsClosed(t *testing.T) {
	r, _ := newReporter(t)
	r.LastReportFile = filepath.Join(t.TempDir(), "missing-dir", "marker")
	if r.shouldReport() {
		t.Error("untouchable marker must fail closed")
	}
}
