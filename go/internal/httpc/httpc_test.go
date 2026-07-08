package httpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFakeCurl puts an executable `curl` shim first on PATH that records
// its argv and stdin, then behaves per CURL_STDOUT / CURL_EXIT.
func installFakeCurl(t *testing.T) (argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")
	script := `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > "$CURL_ARGS_FILE"
cat > "$CURL_STDIN_FILE"
[ -n "$CURL_SLEEP" ] && sleep "$CURL_SLEEP"
printf '%s' "$CURL_STDOUT"
[ -n "$CURL_STDERR" ] && printf '%s' "$CURL_STDERR" >&2
exit "${CURL_EXIT:-0}"
`
	if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CURL_ARGS_FILE", argsFile)
	t.Setenv("CURL_STDIN_FILE", stdinFile)
	t.Setenv("CURL_STDOUT", "")
	t.Setenv("CURL_STDERR", "")
	t.Setenv("CURL_EXIT", "0")
	t.Setenv("CURL_SLEEP", "")
	return argsFile, stdinFile
}

func recordedArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestPostJSONArgsMirrorPython(t *testing.T) {
	argsFile, stdinFile := installFakeCurl(t)
	t.Setenv("CURL_STDOUT", `{"decision": "allow"}`)

	res, err := PostJSON("https://gw.example.com/v1/hooks/pretool", "sk-123",
		[]byte(`{"a": 1}`), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != `{"decision": "allow"}` {
		t.Errorf("Result = %+v", res)
	}

	want := []string{"-fsSL", "-X", "POST",
		"-H", "Authorization: Bearer sk-123",
		"-H", "Content-Type: application/json",
		"--data-binary", "@-",
		"https://gw.example.com/v1/hooks/pretool"}
	got := recordedArgs(t, argsFile)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", got, want)
	}
	body, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"a": 1}` {
		t.Errorf("stdin = %q", body)
	}
}

func TestGetArgsMirrorPython(t *testing.T) {
	argsFile, _ := installFakeCurl(t)
	t.Setenv("CURL_STDOUT", `{"enabled": true}`)

	res, err := Get("https://gw.example.com/v1/hooks/discovery-enabled", "sk-123", 5, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || string(res.Stdout) != `{"enabled": true}` {
		t.Errorf("Result = %+v", res)
	}
	want := []string{"-fsSL",
		"-H", "Authorization: Bearer sk-123",
		"--max-time", "5",
		"https://gw.example.com/v1/hooks/discovery-enabled"}
	got := recordedArgs(t, argsFile)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestFetchArgsMirrorPython(t *testing.T) {
	argsFile, _ := installFakeCurl(t)
	if _, err := Fetch("https://raw.example.com/unbound.py", 10, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	want := []string{"-fsSL", "--max-time", "10", "https://raw.example.com/unbound.py"}
	got := recordedArgs(t, argsFile)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestDownloadArgsMirrorPython(t *testing.T) {
	argsFile, _ := installFakeCurl(t)
	if _, err := Download("https://raw.example.com/install.sh", "/tmp/install.tmp", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	want := []string{"-fsSL", "-o", "/tmp/install.tmp", "https://raw.example.com/install.sh"}
	got := recordedArgs(t, argsFile)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", got, want)
	}
}

func TestNonZeroExitIsResultNotError(t *testing.T) {
	installFakeCurl(t)
	t.Setenv("CURL_EXIT", "22")
	t.Setenv("CURL_STDERR", "curl: (22) The requested URL returned error: 500")

	res, err := PostJSON("https://gw.example.com/x", "k", []byte("{}"), 10*time.Second)
	if err != nil {
		t.Fatalf("non-zero exit must not be an error (python checks returncode): %v", err)
	}
	if res.ExitCode != 22 {
		t.Errorf("ExitCode = %d, want 22", res.ExitCode)
	}
	if !strings.Contains(string(res.Stderr), "(22)") {
		t.Errorf("Stderr = %q", res.Stderr)
	}
}

func TestTimeoutIsError(t *testing.T) {
	installFakeCurl(t)
	t.Setenv("CURL_SLEEP", "5")
	if _, err := Get("https://gw.example.com/x", "k", 5, 200*time.Millisecond); err == nil {
		t.Error("expected timeout error (python TimeoutExpired)")
	}
}

func TestPostJSONDetachedDeliversBody(t *testing.T) {
	_, stdinFile := installFakeCurl(t)
	if err := PostJSONDetached("https://gw.example.com/v1/hooks/errors", "k", []byte(`{"errors": []}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(stdinFile); err == nil && string(data) == `{"errors": []}` {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("detached curl never received the body")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
