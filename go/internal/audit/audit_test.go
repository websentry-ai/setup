package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// sessionKey mirrors claude-code cleanup_old_logs: top-level session_id.
func sessionKey(entry any) string {
	obj, ok := entry.(*pyjson.Object)
	if !ok {
		return ""
	}
	if s, ok := obj.GetDefault("session_id", nil).(string); ok {
		return s
	}
	return ""
}

func entryLine(session string, n int) string {
	return fmt.Sprintf(`{"timestamp": "2026-06-12T00:00:%02dZ", "session_id": "%s", "event": {"hook_event_name": "PostToolUse", "n": %d}}`, n%60, session, n)
}

func writeLog(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSkipsBlankAndCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	writeLog(t, path, []string{
		entryLine("s1", 0),
		"",
		"   ",
		"{not json",
		entryLine("s1", 1),
	})
	logs := Load(path)
	if len(logs) != 2 {
		t.Fatalf("got %d entries, want 2", len(logs))
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	if logs := Load(filepath.Join(t.TempDir(), "nope")); len(logs) != 0 {
		t.Errorf("got %d entries", len(logs))
	}
}

func TestAppendThenLoadRoundTripsBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	line := entryLine("s1", 0)
	entry, err := pyjson.Loads([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	Append(path, entry)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != line+"\n" {
		t.Errorf("file = %q, want %q", got, line+"\n")
	}
}

func TestAppendCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "hooks", "agent-audit.log")
	Append(path, pyjson.NewObject().Set("k", "v"))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log not created: %v", err)
	}
}

func TestSaveRewritesPythonFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	// compact input must come back python-formatted, like json.dumps(json.loads(line))
	entry, err := pyjson.Loads([]byte(`{"session_id":"s1","event":{"a":1,"b":[1,2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	Save(path, []any{entry})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"session_id": "s1", "event": {"a": 1, "b": [1, 2]}}` + "\n"
	if string(data) != want {
		t.Errorf("file = %q, want %q", string(data), want)
	}
}

func TestCleanupUnderLimitUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	lines := []string{entryLine("s1", 0), entryLine("s2", 1)}
	writeLog(t, path, lines)
	before, _ := os.ReadFile(path)
	Cleanup(path, 100, sessionKey)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("under-limit log must not be rewritten")
	}
}

func TestCleanupMultiSessionKeepsOnlyMostRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	var lines []string
	for i := 0; i < 60; i++ {
		lines = append(lines, entryLine("old-session", i))
	}
	for i := 0; i < 50; i++ {
		lines = append(lines, entryLine("new-session", i))
	}
	writeLog(t, path, lines)
	Cleanup(path, 100, sessionKey)
	logs := Load(path)
	if len(logs) != 50 {
		t.Fatalf("got %d entries, want 50", len(logs))
	}
	for _, e := range logs {
		if sessionKey(e) != "new-session" {
			t.Fatalf("kept entry from %q", sessionKey(e))
		}
	}
}

func TestCleanupSingleSessionTrimsToLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	var lines []string
	for i := 0; i < 130; i++ {
		lines = append(lines, entryLine("only-session", i))
	}
	writeLog(t, path, lines)
	Cleanup(path, 100, sessionKey)
	logs := Load(path)
	if len(logs) != 100 {
		t.Fatalf("got %d entries, want 100", len(logs))
	}
	// must keep the NEWEST 100
	first, _ := logs[0].(*pyjson.Object)
	ev, _ := first.GetDefault("event", nil).(*pyjson.Object)
	if n, _ := ev.Get("n"); n != pyjson.Number("30") {
		t.Errorf("first kept entry n = %v, want 30", n)
	}
}

func TestCleanupDropsKeylessEntriesWhenMultiSession(t *testing.T) {
	// python: logs without session_id are dropped by the kept_logs filter
	path := filepath.Join(t.TempDir(), "agent-audit.log")
	var lines []string
	for i := 0; i < 60; i++ {
		lines = append(lines, entryLine("a", i))
	}
	lines = append(lines, `{"event": {"hook_event_name": "Stop"}}`)
	for i := 0; i < 50; i++ {
		lines = append(lines, entryLine("b", i))
	}
	writeLog(t, path, lines)
	Cleanup(path, 100, sessionKey)
	for _, e := range Load(path) {
		if sessionKey(e) != "b" {
			t.Fatalf("kept non-b entry: %v", e)
		}
	}
}
