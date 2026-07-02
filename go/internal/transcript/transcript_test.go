package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

func writeFixture(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	userLine1 = `{"type": "user", "timestamp": "2026-06-12T00:00:01Z", "message": {"role": "user", "content": "first prompt"}}`
	// list-form content is kept verbatim (python appends whatever truthy value)
	userLine2 = `{"type": "user", "timestamp": "2026-06-12T00:00:05Z", "message": {"role": "user", "content": [{"type": "text", "text": "second prompt"}]}}`
	// empty content is dropped
	userEmpty = `{"type": "user", "timestamp": "2026-06-12T00:00:06Z", "message": {"role": "user", "content": ""}}`
	// assistant BEFORE the boundary timestamp
	asstEarly = `{"type": "assistant", "timestamp": "2026-06-12T00:00:02Z", "message": {"role": "assistant", "model": "model-early", "content": [{"type": "text", "text": "early reply"}], "usage": {"input_tokens": 1, "output_tokens": 1}}}`
	// assistant AFTER the boundary: two text blocks, a tool_use block, usage
	asstLate = `{"type": "assistant", "timestamp": "2026-06-12T00:00:07Z", "message": {"role": "assistant", "model": "claude-sonnet-4-5", "content": [{"type": "text", "text": "part one"}, {"type": "tool_use", "id": "t1"}, {"type": "text", "text": "part two"}], "usage": {"input_tokens": 10, "output_tokens": 20, "cache_read_input_tokens": 30, "cache_creation_input_tokens": 40}}}`
	// usage-less assistant entry — model still captured, but first model wins
	asstNoUsage = `{"type": "assistant", "timestamp": "2026-06-12T00:00:08Z", "message": {"role": "assistant", "model": "model-late", "content": [{"type": "text", "text": "tail"}]}}`
)

func TestParseFileNoBoundary(t *testing.T) {
	path := writeFixture(t, userLine1, asstEarly, userLine2, userEmpty, "", "  ", "{bad json", asstLate, asstNoUsage)
	d := ParseFile(path, "")

	if len(d.UserMessages) != 2 {
		t.Fatalf("UserMessages = %d, want 2", len(d.UserMessages))
	}
	if d.UserMessages[0].Content != "first prompt" {
		t.Errorf("user[0] = %v", d.UserMessages[0].Content)
	}
	if _, ok := d.UserMessages[1].Content.([]any); !ok {
		t.Errorf("user[1] content kept verbatim, got %T", d.UserMessages[1].Content)
	}
	if d.UserMessages[0].Timestamp != "2026-06-12T00:00:01Z" {
		t.Errorf("user[0] ts = %v", d.UserMessages[0].Timestamp)
	}

	var texts []string
	for _, m := range d.AssistantMessages {
		texts = append(texts, m.Content.(string))
	}
	want := []string{"early reply", "part one", "part two", "tail"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("assistant texts = %v, want %v", texts, want)
	}

	if d.Model != "model-early" { // first truthy model wins
		t.Errorf("Model = %v, want model-early", d.Model)
	}
	if d.Usage == nil {
		t.Fatal("Usage = nil")
	}
	if d.Usage.InputTokens != 11 || d.Usage.OutputTokens != 21 ||
		d.Usage.CacheReadInputTokens != 30 || d.Usage.CacheCreationInputTokens != 40 ||
		d.Usage.TotalTokens != 102 {
		t.Errorf("Usage = %+v", *d.Usage)
	}
	if len(d.ToolUses) != 0 {
		t.Errorf("ToolUses must stay empty (python never fills it)")
	}
}

func TestParseFileBoundaryFiltersAssistantOnly(t *testing.T) {
	path := writeFixture(t, userLine1, asstEarly, userLine2, asstLate, asstNoUsage)
	d := ParseFile(path, "2026-06-12T00:00:05Z")

	// user messages are NOT filtered (python quirk)
	if len(d.UserMessages) != 2 {
		t.Fatalf("UserMessages = %d, want 2", len(d.UserMessages))
	}
	var texts []string
	for _, m := range d.AssistantMessages {
		texts = append(texts, m.Content.(string))
	}
	want := []string{"part one", "part two", "tail"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("assistant texts = %v, want %v", texts, want)
	}
	// early entry filtered before usage/model capture
	if d.Model != "claude-sonnet-4-5" {
		t.Errorf("Model = %v", d.Model)
	}
	if d.Usage == nil || d.Usage.InputTokens != 10 || d.Usage.TotalTokens != 100 {
		t.Errorf("Usage = %+v", d.Usage)
	}
}

func TestParseFileMissingOrEmptyPath(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "nope.jsonl")} {
		d := ParseFile(path, "")
		if len(d.UserMessages) != 0 || len(d.AssistantMessages) != 0 || d.Usage != nil || d.Model != nil {
			t.Errorf("ParseFile(%q) not empty: %+v", path, d)
		}
	}
}

func TestParseFileZeroUsageStaysNil(t *testing.T) {
	path := writeFixture(t, `{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "x"}], "usage": {"input_tokens": 0, "output_tokens": 0}}}`)
	d := ParseFile(path, "")
	if d.Usage != nil { // python: any(usage.values()) is False
		t.Errorf("Usage = %+v, want nil", *d.Usage)
	}
}

func TestParseFileNonDictEntryAbortsKeepingPriorData(t *testing.T) {
	// python: entry.get on a list raises AttributeError -> blanket except
	// aborts the scan, keeping what was collected so far.
	path := writeFixture(t, userLine1, `["not", "a", "dict"]`, userLine2)
	d := ParseFile(path, "")
	if len(d.UserMessages) != 1 || d.UserMessages[0].Content != "first prompt" {
		t.Errorf("UserMessages = %+v, want only the first", d.UserMessages)
	}
}

func TestParseFileNullContentAborts(t *testing.T) {
	// python: `for item in None` raises TypeError -> abort.
	path := writeFixture(t,
		userLine1,
		`{"type": "assistant", "message": {"role": "assistant", "content": null}}`,
		userLine2)
	d := ParseFile(path, "")
	if len(d.UserMessages) != 1 {
		t.Errorf("UserMessages = %d, want 1 (scan aborted)", len(d.UserMessages))
	}
}

func TestParseFileStringContentIsNoop(t *testing.T) {
	// python iterates the chars of a string content; none are dicts.
	path := writeFixture(t,
		`{"type": "assistant", "message": {"role": "assistant", "model": "m", "content": "plain string"}}`,
		userLine1)
	d := ParseFile(path, "")
	if len(d.AssistantMessages) != 0 {
		t.Errorf("AssistantMessages = %+v", d.AssistantMessages)
	}
	if d.Model != "m" || len(d.UserMessages) != 1 {
		t.Errorf("scan must continue: Model=%v users=%d", d.Model, len(d.UserMessages))
	}
}

func TestParseFileBadUsageValueAborts(t *testing.T) {
	// python: int("garbage") raises ValueError -> abort, keeping prior sums.
	path := writeFixture(t,
		asstLate,
		`{"type": "assistant", "timestamp": "2026-06-12T00:00:09Z", "message": {"role": "assistant", "content": [], "usage": {"input_tokens": "garbage"}}}`,
		userLine1)
	d := ParseFile(path, "")
	if d.Usage == nil || d.Usage.InputTokens != 10 {
		t.Errorf("Usage = %+v, want sums from the first entry only", d.Usage)
	}
	if len(d.UserMessages) != 0 {
		t.Error("scan must have aborted before the user line")
	}
}

func TestParseFileUsageCoercion(t *testing.T) {
	// python int() semantics: "5" parses, 5.9 truncates, null/absent are 0.
	path := writeFixture(t, `{"type": "assistant", "message": {"role": "assistant", "content": [], "usage": {"input_tokens": "5", "output_tokens": 5.9, "cache_read_input_tokens": null}}}`)
	d := ParseFile(path, "")
	if d.Usage == nil || d.Usage.InputTokens != 5 || d.Usage.OutputTokens != 5 ||
		d.Usage.CacheReadInputTokens != 0 || d.Usage.TotalTokens != 10 {
		t.Errorf("Usage = %+v", d.Usage)
	}
}

func TestPyInt(t *testing.T) {
	cases := []struct {
		in   any
		want int64
		ok   bool
	}{
		{nil, 0, true},
		{false, 0, true},
		{true, 1, true},
		{"", 0, true},
		{" 7 ", 7, true},
		{"x", 0, false},
		{pyjson.Number("12"), 12, true},
		{pyjson.Number("5.9"), 5, true},
		{pyjson.Number("-5.9"), -5, true}, // int() truncates toward zero
		{pyjson.Number("0"), 0, true},
		{[]any{}, 0, true}, // falsy -> 0
		{[]any{1}, 0, false},
	}
	for _, c := range cases {
		got, ok := pyInt(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("pyInt(%#v) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
