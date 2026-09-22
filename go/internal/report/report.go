// Package report ports the python hooks' error logging + best-effort
// backend reporting. It must never fail the hook: every path swallows its
// own errors, mirroring the blanket try/except in the python originals.
//
//   - Reporter.LogError mirrors log_error (claude-code/hooks/unbound.py
//     lines 120-141): "<timestamp>: <message>\n" appended to error.log,
//     trimmed to the last 25 lines, then forwarded to the gateway.
//   - Reporter.ReportToGateway mirrors report_error_to_gateway (lines
//     92-117): rate-limited to one report per 60s via the .last_error_report
//     marker mtime (_should_report, fail-closed), reentrancy-guarded, and
//     fired as a detached curl POST to /v1/hooks/errors with payload
//     {"errors": [{"message", "timestamp", "category"}], "hook_source"}.
//     No message truncation — python sends the full string.
//
// Timestamp quirk copied as-is: claude-code and codex stamp error.log lines
// with datetime.utcnow().isoformat()+"Z" while cursor and copilot use the
// local-zone datetime.now().astimezone().isoformat() (with "+00:00"
// rewritten to "Z"); the gateway payload timestamp is always the UTC form.
// Python isoformat omits the .%06d microseconds entirely when they are
// exactly zero — UTCTimestamp/LocalTimestamp reproduce that.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/websentry-ai/setup/go/internal/httpc"
	"github.com/websentry-ai/setup/go/internal/locks"
	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// maxErrorLogLines mirrors the "keep only last 25 errors" trim.
const maxErrorLogLines = 25

// rateLimitWindow mirrors _should_report's 60-second window.
const rateLimitWindow = 60 * time.Second

// Reporter carries the per-tool error-reporting state that lives in module
// globals on the python side.
type Reporter struct {
	GatewayURL     string // already slash-stripped (config.GatewayURL)
	HookSource     string // "claude-code" | "cursor" | "codex" | "copilot"
	ErrorLog       string // per-tool error.log path
	LastReportFile string // per-tool .last_error_report marker
	APIKey         string // _cached_api_key: set once by main, used by LogError
	LocalTime      bool   // cursor/copilot stamp error.log in local time

	reporting bool             // _reporting_error reentrancy flag
	now       func() time.Time // test seam; nil means time.Now
}

func (r *Reporter) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// isoSeconds renders python datetime.isoformat()'s date-time part:
// microseconds are six digits, omitted entirely when zero.
func isoSeconds(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

// UTCTimestamp mirrors datetime.utcnow().isoformat() + "Z".
func UTCTimestamp(t time.Time) string {
	return isoSeconds(t.UTC()) + "Z"
}

// LocalTimestamp mirrors
// datetime.now().astimezone().isoformat().replace("+00:00", "Z").
func LocalTimestamp(t time.Time) string {
	local := t.Local()
	_, offset := local.Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	suffix := fmt.Sprintf("%s%02d:%02d", sign, offset/3600, offset%3600/60)
	if suffix == "+00:00" {
		suffix = "Z"
	}
	return isoSeconds(local) + suffix
}

// shouldReport rate-limits to one gateway report per window. Fails closed:
// any filesystem error means "do not report".
func (r *Reporter) shouldReport() bool {
	if fi, err := os.Stat(r.LastReportFile); err == nil {
		if r.clock().Sub(fi.ModTime()) < rateLimitWindow {
			return false
		}
	}
	if err := locks.Touch(r.LastReportFile); err != nil {
		return false
	}
	return true
}

// ReportToGateway fires a best-effort error report. Never blocks (detached
// curl), never returns an error.
func (r *Reporter) ReportToGateway(message, category, apiKey string) {
	if r.reporting || apiKey == "" || !r.shouldReport() {
		return
	}
	r.reporting = true
	defer func() { r.reporting = false }()

	entry := pyjson.NewObject().
		Set("message", message).
		Set("timestamp", UTCTimestamp(r.clock())).
		Set("category", category)
	payload, err := pyjson.Dumps(pyjson.NewObject().
		Set("errors", []any{entry}).
		Set("hook_source", r.HookSource))
	if err != nil {
		return
	}
	_ = httpc.PostJSONDetached(r.GatewayURL+"/v1/hooks/errors", apiKey, []byte(payload))
}

// LogError appends a timestamped line to error.log, trims it to the last
// 25 lines, then forwards the message to the gateway using the cached API
// key. All errors are swallowed.
func (r *Reporter) LogError(message, category string) {
	ts := UTCTimestamp(r.clock())
	if r.LocalTime {
		ts = LocalTimestamp(r.clock())
	}
	r.appendAndTrim(ts + ": " + message + "\n")
	r.ReportToGateway(message, category, r.APIKey)
}

// appendAndTrim mirrors log_error's file handling. claude-code mkdirs the
// parent first (lines 126); cursor/copilot create LOG_DIR at startup
// instead, so the mkdir is a no-op there — kept unconditional.
func (r *Reporter) appendAndTrim(entry string) {
	if err := os.MkdirAll(filepath.Dir(r.ErrorLog), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(r.ErrorLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, werr := f.WriteString(entry)
	if cerr := f.Close(); werr != nil || cerr != nil {
		return
	}

	data, err := os.ReadFile(r.ErrorLog)
	if err != nil {
		return
	}
	lines := splitKeepEnds(string(data))
	if len(lines) > maxErrorLogLines {
		trimmed := strings.Join(lines[len(lines)-maxErrorLogLines:], "")
		_ = os.WriteFile(r.ErrorLog, []byte(trimmed), 0o644)
	}
}

// splitKeepEnds mirrors python readlines(): split after each '\n', a
// trailing unterminated chunk counts as a line.
func splitKeepEnds(s string) []string {
	var lines []string
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			lines = append(lines, s)
			break
		}
		lines = append(lines, s[:i+1])
		s = s[i+1:]
	}
	return lines
}
