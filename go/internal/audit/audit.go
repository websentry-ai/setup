// Package audit ports the per-tool agent-audit.log JSONL handling:
// load_existing_logs / save_logs / append_to_audit_log
// (claude-code/hooks/unbound.py lines 205-238) and cleanup_old_logs
// (lines 1103-1126; cursor/unbound.py keys on event.conversation_id
// instead of the top-level session_id, so the grouping key is a caller
// parameter here).
//
// Entries are decoded pyjson values so that Save re-renders each line
// byte-identically to python's json.dumps(json.loads(line)). Paths are
// per tool and owned by callers (~/.claude/hooks/agent-audit.log,
// ~/.cursor/hooks/..., ~/.codex/hooks/..., ~/.copilot/hooks/...). There is
// no size-based rotation — only the session-scoped cleanup; files are
// created with the process umask like python's open().
//
// Quirk copied as-is: a non-object JSONL line loads fine in python and
// only blows up later (AttributeError in cleanup, caught by main's blanket
// handler). Here Cleanup's key func decides what such entries map to.
package audit

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// Load reads every parseable JSONL entry. Blank and undecodable lines are
// skipped; an unreadable file yields whatever was collected (python
// swallows the exception and returns the partial list).
func Load(path string) []any {
	logs := []any{}
	f, err := os.Open(path)
	if err != nil {
		return logs
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			if entry, perr := pyjson.Loads(trimmed); perr == nil {
				logs = append(logs, entry)
			}
		}
		if err != nil {
			return logs
		}
	}
}

// Save rewrites the file with one python-format JSON line per entry.
// Errors are swallowed; an entry that fails to encode aborts the rest,
// leaving a partial file exactly like a mid-write python exception would.
func Save(path string, logs []any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	for _, entry := range logs {
		line, err := pyjson.Dumps(entry)
		if err != nil {
			return
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			return
		}
	}
}

// Append adds one entry to the log. Errors are swallowed.
func Append(path string, entry any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	line, err := pyjson.Dumps(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line + "\n")
}

// Cleanup trims the log once it exceeds limit entries. key extracts each
// entry's grouping id ("" for none): with more than one distinct id, only
// the most recently first-seen id's entries survive (entries with other or
// missing ids are dropped, including the size headroom — python keeps the
// whole last session however large); with at most one, the newest `limit`
// entries survive.
func Cleanup(path string, limit int, key func(entry any) string) {
	logs := Load(path)
	if len(logs) <= limit {
		return
	}

	var order []string
	seen := map[string]bool{}
	for _, entry := range logs {
		if id := key(entry); id != "" && !seen[id] {
			order = append(order, id)
			seen[id] = true
		}
	}

	if len(order) > 1 {
		latest := order[len(order)-1]
		kept := []any{}
		for _, entry := range logs {
			if key(entry) == latest {
				kept = append(kept, entry)
			}
		}
		Save(path, kept)
	} else if len(logs) > limit {
		Save(path, logs[len(logs)-limit:])
	}
}
