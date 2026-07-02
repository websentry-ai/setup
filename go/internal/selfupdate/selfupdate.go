// Package selfupdate will hold the Go binary's self-update, the
// binary-swap variant of _check_self_update and its helpers
// (claude-code/hooks/unbound.py lines 1283-1344: the 2h throttle via the
// .self_update_check mtime, the 30s .self_update.lock, the curl download,
// and the same-directory tempfile + rename swap; cursor/codex/copilot carry
// per-tool copies of the same flow).
//
// Until that lands, Check is a deliberate no-op — and a faithful one: the
// python frozen-binary gate (lines 1284-1286) skips self-update entirely
// because packaged deployments are updated by the MDM package, never in
// place, and the managed-location gate (lines 1292-1301) skips whenever the
// running file is not the user-level ~/.claude/hooks/unbound.py script,
// which is never true for this binary. No state files are written and no
// network calls are made.
package selfupdate

// Check is the SessionStart self-update entry point (unbound.py line 1631).
// No-op for now; see the package comment.
func Check() {}
