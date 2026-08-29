// Package hooks dispatches `unbound-hook hook <tool> [<event>]`: the tool's
// handler reads the event JSON from stdin and prints its response JSON to
// stdout, exactly as the python serving path does. The <event> argument
// exists because managed settings register one command per event; handlers
// dispatch on the stdin payload's hook_event_name, so argv is
// routing/diagnostics only.
//
// Fail-open is non-negotiable here: this process sits between the user and
// their editor. Any dispatcher-level failure prints neutral JSON and exits 0.
// Mirrors binary/src/unbound_hook/hook_cmd.py.
package hooks

import (
	"fmt"
	"io"
)

type handler func(event string, stdin io.Reader, stdout io.Writer) int

var handlers = map[string]handler{
	"claude-code": runClaudeCode,
	"cursor":      runCursor,
	"copilot":     runCopilot,
	"codex":       runCodex,
}

// Dispatch runs the tool's hook handler. Unknown/missing tool or a panic
// anywhere below never blocks the editor: neutral JSON, exit 0.
func Dispatch(tool, event string, stdin io.Reader, stdout io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(stdout, "{}")
			code = 0
		}
	}()
	h, ok := handlers[tool]
	if !ok {
		fmt.Fprintln(stdout, "{}")
		return 0
	}
	return h(event, stdin, stdout)
}

// failOpenStub is the shared phase-1 handler body: consume the event JSON,
// answer with neutral JSON, exit 0.
func failOpenStub(stdin io.Reader, stdout io.Writer) int {
	_, _ = io.Copy(io.Discard, stdin)
	fmt.Fprintln(stdout, "{}")
	return 0
}
