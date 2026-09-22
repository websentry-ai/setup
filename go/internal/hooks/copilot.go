package hooks

import "io"

// TODO: port copilot/hooks/unbound.py — fail-open stub until then.
func runCopilot(event string, stdin io.Reader, stdout io.Writer) int {
	return failOpenStub(stdin, stdout)
}
