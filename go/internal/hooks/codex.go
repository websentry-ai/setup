package hooks

import "io"

// TODO: port codex/hooks/unbound.py — fail-open stub until then.
func runCodex(event string, stdin io.Reader, stdout io.Writer) int {
	return failOpenStub(stdin, stdout)
}
