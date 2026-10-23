package hooks

import "io"

// TODO: port cursor/unbound.py — fail-open stub until then. Note: the real
// module exits 2 on deny; that contract exit must be preserved in the port.
func runCursor(event string, stdin io.Reader, stdout io.Writer) int {
	return failOpenStub(stdin, stdout)
}
