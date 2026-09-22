package hooks

import (
	"testing"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

func TestPosixDirname(t *testing.T) {
	cases := map[string]string{
		"/a/b/c": "/a/b",
		"/a/b":   "/a",
		"/a":     "/",
		"/":      "/",
		"a/b":    "a",
		"a":      "",
		"":       "",
		"//a":    "//",
	}
	for in, want := range cases {
		if got := posixDirname(in); got != want {
			t.Errorf("posixDirname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPyEq(t *testing.T) {
	cases := []struct {
		a, b any
		want bool
	}{
		{pyjson.Number("1"), pyjson.Number("1.0"), true}, // python 1 == 1.0
		{true, pyjson.Number("1"), true},                 // python True == 1
		{false, pyjson.Number("0"), true},
		{pyjson.Number("1"), "1", false},
		{"x", "x", true},
		{nil, nil, true},
		{nil, "", false},
		{[]any{pyjson.Number("1"), "a"}, []any{pyjson.Number("1"), "a"}, true},
		{[]any{}, []any{}, true},
		{
			pyjson.NewObject().Set("a", pyjson.Number("1")).Set("b", "x"),
			pyjson.NewObject().Set("b", "x").Set("a", pyjson.Number("1.0")),
			true, // dict equality is order-insensitive
		},
		{
			pyjson.NewObject().Set("a", pyjson.Number("1")),
			pyjson.NewObject().Set("a", pyjson.Number("2")),
			false,
		},
	}
	for _, c := range cases {
		if got := pyEq(c.a, c.b); got != c.want {
			t.Errorf("pyEq(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestPyIn(t *testing.T) {
	if !pyIn("comm", "this command") { // python: substring test on str
		t.Error("substring containment failed")
	}
	if pyIn("xyz", "this command") {
		t.Error("false substring matched")
	}
	if !pyIn("a", []any{"b", "a"}) {
		t.Error("list membership failed")
	}
	if !pyIn("k", pyjson.NewObject().Set("k", nil)) {
		t.Error("dict key with None value must count as present")
	}
}

func TestNextPollInterval(t *testing.T) {
	cases := map[float64]int{0: 3, 299: 3, 300: 15, 1799: 15, 1800: 60, 7199: 60, 7200: 120, 99999: 120}
	for elapsed, want := range cases {
		if got := nextPollInterval(elapsed); got != want {
			t.Errorf("nextPollInterval(%v) = %d, want %d", elapsed, got, want)
		}
	}
}
