package pyjson

import (
	"math"
	"testing"
)

// bs is a literal backslash for building \u goldens (kept out of string
// literals so tooling cannot normalize the escapes).
const bs = "\x5c"

// Golden values produced by python3 json.dumps / repr. Any change here must
// be re-verified against python.
func TestFloatReprMatchesPython(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{1e15, "1000000000000000.0"},
		{1e16, "1e+16"},
		{1e17, "1e+17"},
		{123456789012345.0, "123456789012345.0"},
		{1234567890123456.0, "1234567890123456.0"},
		{0.0001, "0.0001"},
		{1e-5, "1e-05"},
		{1.5, "1.5"},
		{0.0, "0.0"},
		{math.Copysign(0, -1), "-0.0"},
		{3.14, "3.14"},
		{1e100, "1e+100"},
		{5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"},
		{2.5e-10, "2.5e-10"},
		{100000.0, "100000.0"},
		{1e21, "1e+21"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
		{math.NaN(), "NaN"},
	}
	for _, c := range cases {
		if got := FloatRepr(c.in); got != c.want {
			t.Errorf("FloatRepr(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDumpsMatchesPython(t *testing.T) {
	obj := NewObject().
		Set("a", 1).
		Set("b", "héllo ☃").
		Set("c", []any{true, nil, math.Copysign(0, -1)})
	got, err := Dumps(obj)
	if err != nil {
		t.Fatal(err)
	}
	// python: json.dumps({'a': 1, 'b': 'h\xe9llo ☃', 'c': [True, None, -0.0]})
	want := `{"a": 1, "b": "h` + bs + `u00e9llo ` + bs + `u2603", "c": [true, null, -0.0]}`
	if got != want {
		t.Errorf("Dumps = %q, want %q", got, want)
	}
}

func TestDumpsStringEscaping(t *testing.T) {
	got, err := Dumps("a\x7f\x01\"\\/\n")
	if err != nil {
		t.Fatal(err)
	}
	// python golden: '/' not escaped, DEL and control chars \u-escaped
	want := `"a` + bs + `u007f` + bs + `u0001\"\\/\n"`
	if got != want {
		t.Errorf("Dumps = %q, want %q", got, want)
	}
}
func TestDumpsSurrogatePairs(t *testing.T) {
	got, err := Dumps("\U0001F600\u2028")
	if err != nil {
		t.Fatal(err)
	}
	// python golden: astral plane as a surrogate pair, U+2028 escaped too
	want := `"` + bs + `ud83d` + bs + `ude00` + bs + `u2028"`
	if got != want {
		t.Errorf("Dumps = %q, want %q", got, want)
	}
}

func TestNumberLiterals(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1E2", "100.0"}, // python float normalization
		{"-0", "0"},      // python int("-0") == 0
		{"5.00", "5.0"},
		{"123456789012345678901234567890", "123456789012345678901234567890"}, // big int verbatim
		{"1e5", "100000.0"},
		{"1e400", "Infinity"}, // overflow like python json.loads
	}
	for _, c := range cases {
		got, err := Dumps(Number(c.in))
		if err != nil {
			t.Fatalf("Dumps(Number(%q)): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Dumps(Number(%q)) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadsDumpsRoundTrip(t *testing.T) {
	// A claude-code audit-log style line: order must be preserved.
	in := `{"timestamp": "2026-06-12T01:02:03Z", "session_id": "s1", "event": {"hook_event_name": "Stop", "n": 5, "f": 1.5, "deep": [1, {"k": null}]}}`
	v, err := Loads([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Dumps(v)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip changed bytes:\n in: %s\nout: %s", in, out)
	}
}

func TestLoadsCompactInputNormalized(t *testing.T) {
	// python json.dumps(json.loads(s)) normalizes whitespace.
	v, err := Loads([]byte(`{"a":1,"b":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Dumps(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a": 1, "b": [1, 2]}`; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestLoadsDuplicateKeysLastValueFirstPosition(t *testing.T) {
	v, err := Loads([]byte(`{"a": 1, "b": 2, "a": 3}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Dumps(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a": 3, "b": 2}`; out != want { // python dict semantics
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestLoadsRejectsTrailingData(t *testing.T) {
	if _, err := Loads([]byte(`{} {}`)); err == nil {
		t.Error("expected error for trailing data")
	}
	if _, err := Loads([]byte(`{"a": 1}` + "\n  ")); err != nil {
		t.Errorf("trailing whitespace should be fine: %v", err)
	}
}

func TestObjectSetUpdatesInPlace(t *testing.T) {
	o := NewObject().Set("x", 1).Set("y", 2).Set("x", 3)
	out, err := Dumps(o)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"x": 3, "y": 2}`; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
	if v, ok := o.Get("x"); !ok || v != 3 {
		t.Errorf("Get(x) = %v, %v", v, ok)
	}
}

func TestTruthy(t *testing.T) {
	truthy := []any{true, "x", Number("1"), Number("0.5"), []any{nil}, NewObject().Set("k", nil), 1, int64(2), 0.1}
	falsy := []any{nil, false, "", Number("0"), Number("0.0"), Number("-0"), []any{}, NewObject(), 0, int64(0), 0.0}
	for _, v := range truthy {
		if !Truthy(v) {
			t.Errorf("Truthy(%#v) = false, want true", v)
		}
	}
	for _, v := range falsy {
		if Truthy(v) {
			t.Errorf("Truthy(%#v) = true, want false", v)
		}
	}
}

func TestDumpsEmptyContainers(t *testing.T) {
	for in, want := range map[string]string{`{}`: `{}`, `[]`: `[]`, `[[]]`: `[[]]`} {
		v, err := Loads([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		out, err := Dumps(v)
		if err != nil {
			t.Fatal(err)
		}
		if out != want {
			t.Errorf("Dumps(Loads(%q)) = %q, want %q", in, out, want)
		}
	}
}

func TestDumpsIndentSortedMatchesPython(t *testing.T) {
	// python: json.dumps(v, indent=2, sort_keys=True) goldens.
	obj := NewObject().
		Set("b", []any{1, 2.5, "x"}).
		Set("a", NewObject().
			Set("nested", NewObject().Set("z", nil).Set("y", true)).
			Set("empty", NewObject()).
			Set("list", []any{})).
		Set("c", "ué")
	got, err := DumpsIndentSorted(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": {\n    \"empty\": {},\n    \"list\": [],\n    \"nested\": {\n      \"y\": true,\n      \"z\": null\n    }\n  },\n  \"b\": [\n    1,\n    2.5,\n    \"x\"\n  ],\n  \"c\": \"u" + bs + "u00e9\"\n}"
	if got != want {
		t.Errorf("DumpsIndentSorted = %q, want %q", got, want)
	}

	if got, _ := DumpsIndentSorted(NewObject()); got != "{}" {
		t.Errorf("empty object = %q, want {}", got)
	}
	if got, _ := DumpsIndentSorted([]any{1, []any{2}}); got != "[\n  1,\n  [\n    2\n  ]\n]" {
		t.Errorf("nested list = %q", got)
	}
}
