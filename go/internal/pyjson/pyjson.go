// Package pyjson encodes and decodes JSON byte-identically to python's
// stdlib json module with default options, as used throughout
// claude-code/hooks/unbound.py (json.dumps / json.loads): separators
// (", ", ": "), ensure_ascii=True (non-ASCII escaped as lowercase \uXXXX,
// astral planes as surrogate pairs), floats printed with python's
// repr(float) rules, and object key order preserved (python dicts are
// insertion-ordered). The parity harness compares stdout byte-for-byte
// against the python hooks, and audit-log lines are rewritten via
// json.dumps(json.loads(line)), so a standard-library json.Marshal
// (",":" separators, sorted map keys, HTML escaping) would diverge.
//
// Known gaps, deliberate: Loads rejects the non-standard NaN/Infinity
// literals python accepts (they never occur in hook inputs, which are
// themselves produced by JSON serializers), and invalid UTF-8 is replaced
// with U+FFFD where python would raise UnicodeDecodeError.
package pyjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Object is an insertion-ordered JSON object mirroring python dict
// semantics: setting an existing key updates the value in place and keeps
// the original position.
type Object struct {
	members []Member
	index   map[string]int
}

// Member is a single key/value pair of an Object.
type Member struct {
	Key   string
	Value any
}

// NewObject returns an empty ordered object.
func NewObject() *Object {
	return &Object{index: map[string]int{}}
}

// Set inserts or updates a key, preserving insertion order on update.
func (o *Object) Set(key string, value any) *Object {
	if i, ok := o.index[key]; ok {
		o.members[i].Value = value
		return o
	}
	o.index[key] = len(o.members)
	o.members = append(o.members, Member{Key: key, Value: value})
	return o
}

// Get returns the value for key and whether it was present.
func (o *Object) Get(key string) (any, bool) {
	if i, ok := o.index[key]; ok {
		return o.members[i].Value, true
	}
	return nil, false
}

// GetDefault mirrors python dict.get(key, default).
func (o *Object) GetDefault(key string, def any) any {
	if v, ok := o.Get(key); ok {
		return v
	}
	return def
}

// Len returns the number of members.
func (o *Object) Len() int { return len(o.members) }

// Members returns the key/value pairs in insertion order. The returned
// slice is the Object's backing storage; do not mutate.
func (o *Object) Members() []Member { return o.members }

// Number holds a JSON number literal verbatim. Integer literals round-trip
// unchanged (python int(str) -> repr emits the same digits, except "-0"
// which python normalizes to "0"); literals containing '.', 'e' or 'E' are
// floats in python and are re-rendered with repr(float) on encode (python
// normalizes e.g. "1e5" to "100000.0").
type Number string

// Loads decodes a single JSON document the way python json.loads does:
// objects keep key order (duplicate keys keep the first position, last
// value), numbers keep their literal text, and trailing non-whitespace
// data is an error.
func Loads(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("pyjson: trailing data after JSON document")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return decodeObject(dec)
		case '[':
			return decodeArray(dec)
		}
		return nil, fmt.Errorf("pyjson: unexpected delimiter %q", t.String())
	case string:
		return t, nil
	case json.Number:
		return Number(t.String()), nil
	case bool:
		return t, nil
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("pyjson: unexpected token %v", tok)
}

func decodeObject(dec *json.Decoder) (*Object, error) {
	obj := NewObject()
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return obj, nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("pyjson: non-string object key %v", tok)
		}
		val, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		obj.Set(key, val)
	}
}

func decodeArray(dec *json.Decoder) ([]any, error) {
	arr := []any{}
	for {
		if !dec.More() {
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return arr, nil
		}
		v, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
}

// Dumps encodes v exactly as python json.dumps(v) would. Supported values:
// nil, bool, string, Number, int, int64, float64, []any, *Object.
func Dumps(v any) (string, error) {
	var sb strings.Builder
	if err := encode(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func encode(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		encodeString(sb, t)
	case Number:
		return encodeNumber(sb, t)
	case int:
		sb.WriteString(strconv.Itoa(t))
	case int64:
		sb.WriteString(strconv.FormatInt(t, 10))
	case float64:
		sb.WriteString(FloatRepr(t))
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteString(", ")
			}
			if err := encode(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case *Object:
		sb.WriteByte('{')
		for i, m := range t.Members() {
			if i > 0 {
				sb.WriteString(", ")
			}
			encodeString(sb, m.Key)
			sb.WriteString(": ")
			if err := encode(sb, m.Value); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("pyjson: unsupported type %T", v)
	}
	return nil
}

func encodeNumber(sb *strings.Builder, n Number) error {
	s := string(n)
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return fmt.Errorf("pyjson: bad number literal %q", s)
		}
		// Out-of-range literals overflow to ±Inf in python too
		// (json.loads("1e400") -> inf -> dumps -> "Infinity").
		sb.WriteString(FloatRepr(f))
		return nil
	}
	if s == "-0" {
		s = "0" // python: int("-0") == 0
	}
	sb.WriteString(s)
	return nil
}

// DumpsIndentSorted encodes v exactly as python
// json.dumps(v, indent=2, sort_keys=True) — the discovery-cache writer's
// format (claude-code/hooks/unbound.py lines 1405, 1596): newline plus a
// two-space per-level indent after '{' / '[' and each ',', ": " after keys,
// the closing bracket at the parent's indent, object keys sorted by code
// point, and empty containers rendered inline as {} / [].
func DumpsIndentSorted(v any) (string, error) {
	var sb strings.Builder
	if err := encodeIndent(&sb, v, 0); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func encodeIndent(sb *strings.Builder, v any, level int) error {
	const indent = 2
	pad := strings.Repeat(" ", indent*(level+1))
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			sb.WriteString("[]")
			return nil
		}
		sb.WriteString("[\n")
		for i, e := range t {
			if i > 0 {
				sb.WriteString(",\n")
			}
			sb.WriteString(pad)
			if err := encodeIndent(sb, e, level+1); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + strings.Repeat(" ", indent*level) + "]")
	case *Object:
		if t.Len() == 0 {
			sb.WriteString("{}")
			return nil
		}
		members := append([]Member(nil), t.Members()...)
		sort.SliceStable(members, func(i, j int) bool { return members[i].Key < members[j].Key })
		sb.WriteString("{\n")
		for i, m := range members {
			if i > 0 {
				sb.WriteString(",\n")
			}
			sb.WriteString(pad)
			encodeString(sb, m.Key)
			sb.WriteString(": ")
			if err := encodeIndent(sb, m.Value, level+1); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + strings.Repeat(" ", indent*level) + "}")
	default:
		return encode(sb, v)
	}
	return nil
}

// python json's ESCAPE_DCT short escapes.
var shortEscapes = map[rune]string{
	'"':  `\"`,
	'\\': `\\`,
	'\b': `\b`,
	'\f': `\f`,
	'\n': `\n`,
	'\r': `\r`,
	'\t': `\t`,
}

// encodeString mirrors python json.encoder.py_encode_basestring_ascii:
// everything outside 0x20-0x7e is escaped, '/' is not.
func encodeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		if esc, ok := shortEscapes[r]; ok {
			sb.WriteString(esc)
			continue
		}
		if r >= 0x20 && r <= 0x7e {
			sb.WriteRune(r)
			continue
		}
		if r > 0xffff {
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(sb, `\u%04x\u%04x`, r1, r2)
			continue
		}
		fmt.Fprintf(sb, `\u%04x`, r)
	}
	sb.WriteByte('"')
}

// FloatRepr renders f exactly as python repr(float) / json.dumps(float):
// shortest round-trip digits, fixed notation while the decimal point
// position is in (-4, 16], otherwise scientific with a sign and at least
// two exponent digits. Non-finite values use python json's non-standard
// Infinity / -Infinity / NaN spellings.
func FloatRepr(f float64) string {
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	mant, expStr, _ := strings.Cut(s, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	decpt := exp + 1 // decimal point position relative to digits

	var body string
	switch {
	case decpt <= -4 || decpt > 16:
		body = digits[:1]
		if len(digits) > 1 {
			body += "." + digits[1:]
		}
		e := decpt - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		body += "e" + sign + fmt.Sprintf("%02d", e)
	case decpt <= 0:
		body = "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		body = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		body = digits[:decpt] + "." + digits[decpt:]
	}
	if neg {
		body = "-" + body
	}
	return body
}

// Truthy mirrors python truthiness for the value kinds Loads produces.
// Used by ports of python code that branch on `if value:`.
func Truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case Number:
		f, err := strconv.ParseFloat(string(t), 64)
		return err != nil || f != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case *Object:
		return t.Len() > 0
	}
	return true
}
