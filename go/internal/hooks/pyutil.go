package hooks

// Python-semantics helpers for the hook ports. The python originals run
// under main()'s blanket try/except; raise() panics stand in for the
// exceptions that escape a handler and are recovered at the port's main()
// equivalent, which logs and prints the neutral response like the python
// except branch does.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// pyRaise is the panic payload standing in for an uncaught python exception.
type pyRaise struct{ msg string }

func (e pyRaise) String() string { return e.msg }

func raise(format string, args ...any) {
	panic(pyRaise{fmt.Sprintf(format, args...)})
}

// mustObj mirrors dict-method access on a value assumed to be a dict: any
// other type raises (python AttributeError).
func mustObj(v any) *pyjson.Object {
	obj, ok := v.(*pyjson.Object)
	if !ok {
		raise("'%T' object has no attribute 'get'", v)
	}
	return obj
}

// objGet mirrors value.get(key, def) where value must be a dict.
func objGet(v any, key string, def any) any {
	return mustObj(v).GetDefault(key, def)
}

// pyIn mirrors `key in container` for string keys: dict key lookup,
// substring test on str, membership on list; anything else raises
// (python TypeError).
func pyIn(key string, container any) bool {
	switch t := container.(type) {
	case *pyjson.Object:
		_, ok := t.Get(key)
		return ok
	case string:
		return strings.Contains(t, key)
	case []any:
		for _, e := range t {
			if pyEq(e, key) {
				return true
			}
		}
		return false
	}
	raise("argument of type '%T' is not iterable", container)
	return false
}

// pyIndex mirrors container[key] with a string key: only dicts support it;
// a missing key raises like python KeyError.
func pyIndex(container any, key string) any {
	obj, ok := container.(*pyjson.Object)
	if !ok {
		raise("'%T' object is not subscriptable with a str", container)
	}
	v, has := obj.Get(key)
	if !has {
		raise("KeyError: %s", key)
	}
	return v
}

// pyStr approximates python str() for f-string interpolation. Hook inputs
// make these strings in practice; non-strings fall back to their JSON form
// (python would render repr-style — accepted divergence).
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case string:
		return t
	case pyjson.Number:
		return string(t)
	}
	if s, err := pyjson.Dumps(v); err == nil {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// pyEq mirrors python ==: deep equality with cross-type numeric equality
// (True == 1, 1 == 1.0) and order-insensitive dict comparison.
func pyEq(a, b any) bool {
	an, aNum := numVal(a)
	bn, bNum := numVal(b)
	if aNum || bNum {
		return aNum && bNum && numEq(an, bn)
	}
	switch ta := a.(type) {
	case nil:
		return b == nil
	case string:
		tb, ok := b.(string)
		return ok && ta == tb
	case []any:
		tb, ok := b.([]any)
		if !ok || len(ta) != len(tb) {
			return false
		}
		for i := range ta {
			if !pyEq(ta[i], tb[i]) {
				return false
			}
		}
		return true
	case *pyjson.Object:
		tb, ok := b.(*pyjson.Object)
		if !ok || ta.Len() != tb.Len() {
			return false
		}
		for _, m := range ta.Members() {
			bv, has := tb.Get(m.Key)
			if !has || !pyEq(m.Value, bv) {
				return false
			}
		}
		return true
	}
	return false
}

type pyNum struct {
	f     float64
	i     int64
	isInt bool
}

func numVal(v any) (pyNum, bool) {
	switch t := v.(type) {
	case bool:
		if t {
			return pyNum{1, 1, true}, true
		}
		return pyNum{0, 0, true}, true
	case int:
		return pyNum{float64(t), int64(t), true}, true
	case int64:
		return pyNum{float64(t), t, true}, true
	case float64:
		return pyNum{t, 0, false}, true
	case pyjson.Number:
		s := string(t)
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return pyNum{float64(i), i, true}, true
			}
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return pyNum{}, false
		}
		return pyNum{f, 0, false}, true
	}
	return pyNum{}, false
}

func numEq(a, b pyNum) bool {
	if a.isInt && b.isInt {
		return a.i == b.i
	}
	return a.f == b.f
}

// toFloat mirrors python float coercion in arithmetic (time.time() - ts):
// non-numeric operands make the caller raise.
func toFloat(v any) (float64, bool) {
	n, ok := numVal(v)
	if !ok {
		return 0, false
	}
	return n.f, ok
}

// copyObject mirrors dict(d): a shallow copy preserving insertion order.
func copyObject(o *pyjson.Object) *pyjson.Object {
	out := pyjson.NewObject()
	for _, m := range o.Members() {
		out.Set(m.Key, m.Value)
	}
	return out
}

// posixDirname mirrors posixpath.dirname for the project-path walk in
// _read_mcp_server_config (claude-code/hooks/unbound.py line 658).
func posixDirname(p string) string {
	i := strings.LastIndexByte(p, '/') + 1
	head := p[:i]
	if head != "" && head != strings.Repeat("/", len(head)) {
		head = strings.TrimRight(head, "/")
	}
	return head
}
