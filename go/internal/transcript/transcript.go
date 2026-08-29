// Package transcript ports the claude-code Stop-path transcript reader:
// parse_transcript_file (claude-code/hooks/unbound.py lines 367-438), the
// JSONL primitive process_stop_event and get_recent_user_prompts_for_session
// build on. It walks the ~/.claude/projects session transcript line by
// line, collecting user messages, this turn's assistant text, the turn
// model, and summed token usage.
//
// Python quirks copied as-is:
//
//   - The userPromptTimestamp exchange-boundary filter (string-compare
//     entry.timestamp <= boundary) applies ONLY to assistant entries; user
//     messages are collected from the whole file.
//   - The first truthy assistant model wins ("turn_model = turn_model or
//     message.get('model')"), captured even on usage-less entries.
//   - Undecodable lines are skipped (except json.JSONDecodeError), but any
//     other "exception" — a non-object entry, a non-dict message, a null /
//     numeric content, a non-dict usage, an uncoercible usage value, a
//     non-string timestamp on a filtered assistant entry — aborts the scan
//     (python's blanket `except Exception: pass`), keeping whatever was
//     accumulated.
//   - Usage is reported only when some counter is non-zero
//     (any(usage.values())); total_tokens is the sum of the four counters.
//   - ToolUses exists in the python result shape but is never populated;
//     kept for parity.
//
// Divergences from python, accepted: invalid UTF-8 becomes U+FFFD instead
// of aborting (python text mode raises UnicodeDecodeError), and usage
// values beyond int64 fail the int coercion (python ints are unbounded).
package transcript

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// Message is one collected transcript message. Content and Timestamp hold
// the raw pyjson values (content may be a string or a content-block list;
// timestamp may be absent = nil), exactly what python stores.
type Message struct {
	Content   any
	Timestamp any
}

// Usage is the summed token usage across the scanned assistant entries.
type Usage struct {
	InputTokens              int64
	OutputTokens             int64
	CacheReadInputTokens     int64
	CacheCreationInputTokens int64
	TotalTokens              int64
}

// Data mirrors parse_transcript_file's conversation_data dict.
type Data struct {
	UserMessages      []Message
	AssistantMessages []Message
	ToolUses          []any // never populated, like python
	Usage             *Usage
	Model             any // raw model value; nil when none seen
}

var usageKeys = [4]string{
	"input_tokens", "output_tokens",
	"cache_read_input_tokens", "cache_creation_input_tokens",
}

// ParseFile reads a transcript JSONL file. userPromptTimestamp == "" means
// no boundary filter (python's None). Missing/empty path or an unreadable
// file returns empty Data; nothing here ever fails the hook.
func ParseFile(path, userPromptTimestamp string) Data {
	data := Data{
		UserMessages:      []Message{},
		AssistantMessages: []Message{},
		ToolUses:          []any{},
	}
	if path == "" {
		return data
	}
	f, err := os.Open(path)
	if err != nil {
		return data
	}
	defer f.Close()

	var counts [4]int64
	var turnModel any

	r := bufio.NewReader(f)
scan:
	for {
		line, readErr := r.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			abort := scanEntry(trimmed, userPromptTimestamp, &data, &counts, &turnModel)
			if abort {
				break scan
			}
		}
		if readErr != nil {
			break scan
		}
	}

	if counts[0] != 0 || counts[1] != 0 || counts[2] != 0 || counts[3] != 0 {
		data.Usage = &Usage{
			InputTokens:              counts[0],
			OutputTokens:             counts[1],
			CacheReadInputTokens:     counts[2],
			CacheCreationInputTokens: counts[3],
			TotalTokens:              counts[0] + counts[1] + counts[2] + counts[3],
		}
	}
	if pyjson.Truthy(turnModel) {
		data.Model = turnModel
	}
	return data
}

// scanEntry processes one JSONL line. Returns true where python would have
// raised out of the per-line code into the file-level `except Exception`.
func scanEntry(line []byte, userPromptTimestamp string, data *Data, counts *[4]int64, turnModel *any) bool {
	entry, err := pyjson.Loads(line)
	if err != nil {
		return false // json.JSONDecodeError: continue
	}
	obj, ok := entry.(*pyjson.Object)
	if !ok {
		return true // entry.get on a non-dict: AttributeError
	}
	entryType, _ := obj.GetDefault("type", "").(string)
	entryTimestamp, _ := obj.Get("timestamp")

	switch entryType {
	case "user":
		msg, ok := obj.GetDefault("message", pyjson.NewObject()).(*pyjson.Object)
		if !ok {
			return true // message.get on a non-dict
		}
		if role, _ := msg.GetDefault("role", nil).(string); role == "user" {
			content := msg.GetDefault("content", "")
			if pyjson.Truthy(content) {
				data.UserMessages = append(data.UserMessages, Message{content, entryTimestamp})
			}
		}

	case "assistant":
		if userPromptTimestamp != "" && pyjson.Truthy(entryTimestamp) {
			ts, ok := entryTimestamp.(string)
			if !ok {
				return true // str <= non-str: TypeError
			}
			if ts <= userPromptTimestamp {
				return false
			}
		}
		msg, ok := obj.GetDefault("message", pyjson.NewObject()).(*pyjson.Object)
		if !ok {
			return true
		}
		if role, _ := msg.GetDefault("role", nil).(string); role != "assistant" {
			return false
		}

		switch content := msg.GetDefault("content", []any{}).(type) {
		case []any:
			for _, item := range content {
				io, ok := item.(*pyjson.Object)
				if !ok {
					continue // isinstance(content_item, dict) check
				}
				if t, _ := io.GetDefault("type", nil).(string); t != "text" {
					continue
				}
				text := io.GetDefault("text", "")
				if pyjson.Truthy(text) {
					data.AssistantMessages = append(data.AssistantMessages, Message{text, entryTimestamp})
				}
			}
		case string, *pyjson.Object:
			// python iterates chars / keys — strings are never dicts, so no-op
		default:
			return true // `for ... in None/number/bool`: TypeError
		}

		if !pyjson.Truthy(*turnModel) {
			*turnModel = msg.GetDefault("model", nil)
		}

		usageVal := msg.GetDefault("usage", nil)
		if pyjson.Truthy(usageVal) { // `message.get('usage') or {}` then `if msg_usage:`
			uo, ok := usageVal.(*pyjson.Object)
			if !ok {
				return true // msg_usage.get on a non-dict
			}
			for i, key := range usageKeys {
				n, ok := pyInt(uo.GetDefault(key, nil))
				if !ok {
					return true // int() raised
				}
				counts[i] += n
			}
		}
	}
	return false
}

// pyInt mirrors `int(value or 0)`: falsy values are 0; numbers truncate
// toward zero; numeric strings parse base-10 after strip. ok=false where
// python int() would raise (and the scan must abort).
func pyInt(v any) (int64, bool) {
	if !pyjson.Truthy(v) {
		return 0, true
	}
	switch t := v.(type) {
	case bool:
		return 1, true // only reachable for true; false is falsy
	case pyjson.Number:
		s := string(t)
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return 0, false
			}
			return int64(math.Trunc(f)), true
		}
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(math.Trunc(t)), true
	}
	return 0, false // TypeError: dict/list
}
