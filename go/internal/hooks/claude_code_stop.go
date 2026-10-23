package hooks

// Stop path of the claude-code port: session-event extraction from the
// audit log, transcript merge, exchange build, and the /v1/hooks/claude
// POST.

import (
	"fmt"
	"strings"
	"time"

	"github.com/websentry-ai/setup/go/internal/audit"
	"github.com/websentry-ai/setup/go/internal/httpc"
	"github.com/websentry-ai/setup/go/internal/pyjson"
	"github.com/websentry-ai/setup/go/internal/transcript"
)

// processStopEvent mirrors process_stop_event (1129-1178).
func (c *claudeCodeHook) processStopEvent(event *pyjson.Object) {
	sessionID := event.GetDefault("session_id", nil)
	transcriptPath := event.GetDefault("transcript_path", nil)
	lastAssistantMessage := event.GetDefault("last_assistant_message", nil)

	logs := audit.Load(c.auditLog)

	// A new UserPromptSubmit RESETS the list: the exchange covers the
	// latest turn only (1140-1151).
	sessionEvents := []any{}
	currentConversationStarted := false
	var userPromptTimestamp any

	for _, entry := range logs {
		log := mustObj(entry)
		logSessionID := log.GetDefault("session_id", nil)
		if !pyjson.Truthy(logSessionID) {
			logSessionID = objGet(log.GetDefault("event", pyjson.NewObject()), "session_id", nil)
		}
		if !pyEq(logSessionID, sessionID) {
			continue
		}
		var eventName any
		if v, has := log.Get("event"); has {
			eventName = objGet(v, "hook_event_name", nil)
		} else {
			eventName = log.GetDefault("hook_event_name", nil)
		}

		if en, _ := eventName.(string); en == "UserPromptSubmit" {
			sessionEvents = []any{entry}
			currentConversationStarted = true
			userPromptTimestamp = log.GetDefault("timestamp", nil)
		} else if currentConversationStarted {
			sessionEvents = append(sessionEvents, entry)
		}
	}

	transcriptAssistantMessages := []any{}
	var transcriptUsage *transcript.Usage
	var transcriptModel any
	if pyjson.Truthy(transcriptPath) {
		tp, isStr := transcriptPath.(string)
		// python `transcript_path != 'undefined'` is True for any non-str.
		if (!isStr || tp != "undefined") && pyjson.Truthy(userPromptTimestamp) {
			if !isStr {
				raise("os.path.exists on a non-str transcript_path")
			}
			ts, ok := userPromptTimestamp.(string)
			if !ok {
				// python would abort the transcript scan on the first
				// filtered assistant entry instead — accepted divergence
				// on corrupt audit timestamps.
				ts = ""
			}
			data := transcript.ParseFile(tp, ts)
			for _, m := range data.AssistantMessages {
				if pyjson.Truthy(m.Content) {
					transcriptAssistantMessages = append(transcriptAssistantMessages, m.Content)
				}
			}
			transcriptUsage = data.Usage
			transcriptModel = data.Model
		}
	}

	// Prefer the dominant model from the transcript (covers sub-agent turns
	// where the cached session model is wrong); audit log otherwise (1167).
	sessionModel := transcriptModel
	if !pyjson.Truthy(sessionModel) {
		sessionModel = extractSessionModel(logs, sessionID)
	}
	if !pyjson.Truthy(sessionModel) {
		sessionModel = "auto"
	}

	exchange := c.buildLLMExchange(sessionEvents, lastAssistantMessage, transcriptAssistantMessages, sessionModel, transcriptUsage)
	if exchange != nil {
		c.sendToAPI(exchange)
	}
}

// buildLLMExchange mirrors build_llm_exchange (989-1070). Returns nil when
// fewer than two messages were assembled — send nothing.
func (c *claudeCodeHook) buildLLMExchange(events []any, stopAssistantMessage any, transcriptAssistantMessages []any, model any, usage *transcript.Usage) *pyjson.Object {
	messages := []any{}
	assistantToolUses := []any{}

	var userPrompt, sessionID, permissionMode any

	for _, logEntry := range events {
		le := mustObj(logEntry)
		event := le
		if v, has := le.Get("event"); has {
			event = mustObj(v)
		}
		hookEventName, _ := event.GetDefault("hook_event_name", nil).(string)

		if !pyjson.Truthy(sessionID) {
			sessionID = event.GetDefault("session_id", nil)
		}
		if !pyjson.Truthy(permissionMode) {
			permissionMode = event.GetDefault("permission_mode", nil)
		}

		if hookEventName == "UserPromptSubmit" {
			if prompt := event.GetDefault("prompt", nil); pyjson.Truthy(prompt) {
				userPrompt = prompt
			}
		} else if hookEventName == "PostToolUse" {
			toolName := event.GetDefault("tool_name", nil)
			toolInput := event.GetDefault("tool_input", pyjson.NewObject())
			toolResponse := event.GetDefault("tool_response", pyjson.NewObject())

			// Dedup: drop the response content when it just echoes the
			// input content (1017-1019).
			if pyIn("content", toolResponse) && pyIn("content", toolInput) {
				if pyEq(pyIndex(toolResponse, "content"), pyIndex(toolInput, "content")) {
					tr := mustObj(toolResponse)
					copied := pyjson.NewObject()
					for _, m := range tr.Members() {
						if m.Key != "content" {
							copied.Set(m.Key, m.Value)
						}
					}
					toolResponse = copied
				}
			}

			assistantToolUses = append(assistantToolUses, pyjson.NewObject().
				Set("type", "PostToolUse").
				Set("tool_name", toolName).
				Set("tool_input", toolInput).
				Set("tool_response", toolResponse))
		}
	}

	if pyjson.Truthy(userPrompt) {
		messages = append(messages, pyjson.NewObject().Set("role", "user").Set("content", userPrompt))
	}

	allResponses := append([]any{}, transcriptAssistantMessages...)
	if pyjson.Truthy(stopAssistantMessage) {
		found := false
		for _, r := range allResponses {
			if pyEq(r, stopAssistantMessage) {
				found = true
				break
			}
		}
		if !found {
			allResponses = append(allResponses, stopAssistantMessage)
		}
	}
	assistantResponse := ""
	if len(allResponses) > 0 {
		parts := make([]string, len(allResponses))
		for i, r := range allResponses {
			s, ok := r.(string)
			if !ok {
				raise("sequence item %d: expected str instance in join", i)
			}
			parts[i] = s
		}
		assistantResponse = strings.Join(parts, "\n\n")
	}

	if assistantResponse != "" || len(assistantToolUses) > 0 {
		assistantMsg := pyjson.NewObject().
			Set("role", "assistant").
			Set("content", assistantResponse)
		if len(assistantToolUses) > 0 {
			assistantMsg.Set("tool_use", assistantToolUses)
		}
		messages = append(messages, assistantMsg)
	}

	if len(messages) < 2 {
		return nil
	}

	if !pyjson.Truthy(permissionMode) {
		permissionMode = "default"
	}

	if !pyjson.Truthy(model) {
		model = c.getSessionModel(sessionID)
		if !pyjson.Truthy(model) {
			model = "auto"
		}
	}

	conversationID := sessionID
	if !pyjson.Truthy(conversationID) {
		conversationID = "unknown"
	}
	exchange := pyjson.NewObject().
		Set("conversation_id", conversationID).
		Set("model", model).
		Set("messages", messages).
		Set("permission_mode", permissionMode).
		Set("account_identity", c.buildAccountIdentity(true))

	if usage != nil {
		exchange.Set("usage", pyjson.NewObject().
			Set("input_tokens", usage.InputTokens).
			Set("output_tokens", usage.OutputTokens).
			Set("cache_read_input_tokens", usage.CacheReadInputTokens).
			Set("cache_creation_input_tokens", usage.CacheCreationInputTokens).
			Set("total_tokens", usage.TotalTokens))
	}

	return exchange
}

// sendToAPI mirrors send_to_api (1073-1100): POST the exchange, log-only on
// any failure.
func (c *claudeCodeHook) sendToAPI(exchange *pyjson.Object) bool {
	if c.apiKey == "" {
		c.rep.LogError("No API key present in send_to_api function", "config")
		return false
	}
	data, err := pyjson.Dumps(exchange)
	if err != nil {
		c.rep.LogError(fmt.Sprintf("Exception in send_to_api: %v", err), "api_call")
		return false
	}
	res, err := httpc.PostJSON(c.gatewayURL+"/v1/hooks/claude", c.apiKey, []byte(data), 10*time.Second)
	if err != nil {
		c.rep.LogError(fmt.Sprintf("Exception in send_to_api: %v", err), "api_call")
		return false
	}
	if res.ExitCode != 0 {
		errorMsg := "Unknown error"
		if len(res.Stderr) > 0 {
			errorMsg = strings.TrimSpace(string(res.Stderr))
		}
		c.rep.LogError("API request failed: "+errorMsg, "api_call")
		return false
	}
	return true
}
