package hooks

// PreToolUse / UserPromptSubmit path of the claude-code port: policy cache,
// approval marker + polling, command extraction, MCP server config lookup,
// gateway call, and the Claude Code response transforms.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/websentry-ai/setup/go/internal/audit"
	"github.com/websentry-ai/setup/go/internal/httpc"
	"github.com/websentry-ai/setup/go/internal/pyjson"
	"github.com/websentry-ai/setup/go/internal/report"
	"github.com/websentry-ai/setup/go/internal/transcript"
)

// processPreToolUse mirrors process_pre_tool_use (834-967). DO NOT LOG.
func (c *claudeCodeHook) processPreToolUse(event *pyjson.Object) *pyjson.Object {
	sessionID := event.GetDefault("session_id", nil)
	model := event.GetDefault("model", nil)
	if !pyjson.Truthy(model) {
		model = c.getSessionModel(sessionID)
	}
	if !pyjson.Truthy(model) {
		model = "auto"
	}
	transcriptPath := event.GetDefault("transcript_path", nil)
	tn := event.GetDefault("tool_name", "")
	toolName, ok := tn.(string)
	if !ok {
		raise("tool_name %v has no attribute 'startswith'", tn)
	}

	isMCP := strings.HasPrefix(toolName, mcpToolPrefix)
	if !isMCP && !slices.Contains(ccAllowedNonMCPHookNames, toolName) {
		return pyjson.NewObject()
	}

	cache := c.loadPolicyCache()
	toolsToCheck := []any{}
	if cache != nil {
		toolsToCheck, _ = cache.GetDefault("tools_to_check", []any{}).([]any)
	}
	needPullPolicies := cache == nil || c.isCacheStale(cache)

	if ccNativeFileTools[toolName] && !pyIn(toolName, toolsToCheck) && !needPullPolicies {
		return pyjson.NewObject()
	}

	recentUserPrompts := c.getRecentUserPromptsForSession(sessionID, ccPretoolUserMessagesLimit, transcriptPath)
	command := extractCommandForPretool(event)

	// Build metadata with the raw event (861-865).
	metadata := copyObject(event)
	toolInput := event.GetDefault("tool_input", nil)
	if !pyjson.Truthy(toolInput) {
		toolInput = pyjson.NewObject()
	}
	if pyIn("file_path", toolInput) {
		metadata.Set("file_path", pyIndex(toolInput, "file_path"))
	}

	if isMCP {
		// Parse mcp__<server>__<tool> for gateway matching (867-880).
		parts := strings.SplitN(toolName[len(mcpToolPrefix):], "__", 2)
		mcpServerName := parts[0]
		metadata.Set("mcp_server", mcpServerName)
		mcpTool := ""
		if len(parts) >= 2 {
			mcpTool = parts[1]
		}
		metadata.Set("mcp_tool", mcpTool)

		if mcpServerName != "" {
			cwd := event.GetDefault("cwd", nil)
			if serverCfg := c.readMCPServerConfig(mcpServerName, cwd); serverCfg != nil {
				metadata.Set("mcp_server_config", serverCfg)
			}
		}
	}

	approvalKey := toolName + ":" + pyStr(command)
	isRetry := c.isApprovalRetry(approvalKey)

	requestBody := pyjson.NewObject().
		Set("conversation_id", sessionID).
		Set("unbound_app_label", "claude-code").
		Set("model", model).
		Set("event_name", "tool_use").
		Set("pre_tool_use_data", pyjson.NewObject().
			Set("command", command).
			Set("tool_name", toolName).
			Set("metadata", metadata)).
		Set("account_identity", c.buildAccountIdentity(false))
	// **_build_user_prompt_payload (473-478, 896).
	messages := []any{}
	if len(recentUserPrompts) > 0 {
		if last := recentUserPrompts[len(recentUserPrompts)-1]; pyjson.Truthy(last) {
			messages = []any{pyjson.NewObject().Set("role", "user").Set("content", last)}
		}
	}
	requestBody.Set("messages", messages)
	requestBody.Set("user_prompts", recentUserPrompts)

	if !isRetry {
		requestBody.Set("first_approval_check", true)
	} else if markerData := c.getApprovalMarkerData(); markerData != nil && markerData.Len() > 0 {
		policyIDs := markerData.GetDefault("policyIds", []any{})
		applicationID := markerData.GetDefault("applicationId", "")
		requestID := markerData.GetDefault("requestId", "")
		c.clearApprovalMarker()
		result := c.pollApprovalStatus(policyIDs, applicationID, requestID, approvalTimeout)

		switch result {
		case "approved":
			return transformResponseForClaude(pyjson.NewObject().Set("decision", "allow"))
		case "deny":
			return transformResponseForClaude(pyjson.NewObject().
				Set("decision", "deny").
				Set("reason", "Blocked by organization policy. This command was denied via Slack.").
				Set("additionalContext", "This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop."))
		default:
			adminContact := markerData.GetDefault("escalatedAdminContact", "")
			var timeoutReason string
			if pyjson.Truthy(adminContact) {
				timeoutReason = "Blocked by organization policy. Approval request timed out — " +
					"ask " + pyStr(adminContact) + " to check Slack and retry the command."
			} else {
				timeoutReason = "Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command."
			}
			return transformResponseForClaude(pyjson.NewObject().
				Set("decision", "deny").
				Set("reason", timeoutReason).
				Set("additionalContext", "This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry."))
		}
	}

	if needPullPolicies {
		requestBody.Set("pull_policies", true)
	}

	apiResponse := c.sendToHookAPI(requestBody)

	if apiResponse == nil {
		if c.getPolicyCheckFailureAction() == "block" {
			return transformResponseForClaude(pyjson.NewObject().
				Set("decision", "deny").
				Set("reason", ccPolicyCheckFailureBlockReason).
				Set("additionalContext", "The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry."))
		}
		c.rep.ReportToGateway(
			fmt.Sprintf("Hook bypassed_due_to_failure: gateway unreachable for tool=%s", toolName),
			"bypassed_due_to_failure", c.apiKey)
		return pyjson.NewObject()
	}

	_, hasTools := apiResponse.Get("tools_to_check")
	_, hasAction := apiResponse.Get("policy_check_failure_action")
	if hasTools || hasAction {
		c.savePolicyCache(
			apiResponse.GetDefault("tools_to_check", nil),
			apiResponse.GetDefault("policy_check_failure_action", nil))
	}

	if d, _ := apiResponse.GetDefault("decision", nil).(string); d == "approval_required" {
		return c.handleApprovalRequiredResponse(apiResponse, approvalKey)
	}

	if isMCP && pyjson.Truthy(apiResponse.GetDefault("unknown_mcp_server", nil)) {
		if serverCfg, ok := metadata.GetDefault("mcp_server_config", nil).(*pyjson.Object); ok && pyjson.Truthy(serverCfg) {
			serverName, _ := metadata.GetDefault("mcp_server", "").(string)
			c.dispatchMCPServerScan(serverName, serverCfg)
		}
	}

	return transformResponseForClaude(apiResponse)
}

// processUserPromptSubmit mirrors process_user_prompt_submit (970-986).
func (c *claudeCodeHook) processUserPromptSubmit(event *pyjson.Object) *pyjson.Object {
	sessionID := event.GetDefault("session_id", nil)
	model := event.GetDefault("model", nil)
	if !pyjson.Truthy(model) {
		model = c.getSessionModel(sessionID)
	}
	if !pyjson.Truthy(model) {
		model = "auto"
	}
	prompt := event.GetDefault("prompt", "")

	messages := []any{}
	if pyjson.Truthy(prompt) {
		messages = []any{pyjson.NewObject().Set("role", "user").Set("content", prompt)}
	}
	requestBody := pyjson.NewObject().
		Set("conversation_id", sessionID).
		Set("unbound_app_label", "claude-code").
		Set("model", model).
		Set("event_name", "user_prompt").
		Set("account_identity", c.buildAccountIdentity(false)).
		Set("messages", messages)

	return transformResponseForClaudePrompt(c.sendToHookAPI(requestBody))
}

// sendToHookAPI mirrors send_to_hook_api (514-538). nil stands in for
// python's falsy {} on every no-result path; a truthy non-dict response
// raises like the attribute access python would hit next (a str body that
// happens to contain a checked substring diverges — accepted).
func (c *claudeCodeHook) sendToHookAPI(requestBody *pyjson.Object) *pyjson.Object {
	if c.apiKey == "" {
		return nil
	}
	data, err := pyjson.Dumps(requestBody)
	if err != nil {
		c.rep.LogError(fmt.Sprintf("Hook API error: %v", err), "api_call")
		return nil
	}
	res, err := httpc.PostJSON(c.gatewayURL+"/v1/hooks/pretool", c.apiKey, []byte(data), 20*time.Second)
	if err != nil {
		c.rep.LogError(fmt.Sprintf("Hook API error: %v", err), "api_call")
		return nil
	}
	if res.ExitCode == 0 && len(res.Stdout) > 0 {
		parsed, perr := pyjson.Loads(res.Stdout)
		if perr != nil {
			c.rep.LogError(fmt.Sprintf("Hook API error: %v", perr), "api_call")
			return nil
		}
		if obj, ok := parsed.(*pyjson.Object); ok {
			if obj.Len() == 0 {
				return nil
			}
			return obj
		}
		if pyjson.Truthy(parsed) {
			raise("hook api response is not a dict")
		}
	}
	return nil
}

// transformResponseForClaude mirrors transform_response_for_claude (586-602).
func transformResponseForClaude(apiResponse *pyjson.Object) *pyjson.Object {
	if apiResponse == nil || apiResponse.Len() == 0 {
		return pyjson.NewObject()
	}
	return pyjson.NewObject().Set("hookSpecificOutput", pyjson.NewObject().
		Set("hookEventName", "PreToolUse").
		Set("permissionDecision", apiResponse.GetDefault("decision", "allow")).
		Set("permissionDecisionReason", apiResponse.GetDefault("reason", "")).
		Set("additionalContext", apiResponse.GetDefault("additionalContext", "")))
}

// transformResponseForClaudePrompt mirrors transform_response_for_claude_prompt
// (605-620): for UserPromptSubmit, 'deny' maps to 'block'.
func transformResponseForClaudePrompt(apiResponse *pyjson.Object) *pyjson.Object {
	if apiResponse == nil || apiResponse.Len() == 0 {
		return pyjson.NewObject()
	}
	if d, _ := apiResponse.GetDefault("decision", "allow").(string); d == "deny" {
		return pyjson.NewObject().
			Set("decision", "block").
			Set("reason", apiResponse.GetDefault("reason", ""))
	}
	return pyjson.NewObject()
}

// extractCommandForPretool mirrors extract_command_for_pretool (481-511).
func extractCommandForPretool(event *pyjson.Object) any {
	toolInput := event.GetDefault("tool_input", nil)
	if !pyjson.Truthy(toolInput) {
		toolInput = pyjson.NewObject()
	}
	tn := event.GetDefault("tool_name", "")
	toolName, ok := tn.(string)
	if !ok {
		raise("tool_name %v has no attribute 'startswith'", tn)
	}

	switch {
	case toolName == "Bash" && pyIn("command", toolInput):
		return pyIndex(toolInput, "command")
	case strings.HasPrefix(toolName, mcpToolPrefix):
		s, err := pyjson.Dumps(toolInput)
		if err != nil {
			raise("json dumps failed: %v", err)
		}
		return s
	case (toolName == "Write" || toolName == "Edit" || toolName == "Read") && pyIn("file_path", toolInput):
		return pyIndex(toolInput, "file_path")
	case toolName == "Grep" && pyIn("pattern", toolInput):
		return pyIndex(toolInput, "pattern")
	case toolName == "Glob" && pyIn("pattern", toolInput):
		return pyIndex(toolInput, "pattern")
	case toolName == "WebFetch" && pyIn("url", toolInput):
		return pyIndex(toolInput, "url")
	case toolName == "WebSearch" && pyIn("query", toolInput):
		return pyIndex(toolInput, "query")
	case toolName == "Task" && pyIn("prompt", toolInput):
		return pyIndex(toolInput, "prompt")
	}
	return toolName
}

// getRecentUserPromptsForSession mirrors get_recent_user_prompts_for_session
// (441-470): audit-log prompts first, transcript user messages as fallback.
func (c *claudeCodeHook) getRecentUserPromptsForSession(sessionID any, n int, transcriptPath any) []any {
	if n <= 0 {
		return []any{}
	}

	prompts := []any{}
	for _, entry := range audit.Load(c.auditLog) {
		log := mustObj(entry)
		logSession := log.GetDefault("session_id", nil)
		if !pyjson.Truthy(logSession) {
			logSession = objGet(log.GetDefault("event", pyjson.NewObject()), "session_id", nil)
		}
		if !pyEq(logSession, sessionID) {
			continue
		}
		event := mustObj(log.GetDefault("event", pyjson.NewObject()))
		if hen, _ := event.GetDefault("hook_event_name", nil).(string); hen != "UserPromptSubmit" {
			continue
		}
		if prompt := event.GetDefault("prompt", nil); pyjson.Truthy(prompt) {
			prompts = append(prompts, prompt)
		}
	}

	if len(prompts) > 0 {
		if len(prompts) > n {
			prompts = prompts[len(prompts)-n:]
		}
		return prompts
	}

	if pyjson.Truthy(transcriptPath) {
		tp, ok := transcriptPath.(string)
		if !ok {
			raise("os.path.exists on a non-str transcript_path")
		}
		if tp != "undefined" {
			if _, err := os.Stat(tp); err == nil {
				userMessages := transcript.ParseFile(tp, "").UserMessages
				if len(userMessages) > n {
					userMessages = userMessages[len(userMessages)-n:]
				}
				out := []any{}
				for _, m := range userMessages {
					if pyjson.Truthy(m.Content) {
						out = append(out, m.Content)
					}
				}
				return out
			}
		}
	}

	return []any{}
}

// --- policy cache (144-202) ---

// readPolicyCacheRaw mirrors _read_policy_cache_raw (144-153): nil on
// missing, unreadable, corrupt, or non-dict.
func (c *claudeCodeHook) readPolicyCacheRaw() *pyjson.Object {
	data, err := os.ReadFile(c.policyCache)
	if err != nil {
		return nil
	}
	parsed, perr := pyjson.Loads(data)
	if perr != nil {
		return nil
	}
	obj, _ := parsed.(*pyjson.Object)
	return obj
}

// loadPolicyCache mirrors load_policy_cache (156-163).
func (c *claudeCodeHook) loadPolicyCache() *pyjson.Object {
	cache := c.readPolicyCacheRaw()
	if cache == nil {
		return nil
	}
	if _, ok := cache.Get("last_synced"); !ok {
		return nil
	}
	ttc, ok := cache.Get("tools_to_check")
	if !ok {
		return nil
	}
	if _, ok := ttc.([]any); !ok {
		return nil
	}
	return cache
}

// getPolicyCheckFailureAction mirrors get_policy_check_failure_action
// (166-172): defaults to 'allow', ignores TTL.
func (c *claudeCodeHook) getPolicyCheckFailureAction() string {
	cache := c.readPolicyCacheRaw()
	if cache == nil {
		return "allow"
	}
	if v, _ := cache.GetDefault("policy_check_failure_action", nil).(string); v == "allow" || v == "block" {
		return v
	}
	return "allow"
}

// savePolicyCache mirrors save_policy_cache (175-192): nil for either field
// preserves the prior value; all errors are swallowed.
func (c *claudeCodeHook) savePolicyCache(toolsToCheck any, policyCheckFailureAction any) {
	if err := os.MkdirAll(filepath.Dir(c.policyCache), 0o755); err != nil {
		return
	}
	if toolsToCheck == nil {
		toolsToCheck = []any{}
		if prior := c.readPolicyCacheRaw(); prior != nil {
			toolsToCheck = prior.GetDefault("tools_to_check", []any{})
		}
	}
	action, ok := policyCheckFailureAction.(string)
	if !ok || (action != "allow" && action != "block") {
		action = c.getPolicyCheckFailureAction()
	}
	cache := pyjson.NewObject().
		Set("last_synced", report.UTCTimestamp(time.Now())).
		Set("tools_to_check", toolsToCheck).
		Set("policy_check_failure_action", action)
	s, err := pyjson.Dumps(cache)
	if err != nil {
		return
	}
	_ = os.WriteFile(c.policyCache, []byte(s), 0o644)
}

// isCacheStale mirrors is_cache_stale (195-202): parse errors mean stale; a
// non-str last_synced raises (python AttributeError is not in the except).
func (c *claudeCodeHook) isCacheStale(cache *pyjson.Object) bool {
	v, ok := cache.Get("last_synced")
	if !ok {
		return true
	}
	s, isStr := v.(string)
	if !isStr {
		raise("last_synced %v has no attribute 'rstrip'", v)
	}
	// fromisoformat parse of our own isoformat()+'Z' output. (Python 3.11+
	// accepts more ISO shapes; this layout is the only one the hook writes.)
	synced, err := time.Parse("2006-01-02T15:04:05.999999", strings.TrimRight(s, "Z"))
	if err != nil {
		return true
	}
	return time.Now().UTC().Sub(synced).Seconds() > ccCacheTTLSeconds
}

// --- approval marker + polling (241-328, 541-583) ---

func approvalCmdHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])[:16]
}

// isApprovalRetry mirrors _is_approval_retry (244-253): true iff a marker
// exists for this exact command and is fresh. A non-dict / non-numeric
// marker raises (python only catches OSError and JSONDecodeError here).
func (c *claudeCodeHook) isApprovalRetry(command string) bool {
	data, err := os.ReadFile(c.approvalMarker)
	if err != nil {
		return false
	}
	parsed, perr := pyjson.Loads(data)
	if perr != nil {
		return false
	}
	obj := mustObj(parsed)
	if !pyEq(obj.GetDefault("cmd", nil), approvalCmdHash(command)) {
		return false
	}
	ts, ok := toFloat(obj.GetDefault("ts", pyjson.Number("0")))
	if !ok {
		raise("unsupported operand type for -: approval marker ts")
	}
	return float64(time.Now().UnixNano())/1e9-ts < approvalTimeout.Seconds()
}

// setApprovalMarker mirrors _set_approval_marker (256-272). Errors raise:
// python has no try here, exceptions surface in main's blanket except.
func (c *claudeCodeHook) setApprovalMarker(command string, policyIDs, applicationID, requestID, escalatedAdminContact any) {
	if err := os.MkdirAll(filepath.Dir(c.approvalMarker), 0o755); err != nil {
		raise("approval marker mkdir failed: %v", err)
	}
	data := pyjson.NewObject().
		Set("cmd", approvalCmdHash(command)).
		Set("ts", float64(time.Now().UnixNano())/1e9).
		Set("policyIds", policyIDs).
		Set("applicationId", applicationID).
		Set("requestId", requestID).
		Set("escalatedAdminContact", escalatedAdminContact)
	s, err := pyjson.Dumps(data)
	if err != nil {
		raise("json dumps failed: %v", err)
	}
	if err := os.WriteFile(c.approvalMarker, []byte(s), 0o644); err != nil {
		raise("approval marker write failed: %v", err)
	}
}

// getApprovalMarkerData mirrors _get_approval_marker_data (275-281).
func (c *claudeCodeHook) getApprovalMarkerData() *pyjson.Object {
	data, err := os.ReadFile(c.approvalMarker)
	if err != nil {
		return nil
	}
	parsed, perr := pyjson.Loads(data)
	if perr != nil {
		return nil
	}
	// python returns whatever json gives; a non-dict raises at the caller's
	// first .get — raised here instead, same outcome.
	return mustObj(parsed)
}

func (c *claudeCodeHook) clearApprovalMarker() {
	_ = os.Remove(c.approvalMarker)
}

// handleApprovalRequiredResponse mirrors _handle_approval_required_response
// (291-328): set the marker, deny with explicit retry instructions.
func (c *claudeCodeHook) handleApprovalRequiredResponse(apiResponse *pyjson.Object, approvalKey string) *pyjson.Object {
	approvalCheck := mustObj(apiResponse.GetDefault("approvalCheck", pyjson.NewObject()))
	policyIDs := approvalCheck.GetDefault("policyIds", []any{})
	applicationID := approvalCheck.GetDefault("applicationId", "")
	requestID := approvalCheck.GetDefault("requestId", "")
	adminContact := approvalCheck.GetDefault("escalatedAdminContact", "")
	if !pyjson.Truthy(adminContact) {
		adminContact = "" // `or ''`
	}

	var reason, tellUser string
	if pyjson.Truthy(adminContact) {
		reason = "We could not find your Slack account, so an approval request was sent to " + pyStr(adminContact) + ". " +
			"Please ask them to approve it in Slack."
		tellUser = `Tell the user: "` + reason + `" `
	} else {
		reason = "An approval request has been sent to your Slack DMs. Please approve it there."
		tellUser = `Tell the user: "An approval request has been sent to your Slack DMs. ` +
			`Please approve it and I will retry automatically." `
	}

	c.setApprovalMarker(approvalKey, policyIDs, applicationID, requestID, adminContact)
	return transformResponseForClaude(pyjson.NewObject().
		Set("decision", "deny").
		Set("reason", reason).
		Set("additionalContext",
			"This is NOT a permanent block — it is a temporary hold pending Slack approval. "+
				tellUser+
				"Then immediately retry the exact same tool call with the exact same command — "+
				"do not modify the command in any way, do not add sleep or any prefix. "+
				"Retry exactly once — the second attempt will wait for the approval."))
}

// nextPollInterval mirrors _next_poll_interval (541-546).
func nextPollInterval(elapsed float64) int {
	for _, phase := range approvalPollPhases {
		if elapsed < float64(phase[0]) {
			return phase[1]
		}
	}
	return approvalPollPhases[len(approvalPollPhases)-1][1]
}

// pollApprovalStatus mirrors poll_approval_status (548-583): poll until
// approved, denied, or timeout, sleeping per the backoff phases.
func (c *claudeCodeHook) pollApprovalStatus(policyIDs, applicationID, requestID any, timeout time.Duration) string {
	url := c.gatewayURL + "/v1/hooks/pretool/approval-status"
	payload := pyjson.NewObject().
		Set("policyIds", policyIDs).
		Set("applicationId", applicationID)
	if pyjson.Truthy(requestID) {
		payload.Set("requestId", requestID)
	}
	body, err := pyjson.Dumps(payload)
	if err != nil {
		raise("json dumps failed: %v", err)
	}

	start := time.Now()
	deadline := start.Add(timeout)

	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(nextPollInterval(time.Since(start).Seconds())) * time.Second)
		res, err := httpc.PostJSON(url, c.apiKey, []byte(body), 10*time.Second)
		if err != nil {
			c.rep.LogError(fmt.Sprintf("Approval poll error: %v", err), "general")
			continue
		}
		if res.ExitCode == 0 && len(res.Stdout) > 0 {
			parsed, perr := pyjson.Loads(res.Stdout)
			if perr != nil {
				c.rep.LogError(fmt.Sprintf("Approval poll error: %v", perr), "general")
				continue
			}
			obj, ok := parsed.(*pyjson.Object)
			if !ok {
				c.rep.LogError("Approval poll error: response is not a dict", "general")
				continue
			}
			decision, _ := obj.GetDefault("decision", "pending").(string)
			if decision == "allow" {
				return "approved"
			}
			if decision == "deny" {
				return "deny"
			}
		}
	}

	return "timeout"
}

// --- MCP server config (623-671) ---

// extractMCPServerFields mirrors _extract_mcp_server_fields (623-635).
func extractMCPServerFields(server any) *pyjson.Object {
	obj, ok := server.(*pyjson.Object)
	if !ok {
		return nil
	}
	result := pyjson.NewObject()
	for _, key := range []string{"url", "command", "args", "type"} {
		if v := obj.GetDefault(key, nil); pyjson.Truthy(v) {
			result.Set(key, v)
		}
	}
	if result.Len() == 0 {
		return nil
	}
	return result
}

// readMCPServerConfig mirrors _read_mcp_server_config (638-671): project
// servers for cwd (walking up parents) first, then top-level mcpServers.
// Any failure returns nil (python's broad except).
func (c *claudeCodeHook) readMCPServerConfig(serverName string, cwd any) *pyjson.Object {
	data, err := os.ReadFile(c.claudeConfig)
	if err != nil {
		return nil
	}
	parsed, perr := pyjson.Loads(data)
	if perr != nil {
		return nil
	}
	cfg, ok := parsed.(*pyjson.Object)
	if !ok {
		return nil
	}

	if pyjson.Truthy(cwd) {
		cwdStr, isStr := cwd.(string)
		if !isStr {
			return nil // cwd.replace would have raised into the broad except
		}
		if projects, ok := cfg.GetDefault("projects", pyjson.NewObject()).(*pyjson.Object); ok {
			cwdPath := strings.TrimRight(strings.ReplaceAll(cwdStr, "\\", "/"), "/")
			for cwdPath != "" {
				if projData, ok := projects.GetDefault(cwdPath, nil).(*pyjson.Object); ok {
					if projServers, ok := projData.GetDefault("mcpServers", pyjson.NewObject()).(*pyjson.Object); ok {
						if v, has := projServers.Get(serverName); has {
							if result := extractMCPServerFields(v); result != nil {
								return result
							}
						}
					}
				}
				parent := posixDirname(cwdPath)
				if parent == cwdPath {
					break
				}
				cwdPath = parent
			}
		}
	}

	if topServers, ok := cfg.GetDefault("mcpServers", pyjson.NewObject()).(*pyjson.Object); ok {
		if v, has := topServers.Get(serverName); has {
			if result := extractMCPServerFields(v); result != nil {
				return result
			}
		}
	}

	return nil
}
