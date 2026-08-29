package hooks

// claude-code hook handler: a behavioral port of
// claude-code/hooks/unbound.py — the golden reference; doc comments cite
// its line numbers and quirks are copied verbatim. This binary is the
// packaged ("frozen") variant: self-update is the internal/selfupdate
// no-op and discovery always runs the locally installed binary, never the
// install.sh download path (unbound.py lines 60-66).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/websentry-ai/setup/go/internal/audit"
	"github.com/websentry-ai/setup/go/internal/config"
	"github.com/websentry-ai/setup/go/internal/pyjson"
	"github.com/websentry-ai/setup/go/internal/report"
	"github.com/websentry-ai/setup/go/internal/selfupdate"
)

// Module constants (unbound.py lines 17-73).
const (
	mcpToolPrefix                   = "mcp__"
	ccCacheTTLSeconds               = 300
	ccPolicyCheckFailureBlockReason = "policy engine unavailable — please retry"
	ccPretoolUserMessagesLimit      = 5
	ccAuditLogTotalLimit            = 100

	approvalTimeout = 4 * time.Hour

	discoveryDebounce     = 24 * time.Hour
	discoveryHookFlagTTL  = 24 * time.Hour
	discoveryHookFlagPath = "/v1/hooks/discovery-enabled"
	discoveryStaleLock    = 15 * time.Minute
	discoveryDispatchTTL  = 10 * time.Second
)

// ALLOWED_NON_MCP_HOOK_NAMES / NATIVE_FILE_TOOLS (lines 23-24): MCP tools
// (mcp__*) are always checked separately.
var (
	ccAllowedNonMCPHookNames = []string{"Bash", "Read", "Write", "Edit"}
	ccNativeFileTools        = map[string]bool{"Read": true, "Write": true, "Edit": true}
)

// approvalPollPhases mirrors APPROVAL_POLL_PHASES (lines 68-73):
// (elapsed-below, interval) pairs in seconds.
var approvalPollPhases = [4][2]int{
	{5 * 60, 3},
	{30 * 60, 15},
	{2 * 60 * 60, 60},
	{4 * 60 * 60, 120},
}

// claudeCodeHook carries per-process state held in module globals on the
// python side, plus the home-derived paths (lines 20-58).
type claudeCodeHook struct {
	gatewayURL string
	apiKey     string
	rep        *report.Reporter

	auditLog       string // ~/.claude/hooks/agent-audit.log
	policyCache    string // ~/.claude/hooks/.policy_cache.json
	approvalMarker string // ~/.claude/hooks/.approval_pending
	claudeConfig   string // ~/.claude.json
	unboundConfig  string // ~/.unbound/config.json
	identityCache  string // ~/.unbound/identity.json
	discoveryCache string // ~/.unbound/discovery-cache.json
	discoveryLock  string // ~/.unbound/discovery.lock
	dispatchLock   string // ~/.unbound/discovery.dispatch.lock
}

func newClaudeCodeHook() (*claudeCodeHook, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	hooksDir := filepath.Join(home, ".claude", "hooks")
	unboundDir := filepath.Join(home, ".unbound")
	gw := config.GatewayURL()
	return &claudeCodeHook{
		gatewayURL: gw,
		rep: &report.Reporter{
			GatewayURL:     gw,
			HookSource:     "claude-code",
			ErrorLog:       filepath.Join(hooksDir, "error.log"),
			LastReportFile: filepath.Join(hooksDir, ".last_error_report"),
		},
		auditLog:       filepath.Join(hooksDir, "agent-audit.log"),
		policyCache:    filepath.Join(hooksDir, ".policy_cache.json"),
		approvalMarker: filepath.Join(hooksDir, ".approval_pending"),
		claudeConfig:   filepath.Join(home, ".claude.json"),
		unboundConfig:  filepath.Join(unboundDir, "config.json"),
		identityCache:  filepath.Join(unboundDir, "identity.json"),
		discoveryCache: filepath.Join(unboundDir, "discovery-cache.json"),
		discoveryLock:  filepath.Join(unboundDir, "discovery.lock"),
		dispatchLock:   filepath.Join(unboundDir, "discovery.dispatch.lock"),
	}, nil
}

func runClaudeCode(_ string, stdin io.Reader, stdout io.Writer) int {
	c, err := newClaudeCodeHook()
	if err != nil {
		// No resolvable home; the dispatcher contract is fail-open.
		fmt.Fprintln(stdout, `{"suppressOutput": true}`)
		return 0
	}
	c.main(stdin, stdout)
	return 0
}

// main mirrors main() (lines 1607-1681). All paths print one JSON line and
// exit 0; the deferred recover is python's blanket except (1677-1680).
func (c *claudeCodeHook) main(stdin io.Reader, stdout io.Writer) {
	// get_api_key (1181-1203) + the _cached_api_key global (1608-1610).
	key, err := config.APIKey("claude-code")
	if err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) {
			c.rep.LogError(fmt.Sprintf("~/.unbound/config.json is not valid JSON: %v", err), "config")
		} else {
			c.rep.LogError(fmt.Sprintf("Failed to read config file: %v", err), "config")
		}
		key = ""
	}
	c.apiKey = key
	c.rep.APIKey = key

	defer func() {
		if r := recover(); r != nil {
			c.rep.LogError(fmt.Sprintf("Exception in main: %v", r), "general")
			fmt.Fprintln(stdout, `{"suppressOutput": true}`)
		}
	}()

	raw, err := io.ReadAll(stdin)
	if err != nil {
		raise("stdin read failed: %v", err)
	}
	input := strings.TrimSpace(string(raw))
	if input == "" {
		fmt.Fprintln(stdout, `{"suppressOutput": true}`)
		return
	}
	parsed, err := pyjson.Loads([]byte(input))
	if err != nil {
		fmt.Fprintln(stdout, `{"suppressOutput": true}`)
		return
	}
	event := mustObj(parsed)
	hookEventName, _ := event.GetDefault("hook_event_name", nil).(string)

	// SessionStart fires once per session — natural TTL gate for the
	// debounced discovery scan dispatch (1629-1634).
	if hookEventName == "SessionStart" {
		c.deviceSerial(true) // warm the (slow) serial probe + cache once per session
		selfupdate.Check()
		c.dispatchDiscovery()
		fmt.Fprintln(stdout, "{}")
		return
	}
	sessionID := event.GetDefault("session_id", nil)

	if hookEventName == "PreToolUse" {
		response := c.processPreToolUse(event)
		response.Set("suppressOutput", true)
		c.printJSON(stdout, response)
		return
	}

	if hookEventName == "UserPromptSubmit" {
		response := c.processUserPromptSubmit(event)
		if d, _ := response.GetDefault("decision", nil).(string); d == "block" {
			audit.Append(c.auditLog, pyjson.NewObject().
				Set("timestamp", report.UTCTimestamp(time.Now())).
				Set("session_id", event.GetDefault("session_id", nil)).
				Set("event", event))
			response.Set("suppressOutput", true)
			c.printJSON(stdout, response)
			return
		}
		// Allowed: continue to log the event (output printed at end).
	}

	audit.Append(c.auditLog, pyjson.NewObject().
		Set("timestamp", report.UTCTimestamp(time.Now())).
		Set("session_id", event.GetDefault("session_id", nil)).
		Set("event", event))

	if hookEventName == "Stop" && pyjson.Truthy(sessionID) {
		c.processStopEvent(event)
	}

	c.cleanupOldLogs()

	fmt.Fprintln(stdout, `{"suppressOutput": true}`)
}

func (c *claudeCodeHook) printJSON(w io.Writer, v any) {
	s, err := pyjson.Dumps(v)
	if err != nil {
		raise("json dumps failed: %v", err)
	}
	fmt.Fprintln(w, s)
}

// cleanupOldLogs mirrors cleanup_old_logs (1103-1126): grouping is by the
// TOP-LEVEL session_id only.
func (c *claudeCodeHook) cleanupOldLogs() {
	audit.Cleanup(c.auditLog, ccAuditLogTotalLimit, func(entry any) string {
		obj, ok := entry.(*pyjson.Object)
		if !ok {
			return ""
		}
		v, _ := obj.Get("session_id")
		if !pyjson.Truthy(v) {
			return ""
		}
		if s, ok := v.(string); ok {
			return "s:" + s
		}
		// Non-string ids are keyed by their JSON form, prefixed so they
		// never collide with a string id of the same spelling.
		s, err := pyjson.Dumps(v)
		if err != nil {
			return ""
		}
		return "j:" + s
	})
}

// getSessionModel mirrors _get_session_model (355-364).
func (c *claudeCodeHook) getSessionModel(sessionID any) any {
	if !pyjson.Truthy(sessionID) {
		return nil
	}
	return extractSessionModel(audit.Load(c.auditLog), sessionID)
}

// extractSessionModel mirrors _extract_session_model (331-352): forward
// scan, latest SessionStart wins; the first malformed entry aborts the scan
// keeping what was found (python's broad except around the loop).
func extractSessionModel(logs []any, sessionID any) (found any) {
	if !pyjson.Truthy(sessionID) || len(logs) == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(pyRaise); !ok {
				panic(r)
			}
		}
	}()
	for _, entry := range logs {
		log := mustObj(entry)
		logSession := log.GetDefault("session_id", nil)
		if !pyjson.Truthy(logSession) {
			logSession = objGet(log.GetDefault("event", pyjson.NewObject()), "session_id", nil)
		}
		if !pyEq(logSession, sessionID) {
			continue
		}
		event := log
		if v, has := log.Get("event"); has {
			event = mustObj(v)
		}
		if hen, _ := event.GetDefault("hook_event_name", nil).(string); hen == "SessionStart" {
			if model := event.GetDefault("model", nil); pyjson.Truthy(model) {
				found = model // keep scanning — latest SessionStart wins
			}
		}
	}
	return found
}
