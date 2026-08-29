package hooks

// Hermetic tests for the claude-code port: temp HOME, fake curl /
// system_profiler shims on PATH (the httpc test pattern), no network.
// Byte-level python parity is enforced separately by
// binary/tests/test_hook_cli.py against the real python hook.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

const suppressLine = "{\"suppressOutput\": true}\n"

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// installFakeBins shims curl and system_profiler. curl records argv/stdin
// and answers per CURL_STDOUT / CURL_EXIT; system_profiler prints a
// hardware-serial line per FAKE_SERIAL.
func installFakeBins(t *testing.T) (argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "curl-args")
	stdinFile = filepath.Join(dir, "curl-stdin")
	writeScript(t, filepath.Join(dir, "curl"), `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > "$CURL_ARGS_FILE"
cat > "$CURL_STDIN_FILE"
printf '%s' "$CURL_STDOUT"
exit "${CURL_EXIT:-0}"
`)
	writeScript(t, filepath.Join(dir, "system_profiler"), `#!/bin/sh
printf '      Serial Number (system): %s\n' "$FAKE_SERIAL"
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CURL_ARGS_FILE", argsFile)
	t.Setenv("CURL_STDIN_FILE", stdinFile)
	t.Setenv("CURL_STDOUT", "")
	t.Setenv("CURL_EXIT", "0")
	t.Setenv("FAKE_SERIAL", "TESTSERIAL123")
	return argsFile, stdinFile
}

func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("UNBOUND_GATEWAY_URL", "https://gw.test")
	t.Setenv("UNBOUND_CLAUDE_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_API_KEY", "")
	return home
}

func runHook(t *testing.T, payload string) string {
	t.Helper()
	var out bytes.Buffer
	if code := Dispatch("claude-code", "", strings.NewReader(payload), &out); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	return out.String()
}

func auditLines(t *testing.T, home string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".claude", "hooks", "agent-audit.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func loadsObj(t *testing.T, s string) *pyjson.Object {
	t.Helper()
	v, err := pyjson.Loads([]byte(s))
	if err != nil {
		t.Fatalf("Loads(%q): %v", s, err)
	}
	obj, ok := v.(*pyjson.Object)
	if !ok {
		t.Fatalf("not an object: %q", s)
	}
	return obj
}

func waitForFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("file never appeared: %s", path)
	return ""
}

// --- entry semantics (main, lines 1607-1681) ---

func TestEntryEmptyStdinSuppresses(t *testing.T) {
	setupHome(t)
	installFakeBins(t)
	for _, in := range []string{"", "   \n\t "} {
		if got := runHook(t, in); got != suppressLine {
			t.Errorf("stdin %q -> %q, want %q", in, got, suppressLine)
		}
	}
}

func TestEntryMalformedJSONSuppresses(t *testing.T) {
	setupHome(t)
	installFakeBins(t)
	if got := runHook(t, "not json at all"); got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
}

func TestEntryNonDictEventLogsAndSuppresses(t *testing.T) {
	home := setupHome(t)
	t.Setenv("UNBOUND_CLAUDE_API_KEY", "") // keep the error report offline
	installFakeBins(t)
	if got := runHook(t, "[1, 2]"); got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "hooks", "error.log"))
	if err != nil || !strings.Contains(string(data), "Exception in main") {
		t.Errorf("error.log = %q, %v", data, err)
	}
}

func TestEntryUnknownEventIsAuditLogged(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	if got := runHook(t, `{"hook_event_name": "SomethingNew", "session_id": "s1"}`); got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	lines := auditLines(t, home)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want 1", len(lines))
	}
	entry := loadsObj(t, lines[0])
	if v, _ := entry.Get("session_id"); v != "s1" {
		t.Errorf("session_id = %v", v)
	}
	if _, ok := entry.Get("timestamp"); !ok {
		t.Error("timestamp missing from audit entry")
	}
}

// --- PreToolUse (process_pre_tool_use, lines 834-967) ---

func TestPreToolUseUncheckedToolSkipsGateway(t *testing.T) {
	home := setupHome(t)
	argsFile, _ := installFakeBins(t)
	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Grep", "tool_input": {"pattern": "x"}}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Error("gateway was called for a non-allowed tool")
	}
	if lines := auditLines(t, home); lines != nil {
		t.Errorf("PreToolUse must not audit-log, got %v", lines)
	}
}

func TestPreToolUseNativeToolSkippedOnFreshCache(t *testing.T) {
	home := setupHome(t)
	argsFile, _ := installFakeBins(t)
	cacheFile := filepath.Join(home, ".claude", "hooks", ".policy_cache.json")
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0o755); err != nil {
		t.Fatal(err)
	}
	cache := fmt.Sprintf(`{"last_synced": "%s", "tools_to_check": [], "policy_check_failure_action": "allow"}`,
		time.Now().UTC().Format("2006-01-02T15:04:05.000000")+"Z")
	if err := os.WriteFile(cacheFile, []byte(cache), 0o644); err != nil {
		t.Fatal(err)
	}
	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Error("gateway was called for an unchecked native tool with a fresh cache")
	}
}

func TestPreToolUseDenySavesCacheAndTransforms(t *testing.T) {
	home := setupHome(t)
	_, stdinFile := installFakeBins(t)
	t.Setenv("CURL_STDOUT", `{"decision": "deny", "reason": "blocked by policy", "additionalContext": "ctx", "tools_to_check": ["Bash"], "policy_check_failure_action": "block"}`)

	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "git status"}}`)
	want := `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "blocked by policy", "additionalContext": "ctx"}, "suppressOutput": true}` + "\n"
	if got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}

	body := loadsObj(t, waitForFile(t, stdinFile))
	for key, wantVal := range map[string]any{
		"conversation_id":      "s1",
		"unbound_app_label":    "claude-code",
		"model":                "auto",
		"event_name":           "tool_use",
		"first_approval_check": true,
		"pull_policies":        true,
	} {
		if v, _ := body.Get(key); v != wantVal {
			t.Errorf("request %s = %v, want %v", key, v, wantVal)
		}
	}
	pretool := body.GetDefault("pre_tool_use_data", nil).(*pyjson.Object)
	if cmd, _ := pretool.Get("command"); cmd != "git status" {
		t.Errorf("command = %v", cmd)
	}

	cacheData, err := os.ReadFile(filepath.Join(home, ".claude", "hooks", ".policy_cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	cache := loadsObj(t, string(cacheData))
	if v, _ := cache.Get("policy_check_failure_action"); v != "block" {
		t.Errorf("cached failure action = %v", v)
	}
	if !pyEq(cache.GetDefault("tools_to_check", nil), []any{"Bash"}) {
		t.Errorf("cached tools_to_check = %v", cache.GetDefault("tools_to_check", nil))
	}
}

func TestPreToolUseGatewayFailureFailsOpenByDefault(t *testing.T) {
	setupHome(t)
	installFakeBins(t)
	t.Setenv("CURL_EXIT", "7")
	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "git status"}}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
}

func TestPreToolUseGatewayFailureBlocksWhenCachedActionIsBlock(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	t.Setenv("CURL_EXIT", "7")
	cacheFile := filepath.Join(home, ".claude", "hooks", ".policy_cache.json")
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0o755); err != nil {
		t.Fatal(err)
	}
	// Stale on purpose: get_policy_check_failure_action ignores the TTL.
	if err := os.WriteFile(cacheFile, []byte(`{"last_synced": "2020-01-01T00:00:00Z", "tools_to_check": [], "policy_check_failure_action": "block"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "git status"}}`)
	resp := loadsObj(t, got)
	hso := resp.GetDefault("hookSpecificOutput", nil).(*pyjson.Object)
	if v, _ := hso.Get("permissionDecision"); v != "deny" {
		t.Errorf("permissionDecision = %v, want deny", v)
	}
	if v, _ := hso.Get("permissionDecisionReason"); v != "policy engine unavailable — please retry" {
		t.Errorf("reason = %v", v)
	}
}

func TestPreToolUseApprovalRequiredWritesMarker(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	t.Setenv("CURL_STDOUT", `{"decision": "approval_required", "approvalCheck": {"policyIds": ["p1"], "applicationId": "app1", "requestId": "r1"}}`)

	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "git status"}}`)
	resp := loadsObj(t, got)
	hso := resp.GetDefault("hookSpecificOutput", nil).(*pyjson.Object)
	if v, _ := hso.Get("permissionDecision"); v != "deny" {
		t.Errorf("permissionDecision = %v, want deny", v)
	}
	if v, _ := hso.Get("permissionDecisionReason"); v != "An approval request has been sent to your Slack DMs. Please approve it there." {
		t.Errorf("reason = %v", v)
	}

	marker, err := os.ReadFile(filepath.Join(home, ".claude", "hooks", ".approval_pending"))
	if err != nil {
		t.Fatal(err)
	}
	m := loadsObj(t, string(marker))
	if v, _ := m.Get("cmd"); v != approvalCmdHash("Bash:git status") {
		t.Errorf("marker cmd = %v", v)
	}
	if !pyEq(m.GetDefault("policyIds", nil), []any{"p1"}) {
		t.Errorf("marker policyIds = %v", m.GetDefault("policyIds", nil))
	}
	if v, _ := m.Get("requestId"); v != "r1" {
		t.Errorf("marker requestId = %v", v)
	}
}

func TestPreToolUseApprovalRetryPollsAndAllows(t *testing.T) {
	if testing.Short() {
		t.Skip("first poll interval is 3s")
	}
	home := setupHome(t)
	argsFile, stdinFile := installFakeBins(t)
	t.Setenv("CURL_STDOUT", `{"decision": "allow"}`)

	markerPath := filepath.Join(home, ".claude", "hooks", ".approval_pending")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf(`{"cmd": "%s", "ts": %d.5, "policyIds": ["p1"], "applicationId": "app1", "requestId": "r1", "escalatedAdminContact": ""}`,
		approvalCmdHash("Bash:git status"), time.Now().Unix()-10)
	if err := os.WriteFile(markerPath, []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}

	got := runHook(t, `{"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "git status"}}`)
	resp := loadsObj(t, got)
	hso := resp.GetDefault("hookSpecificOutput", nil).(*pyjson.Object)
	if v, _ := hso.Get("permissionDecision"); v != "allow" {
		t.Errorf("permissionDecision = %v, want allow", v)
	}
	if _, err := os.Stat(markerPath); err == nil {
		t.Error("approval marker was not cleared")
	}
	args := waitForFile(t, argsFile)
	if !strings.Contains(args, "https://gw.test/v1/hooks/pretool/approval-status") {
		t.Errorf("poll did not hit approval-status: %q", args)
	}
	wantBody := `{"policyIds": ["p1"], "applicationId": "app1", "requestId": "r1"}`
	if body := waitForFile(t, stdinFile); body != wantBody {
		t.Errorf("poll body = %q, want %q", body, wantBody)
	}
}

// --- UserPromptSubmit (process_user_prompt_submit, lines 970-986) ---

func TestUserPromptSubmitDenyBlocksAndLogs(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	t.Setenv("CURL_STDOUT", `{"decision": "deny", "reason": "nope"}`)
	got := runHook(t, `{"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hello"}`)
	want := `{"decision": "block", "reason": "nope", "suppressOutput": true}` + "\n"
	if got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if lines := auditLines(t, home); len(lines) != 1 {
		t.Errorf("audit lines = %d, want 1", len(lines))
	}
}

func TestUserPromptSubmitAllowFallsThroughAndLogs(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	t.Setenv("CURL_STDOUT", `{"decision": "allow"}`)
	got := runHook(t, `{"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hello"}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	lines := auditLines(t, home)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want 1", len(lines))
	}
	event := loadsObj(t, lines[0]).GetDefault("event", nil).(*pyjson.Object)
	if v, _ := event.Get("prompt"); v != "hello" {
		t.Errorf("logged prompt = %v", v)
	}
}

// --- PostToolUse / audit append ---

func TestPostToolUseAppendsAudit(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	got := runHook(t, `{"hook_event_name": "PostToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"output": "ok"}}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	if lines := auditLines(t, home); len(lines) != 1 {
		t.Errorf("audit lines = %d, want 1", len(lines))
	}
}

// --- Stop (process_stop_event + build_llm_exchange, lines 989-1178) ---

func TestStopSendsExchange(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("deterministic device serial needs the system_profiler shim")
	}
	home := setupHome(t)
	argsFile, stdinFile := installFakeBins(t)

	hooksDir := filepath.Join(home, ".claude", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	auditSeed := `{"timestamp": "2026-01-01T00:00:00Z", "session_id": "s1", "event": {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hi"}}
{"timestamp": "2026-01-01T00:00:00Z", "session_id": "s1", "event": {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"output": "ok"}}}
`
	if err := os.WriteFile(filepath.Join(hooksDir, "agent-audit.log"), []byte(auditSeed), 0o644); err != nil {
		t.Fatal(err)
	}

	transcriptPath := filepath.Join(home, "transcript.jsonl")
	transcriptSeed := `{"type": "assistant", "timestamp": "2026-01-01T00:00:01Z", "message": {"role": "assistant", "model": "claude-test-1", "content": [{"type": "text", "text": "From transcript"}], "usage": {"input_tokens": 5, "output_tokens": 7}}}
`
	if err := os.WriteFile(transcriptPath, []byte(transcriptSeed), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := fmt.Sprintf(`{"hook_event_name": "Stop", "session_id": "s1", "transcript_path": %q, "last_assistant_message": "done"}`, transcriptPath)
	if got := runHook(t, payload); got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}

	args := waitForFile(t, argsFile)
	if !strings.Contains(args, "https://gw.test/v1/hooks/claude") {
		t.Errorf("exchange did not hit /v1/hooks/claude: %q", args)
	}
	want := `{"conversation_id": "s1", "model": "claude-test-1", ` +
		`"messages": [{"role": "user", "content": "hi"}, ` +
		`{"role": "assistant", "content": "From transcript\n\ndone", ` +
		`"tool_use": [{"type": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"output": "ok"}}]}], ` +
		`"permission_mode": "default", ` +
		`"account_identity": {"org_id": null, "plan": null, "auth_mode": null, "user_email": null, "email_domain": null, "device_serial": "TESTSERIAL123"}, ` +
		`"usage": {"input_tokens": 5, "output_tokens": 7, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "total_tokens": 12}}`
	if body := waitForFile(t, stdinFile); body != want {
		t.Errorf("exchange body =\n%s\nwant\n%s", body, want)
	}
}

func TestStopWithoutUserPromptSendsNothing(t *testing.T) {
	setupHome(t)
	argsFile, _ := installFakeBins(t)
	got := runHook(t, `{"hook_event_name": "Stop", "session_id": "s1", "transcript_path": "/nonexistent.jsonl", "last_assistant_message": "done"}`)
	if got != suppressLine {
		t.Errorf("got %q, want %q", got, suppressLine)
	}
	// < 2 messages -> build_llm_exchange returns nothing, no POST.
	if _, err := os.Stat(argsFile); err == nil {
		t.Error("exchange was sent despite < 2 messages")
	}
}

// --- SessionStart: serial probe + discovery dispatch (lines 1629-1634) ---

func seedDiscoveryEnabled(t *testing.T, home string) {
	t.Helper()
	unbound := filepath.Join(home, ".unbound")
	if err := os.MkdirAll(unbound, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"api_key": "k1", "base_url": "https://backend.example"}`
	if err := os.WriteFile(filepath.Join(unbound, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := fmt.Sprintf(`{"hook_discovery": {"enabled": true, "fetched_at": "%s"}}`, utcStamp(time.Now()))
	if err := os.WriteFile(filepath.Join(unbound, "discovery-cache.json"), []byte(cache), 0o644); err != nil {
		t.Fatal(err)
	}
}

func overrideDiscoveryBin(t *testing.T, path string) {
	t.Helper()
	old := frozenDiscoveryBin
	frozenDiscoveryBin = path
	t.Cleanup(func() { frozenDiscoveryBin = old })
}

func TestSessionStartDispatchesDiscovery(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	seedDiscoveryEnabled(t, home)

	outFile := filepath.Join(t.TempDir(), "discovery-out")
	t.Setenv("DISCOVERY_OUT", outFile)
	binPath := filepath.Join(t.TempDir(), "unbound-discovery")
	writeScript(t, binPath, `#!/bin/sh
printf '%s %s' "$UNBOUND_API_KEY" "$*" > "$DISCOVERY_OUT"
`)
	overrideDiscoveryBin(t, binPath)

	if got := runHook(t, `{"hook_event_name": "SessionStart", "session_id": "s1"}`); got != "{}\n" {
		t.Errorf("got %q, want {}", got)
	}
	if out := waitForFile(t, outFile); out != "k1 --domain https://backend.example" {
		t.Errorf("discovery argv/env = %q", out)
	}
	cacheData, err := os.ReadFile(filepath.Join(home, ".unbound", "discovery-cache.json"))
	if err != nil || !strings.Contains(string(cacheData), `"last_run_at"`) {
		t.Errorf("last_run_at not stamped: %q, %v", cacheData, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".unbound", "discovery.dispatch.lock")); err == nil {
		t.Error("dispatch lock not released")
	}
	if serial, err := os.ReadFile(filepath.Join(home, ".unbound", "identity.json")); err != nil ||
		!strings.Contains(string(serial), "TESTSERIAL123") {
		if runtime.GOOS == "darwin" {
			t.Errorf("identity cache = %q, %v", serial, err)
		}
	}
}

func TestSessionStartDiscoveryDebounced(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	seedDiscoveryEnabled(t, home)
	cache := fmt.Sprintf(`{"hook_discovery": {"enabled": true, "fetched_at": "%s"}, "last_run_at": "%s"}`,
		utcStamp(time.Now()), utcStamp(time.Now()))
	if err := os.WriteFile(filepath.Join(home, ".unbound", "discovery-cache.json"), []byte(cache), 0o644); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "discovery-out")
	t.Setenv("DISCOVERY_OUT", outFile)
	binPath := filepath.Join(t.TempDir(), "unbound-discovery")
	writeScript(t, binPath, "#!/bin/sh\ntouch \"$DISCOVERY_OUT\"\n")
	overrideDiscoveryBin(t, binPath)

	if got := runHook(t, `{"hook_event_name": "SessionStart"}`); got != "{}\n" {
		t.Errorf("got %q, want {}", got)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(outFile); err == nil {
		t.Error("discovery dispatched despite fresh last_run_at")
	}
}

func TestSessionStartDiscoveryStaleLockSkips(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	seedDiscoveryEnabled(t, home)
	if err := os.WriteFile(filepath.Join(home, ".unbound", "discovery.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "discovery-out")
	t.Setenv("DISCOVERY_OUT", outFile)
	binPath := filepath.Join(t.TempDir(), "unbound-discovery")
	writeScript(t, binPath, "#!/bin/sh\ntouch \"$DISCOVERY_OUT\"\n")
	overrideDiscoveryBin(t, binPath)

	if got := runHook(t, `{"hook_event_name": "SessionStart"}`); got != "{}\n" {
		t.Errorf("got %q, want {}", got)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(outFile); err == nil {
		t.Error("discovery dispatched despite a fresh discovery.lock")
	}
}

func TestSessionStartDiscoveryBinaryMissingLogsAndSkips(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	seedDiscoveryEnabled(t, home)
	overrideDiscoveryBin(t, filepath.Join(t.TempDir(), "missing-binary"))

	if got := runHook(t, `{"hook_event_name": "SessionStart"}`); got != "{}\n" {
		t.Errorf("got %q, want {}", got)
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "hooks", "error.log"))
	if err != nil || !strings.Contains(string(data), "discovery binary missing") {
		t.Errorf("error.log = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "unbound", "install.sh")); err == nil {
		t.Error("frozen hook downloaded install.sh")
	}
}

// --- device serial + identity (lines 674-831) ---

func TestDeviceSerialProbeCachesAndPlaceholderRejected(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("system_profiler shim is the darwin probe path")
	}
	home := setupHome(t)
	installFakeBins(t)
	c, err := newClaudeCodeHook()
	if err != nil {
		t.Fatal(err)
	}

	if got := c.deviceSerial(false); got != "" {
		t.Errorf("probe=false must not probe, got %q", got)
	}

	t.Setenv("FAKE_SERIAL", "To be filled by O.E.M.")
	if got := c.deviceSerial(true); got != "" {
		t.Errorf("placeholder serial accepted: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".unbound", "identity.json")); err == nil {
		t.Error("identity cache written for a placeholder serial")
	}

	t.Setenv("FAKE_SERIAL", "REALSERIAL9")
	if got := c.deviceSerial(true); got != "REALSERIAL9" {
		t.Errorf("serial = %q", got)
	}
	// Cached value wins over a fresh probe now.
	t.Setenv("FAKE_SERIAL", "OTHER")
	if got := c.deviceSerial(true); got != "REALSERIAL9" {
		t.Errorf("cache not used: %q", got)
	}
}

func TestReadAccountIdentity(t *testing.T) {
	home := setupHome(t)
	installFakeBins(t)
	c, err := newClaudeCodeHook()
	if err != nil {
		t.Fatal(err)
	}

	dumps := func(o *pyjson.Object) string {
		s, err := pyjson.Dumps(o)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Missing ~/.claude.json: every field None.
	want := `{"org_id": null, "plan": null, "auth_mode": null, "user_email": null, "email_domain": null}`
	if got := dumps(c.readAccountIdentity()); got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	claudeJSON := filepath.Join(home, ".claude.json")
	oauth := `{"oauthAccount": {"organizationUuid": "org-1", "organizationType": "team", "emailAddress": "Dev@Example.COM "}}`
	if err := os.WriteFile(claudeJSON, []byte(oauth), 0o644); err != nil {
		t.Fatal(err)
	}
	want = `{"org_id": "org-1", "plan": "team", "auth_mode": "subscription", "user_email": "Dev@Example.COM ", "email_domain": "example.com"}`
	if got := dumps(c.readAccountIdentity()); got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	if err := os.WriteFile(claudeJSON, []byte(`{"customApiKeyResponses": {"approved": ["sk"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	want = `{"org_id": null, "plan": null, "auth_mode": "api_key", "user_email": null, "email_domain": null}`
	if got := dumps(c.readAccountIdentity()); got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	if err := os.WriteFile(claudeJSON, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant")
	if got := dumps(c.readAccountIdentity()); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
