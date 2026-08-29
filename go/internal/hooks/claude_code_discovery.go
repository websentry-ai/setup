package hooks

// Discovery + MCP-scan dispatch for the claude-code port
// (claude-code/hooks/unbound.py lines 1347-1409, 1419-1476, 1479-1604).
// The Go binary is always the frozen variant: it never downloads
// install.sh — discovery runs from the locally installed binary or is
// skipped with a logged error (lines 1441-1448, 1548-1554).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/websentry-ai/setup/go/internal/config"
	"github.com/websentry-ai/setup/go/internal/httpc"
	"github.com/websentry-ai/setup/go/internal/locks"
	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// frozenDiscoveryBin mirrors FROZEN_DISCOVERY_BIN (line 66). Var, not
// const, so tests can point it at a sandbox binary.
var frozenDiscoveryBin = "/opt/unbound/current/unbound-discovery/unbound-discovery"

// utcStamp mirrors datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").
func utcStamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05") + "Z"
}

// parseUTCStamp is the strict strptime("%Y-%m-%dT%H:%M:%SZ") counterpart.
func parseUTCStamp(s string) (time.Time, error) {
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, errors.New("timestamp does not match format")
	}
	return time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(s, "Z"))
}

// readDiscoveryCache mirrors the lenient cache reads (1353-1361,
// 1483-1491): missing, unreadable, corrupt, falsy, or non-dict all yield {}.
func (c *claudeCodeHook) readDiscoveryCache() *pyjson.Object {
	if data, err := os.ReadFile(c.discoveryCache); err == nil {
		if parsed, perr := pyjson.Loads(data); perr == nil && pyjson.Truthy(parsed) {
			if obj, ok := parsed.(*pyjson.Object); ok {
				return obj
			}
		}
	}
	return pyjson.NewObject()
}

// writeDiscoveryCache mirrors the atomic cache writes (1401-1406,
// 1592-1597): json.dump(indent=2, sort_keys=True) to a sibling .tmp, then
// os.replace. Filesystem errors are returned for the caller to handle per
// call site; an unencodable value raises (python json.dump TypeError is
// outside the except OSError).
func (c *claudeCodeHook) writeDiscoveryCache(cache *pyjson.Object) error {
	s, err := pyjson.DumpsIndentSorted(cache)
	if err != nil {
		raise("json dump failed: %v", err)
	}
	// Path.with_suffix(".tmp"): discovery-cache.json -> discovery-cache.tmp.
	tmp := strings.TrimSuffix(c.discoveryCache, ".json") + ".tmp"
	if err := os.MkdirAll(filepath.Dir(c.discoveryCache), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, []byte(s), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.discoveryCache)
}

// hookDiscoveryEnabledForOrg mirrors _hook_discovery_enabled_for_org
// (1347-1409): cached flag within TTL, else refetch from the gateway.
// Fail-closed: any error with no usable cached value means false.
func (c *claudeCodeHook) hookDiscoveryEnabledForOrg() bool {
	cache := c.readDiscoveryCache()
	flag := pyjson.NewObject()
	if hd, ok := cache.GetDefault("hook_discovery", nil).(*pyjson.Object); ok {
		flag = hd
	}
	cachedEnabled := func() bool { return pyjson.Truthy(flag.GetDefault("enabled", false)) }

	if lastFetched, ok := flag.GetDefault("fetched_at", nil).(string); ok {
		if ts, err := parseUTCStamp(lastFetched); err == nil && time.Since(ts) < discoveryHookFlagTTL {
			return cachedEnabled()
		}
	}

	cfg, err := config.Read()
	if err != nil {
		// python catches OSError/JSONDecodeError only; a non-dict config
		// raises at cfg.get into main's blanket except.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			raise("config.json is not a dict: %v", err)
		}
		return cachedEnabled()
	}
	if cfg.APIKey == "" {
		return cachedEnabled()
	}

	res, err := httpc.Get(c.gatewayURL+discoveryHookFlagPath, cfg.APIKey, 5, 8*time.Second)
	if err != nil || res.ExitCode != 0 {
		return cachedEnabled()
	}
	parsed, perr := pyjson.Loads(res.Stdout)
	if perr != nil {
		return cachedEnabled()
	}
	obj, ok := parsed.(*pyjson.Object)
	if !ok {
		return cachedEnabled() // .get raised into the except Exception
	}
	enabled := pyjson.Truthy(obj.GetDefault("enabled", false))

	cache.Set("hook_discovery", pyjson.NewObject().
		Set("enabled", enabled).
		Set("fetched_at", utcStamp(time.Now())))
	_ = c.writeDiscoveryCache(cache) // except OSError: pass
	return enabled
}

// dispatchDiscovery mirrors _dispatch_discovery (1479-1604): org flag,
// 24h debounce, stale-lock check, atomic dispatch claim, then a
// fire-and-forget detached run of the local discovery binary.
func (c *claudeCodeHook) dispatchDiscovery() {
	if !c.hookDiscoveryEnabledForOrg() {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(pyRaise)
			if !ok {
				panic(r)
			}
			c.rep.LogError(fmt.Sprintf("discovery gate failed: %s", pe.msg), "discovery_gate")
		}
	}()

	cache := c.readDiscoveryCache()

	if last, ok := cache.GetDefault("last_run_at", nil).(string); ok {
		if ts, err := parseUTCStamp(last); err == nil && time.Since(ts) < discoveryDebounce {
			return
		}
	}

	// Another run in flight (1502-1508).
	if locks.IsFresh(c.discoveryLock, discoveryStaleLock) {
		return
	}

	// Atomic dispatch claim — first hook to create the marker wins;
	// concurrent peers bail to avoid duplicate detached spawns (1510-1530).
	claimed, err := locks.Claim(c.dispatchLock, discoveryDispatchTTL)
	if err != nil {
		raise("dispatch claim failed: %v", err)
	}
	if !claimed {
		return
	}
	defer locks.Release(c.dispatchLock)

	cfg, err := config.Read()
	if err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			raise("config.json is not a dict: %v", err)
		}
		c.rep.LogError(fmt.Sprintf("discovery gate: could not read %s: %v", c.unboundConfig, err), "discovery_gate")
		return
	}
	if cfg.APIKey == "" {
		c.rep.LogError("discovery gate: api_key missing in ~/.unbound/config.json", "discovery_gate")
		return
	}
	if cfg.BaseURL == "" {
		c.rep.LogError("discovery gate: base_url missing in ~/.unbound/config.json", "discovery_gate")
		return
	}

	// Frozen binary: never fetch install.sh — run the locally installed
	// discovery binary, or skip if it isn't there.
	if fi, err := os.Stat(frozenDiscoveryBin); err != nil || fi.IsDir() {
		c.rep.LogError(fmt.Sprintf("discovery gate: discovery binary missing at %s", frozenDiscoveryBin), "discovery_gate")
		return
	}

	// api_key goes via env so it never appears in argv / /proc/<pid>/cmdline.
	if err := spawnDetached(
		[]string{frozenDiscoveryBin, "--domain", cfg.BaseURL},
		[]string{"UNBOUND_API_KEY=" + cfg.APIKey},
	); err != nil {
		c.rep.LogError(fmt.Sprintf("discovery gate: Popen failed: %v", err), "discovery_gate")
		return
	}

	// Stamp last_run_at only after the spawn succeeds so a launch failure
	// doesn't burn the 24h window (1590-1597).
	cache.Set("last_run_at", utcStamp(time.Now()))
	if err := c.writeDiscoveryCache(cache); err != nil {
		raise("%v", err)
	}
}

// dispatchMCPServerScan mirrors _dispatch_mcp_server_scan (1419-1476):
// report ONE unknown MCP server out-of-band. Detached so the blocking
// PreToolUse hook returns immediately; secrets travel via env, never argv.
func (c *claudeCodeHook) dispatchMCPServerScan(serverName string, serverConfig *pyjson.Object) {
	if serverName == "" {
		c.rep.LogError("mcp scan dispatch: empty server name, skipping", "mcp_server")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(pyRaise)
			if !ok {
				panic(r)
			}
			c.rep.LogError(fmt.Sprintf("mcp scan dispatch failed for %s: %s", serverName, pe.msg), "mcp_server")
		}
	}()

	cfg, err := config.Read()
	if err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			raise("config.json is not a dict: %v", err)
		}
		c.rep.LogError(fmt.Sprintf("mcp scan dispatch: cannot read config: %v", err), "mcp_server")
		return
	}
	if cfg.APIKey == "" || cfg.BaseURL == "" {
		c.rep.LogError("mcp scan dispatch: api_key/base_url missing in config", "mcp_server")
		return
	}

	if fi, err := os.Stat(frozenDiscoveryBin); err != nil || fi.IsDir() {
		c.rep.LogError(fmt.Sprintf("mcp scan dispatch: discovery binary missing at %s", frozenDiscoveryBin), "mcp_server")
		return
	}

	serverJSON, err := pyjson.Dumps(serverConfig)
	if err != nil {
		raise("json dumps failed: %v", err)
	}
	if err := spawnDetached(
		[]string{frozenDiscoveryBin, "mcp-scan", "--name", serverName, "--domain", cfg.BaseURL},
		[]string{
			"UNBOUND_API_KEY=" + cfg.APIKey,
			"UNBOUND_MCP_SERVER_JSON=" + serverJSON,
			"UNBOUND_MCP_SERVER_NAME=" + serverName,
			"UNBOUND_MCP_DOMAIN=" + cfg.BaseURL,
		},
	); err != nil {
		raise("Popen failed: %v", err)
	}
}

// spawnDetached mirrors the fire-and-forget Popen kwargs (1460-1473,
// 1577-1585): all stdio on the null device (os/exec's default for nil
// std fields), a new session (start_new_session=True), and no wait.
func spawnDetached(argv, extraEnv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
