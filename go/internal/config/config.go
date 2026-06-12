// Package config reads ~/.unbound/config.json and the hook environment
// variables, mirroring the python hook modules:
//
//   - GatewayURL mirrors the UNBOUND_GATEWAY_URL module constant
//     (claude-code/hooks/unbound.py lines 17-19): env value if the variable
//     is set (even empty, like os.environ.get), else the baked default,
//     with trailing slashes stripped.
//   - APIKey mirrors get_api_key (claude-code/hooks/unbound.py lines
//     1181-1203, cursor/unbound.py lines 1182-1195, copilot/hooks/unbound.py
//     lines 938-951) and codex's env-only lookup (codex/hooks/unbound.py
//     line 1523): per-tool env var first, then config.json's api_key —
//     except codex, which reads ONLY the env var (quirk copied as-is).
//   - Read mirrors the discovery/mcp-scan config reads
//     (claude-code/hooks/unbound.py lines 1429-1439, 1533-1546): api_key
//     and base_url come from config.json; gateway_url and frontend_url are
//     also written there by the setup scripts (claude-code/hooks/setup.py
//     write_unbound_config, line 1245) and exposed for future callers.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultGatewayURL is the python modules' baked env-var default. The
// python install path rewrites the literal in the script for non-default
// tenants; the Go equivalent is -ldflags "-X .../config.DefaultGatewayURL=...".
var DefaultGatewayURL = "https://api.getunbound.ai"

// APIKeyEnvVars maps each tool to its API-key environment variable.
var APIKeyEnvVars = map[string]string{
	"claude-code": "UNBOUND_CLAUDE_API_KEY",
	"cursor":      "UNBOUND_CURSOR_API_KEY",
	"codex":       "UNBOUND_CODEX_API_KEY",
	"copilot":     "UNBOUND_COPILOT_API_KEY",
}

// Config is the subset of ~/.unbound/config.json the hooks consume.
// Non-string values for any field are treated as missing (python's
// dict.get would pass them through, but no caller survives one).
type Config struct {
	APIKey      string // "api_key"
	BaseURL     string // "base_url" — the backend, used as discovery --domain
	GatewayURL  string // "gateway_url"
	FrontendURL string // "frontend_url"
}

// Path returns ~/.unbound/config.json (UNBOUND_CONFIG_PATH in python).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".unbound", "config.json"), nil
}

// GatewayURL resolves the gateway base URL: UNBOUND_GATEWAY_URL if set
// (python os.environ.get treats a set-but-empty variable as set), else
// DefaultGatewayURL; trailing '/' stripped like python's rstrip("/").
func GatewayURL() string {
	url, ok := os.LookupEnv("UNBOUND_GATEWAY_URL")
	if !ok {
		url = DefaultGatewayURL
	}
	return strings.TrimRight(url, "/")
}

// Read parses ~/.unbound/config.json. A missing file returns fs.ErrNotExist
// (python's FileNotFoundError branch); other read/parse failures return
// their error so callers can log them the way the python modules do.
func Read() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}
	return readFile(path)
}

func readFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, err
	}
	str := func(key string) string {
		if s, ok := raw[key].(string); ok {
			return s
		}
		return ""
	}
	return Config{
		APIKey:      str("api_key"),
		BaseURL:     str("base_url"),
		GatewayURL:  str("gateway_url"),
		FrontendURL: str("frontend_url"),
	}, nil
}

// APIKey resolves the API key for a tool: the tool's env var when non-empty
// (python: `if key:` — a set-but-empty var falls through), then config.json.
// codex never falls back to config.json (its main() reads only the env var).
// A missing config file yields ("", nil), mirroring the silent
// FileNotFoundError branch; any other failure is returned for the caller to
// log ('config' category in python).
func APIKey(tool string) (string, error) {
	if env := APIKeyEnvVars[tool]; env != "" {
		if key := os.Getenv(env); key != "" {
			return key, nil
		}
	}
	if tool == "codex" {
		return "", nil
	}
	cfg, err := Read()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return cfg.APIKey, nil
}
