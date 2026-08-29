package config

import (
	"os"
	"path/filepath"
	"testing"
)

func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func writeConfig(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".unbound")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayURLDefault(t *testing.T) {
	os.Unsetenv("UNBOUND_GATEWAY_URL")
	if got := GatewayURL(); got != "https://api.getunbound.ai" {
		t.Errorf("GatewayURL() = %q", got)
	}
}

func TestGatewayURLEnvAndRstrip(t *testing.T) {
	t.Setenv("UNBOUND_GATEWAY_URL", "https://tenant.example.com///")
	if got := GatewayURL(); got != "https://tenant.example.com" {
		t.Errorf("GatewayURL() = %q", got)
	}
}

func TestGatewayURLSetButEmptyCountsAsSet(t *testing.T) {
	// python os.environ.get returns "" for a set-but-empty var.
	t.Setenv("UNBOUND_GATEWAY_URL", "")
	if got := GatewayURL(); got != "" {
		t.Errorf("GatewayURL() = %q, want empty", got)
	}
}

func TestAPIKeyEnvWins(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{"api_key": "from-config"}`)
	t.Setenv("UNBOUND_CLAUDE_API_KEY", "from-env")
	key, err := APIKey("claude-code")
	if err != nil || key != "from-env" {
		t.Errorf("APIKey = %q, %v", key, err)
	}
}

func TestAPIKeyEmptyEnvFallsThroughToConfig(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{"api_key": "from-config"}`)
	t.Setenv("UNBOUND_CLAUDE_API_KEY", "") // falsy in python: falls through
	key, err := APIKey("claude-code")
	if err != nil || key != "from-config" {
		t.Errorf("APIKey = %q, %v", key, err)
	}
}

func TestAPIKeyCodexNeverReadsConfig(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{"api_key": "from-config"}`)
	os.Unsetenv("UNBOUND_CODEX_API_KEY")
	key, err := APIKey("codex")
	if err != nil || key != "" {
		t.Errorf("APIKey(codex) = %q, %v; codex is env-only", key, err)
	}
	t.Setenv("UNBOUND_CODEX_API_KEY", "codex-env")
	if key, _ := APIKey("codex"); key != "codex-env" {
		t.Errorf("APIKey(codex) = %q", key)
	}
}

func TestAPIKeyMissingFileIsSilent(t *testing.T) {
	withHome(t)
	os.Unsetenv("UNBOUND_CURSOR_API_KEY")
	key, err := APIKey("cursor")
	if err != nil || key != "" {
		t.Errorf("APIKey = %q, %v; want silent empty (FileNotFoundError branch)", key, err)
	}
}

func TestAPIKeyCorruptConfigReturnsError(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{not json`)
	os.Unsetenv("UNBOUND_COPILOT_API_KEY")
	if _, err := APIKey("copilot"); err == nil {
		t.Error("expected error for corrupt config.json (python logs it)")
	}
}

func TestReadAllFields(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{
		"api_key": "k",
		"base_url": "https://backend.example.com",
		"gateway_url": "https://gw.example.com",
		"frontend_url": "https://fe.example.com",
		"extra": 42
	}`)
	cfg, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		APIKey:      "k",
		BaseURL:     "https://backend.example.com",
		GatewayURL:  "https://gw.example.com",
		FrontendURL: "https://fe.example.com",
	}
	if cfg != want {
		t.Errorf("Read() = %+v, want %+v", cfg, want)
	}
}

func TestReadNonStringFieldTreatedAsMissing(t *testing.T) {
	home := withHome(t)
	writeConfig(t, home, `{"api_key": 12345, "base_url": "ok"}`)
	cfg, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "" || cfg.BaseURL != "ok" {
		t.Errorf("Read() = %+v", cfg)
	}
}
