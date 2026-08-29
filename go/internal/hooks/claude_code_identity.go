package hooks

// Account identity + device serial for the claude-code port
// (claude-code/hooks/unbound.py lines 674-831).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/websentry-ai/setup/go/internal/pyjson"
)

// placeholderSerials mirrors _PLACEHOLDER_SERIALS (713-719): DMI/BIOS
// serials that are shared sentinel strings on VMs and OEM boards — treat as
// "no serial" so machines never collide on the same fake value.
var placeholderSerials = map[string]bool{
	"": true, "0": true, "00000000": true, "000000000": true, "0000000000": true,
	"none": true, "na": true, "n/a": true,
	"unknown": true, "default": true, "default string": true,
	"to be filled by o.e.m.": true, "to be filled by oem": true,
	"system serial number": true, "serial number": true,
	"not applicable": true, "not specified": true, "not available": true,
	"oem": true, "o.e.m.": true, "invalid": true, "123456789": true, "xxxxxxxx": true,
}

// validSerial mirrors _valid_serial (722-723).
func validSerial(value string) bool {
	return value != "" && !placeholderSerials[strings.ToLower(strings.TrimSpace(value))]
}

// runProbe runs a probe command with a hard timeout, mirroring
// subprocess.run(capture_output=True, text=True, timeout=N). ok is the
// returncode == 0 check; timeouts and spawn failures report !ok.
func runProbe(timeout time.Duration, name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return "", false
	}
	return string(out), true
}

// getDeviceSerial mirrors _get_device_serial (726-775): best-effort
// hardware serial, filtering placeholders, falling through to a stable
// per-install id. "" stands in for python's None.
func getDeviceSerial() string {
	switch runtime.GOOS {
	case "darwin":
		if out, ok := runProbe(10*time.Second, "system_profiler", "SPHardwareDataType"); ok {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "Serial Number") {
					parts := strings.SplitN(line, ": ", 2)
					if len(parts) >= 2 && validSerial(parts[1]) {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	case "linux":
		if out, ok := runProbe(10*time.Second, "dmidecode", "-s", "system-serial-number"); ok && validSerial(out) {
			return strings.TrimSpace(out)
		}
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if data, err := os.ReadFile(path); err == nil {
				value := strings.TrimSpace(string(data))
				if validSerial(value) {
					return value
				}
			}
		}
	case "windows":
		if out, ok := runProbe(10*time.Second, "powershell", "-NoProfile", "-Command",
			"(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"); ok && validSerial(out) {
			return strings.TrimSpace(out)
		}
		if out, ok := runProbe(10*time.Second, "powershell", "-NoProfile", "-Command",
			`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid`); ok && validSerial(out) {
			return strings.TrimSpace(out)
		}
	}
	return ""
}

// deviceSerial mirrors _device_serial (778-811): cache-first, probe only
// when probe=true (SessionStart and the end-of-turn exchange; the
// latency-critical pre-tool path passes false). The cache is shared with
// the cursor hook, so it is merged and written atomically.
func (c *claudeCodeHook) deviceSerial(probe bool) string {
	data := pyjson.NewObject()
	if raw, err := os.ReadFile(c.identityCache); err == nil {
		if parsed, perr := pyjson.Loads(raw); perr == nil {
			if obj, ok := parsed.(*pyjson.Object); ok {
				data = obj
				if cached, ok := obj.GetDefault("device_serial", nil).(string); ok && strings.TrimSpace(cached) != "" {
					return strings.TrimSpace(cached)
				}
			}
		}
	}
	if !probe {
		return ""
	}
	serial := getDeviceSerial()
	if serial != "" {
		data.Set("device_serial", serial)
		if err := os.MkdirAll(filepath.Dir(c.identityCache), 0o755); err == nil {
			if s, err := pyjson.Dumps(data); err == nil {
				tmp := filepath.Join(filepath.Dir(c.identityCache), fmt.Sprintf(".identity.%d.tmp", os.Getpid()))
				if os.WriteFile(tmp, []byte(s), 0o644) == nil {
					_ = os.Rename(tmp, c.identityCache)
				}
			}
		}
	}
	return serial
}

// orNone mirrors `value or None`: falsy collapses to nil.
func orNone(v any) any {
	if pyjson.Truthy(v) {
		return v
	}
	return nil
}

// emailDomain mirrors _email_domain (674-681). Any non-string input ends
// as None in python (TypeError into the bare except, or a failed rsplit).
func emailDomain(email any) any {
	s, ok := email.(string)
	if !ok || s == "" || !strings.Contains(s, "@") {
		return nil
	}
	domain := strings.ToLower(strings.TrimSpace(s[strings.LastIndex(s, "@")+1:]))
	if domain == "" {
		return nil
	}
	return domain
}

// readAccountIdentity mirrors read_account_identity (684-707): pulled from
// ~/.claude.json; every failure leaves the fields None.
func (c *claudeCodeHook) readAccountIdentity() *pyjson.Object {
	var orgID, plan, authMode, email any
	func() {
		data, err := os.ReadFile(c.claudeConfig)
		if err != nil {
			return
		}
		parsed, perr := pyjson.Loads(data)
		if perr != nil {
			return
		}
		cfg, ok := parsed.(*pyjson.Object)
		if !ok {
			return
		}
		if oauth, ok := cfg.GetDefault("oauthAccount", nil).(*pyjson.Object); ok {
			orgID = orNone(oauth.GetDefault("organizationUuid", nil))
			plan = orNone(oauth.GetDefault("organizationType", nil))
			email = orNone(oauth.GetDefault("emailAddress", nil))
			authMode = "subscription"
			return
		}
		if os.Getenv("ANTHROPIC_API_KEY") != "" {
			authMode = "api_key"
			return
		}
		cak := cfg.GetDefault("customApiKeyResponses", nil)
		if !pyjson.Truthy(cak) {
			return // (None or {}).get('approved') -> None
		}
		cakObj, ok := cak.(*pyjson.Object)
		if !ok {
			return // .get on a non-dict raised into the bare except
		}
		if pyjson.Truthy(cakObj.GetDefault("approved", nil)) {
			authMode = "api_key"
		}
	}()
	return pyjson.NewObject().
		Set("org_id", orgID).
		Set("plan", plan).
		Set("auth_mode", authMode).
		Set("user_email", email).
		Set("email_domain", emailDomain(email))
}

// buildAccountIdentity mirrors build_account_identity (814-831): the
// account identity plus the (possibly cached-only) device serial.
func (c *claudeCodeHook) buildAccountIdentity(probe bool) *pyjson.Object {
	identity := c.readAccountIdentity()
	if serial := c.deviceSerial(probe); serial != "" {
		identity.Set("device_serial", serial)
	}
	return identity
}
