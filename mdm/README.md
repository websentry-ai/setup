# mdm-onboard

Runs all five MDM setup steps for an admin device enrollment in one shot:

1. **Claude Code** MDM setup
2. **Cursor** MDM setup
3. **Codex** MDM setup
4. **GitHub Copilot** MDM setup
5. **Coding-discovery** scan (separate repo, separate API key)

Steps 1–4 use `--api-key` (the admin MDM key). Step 5 uses `--discovery-key` (a separate discovery-specific key — the two are different credentials and the backend distinguishes them).

Each step runs in its own subprocess; a failure in one does not abort the others. A summary at the end lists which steps succeeded and which failed.

## Windows

MDM setup requires Administrator privileges. Download and execute the PowerShell wrapper:

```powershell
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/onboard.ps1' -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_API_KEY -DiscoveryKey YOUR_DISCOVERY_KEY
```

The wrapper automatically:
- Checks for Administrator privileges
- Detects Python (py/python3/python)
- Downloads and executes onboard.py
- Deletes itself after completion

Optional parameters:
```powershell
# Tenant deployment URLs
.\onboard.ps1 -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY -BackendUrl https://backend.example.com -GatewayUrl https://api.example.com

# Explicit backfill (enabled by default, but can be specified for clarity)
.\onboard.ps1 -ApiKey YOUR_KEY -DiscoveryKey YOUR_KEY -Backfill
```

### Clearing Setup (Windows)

```powershell
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/onboard.ps1' -OutFile onboard.ps1; .\onboard.ps1 -Clear
```

## macOS/Linux

MDM setup requires root privileges. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
    --api-key YOUR_ADMIN_API_KEY \
    --discovery-key YOUR_DISCOVERY_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" \
    --api-key YOUR_ADMIN_API_KEY \
    --discovery-key YOUR_DISCOVERY_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`). The `--backend-url` value also becomes the discovery scan's `--domain`.

### Clearing Setup (macOS/Linux)

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" --clear
```
