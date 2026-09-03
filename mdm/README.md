# mdm-onboard

Runs all five MDM setup steps for an admin device enrollment in one shot:

1. **Claude Code** MDM setup
2. **Cursor** MDM setup
3. **Codex** MDM setup
4. **GitHub Copilot** MDM setup
5. **Coding-discovery** scan (separate repo)

All steps use `--api-key` (the admin MDM key). The backend accepts the admin key for discovery uploads, so a separate discovery key is no longer needed. `--discovery-key` / `-DiscoveryKey` is still accepted for back-compat (deprecated) and, when given, is used for the discovery scan in place of the admin key.

Each step runs in its own subprocess; a failure in one does not abort the others. A summary at the end lists which steps succeeded and which failed.

## Windows

MDM setup requires Administrator privileges. Download and execute the PowerShell wrapper:

```powershell
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/windows/onboard' -OutFile onboard.ps1; .\onboard.ps1 -ApiKey YOUR_ADMIN_API_KEY
```

The wrapper automatically:
- Checks for Administrator privileges
- Detects Python (py/python3/python)
- Downloads and executes onboard.py
- Deletes itself after completion

Optional parameters:
```powershell
# Tenant deployment URLs
.\onboard.ps1 -ApiKey YOUR_KEY -BackendUrl https://backend.example.com -GatewayUrl https://api.example.com

# Enable backfill of historical transcripts (opt-in)
.\onboard.ps1 -ApiKey YOUR_KEY -Backfill

# Claude Code only: install the hook script, leave managed-settings.json alone
.\onboard.ps1 -ApiKey YOUR_KEY -SkipManagedSettings
```

### Clearing Setup (Windows)

```powershell
Invoke-WebRequest -Uri 'https://getunbound.ai/setup/mdm/windows/onboard' -OutFile onboard.ps1; .\onboard.ps1 -Clear
```

## macOS/Linux

MDM setup requires root privileges. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
    --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" \
    --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`). The `--backend-url` value also becomes the discovery scan's `--domain`.

`--skip-managed-settings` is passed to the **Claude Code** step only: it installs the hook script and leaves `managed-settings.json` alone, for orgs whose Claude Code policy is managed remotely from the Anthropic admin console. See `claude-code/hooks/mdm/README.md` for the ordering caveats.

### Clearing Setup (macOS/Linux)

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" --clear
```
