# Claude Code Hooks - MDM Setup

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

`--skip-managed-settings` installs only the hook script (`<managed settings dir>/hooks/unbound.py`) and neither creates nor modifies `managed-settings.json`. Use it for orgs on a Claude Enterprise / Teams plan whose Claude Code policy is managed remotely from the Anthropic admin console: remote settings override the file-based ones, so the local file is ignored anyway. Their admin must point the remote policy's hook commands at the installed script path. Set the remote policy up before running this, not after: like every MDM run it strips any user-level Unbound hooks, so nothing enforces on the device until the remote policy names the script. On a device that already has a full MDM install, run `--clear` first: the flag leaves an existing `managed-settings.json` exactly as it is, hooks included.

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --clear
```
