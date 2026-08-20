# Claude Code Hooks - MDM Setup

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

`--skip-managed-settings` installs only the hook script (`<managed settings dir>/hooks/unbound.py`) and writes no hook config of its own: `managed-settings.json` is never created, and an existing one has Unbound's hooks stripped out of it (same matching `--clear` uses), with any org policy in the same file left untouched. Use it for orgs on a Claude Enterprise / Teams plan whose Claude Code policy is managed remotely from the Anthropic admin console: remote settings override the file-based ones, so a local copy is ignored anyway and only leaves the device able to enforce from two places. Their admin must point the remote policy's hook commands at the installed script path. Set the remote policy up before running this, not after: like every MDM run it strips any user-level Unbound hooks, so nothing enforces on the device until the remote policy names the script.

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --clear
```
