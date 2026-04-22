# Codex Hooks - MDM Setup

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/codex/hooks/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/codex/hooks/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/mdm/setup.py)" --clear
```
