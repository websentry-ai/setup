# claude-code-mdm-setup

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/gateway/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/gateway/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

### Optional Parameters

- `--backend-url <url>` - Backend REST API host (default: `https://backend.getunbound.ai`)
- `--gateway-url <url>` - AI gateway host wired into ANTHROPIC_BASE_URL (default: `https://api.getunbound.ai`)
- `--app_name JumpCloud` - Specify MDM provider
- `--debug` - Show detailed output

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/gateway/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/gateway/mdm/setup.py)" --clear
```
