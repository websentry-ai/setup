# codex-mdm-setup

```bash
sudo python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/gateway/mdm/setup.py) --url https://backend.getunbound.ai --api_key YOUR_ADMIN_API_KEY
```

### Optional Parameters

- `--app_name JumpCloud` - Specify MDM provider
- `--debug` - Show detailed output

### Clearing Setup

```bash
sudo python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/gateway/mdm/setup.py) --clear
```
