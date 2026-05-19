# Copilot Hooks - MDM Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/copilot/hooks/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/copilot/hooks/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/mdm/setup.py)" --clear
```
