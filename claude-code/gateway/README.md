# Claude Code Setup for Unbound Gateway

## Setup with Browser Authentication

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/claude-code/gateway/install) --domain gateway.getunbound.ai
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/gateway/setup.py) --domain gateway.getunbound.ai
```

## Setup with API Key

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/gateway/setup_with_api_key.py) --api-key YOUR_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).
