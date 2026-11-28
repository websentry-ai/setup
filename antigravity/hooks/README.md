# Antigravity Hooks for Unbound Gateway

Run the command to set up Antigravity hooks with Unbound:

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/antigravity/hooks/setup.py) --domain gateway.getunbound.ai
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

If you already have an API key:

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/antigravity/hooks/setup.py) --api-key <your-key>
```

Uninstall:

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/antigravity/hooks/setup.py) --clear
```
