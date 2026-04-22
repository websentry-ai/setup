# cursor-setup

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/cursor/install) --domain gateway.getunbound.ai
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/setup.py) --domain gateway.getunbound.ai
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).