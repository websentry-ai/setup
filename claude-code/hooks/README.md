# Claude Code Hooks for Unbound Gateway
Run the command to setup Claude Code Hooks with Unbound:

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/install) --domain gateway.getunbound.ai
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/setup.py) --domain gateway.getunbound.ai
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).
