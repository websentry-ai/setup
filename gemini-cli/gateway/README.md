# Gemini CLI Setup for Unbound Gateway

Usage
```
python3 <(curl -fsSL https://getunbound.ai/setup/gemini-cli/gateway/install) --domain <DOMAIN>
```

```
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/gemini-cli/gateway/setup.py) --domain <DOMAIN>
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).
