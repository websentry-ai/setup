# Copilot Hooks Setup
## Usage

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/copilot/hooks/install) --domain gateway.getunbound.ai
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/setup.py) --domain gateway.getunbound.ai
```

Or with an API key directly:

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/copilot/hooks/install) --api-key YOUR_API_KEY
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/setup.py) --api-key YOUR_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

## Clear Setup

```bash
python3 <(curl -fsSL https://getunbound.ai/setup/copilot/hooks/install) --clear
```

```bash
python3 <(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/setup.py) --clear
```
