# Codex Hooks Setup

Sets up Unbound hooks for Codex CLI to enable tracking, analytics, and policy enforcement while using your OpenAI subscription.

## Usage

```bash
python3 <(curl -fsSl https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/setup.py) --domain gateway.getunbound.ai
```

Or with an API key directly:

```bash
python3 <(curl -fsSl https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/setup.py) --api-key YOUR_API_KEY
```

## Clear Setup

```bash
python3 <(curl -fsSl https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/setup.py) --clear
```
