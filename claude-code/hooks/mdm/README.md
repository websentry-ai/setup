# Claude Code Hooks - MDM Setup

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --api-key YOUR_ADMIN_API_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --api-key YOUR_ADMIN_API_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`).

### Tool policy skill

The `unbound-tool-policy` Claude Code skill steers Claude toward the AI-assisted policy creation endpoint rather than hand-authoring policy flags. It is installed per-user at `~/.claude/skills/unbound-tool-policy/SKILL.md` for every enumerated end user on the device. Installed during `setup.py`, removed during `setup.py --clear`. The skill is re-fetched from `main` on every run so content updates propagate without re-imaging. Source-of-truth lives at `claude-code/skills/unbound-tool-policy/SKILL.md` in this repo.

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/claude-code/hooks/mdm-install)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/mdm/setup.py)" --clear
```
