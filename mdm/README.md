# mdm-onboard

Runs all four MDM setup steps for an admin device enrollment in one shot:

1. **Claude Code** MDM setup
2. **Cursor** MDM setup
3. **Codex** MDM setup
4. **Coding-discovery** scan (separate repo, separate API key)

Steps 1–3 use `--api-key` (the admin MDM key). Step 4 uses `--discovery-key` (a separate discovery-specific key — the two are different credentials and the backend distinguishes them).

Each step runs in its own subprocess; a failure in one does not abort the others. A summary at the end lists which steps succeeded and which failed.

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" \
    --api-key YOUR_ADMIN_API_KEY \
    --discovery-key YOUR_DISCOVERY_KEY
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" \
    --api-key YOUR_ADMIN_API_KEY \
    --discovery-key YOUR_DISCOVERY_KEY
```

Optional overrides for tenant deployments: `--backend-url <url>`, `--gateway-url <url>` (defaults: `https://backend.getunbound.ai`, `https://api.getunbound.ai`). The `--backend-url` value also becomes the discovery scan's `--domain`.

### Clearing Setup

Removes MDM configuration for the three tools. Discovery is skipped — it's a one-shot scan with nothing to remove.

```bash
sudo python3 -c "$(curl -fsSL https://getunbound.ai/setup/mdm/onboard)" --clear
```

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/mdm/onboard.py)" --clear
```
