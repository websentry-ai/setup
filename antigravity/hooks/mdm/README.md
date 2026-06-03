# Antigravity Hooks - MDM Setup

Device-wide installation of Unbound hooks for Antigravity. Requires root.

```bash
sudo python3 setup.py --api-key <mdm-admin-api-key>
```

Optional flags: `--backend-url <url>`, `--gateway-url <url>`, `--app_name <name>`.

Uninstall:

```bash
sudo python3 setup.py --clear
```

The MDM installer enumerates every user on the device, fetches a per-device API key from the Unbound backend, drops privileges to each user, and writes `~/.antigravity/settings.json` plus `~/.antigravity/hooks/unbound_*.py` for that user. A marker is dropped at `/etc/unbound/antigravity.policy.json` (or `%ProgramFiles%\Unbound\antigravity.policy.json` on Windows) so reruns are idempotent.
