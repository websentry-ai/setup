# cursor-mdm-setup

Allowed app names: JumpCloud

MDM setup requires root. Pass the script to `python3 -c` via command substitution — bash process substitution `<(...)` does not survive the `sudo` boundary and fails with `Bad file descriptor`.

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/mdm/setup.py)" --api-key YOUR_API_KEY
```

### Clearing Setup

```bash
sudo python3 -c "$(curl -fsSL https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/mdm/setup.py)" --clear
```
