#!/bin/sh
# Bundled by unbound-hooks: symlink a mounted Unbound config into every user's home so the
# hook (which reads $HOME/.unbound/config.json) works as ANY user, incl. after su/sudo.
# Idempotent and best-effort (skips homes it can't write). Consumers must mount the config
# to /usr/local/share/unbound/config.json (e.g. devcontainer.json mounts:
#   source=${localEnv:HOME}/.unbound/config.json,target=/usr/local/share/unbound/config.json,type=bind,readonly).
SRC=/usr/local/share/unbound/config.json
[ -e "$SRC" ] || exit 0   # nothing mounted -> nothing to link (hook can still use env)
for h in /root /home/*; do
  [ -d "$h" ] || continue
  mkdir -p "$h/.unbound" 2>/dev/null || continue
  ln -sf "$SRC" "$h/.unbound/config.json" 2>/dev/null || continue
  u=$(stat -c %u "$h" 2>/dev/null) && g=$(stat -c %g "$h" 2>/dev/null) && {
    chown "$u:$g" "$h/.unbound" 2>/dev/null || true
    chown -h "$u:$g" "$h/.unbound/config.json" 2>/dev/null || true
  }
done
exit 0
