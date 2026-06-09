#!/bin/sh
# Bundled by unbound-hooks: symlink a mounted Unbound config into every user's home so the
# hook (which reads $HOME/.unbound/config.json) works as ANY user, incl. after su/sudo.
# The host-mounted config is the source of truth and intentionally overrides any
# container-local config (a local file must not shadow the host-enforced credential).
# Idempotent and best-effort; only acts when the host config is actually mounted.
SRC=/usr/local/share/unbound/config.json
if [ ! -e "$SRC" ]; then
  echo "unbound-hooks: $SRC not mounted; left existing configs untouched"
  exit 0
fi
linked=0; replaced=0
for h in /root /home/*; do
  [ -d "$h" ] || continue
  dest="$h/.unbound/config.json"
  # INTENTIONAL OVERRIDE: ln -sf below replaces whatever is at $dest, including a real
  # (non-symlink) config a user/image placed. This is by design for an enforcement tool —
  # the host-mounted config must win so a local file can't shadow the enforced credential.
  # We only COUNT real-file replacements here to surface them in the summary log (not skip).
  [ -e "$dest" ] && [ ! -L "$dest" ] && replaced=$((replaced+1))
  mkdir -p "$h/.unbound" 2>/dev/null || continue
  ln -sf "$SRC" "$dest" 2>/dev/null || continue
  u=$(stat -c %u "$h" 2>/dev/null) && g=$(stat -c %g "$h" 2>/dev/null) && {
    chown "$u:$g" "$h/.unbound" 2>/dev/null || true
    chown -h "$u:$g" "$dest" 2>/dev/null || true
  }
  linked=$((linked+1))
done
echo "unbound-hooks: linked host config into $linked home(s) (replaced $replaced local file(s))"
