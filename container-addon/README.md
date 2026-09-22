# Unbound container add-on

Installs the canonical Unbound hook plus managed settings so AI coding tools (Claude Code)
enforce Unbound policy inside a container. The hook is sourced directly from this repo's
[`claude-code/hooks/unbound.py`](../claude-code/hooks/unbound.py) — it is not vendored, so the
add-on never drifts from the canonical copy.

## Two delivery methods

| Method | Reference | How it's consumed |
|---|---|---|
| devcontainer Feature | `ghcr.io/websentry-ai/setup/unbound-hooks:<v>` | Add to the `features` block of `devcontainer.json`. Installs `python3` + `curl` best-effort. |
| `COPY --from` add-on | `ghcr.io/websentry-ai/setup/addon:<v>` | `COPY --from=…/addon:<v> / /` onto any base image that already has (or installs) `python3` + `curl`. Multi-arch (amd64/arm64). |

The Feature is the turn-key path: it installs dependencies for you. The `COPY --from` add-on is a
`scratch` payload (hook + managed settings + `link-unbound.sh`) and expects the base image to
provide `python3` + `curl` — install them yourself (see the consumer Dockerfile below).

## Supported base images

| Base | `COPY --from` add-on | Feature |
|---|---|---|
| Debian / Ubuntu (apt) | ✅ | ✅ |
| RHEL / Fedora / CentOS (dnf/yum/microdnf) | ✅ | ✅ |
| Alpine (musl, apk) | ✅ (base needs python3+curl) | ✅ |
| Distroless / no package manager | ❌ | ❌ |

Notes:

- The hook needs **python3** + **curl**. The Feature installs both best-effort across
  apt/apk/dnf/microdnf/yum. For the `COPY --from` add-on you install them yourself.
- Device-serial identity **degrades gracefully** where `dmidecode` is absent (e.g. Alpine, most
  rootless containers) — this is non-fatal; the hook still enforces policy.
- The add-on image is **multi-arch** (amd64/arm64), so `COPY --from` works on both.

## Credentials

The hook resolves credentials at runtime from `UNBOUND_CLAUDE_API_KEY` in the env **or** a mounted
`~/.unbound/config.json`. To supply the host config, mount it into the container. Two patterns:

### Single user

Mount the host config straight into the running user's home:

```jsonc
// devcontainer.json
"mounts": [
  "source=${localEnv:HOME}/.unbound/config.json,target=${containerEnv:HOME}/.unbound/config.json,type=bind,readonly"
]
```

### Any user / su-sudo switches

If the container switches users (`su`/`sudo`), mount to a shared path and let the bundled
`link-unbound.sh` symlink it into every user's home:

```jsonc
// devcontainer.json
"mounts": [
  "source=${localEnv:HOME}/.unbound/config.json,target=/usr/local/share/unbound/config.json,type=bind,readonly"
]
```

- With the **Feature**, `link-unbound.sh` is auto-run via the Feature's `postStartCommand` — no
  extra config needed.
- With the **`COPY --from` add-on**, add the `postStartCommand` yourself:

  ```jsonc
  "postStartCommand": "sudo -n sh /usr/local/share/unbound/link-unbound.sh 2>/dev/null || sh /usr/local/share/unbound/link-unbound.sh"
  ```

**0600-perm caveat:** a `0600` host config is readable by root and the owning uid (so root + the
owner work fine), but a *third*, non-root uid cannot read it through the symlink. For that case,
relax the host file to `0644` or copy the config per-user instead of symlinking.

## OS-agnostic consumer Dockerfile (`COPY --from` path)

Install `python3` + `curl` with whatever package manager the base image has, then copy the add-on
payload on top. See [`consumer.Dockerfile.example`](./consumer.Dockerfile.example) for a complete
minimal example.

```dockerfile
RUN set -eu; \
  if   command -v apt-get  >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends python3 curl && rm -rf /var/lib/apt/lists/*; \
  elif command -v apk      >/dev/null 2>&1; then apk add --no-cache python3 curl; \
  elif command -v dnf      >/dev/null 2>&1; then dnf install -y python3 curl; \
  elif command -v microdnf >/dev/null 2>&1; then microdnf install -y python3 curl; \
  elif command -v yum      >/dev/null 2>&1; then yum install -y python3 curl; \
  else echo "need python3 + curl: no supported package manager" >&2; exit 1; fi
COPY --from=ghcr.io/websentry-ai/setup/addon:<v> / /
```

## Out of scope

- **Windows containers** — different managed-settings path (`C:\ProgramData\ClaudeCode\…`), no POSIX
  `sh`, and the interpreter is `python` not `python3`. A separate future track.
- **Distroless / no package manager** — `python3` + `curl` cannot be installed, so the hook cannot run.
- **Other AI tools beyond Claude Code** — Cursor/Codex/Copilot hooks exist elsewhere in this repo but
  are not packaged into this add-on yet. Future work.
