# Builds the Unbound container-hooks add-on image: a `scratch` image containing only
# the canonical in-container Python hook and the managed hook settings. It is meant to
# be consumed via
#
#   COPY --from=ghcr.io/websentry-ai/setup/addon:<tag> / /
#
# onto ANY base image that has python3 (the hook's only dependency). No host listener,
# no credentials, and no network egress are baked in — the hook resolves the key at
# runtime (UNBOUND_CLAUDE_API_KEY env passthrough or a mounted ~/.unbound/config.json,
# which the hook reads natively) and talks to the Unbound gateway directly over HTTPS.
#
# Zero-drift: the hook is sourced DIRECTLY from this repo's canonical copy at
# claude-code/hooks/unbound.py — it is NOT vendored, so the add-on is always current.
# The exporter/profile shell scripts from the standalone package are intentionally NOT
# shipped: the canonical hook reads ~/.unbound/config.json itself, so no shell env
# export bridge is needed.
#
# Build context = repo root (paths below are repo-root-relative):
#   docker build -f container-addon/Dockerfile -t unbound/addon:local .
# Multi-arch publish (payload is arch-independent, but we tag both for clean COPY --from):
#   docker buildx build --platform linux/amd64,linux/arm64 -f container-addon/Dockerfile \
#     -t ghcr.io/websentry-ai/setup/addon:0.1.0 --push .

FROM scratch AS addon
COPY claude-code/hooks/unbound.py /unbound/unbound.py
COPY container-addon/managed-settings.json /etc/claude-code/managed-settings.json
COPY container-addon/link-unbound.sh /usr/local/share/unbound/link-unbound.sh
