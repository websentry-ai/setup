"""Resolve the tenant gateway for the vendored hook modules.

Every hook module fixes its gateway once, at import, from the
UNBOUND_GATEWAY_URL environment variable (default https://api.getunbound.ai).
`unbound-hook setup --gateway-url` records the tenant gateway as `gateway_url`
in each user's ~/.unbound/config.json, and the managed hook command carries no
env prefix — so the dispatcher exports the recorded value before the module is
imported. Exporting (rather than patching the module constant) also lets the
hook's detached children (sync-skills, mcp-diagnostic, error reporting)
inherit the same gateway.

Precedence: a non-blank UNBOUND_GATEWAY_URL already in the environment always
wins; config.json is only consulted when it is absent.

Fail-open is non-negotiable here: a missing, unreadable, oversized or corrupt
config.json, or a `gateway_url` that is not a clean https URL, leaves the
environment untouched (the module then uses its built-in default). This never
raises and never writes to stdout — stdout is the hook protocol channel.
"""

import json
import os
from pathlib import Path
from urllib.parse import urlparse

GATEWAY_ENV = "UNBOUND_GATEWAY_URL"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

# config.json is a handful of short strings; anything beyond this is not ours.
_MAX_CONFIG_BYTES = 1024 * 1024


def _clean_gateway_url(value):
    """The normalized https gateway URL, or None if `value` isn't one."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    if not value or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return None
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    # The modules append "/v1/hooks/..." to this string, so it must be a bare
    # base URL: no credentials, query or fragment, and a port that parses
    # (`.port` raises ValueError otherwise — caught by the caller).
    if parsed.username or parsed.password or "?" in value or "#" in value:
        return None
    parsed.port
    return value


def apply_tenant_gateway() -> None:
    """Export the recorded tenant gateway before a hook module is imported."""
    try:
        if (os.environ.get(GATEWAY_ENV) or "").strip():
            return
        # Same location the hook modules read api_key / base_url from.
        config_file = Path.home() / ".unbound" / "config.json"
        with open(config_file, "r", encoding="utf-8") as f:
            raw = f.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            return
        config = json.loads(raw)
        if not isinstance(config, dict):
            return
        gateway = _clean_gateway_url(config.get("gateway_url"))
        if gateway is None or gateway == DEFAULT_GATEWAY_URL:
            return
        os.environ[GATEWAY_ENV] = gateway
    except Exception:
        pass
