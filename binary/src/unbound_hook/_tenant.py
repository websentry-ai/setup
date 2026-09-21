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
config.json, one that is not a regular file, or a `gateway_url` that is not a
clean https base URL, leaves the environment untouched (the module then uses
its built-in default). This never raises, never blocks and never writes to
stdout — stdout is the hook protocol channel.
"""

import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlparse

GATEWAY_ENV = "UNBOUND_GATEWAY_URL"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

# config.json is a handful of short strings; anything beyond this is not ours.
_MAX_CONFIG_BYTES = 1024 * 1024

# The modules hand "<gateway>/v1/hooks/..." to curl, which expands {a,b} and
# [1-3] into several requests — each carrying the bearer key. So the gateway is
# held to a conservative ASCII allowlist (no braces, backslashes, "@", "?",
# "#", whitespace, control or non-ASCII look-alike characters), and brackets
# are accepted only as the delimiters of an IPv6 literal host. "%" is for a
# percent-encoded path prefix only — never the authority (see below).
_GATEWAY_CHARS = re.compile(r"[A-Za-z0-9.\-:\[\]/_~%]+")
_IPV6_NETLOC = re.compile(r"\[[0-9A-Fa-f:.]+\](:[0-9]*)?")


def _clean_gateway_url(value):
    """The normalized https gateway base URL, or None if `value` isn't one."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    if not _GATEWAY_CHARS.fullmatch(value):
        return None
    try:
        parsed = urlparse(value)
        parsed.port  # raises ValueError on a port that doesn't parse
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    # urlparse leaves the authority percent-encoded, so "%40" / "%2F" / "%3A"
    # slip past the "@", path and port checks; curl then either rejects the URL
    # outright or decodes it — neither is the host the value appears to name.
    if "%" in parsed.netloc:
        return None
    if "[" in parsed.path or "]" in parsed.path:
        return None
    if ("[" in parsed.netloc or "]" in parsed.netloc) and not _IPV6_NETLOC.fullmatch(parsed.netloc):
        return None
    return value


def _read_config_bytes(path):
    """Up to _MAX_CONFIG_BYTES + 1 bytes of `path`, or None if it isn't a
    regular file. Symlinks are followed, as the hook modules follow them for
    the same file. O_NONBLOCK so a FIFO planted at the path can't hang the
    hook on open(); the POSIX-only flags are looked up so this stays
    importable everywhere."""
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(str(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, remaining = [], _MAX_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def apply_tenant_gateway() -> None:
    """Export the recorded tenant gateway before a hook module is imported."""
    try:
        if (os.environ.get(GATEWAY_ENV) or "").strip():
            return
        # Same location the hook modules read api_key / base_url from.
        raw = _read_config_bytes(Path.home() / ".unbound" / "config.json")
        if raw is None or len(raw) > _MAX_CONFIG_BYTES:
            return
        config = json.loads(raw.decode("utf-8"))
        if not isinstance(config, dict):
            return
        gateway = _clean_gateway_url(config.get("gateway_url"))
        if gateway is None or gateway == DEFAULT_GATEWAY_URL:
            return
        os.environ[GATEWAY_ENV] = gateway
    except Exception:
        pass
