"""The unbound-hooks dev-container Feature must govern what it claims to govern.

The Feature ships an install.sh that runs at image-build time. It advertises
Claude Code and Cursor, so both hooks have to actually land — Claude Code at
/unbound + /etc/claude-code, Cursor at the enterprise-managed /etc/cursor.

install.sh can't be executed here (it writes to absolute system paths as root),
so these read it statically and pin the Cursor placement to the one source of
truth for "where Cursor reads managed hooks on Linux": cursor/mdm/setup.py's
get_enterprise_hooks_dir(). If MDM's Linux path ever moves, this fails and forces
the Feature to track it, instead of the container silently governing nothing.
"""

import re

import pytest

from tests.conftest import REPO, load_module

FEATURE_DIR = REPO / "devcontainer-feature" / "src" / "unbound-hooks"
INSTALL_SH = (FEATURE_DIR / "install.sh").read_text(encoding="utf-8")
FEATURE_JSON = (FEATURE_DIR / "devcontainer-feature.json").read_text(encoding="utf-8")


def _linux_enterprise_dir():
    """The exact dir cursor/mdm/setup.py hands Cursor's managed hooks on Linux."""
    mdm = load_module("cursor/mdm/setup.py")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mdm.platform, "system", lambda: "Linux")
        return mdm.get_enterprise_hooks_dir()


def test_claude_code_hook_and_managed_settings_land():
    """The pre-existing behaviour, guarded so a Cursor edit can't regress it."""
    assert "install -D -m 0755 \"$HERE/unbound.py\" /unbound/unbound.py" in INSTALL_SH
    assert "/etc/claude-code/managed-settings.json" in INSTALL_SH


def test_cursor_hook_lands_at_the_mdm_linux_enterprise_path():
    """Cursor is governed only if its hook + config sit where Cursor looks on Linux."""
    enterprise = _linux_enterprise_dir()  # /etc/cursor per the MDM installer
    hooks_json = f"{enterprise}/hooks.json"
    script = f"{enterprise}/hooks/unbound.py"

    assert f"install -D -m 0755 \"$HERE/cursor-unbound.py\" {script}" in INSTALL_SH, \
        f"install.sh must place the Cursor hook at {script}"
    assert f"install -D -m 0644 \"$HERE/cursor-hooks.json\" {hooks_json}" in INSTALL_SH, \
        f"install.sh must place the Cursor hooks.json at {hooks_json}"


def test_cursor_hooks_json_relative_command_resolves_to_the_installed_script():
    """cursor/hooks.json invokes the hook by a path relative to hooks.json's own dir.
    The container layout only governs Cursor if that relative path lands on the script
    install.sh actually writes."""
    import json

    enterprise = str(_linux_enterprise_dir())
    hooks = json.loads((REPO / "cursor" / "hooks.json").read_text(encoding="utf-8"))
    commands = {
        entry["command"]
        for event in hooks["hooks"].values()
        for entry in event
    }
    # Every command is the same relative reference; resolve it from the hooks.json dir.
    assert commands == {"./hooks/unbound.py"}, commands
    resolved = f"{enterprise}/hooks/unbound.py"
    assert f"{resolved}" in INSTALL_SH, \
        f"hooks.json's ./hooks/unbound.py resolves to {resolved}, which install.sh must write"


def test_every_installed_source_file_is_present_or_vendored_by_ci():
    """install.sh copies each `$HERE/<file>` into the image. A referenced file that is
    neither committed nor vendored by the publish workflow is a broken build."""
    workflow = (REPO / ".github" / "workflows" / "publish-feature.yml").read_text(encoding="utf-8")
    referenced = set(re.findall(r'\$HERE/([A-Za-z0-9._-]+)', INSTALL_SH))
    assert referenced, "no $HERE/<file> references found — did install.sh change shape?"
    for name in referenced:
        committed = (FEATURE_DIR / name).exists()
        vendored = f"devcontainer-feature/src/unbound-hooks/{name}" in workflow
        assert committed or vendored, \
            f"{name} is referenced by install.sh but neither committed nor vendored by CI"


def test_the_description_names_both_tools_it_governs():
    """Truth-in-labelling, now that Cursor is actually configured."""
    desc = __import__("json").loads(FEATURE_JSON)["description"]
    assert "Claude Code" in desc and "Cursor" in desc, desc
