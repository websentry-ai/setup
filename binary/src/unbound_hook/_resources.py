"""Locating vendored hook/setup sources and fixed install paths.

The binary vendors the EXISTING python modules as source data files — the
same bytes that serve the python path — so frozen behavior can't drift from
the scripts. In a repo checkout the modules are loaded straight from the
repo; in the frozen bundle they're loaded from PyInstaller's _MEIPASS.
"""

import sys
from pathlib import Path

# Fixed install layout (owned by the ai.getunbound.runtime pkg / WEB-4792).
INSTALL_ROOT = Path("/opt/unbound/current")
HOOK_BINARY = INSTALL_ROOT / "unbound-hook" / "unbound-hook"
DISCOVERY_BINARY = INSTALL_ROOT / "unbound-discovery" / "unbound-discovery"

# repo-relative source for each tool's hook module (stdin/stdout contract)
TOOL_HOOK_SOURCES = {
    "claude-code": "claude-code/hooks/unbound.py",
    "cursor": "cursor/unbound.py",
    "copilot": "copilot/hooks/unbound.py",
    "codex": "codex/hooks/unbound.py",
    "augment": "augment/hooks/unbound.py",
}

# repo-relative source for each tool's MDM setup module (setup/backfill/clear)
TOOL_MDM_SETUP_SOURCES = {
    "claude-code": "claude-code/hooks/mdm/setup.py",
    "cursor": "cursor/mdm/setup.py",
    "copilot": "copilot/hooks/mdm/setup.py",
    "codex": "codex/hooks/mdm/setup.py",
    "augment": "augment/hooks/mdm/setup.py",
}

TOOLS = tuple(TOOL_HOOK_SOURCES)

# Events each tool registers in its (managed) hook settings. The hook modules
# themselves dispatch on the stdin payload; these lists drive what `setup`
# writes and what the CLI-boundary tests cover.
TOOL_EVENTS = {
    "claude-code": ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop",
                    "SessionStart", "SessionEnd"),
    "codex": ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop",
              "SessionStart"),
    "copilot": ("SessionStart", "UserPromptSubmit", "PreToolUse",
                "PostToolUse", "Stop"),
    "augment": ("PreToolUse", "PostToolUse", "Stop", "SessionStart",
                "SessionEnd"),
    "cursor": ("preToolUse", "postToolUse", "beforeShellExecution",
               "beforeMCPExecution", "afterShellExecution",
               "afterMCPExecution", "afterFileEdit", "beforeReadFile",
               "beforeSubmitPrompt", "afterAgentResponse", "stop",
               "sessionStart"),
}


def resource_root() -> Path:
    """Directory holding the vendored module tree."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "vendored"
    # binary/src/unbound_hook/_resources.py -> repo root
    return Path(__file__).resolve().parents[3]


def hook_source_path(tool: str) -> Path:
    return resource_root() / TOOL_HOOK_SOURCES[tool]


def mdm_setup_source_path(tool: str) -> Path:
    return resource_root() / TOOL_MDM_SETUP_SOURCES[tool]


def hook_command_for_event(tool: str, event: str) -> str:
    """The command string written into managed hook settings.

    Quoted like the python path quoted its script path; the trailing
    tool+event args route the shared binary (the modules still read the
    event from stdin — argv is routing/diagnostics only).
    """
    return f'"{HOOK_BINARY}" hook {tool} {event}'
