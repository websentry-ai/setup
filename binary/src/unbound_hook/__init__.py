"""unbound-hook — self-contained CLI packaging the Unbound agent hooks.

Wraps the four existing hook modules (claude-code, cursor, copilot, codex)
plus the MDM setup/backfill/clear flows into one PyInstaller onedir binary
for fleets without python3 (WEB-4786).
"""

__version__ = "0.1.6"
