"""The container images' Claude settings register the same hooks the installer writes."""
import json
from pathlib import Path

import pytest

from unbound_hook import setup_cmd

REPO = Path(__file__).resolve().parents[2]
MANAGED_SETTINGS = (REPO / "container-addon" / "managed-settings.json",
                    REPO / "devcontainer-feature" / "src" / "unbound-hooks" / "managed-settings.json")


@pytest.mark.parametrize("path", MANAGED_SETTINGS, ids=lambda path: path.parent.name)
def test_an_event_a_release_adds_is_in_the_container_file_as_the_installer_writes_it(path):
    installed = setup_cmd._claude_hooks_config()
    hooks = json.loads(path.read_text())["hooks"]
    assert set(setup_cmd._CLAUDE_EVENTS_ADDED) <= set(hooks)
    for event, entries in hooks.items():
        assert [entry.get("matcher") for entry in entries] == [entry.get("matcher") for entry in installed[event]], event
