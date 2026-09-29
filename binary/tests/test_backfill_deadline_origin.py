"""One binary process runs every tool's backfill: each tool must get its own
deadline origin, or a slow earlier tool starves the later ones (exit 0)."""
import time
from unittest.mock import patch

from unbound_hook import backfill_cmd
from unbound_hook._loader import load_mdm_setup_module


def test_backfill_cmd_reorigins_the_deadline_per_tool(tmp_path):
    m = load_mdm_setup_module("claude-code")
    m._SCRIPT_START = time.time() - 10_000  # a slow earlier tool spent the budget
    ran = {}

    def fake_run_backfill(api_key, backend_url, user_homes):
        ran["origin"] = m._SCRIPT_START
        ran["has_time"] = m.BACKFILL_SOFT_STOP_SECONDS - (time.time() - m._SCRIPT_START) > 0

    with patch.object(m, "check_admin_privileges", return_value=True), \
         patch.object(m, "get_all_user_homes", return_value=[("u", tmp_path)]), \
         patch.object(backfill_cmd, "_read_user_config",
                      return_value={"api_key": "k", "base_url": "https://b"}), \
         patch.object(m, "run_backfill", side_effect=fake_run_backfill):
        code = backfill_cmd.run(["--all", "--tools", "claude-code"])

    assert code == 0
    assert time.time() - ran["origin"] < 60, "origin must be this tool's turn, not import"
    assert ran["has_time"], "the tool must start with a full soft-stop budget"
