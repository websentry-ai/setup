import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import unbound

DEFAULT = "https://api.getunbound.ai"
TENANT = "https://gateway.benchling.com"


def _script(default_url=DEFAULT, marker="v1"):
    return (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "UNBOUND_GATEWAY_URL = os.environ.get(\n"
        f'    "UNBOUND_GATEWAY_URL", "{default_url}"\n'
        ').rstrip("/")\n'
        f'_DECOY_URL = "{DEFAULT}"  # must survive rebake\n'
        f"# {marker}\n"
    )


class SelfUpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.script = self.tmp / "unbound.py"
        self.state = self.tmp / ".self_update_check"
        self.lock = self.tmp / ".self_update.lock"

        patchers = [
            patch.object(unbound, "SELF_SCRIPT_PATH", self.script),
            patch.object(unbound, "SELF_UPDATE_STATE_PATH", self.state),
            patch.object(unbound, "SELF_UPDATE_LOCK_PATH", self.lock),
            patch.object(unbound, "log_error", MagicMock()),
        ]
        for p in patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patchers])
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _result(self, body):
        result = MagicMock()
        result.returncode = 0
        result.stdout = body.encode() if isinstance(body, str) else body
        return result

    def _set_remote(self, body):
        run = patch.object(unbound.subprocess, "run", return_value=self._result(body))
        mock_run = run.start()
        self.addCleanup(run.stop)
        return mock_run

    def test_due_when_no_state(self):
        self.assertTrue(unbound._self_update_due())

    def test_not_due_when_fresh(self):
        self.state.touch()
        self.assertFalse(unbound._self_update_due())

    def test_due_when_stale(self):
        self.state.touch()
        old = time.time() - (unbound.SELF_UPDATE_INTERVAL_SECONDS + 60)
        os.utime(self.state, (old, old))
        self.assertTrue(unbound._self_update_due())

    def test_invalid_urls_rejected(self):
        for bad in ['https://a .com', 'https://a"b.com', 'ftp://x', 'https://a\nb', '']:
            self.assertFalse(unbound._is_valid_gateway_url(bad))

    def test_valid_urls_accepted(self):
        for ok in [DEFAULT, TENANT, "https://h:8443/v1", "http://localhost:3000"]:
            self.assertTrue(unbound._is_valid_gateway_url(ok))

    def test_rebake_preserves_tenant_url(self):
        self.script.write_text(_script(TENANT, "v1"))
        self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        out = self.script.read_text()
        self.assertIn(f'"UNBOUND_GATEWAY_URL", "{TENANT}"', out)
        self.assertIn("v2", out)

    def test_rebake_only_touches_env_line(self):
        self.script.write_text(_script(TENANT, "v1"))
        self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        out = self.script.read_text()
        self.assertIn(f'_DECOY_URL = "{DEFAULT}"', out)

    def test_two_cycle_tenant_survives(self):
        self.script.write_text(_script(TENANT, "v1"))
        with patch.object(unbound.subprocess, "run", return_value=self._result(_script(DEFAULT, "v2"))):
            unbound._check_self_update()
        self.state.unlink(missing_ok=True)
        with patch.object(unbound.subprocess, "run", return_value=self._result(_script(DEFAULT, "v3"))):
            unbound._check_self_update()
        out = self.script.read_text()
        self.assertIn(f'"UNBOUND_GATEWAY_URL", "{TENANT}"', out)
        self.assertIn("v3", out)
        self.assertNotIn(f'"UNBOUND_GATEWAY_URL", "{DEFAULT}"', out)

    def test_no_swap_when_unchanged(self):
        self.script.write_text(_script(TENANT, "v1"))
        self._set_remote(_script(DEFAULT, "v1"))
        before = self.script.read_bytes()
        unbound._check_self_update()
        self.assertEqual(self.script.read_bytes(), before)
        self.assertTrue(self.state.exists())

    def test_default_install_stays_default(self):
        self.script.write_text(_script(DEFAULT, "v1"))
        self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        out = self.script.read_text()
        self.assertIn(f'"UNBOUND_GATEWAY_URL", "{DEFAULT}"', out)
        self.assertIn("v2", out)

    def test_env_not_used_for_rebake(self):
        self.script.write_text(_script(TENANT, "v1"))
        self._set_remote(_script(DEFAULT, "v2"))
        with patch.dict(os.environ, {"UNBOUND_GATEWAY_URL": "https://attacker.test"}):
            unbound._check_self_update()
        out = self.script.read_text()
        self.assertIn(f'"UNBOUND_GATEWAY_URL", "{TENANT}"', out)
        self.assertNotIn("attacker.test", out)

    def test_invalid_baked_url_skips_download(self):
        self.script.write_text(_script("https://bad .com", "v1"))
        run = self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        run.assert_not_called()

    def test_skip_when_rebake_not_applied(self):
        original = _script(TENANT, "v1")
        self.script.write_text(original)
        # download passes the sentinel but env-line won't match _BAKED_GATEWAY_RE (single quotes)
        bad_remote = (
            "#!/usr/bin/env python3\n"
            "import os\n"
            "UNBOUND_GATEWAY_URL = os.environ.get('UNBOUND_GATEWAY_URL', 'https://api.getunbound.ai')\n"
            "# v2\n"
        )
        self._set_remote(bad_remote)
        unbound._check_self_update()
        self.assertEqual(self.script.read_text(), original)

    def test_corrupt_download_rejected(self):
        original = _script(TENANT, "v1")
        self.script.write_text(original)
        self._set_remote("<html>error</html>")
        unbound._check_self_update()
        self.assertEqual(self.script.read_text(), original)

    def test_fail_open_on_curl_error(self):
        original = _script(TENANT, "v1")
        self.script.write_text(original)
        with patch.object(unbound.subprocess, "run",
                          side_effect=unbound.subprocess.TimeoutExpired("curl", unbound.SELF_UPDATE_CURL_TIMEOUT)):
            unbound._check_self_update()
        self.assertEqual(self.script.read_text(), original)

    def test_fresh_lock_blocks(self):
        self.script.write_text(_script(TENANT, "v1"))
        self.lock.touch()
        run = self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        run.assert_not_called()

    def test_stale_lock_cleared(self):
        self.lock.touch()
        old = time.time() - (unbound.SELF_UPDATE_LOCK_TTL_SECONDS + 5)
        os.utime(self.lock, (old, old))
        self.assertTrue(unbound._acquire_self_update_lock())

    def test_lock_released_after_run(self):
        self.script.write_text(_script(TENANT, "v1"))
        self._set_remote(_script(DEFAULT, "v2"))
        unbound._check_self_update()
        self.assertFalse(self.lock.exists())


if __name__ == "__main__":
    unittest.main()
