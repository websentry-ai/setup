"""
Tests for account-identity helpers in cursor/unbound.py.

Covers:
  - _email_domain
  - _cursor_state_db_path  (darwin / linux / nt)
  - _read_cursor_item_table  (real sqlite, read-only URI, missing file → {})
  - build_account_identity
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("cursor")
# ---------------------------------------------------------------------------
# _email_domain
# ---------------------------------------------------------------------------

class TestEmailDomain(unittest.TestCase):
    def test_normal_address(self):
        self.assertEqual(unbound._email_domain("alice@example.com"), "example.com")

    def test_lowercases_domain(self):
        self.assertEqual(unbound._email_domain("Alice@CORP.COM"), "corp.com")

    def test_none_returns_none(self):
        self.assertIsNone(unbound._email_domain(None))

    def test_empty_string_returns_none(self):
        self.assertIsNone(unbound._email_domain(""))

    def test_no_at_sign_returns_none(self):
        self.assertIsNone(unbound._email_domain("notanemail"))

    def test_empty_domain_after_at_returns_none(self):
        self.assertIsNone(unbound._email_domain("user@"))


# ---------------------------------------------------------------------------
# _cursor_state_db_path
# ---------------------------------------------------------------------------

class TestCursorStateDbPath(unittest.TestCase):
    """_cursor_state_db_path returns the correct path for each OS."""

    def test_darwin_path(self):
        with patch.object(sys, "platform", "darwin"):
            with patch.object(os, "name", "posix"):
                path = unbound._cursor_state_db_path()
        self.assertEqual(
            path,
            Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb",
        )

    def test_linux_path(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(os, "name", "posix"):
                path = unbound._cursor_state_db_path()
        self.assertEqual(
            path,
            Path.home() / ".config" / "Cursor" / "User" / "globalStorage" / "state.vscdb",
        )

    @unittest.skipUnless(os.name == "nt", "WindowsPath can only be instantiated on Windows")
    def test_windows_path(self):
        # pathlib.Path() dispatches on the real os.name at construction time in
        # Python <=3.11; it raises NotImplementedError when os.name='nt' is patched
        # on a non-Windows host.  This test is valid only on actual Windows.
        fake_appdata = r"C:\Users\tester\AppData\Roaming"
        with patch.dict(os.environ, {"APPDATA": fake_appdata}):
            path = unbound._cursor_state_db_path()
        self.assertIn("Cursor", str(path))
        self.assertIn("globalStorage", str(path))
        self.assertIn("state.vscdb", str(path))
        self.assertIn(fake_appdata, str(path))

    def test_windows_no_appdata_returns_none(self):
        with patch.object(sys, "platform", "win32"):
            with patch.object(os, "name", "nt"):
                env = {k: v for k, v in os.environ.items() if k != "APPDATA"}
                with patch.dict(os.environ, env, clear=True):
                    path = unbound._cursor_state_db_path()
        self.assertIsNone(path)


# ---------------------------------------------------------------------------
# _read_cursor_item_table
# ---------------------------------------------------------------------------

def _make_state_db(tmp_dir: Path) -> Path:
    """Create a minimal state.vscdb with an ItemTable and some rows."""
    db_path = tmp_dir / "state.vscdb"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO ItemTable VALUES (?, ?)", ("cursorAuth/cachedEmail", "user@acme.io"))
    conn.execute("INSERT INTO ItemTable VALUES (?, ?)", ("cursorAuth/stripeMembershipType", "pro"))
    conn.execute("INSERT INTO ItemTable VALUES (?, ?)", ("cursorAuth/accessToken", "tok-secret"))
    conn.commit()
    conn.close()
    return db_path


class TestReadCursorItemTable(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = _make_state_db(self.tmp)

    def test_returns_requested_keys(self):
        result = unbound._read_cursor_item_table(
            self.db_path, ["cursorAuth/cachedEmail", "cursorAuth/stripeMembershipType"]
        )
        self.assertEqual(result["cursorAuth/cachedEmail"], "user@acme.io")
        self.assertEqual(result["cursorAuth/stripeMembershipType"], "pro")

    def test_does_not_return_unrequested_keys(self):
        result = unbound._read_cursor_item_table(
            self.db_path, ["cursorAuth/cachedEmail"]
        )
        self.assertNotIn("cursorAuth/accessToken", result)

    def test_missing_key_absent_from_result(self):
        result = unbound._read_cursor_item_table(self.db_path, ["nonexistent/key"])
        self.assertNotIn("nonexistent/key", result)

    def test_missing_file_returns_empty_dict(self):
        result = unbound._read_cursor_item_table(
            self.tmp / "does_not_exist.vscdb",
            ["cursorAuth/cachedEmail"],
        )
        self.assertEqual(result, {})

    def test_missing_file_does_not_raise(self):
        try:
            unbound._read_cursor_item_table(
                self.tmp / "missing.db", ["anything"]
            )
        except Exception as exc:
            self.fail(f"raised {exc!r}")

    def test_empty_keys_list_returns_empty_dict(self):
        result = unbound._read_cursor_item_table(self.db_path, [])
        self.assertEqual(result, {})


class TestUnreadableStateDb(unittest.TestCase):
    """A busy or checkpoint-pending database used to read back empty, which made
    an approved account look unidentified and got it refused by the gate."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = _make_state_db(self.tmp)
        self.cache = self.tmp / "identity.json"
        self._c = patch.object(unbound, "IDENTITY_CACHE_PATH", self.cache)
        self._c.start()
        self.addCleanup(self._c.stop)
        self._p = patch.object(unbound, "_cursor_state_db_path", return_value=self.db_path)
        self._p.start()
        self.addCleanup(self._p.stop)

    def test_a_successful_read_is_remembered(self):
        unbound.read_account_identity()
        stored = json.loads(self.cache.read_text(encoding="utf-8"))["cursor_account"]
        self.assertEqual(stored["user_email"], "user@acme.io")
        self.assertEqual(stored["plan"], "pro")

    def test_an_unreadable_database_falls_back_to_the_last_account(self):
        unbound.read_account_identity()
        with patch.object(unbound, "_read_cursor_item_table", return_value={}):
            result = unbound.read_account_identity()
        self.assertEqual(result["user_email"], "user@acme.io")
        self.assertEqual(result["email_domain"], "acme.io")
        self.assertEqual(result["plan"], "pro")

    def test_no_cache_and_no_database_reports_nothing(self):
        with patch.object(unbound, "_read_cursor_item_table", return_value={}):
            result = unbound.read_account_identity()
        self.assertIsNone(result["user_email"])
        self.assertIsNone(result["email_domain"])

    def test_a_write_ahead_log_value_is_visible(self):
        """The old immutable open ignored the -wal, so a value Cursor had not yet
        checkpointed read back as missing."""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "UPDATE ItemTable SET value = ? WHERE key = ?",
            ("later@acme.io", "cursorAuth/cachedEmail"),
        )
        conn.commit()
        try:
            result = unbound._read_cursor_item_table(
                self.db_path, ["cursorAuth/cachedEmail"]
            )
            self.assertEqual(result["cursorAuth/cachedEmail"], "later@acme.io")
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# build_account_identity
# ---------------------------------------------------------------------------

class TestBuildAccountIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = _make_state_db(self.tmp)
        self._p = patch.object(unbound, "_cursor_state_db_path", return_value=self.db_path)
        self._p.start()
        self.addCleanup(self._p.stop)

    def test_returns_full_identity(self):
        result = unbound.build_account_identity()
        self.assertEqual(result["email_domain"], "acme.io")
        self.assertEqual(result["plan"], "pro")
        self.assertIsNone(result["org_id"])      # cursor has no org_id
        self.assertIsNone(result["auth_mode"])   # cursor has no auth_mode

    def test_keys_limited_to_identity_fields(self):
        result = unbound.build_account_identity()
        self.assertEqual(
            set(result.keys()),
            {"org_id", "plan", "auth_mode", "email_domain",
             "user_email", "device_serial"},
        )


if __name__ == "__main__":
    unittest.main()
