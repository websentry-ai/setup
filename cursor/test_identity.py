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

import unbound


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
            set(result.keys()), {"org_id", "plan", "auth_mode", "email_domain"}
        )


if __name__ == "__main__":
    unittest.main()
