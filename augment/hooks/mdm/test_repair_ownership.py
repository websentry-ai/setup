"""Safety-invariant tests for _repair_user_ownership (WEB-4834).

It chowns user-home paths while running as root, so the guards matter more than
the happy path. The actual chown needs root + a second uid, so these mock
os.fchown and assert exactly WHEN a chown is attempted: only for a real,
single-linked file or a directory owned by another uid. Symlinks (O_NOFOLLOW)
and extra-hard-linked files (hardlink-to-/etc/shadow escalation) must be
refused; a path the user already owns is a no-op.
"""
import importlib.util
import getpass
import os
import unittest
from unittest import mock
from pathlib import Path
import tempfile

_spec = importlib.util.spec_from_file_location(
    "_au_mdm_setup", os.path.join(os.path.dirname(__file__), "setup.py")
)
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)


def _fake_pwd(uid_offset):
    """getpwnam stub that returns a uid offset from the real one (forces the
    uid-mismatch branch without needing a second real account)."""
    real = mdm.pwd.getpwnam(getpass.getuser())

    class _Info:
        pw_uid = real.pw_uid + uid_offset
        pw_gid = real.pw_gid

    return lambda _name: _Info()


class TestRepairUserOwnership(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.me = getpass.getuser()

    def test_self_owned_path_is_noop(self):
        f = self.dir / "mine"
        f.write_text("x")
        with mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership(self.me, [f])  # uid matches -> no chown
            fchown.assert_not_called()

    def test_missing_path_no_chown_no_raise(self):
        with mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership(self.me, [self.dir / "absent"])
            fchown.assert_not_called()

    def test_plain_single_link_file_is_chowned_on_mismatch(self):
        f = self.dir / "mine"
        f.write_text("x")
        with mock.patch.object(mdm.pwd, "getpwnam", _fake_pwd(99999)), \
                mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership("whoever", [f])
            fchown.assert_called_once()

    def _fstat_with_uid(self, fake_uid):
        """Return an os.fstat replacement that overrides st_uid on the real
        stat result (so we can simulate root-owned / other-user-owned dirs
        without actually being root)."""
        real_fstat = os.fstat

        def _fake(fd):
            real = real_fstat(fd)

            class _St:
                st_mode = real.st_mode
                st_nlink = real.st_nlink
                st_uid = fake_uid

            return _St()

        return _fake

    def test_root_owned_directory_is_reclaimed(self):
        """A root-owned (st_uid == 0) dir IS reclaimed — the root-leftover case
        this function exists for."""
        d = self.dir / "sub"
        d.mkdir()
        with mock.patch.object(mdm.pwd, "getpwnam", _fake_pwd(99999)), \
                mock.patch("os.fstat", side_effect=self._fstat_with_uid(0)), \
                mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership("whoever", [d])
            fchown.assert_called_once()

    def test_other_user_directory_is_not_reclaimed(self):
        """A dir owned by some OTHER non-root uid is NOT reclaimed — handing
        another user's dir to this user would be an over-reach (FIX 7)."""
        d = self.dir / "sub"
        d.mkdir()
        real_uid = mdm.pwd.getpwnam(self.me).pw_uid
        # Target uid is real_uid + 99999; the dir is owned by yet another
        # non-root uid (real_uid + 12345), so st_uid is neither 0 nor the target.
        with mock.patch.object(mdm.pwd, "getpwnam", _fake_pwd(99999)), \
                mock.patch("os.fstat", side_effect=self._fstat_with_uid(real_uid + 12345)), \
                mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership("whoever", [d])
            fchown.assert_not_called()

    def test_symlink_is_refused(self):
        target = self.dir / "target"
        target.write_text("x")
        link = self.dir / "link"
        link.symlink_to(target)
        with mock.patch.object(mdm.pwd, "getpwnam", _fake_pwd(99999)), \
                mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership("whoever", [link])  # O_NOFOLLOW -> ELOOP
            fchown.assert_not_called()

    def test_hardlinked_file_is_refused(self):
        target = self.dir / "target"
        target.write_text("x")
        hard = self.dir / "hard"
        os.link(target, hard)  # st_nlink == 2 — could be a hardlink to a root file
        with mock.patch.object(mdm.pwd, "getpwnam", _fake_pwd(99999)), \
                mock.patch("os.fchown") as fchown:
            mdm._repair_user_ownership("whoever", [hard])
            fchown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
