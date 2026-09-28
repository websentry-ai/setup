"""Regressions for the three findings raised on PR #352 by Cursor Bugbot and the
automated security review.

1. **A failed write must not truncate a working extension** (Bugbot, medium). Both
   installers used to open the destination `index.js` with `O_TRUNC` before the new bytes
   were fully written. A write that then failed -- ENOSPC, EIO, a killed process -- left a
   previously working extension truncated, so pi loaded a broken or empty file, logged
   nothing, and enforcement silently disappeared until some later successful run. The fix
   is a sibling temp file plus `os.replace`, so the published name is either all the old
   bytes or all the new ones.

2. **A failed key write must not report success** (Bugbot, medium). `write_unbound_config`
   returns a bool that `main()` ignored, so an installed-but-keyless setup printed
   "Setup complete". On the browser-callback path `config.json` is the ONLY place the
   minted key exists, so that is an extension that can never activate.

3. **Nothing crosses the privilege drop as a pickle** (security review, medium,
   semgrep `avoid-pickle`). The writer has already dropped to the unprivileged user and
   the reader is still root, so unpickling there turns any influence over those bytes into
   code execution as root on every managed device.

The atomicity assertions deliberately fail the write at `os.replace` rather than at the
temp open: replace is the last step, so it is the moment with the most already-written
state to lose, and it is the one an O_TRUNC implementation would pass by accident.
"""

import hashlib
import os
from pathlib import Path

import pytest

ARTIFACT = b"// GENERATED FILE - DO NOT EDIT\nexport default { name: 'unbound' };\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()
OLD_GOOD = b"// the previously installed, working extension\n"

TMP_SUFFIX = ".unbound-tmp"


@pytest.fixture
def good_fetch(pi_setup, fake_fetch):
    return fake_fetch(
        {pi_setup.ARTIFACT_URL: ARTIFACT,
         pi_setup.SHA_URL: f"{DIGEST}  pi/index.js\n"},
        module=pi_setup,
    )


class TestTheUserInstallIsAtomic:
    def test_a_failed_publish_leaves_the_existing_extension_byte_identical(
            self, pi_setup, pi_home, good_fetch, monkeypatch):
        """The whole point: an interrupted upgrade must not disarm a protected machine."""
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        target = pi_setup.artifact_path(pi_home.agent_dir)
        target.write_bytes(OLD_GOOD)

        monkeypatch.setattr(pi_setup.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC")))
        assert pi_setup.install_extension(pi_home.agent_dir) is None
        assert target.read_bytes() == OLD_GOOD, "the working extension survived the failure"

    def test_a_failed_publish_leaves_no_temp_file_behind(
            self, pi_setup, pi_home, good_fetch, monkeypatch):
        """A stray 59 KB temp in the extension dir is litter pi would also try to load."""
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        monkeypatch.setattr(pi_setup.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("EIO")))
        pi_setup.install_extension(pi_home.agent_dir)
        assert list(extdir.glob("*" + TMP_SUFFIX)) == []

    def test_a_successful_install_leaves_no_temp_file_behind(
            self, pi_setup, pi_home, good_fetch):
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        extdir = pi_home.extension_dir()
        assert list(extdir.glob("*" + TMP_SUFFIX)) == []

    def test_a_leftover_temp_from_a_killed_run_does_not_block_the_next_install(
            self, pi_setup, pi_home, good_fetch):
        """O_EXCL would otherwise turn one killed run into a permanently broken installer."""
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / ("index.js" + TMP_SUFFIX)).write_bytes(b"half a bundle")
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        assert pi_setup.artifact_path(pi_home.agent_dir).read_bytes() == ARTIFACT
        assert list(extdir.glob("*" + TMP_SUFFIX)) == []

    def test_the_publish_is_a_rename_not_a_truncating_write(
            self, pi_setup, pi_home, good_fetch, monkeypatch):
        """Pin the mechanism, not just the outcome: an implementation that went back to
        O_TRUNC on the target would still pass the outcome tests on a filesystem that
        never fails mid-write."""
        seen = {}
        real_replace = os.replace

        def spy(src, dst, *a, **k):
            seen["src"], seen["dst"] = str(src), str(dst)
            return real_replace(src, dst, *a, **k)

        monkeypatch.setattr(pi_setup.os, "replace", spy)
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        assert seen["src"].endswith("index.js" + TMP_SUFFIX)
        assert seen["dst"].endswith("index.js")
        assert not seen["dst"].endswith(TMP_SUFFIX)


class TestAFailedKeyWriteIsNotSuccess:
    def test_main_returns_false_and_does_not_claim_completion(
            self, pi_setup, pi_home, good_fetch, monkeypatch, capsys):
        monkeypatch.setattr(pi_setup.sys, "argv",
                            ["setup.py", "--api-key", "notakey", "--backend-url", "https://b"])
        monkeypatch.setattr(pi_setup, "write_unbound_config", lambda *a, **k: False)
        monkeypatch.setattr(pi_setup, "notify_setup_complete",
                            lambda *a, **k: pytest.fail("no report after a failed key write"))

        assert pi_setup.main() is False
        out = capsys.readouterr().out
        assert "Setup complete" not in out
        assert "stay inactive" in out, "the user is told WHY, not just that it failed"
        assert "UNBOUND_PI_API_KEY" in out, "and is given the fallback"

    def test_a_successful_key_write_still_completes(
            self, pi_setup, pi_home, good_fetch, monkeypatch, captured_reports, capsys):
        """The negative above must not be passing because main() is broken outright."""
        captured_reports.attach(pi_setup)
        monkeypatch.setattr(pi_setup.sys, "argv",
                            ["setup.py", "--api-key", "notakey", "--backend-url", "https://b"])
        assert pi_setup.main() is True
        assert "Setup complete" in capsys.readouterr().out


class TestTheMdmDropIsAtomicToo:
    """The MDM path is the higher-stakes one -- it rewrites index.js in every home on the
    device, so one partial write there disarms a user who never ran anything."""

    def test_a_failed_publish_in_a_home_leaves_that_users_extension_intact(
            self, pi_mdm_setup, tmp_path, monkeypatch):
        mod = pi_mdm_setup
        home = tmp_path / "alice"
        extdir = home / ".pi" / "agent" / "extensions" / "unbound"
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_bytes(OLD_GOOD)

        # Run the drop in-process: the privilege drop itself is covered elsewhere and needs
        # root, and what is under test here is the write, not the fork.
        monkeypatch.setattr(mod, "_run_as_user", lambda user, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(mod, "_repair_user_ownership", lambda *a, **k: None)
        monkeypatch.setattr(mod.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC")))

        assert mod.install_for_user("alice", home, ARTIFACT, DIGEST).startswith("failed")
        assert (extdir / "index.js").read_bytes() == OLD_GOOD
        assert list(extdir.glob("*" + TMP_SUFFIX)) == []

    def test_a_clean_run_publishes_by_rename_and_leaves_no_temp(
            self, pi_mdm_setup, tmp_path, monkeypatch):
        mod = pi_mdm_setup
        home = tmp_path / "bob"
        (home / ".pi").mkdir(parents=True)
        monkeypatch.setattr(mod, "_run_as_user", lambda user, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(mod, "_repair_user_ownership", lambda *a, **k: None)

        assert mod.install_for_user("bob", home, ARTIFACT, DIGEST) == "installed"
        extdir = home / ".pi" / "agent" / "extensions" / "unbound"
        assert (extdir / "index.js").read_bytes() == ARTIFACT
        assert list(extdir.glob("*" + TMP_SUFFIX)) == []


class TestNothingCrossesThePrivilegeDropAsAPickle:
    def test_the_source_does_not_call_pickle(self, pi_mdm_setup):
        src = Path(pi_mdm_setup.__file__).read_text(encoding="utf-8")
        calls = [ln for ln in src.splitlines()
                 if "pickle" in ln and not ln.strip().startswith("#")]
        assert calls == [], f"pickle crosses the root/user boundary: {calls}"

    def test_the_boundary_is_json(self, pi_mdm_setup):
        src = Path(pi_mdm_setup.__file__).read_text(encoding="utf-8")
        assert "json.dumps(result)" in src
        assert "json.loads(data.decode('utf-8'))" in src

    @pytest.mark.parametrize("payload", [b"[1, 2, 3, 4]", b'{"a": 1}', b"17", b"not json"])
    def test_an_unexpected_shape_is_a_failure_not_a_value(
            self, pi_mdm_setup, monkeypatch, payload):
        """Root must not pass an arbitrary decoded object along to a caller that expects a
        status string -- the shape is checked, not assumed."""
        mod = pi_mdm_setup
        if not hasattr(os, "fork"):
            pytest.skip("fork is Unix-only")

        monkeypatch.setattr(mod.os, "fork", lambda: 4242)
        monkeypatch.setattr(mod.os, "close", lambda fd: None)
        reads = [payload, b""]
        monkeypatch.setattr(mod.os, "read", lambda fd, n: reads.pop(0) if reads else b"")
        monkeypatch.setattr(mod.os, "waitpid", lambda pid, flags: (pid, 0))
        monkeypatch.setattr(mod.os, "pipe", lambda: (11, 12))
        monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")

        class _Info:
            pw_uid, pw_gid, pw_dir = 501, 20, "/tmp/whoever"

        monkeypatch.setattr(mod.pwd, "getpwnam", lambda u: _Info())

        result = mod._run_as_user("whoever", lambda: None)
        # A list IS an accepted shape (one caller returns a pair), so only the dict, the
        # int and the malformed bytes must come back as None.
        if payload == b"[1, 2, 3, 4]":
            assert result == [1, 2, 3, 4]
        else:
            assert result is None
