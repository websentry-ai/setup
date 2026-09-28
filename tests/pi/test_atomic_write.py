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
import stat
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


@pytest.fixture
def fake_home(pi_setup, pi_home, monkeypatch):
    """Points Path.home() at the throwaway HOME -- write_unbound_config resolves the config
    path from Path.home(), so without this it would touch the real one. Same fixture as
    tests/pi/test_report.py."""
    monkeypatch.setenv("HOME", str(pi_home.home))
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    return pi_home


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
        seen = []
        real_replace = os.replace

        def spy(src, dst, *a, **k):
            seen.append((str(src), str(dst)))
            return real_replace(src, dst, *a, **k)

        monkeypatch.setattr(pi_setup.os, "replace", spy)
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST

        # Every durable file the install writes is published by rename, so assert on the
        # artifact's own pair rather than the last call -- the sidecar is renamed too.
        artifact = [(s, d) for s, d in seen if d.endswith("index.js")]
        assert len(artifact) == 1, f"expected one index.js rename, got {seen}"
        src, dst = artifact[0]
        assert src.endswith("index.js" + TMP_SUFFIX)
        assert not dst.endswith(TMP_SUFFIX)
        # The sidecar too, since a half-written sidecar reads as tampering to a human.
        assert any(d.endswith("index.js.sha256") and s.endswith(TMP_SUFFIX)
                   for s, d in seen), f"the sidecar is not published by rename: {seen}"


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

    def test_a_second_push_refreshes_the_sidecar_rather_than_leaving_the_old_digest(
            self, pi_mdm_setup, tmp_path, monkeypatch):
        """Cursor Bugbot, second round, on the fix for the first: the temp file's O_EXCL was
        reused for the sidecar, whose destination legitimately already exists after the
        first push. EEXIST was swallowed, so index.js advanced while index.js.sha256 kept
        the previous digest -- `shasum -a 256 -c` would then fail in EVERY managed home and
        no later MDM run could repair it. O_EXCL now belongs to the temp file alone."""
        mod = pi_mdm_setup
        home = tmp_path / "carol"
        (home / ".pi").mkdir(parents=True)
        monkeypatch.setattr(mod, "_run_as_user", lambda user, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(mod, "_repair_user_ownership", lambda *a, **k: None)
        extdir = home / ".pi" / "agent" / "extensions" / "unbound"

        old_bytes = b"// an older bundle\n"
        old_digest = hashlib.sha256(old_bytes).hexdigest()
        assert mod.install_for_user("carol", home, old_bytes, old_digest) == "installed"
        assert old_digest in (extdir / "index.js.sha256").read_text()

        # The fleet push that ships a new build.
        assert mod.install_for_user("carol", home, ARTIFACT, DIGEST) == "persisted"
        assert (extdir / "index.js").read_bytes() == ARTIFACT
        sidecar_text = (extdir / "index.js.sha256").read_text()
        assert DIGEST in sidecar_text, "the sidecar advanced with the artifact"
        assert old_digest not in sidecar_text, "and the stale digest is gone"

    def test_the_refreshed_sidecar_actually_verifies_with_shasum(
            self, pi_mdm_setup, tmp_path, monkeypatch):
        """The property a stale sidecar breaks, asserted end to end rather than by digest
        string comparison: recompute from the bytes on disk and compare to the file."""
        mod = pi_mdm_setup
        home = tmp_path / "dave"
        (home / ".pi").mkdir(parents=True)
        monkeypatch.setattr(mod, "_run_as_user", lambda user, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(mod, "_repair_user_ownership", lambda *a, **k: None)
        extdir = home / ".pi" / "agent" / "extensions" / "unbound"

        mod.install_for_user("dave", home, b"// first\n",
                             hashlib.sha256(b"// first\n").hexdigest())
        mod.install_for_user("dave", home, ARTIFACT, DIGEST)

        on_disk = hashlib.sha256((extdir / "index.js").read_bytes()).hexdigest()
        recorded = (extdir / "index.js.sha256").read_text().split()[0]
        assert recorded == on_disk


class TestTheRcRewriteNeverDestroysAUserFile:
    """Cursor Bugbot, third round, HIGH severity -- and the worst defect found on this PR.

    `append_to_file` decoded the rc file as strict UTF-8 and treated ANY failure as an empty
    file, then truncated and rewrote. So a single non-UTF-8 byte in `.zprofile` -- an
    accented name in a comment, a stray 0x80 from a copy-paste -- replaced the user's entire
    shell profile with one `export` line. Running as root, for every account on the device,
    on every MDM push. A security tool destroying user data is strictly worse than a
    security tool that fails to install.
    """

    LATIN1_PROFILE = (
        b"# Andr\xe9's profile -- latin-1, not UTF-8\n"
        b"export EDITOR=vim\n"
        b"alias ll='ls -la'\n"
    )

    def test_a_non_utf8_rc_file_is_preserved_byte_for_byte(self, pi_mdm_setup, tmp_path):
        mod = pi_mdm_setup
        rc = tmp_path / ".zprofile"
        rc.write_bytes(self.LATIN1_PROFILE)

        assert mod.append_to_file(rc, "export UNBOUND_PI_API_KEY=notakey", "UNBOUND_PI_API_KEY")

        after = rc.read_bytes()
        assert b"Andr\xe9" in after, "the undecodable byte survived unchanged"
        assert b"export EDITOR=vim\n" in after
        assert b"alias ll='ls -la'\n" in after
        assert b"export UNBOUND_PI_API_KEY=notakey" in after
        assert after.startswith(self.LATIN1_PROFILE), "nothing before our line was rewritten"

    def test_an_unreadable_rc_file_is_refused_not_rewritten(self, pi_mdm_setup, tmp_path):
        """When the file genuinely cannot be read, losing the export beats losing the file."""
        mod = pi_mdm_setup
        rc = tmp_path / ".zprofile"
        original = b"# precious\nexport EDITOR=vim\n"
        rc.write_bytes(original)
        rc.chmod(0o000)
        try:
            if os.access(str(rc), os.R_OK):  # running as root ignores the mode
                pytest.skip("cannot make a file unreadable as this user")
            assert mod.append_to_file(rc, "export UNBOUND_PI_API_KEY=k",
                                      "UNBOUND_PI_API_KEY") is False
        finally:
            rc.chmod(0o644)
        assert rc.read_bytes() == original, "the file we could not read was left alone"

    def test_a_failed_write_leaves_the_profile_intact(
            self, pi_mdm_setup, tmp_path, monkeypatch):
        mod = pi_mdm_setup
        rc = tmp_path / ".zprofile"
        original = b"# precious\nexport EDITOR=vim\n"
        rc.write_bytes(original)

        monkeypatch.setattr(mod.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC")))
        assert mod.append_to_file(rc, "export UNBOUND_PI_API_KEY=k",
                                  "UNBOUND_PI_API_KEY") is False
        assert rc.read_bytes() == original
        assert list(tmp_path.glob("*" + TMP_SUFFIX)) == []

    def test_an_rc_file_symlinked_into_a_dotfiles_repo_keeps_its_link(
            self, pi_mdm_setup, tmp_path):
        """The docstring calls a dotfiles symlink a legitimate setup, so the rewrite must
        follow the link and edit the real file -- os.replace on the link path would swap the
        link for a regular file and silently detach the user from their dotfiles."""
        mod = pi_mdm_setup
        dotfiles = tmp_path / "dotfiles"
        dotfiles.mkdir()
        real = dotfiles / "zprofile"
        real.write_text("# tracked in git\nexport EDITOR=vim\n")
        home = tmp_path / "home"
        home.mkdir()
        rc = home / ".zprofile"
        rc.symlink_to(real)

        assert mod.append_to_file(rc, "export UNBOUND_PI_API_KEY=k", "UNBOUND_PI_API_KEY")
        assert rc.is_symlink(), "still a symlink into the dotfiles repo"
        assert os.path.realpath(str(rc)) == str(real)
        assert "UNBOUND_PI_API_KEY" in real.read_text(), "the real file got the export"
        assert "# tracked in git" in real.read_text()

    def test_the_file_mode_is_preserved(self, pi_mdm_setup, tmp_path):
        """An rc file is sometimes 0600 on purpose; a rewrite must not widen it."""
        mod = pi_mdm_setup
        rc = tmp_path / ".zprofile"
        rc.write_text("export EDITOR=vim\n")
        rc.chmod(0o600)
        assert mod.append_to_file(rc, "export UNBOUND_PI_API_KEY=k", "UNBOUND_PI_API_KEY")
        assert stat.S_IMODE(rc.stat().st_mode) == 0o600

    def test_removal_also_preserves_a_non_utf8_profile(self, pi_mdm_setup, tmp_path,
                                                       monkeypatch):
        """The clear path read strict UTF-8 too. It never wiped the file (the write was
        inside the same try), but it reported "failed" and left our export behind."""
        mod = pi_mdm_setup
        home = tmp_path / "erin"
        home.mkdir()
        monkeypatch.setattr(mod, "_run_as_user", lambda user, fn, *a, **k: fn(*a, **k))
        monkeypatch.setattr(mod, "_repair_user_ownership", lambda *a, **k: None)
        monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")

        rc = home / ".zprofile"
        rc.write_bytes(self.LATIN1_PROFILE + b"export UNBOUND_PI_API_KEY=notakey\n")

        assert mod.remove_env_var_from_user("erin", home, "UNBOUND_PI_API_KEY") == "cleared"
        after = rc.read_bytes()
        assert b"UNBOUND_PI_API_KEY" not in after, "our export is gone"
        assert b"Andr\xe9" in after, "and the undecodable byte survived"
        assert b"export EDITOR=vim\n" in after


class TestNoDurableFileIsWrittenByTruncation:
    """Cursor Bugbot, fourth round, HIGH severity: `~/.unbound/config.json` was still opened
    with O_TRUNC in both installers, so an interrupt mid-write left the SHARED identity file
    empty -- logging the user out of all six tools that read it, not just pi.

    Rather than patch the fourth instance of one bug class, these tests close the class: no
    durable file either installer writes may be published by truncation. The two remaining
    `open(..., "w")` calls in the pair are `tempfile.mkstemp` curl header files deleted in a
    `finally`, which have no durability story to get wrong.
    """

    def test_neither_installer_opens_a_durable_file_with_o_trunc(
            self, pi_setup, pi_mdm_setup):
        """Matches `os.O_TRUNC`, the flag in use, rather than the bare token -- the prose
        explaining why it is gone legitimately names it."""
        for mod in (pi_setup, pi_mdm_setup):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            offenders = [f"{i}: {ln.strip()}" for i, ln in enumerate(src.splitlines(), 1)
                         if "os.O_TRUNC" in ln]
            assert offenders == [], f"{mod.__file__} truncates in place: {offenders}"

    def test_the_user_config_write_is_atomic(self, pi_setup, fake_home, monkeypatch):
        """The file six tools authenticate with must survive a failed write intact."""
        cfg = fake_home.config_path
        cfg.parent.mkdir(parents=True, exist_ok=True)
        original = '{\n  "api_key": "pre-existing",\n  "email": "someone@example.com"\n}'
        cfg.write_text(original)

        monkeypatch.setattr(pi_setup.os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("ENOSPC")))
        assert pi_setup.write_unbound_config("newkey", {"base_url": "https://b"}) is False
        assert cfg.read_text() == original, "the shared identity file survived"
        assert list(cfg.parent.glob("*" + TMP_SUFFIX)) == []

    def test_a_successful_user_config_write_still_merges(self, pi_setup, fake_home):
        """Positive control: the atomic path must not have broken read-merge-write."""
        cfg = fake_home.config_path
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text('{"email": "someone@example.com", "org_name": "Acme"}')

        assert pi_setup.write_unbound_config("newkey", {"base_url": "https://b"}) is True
        import json as _json
        data = _json.loads(cfg.read_text())
        assert data["api_key"] == "newkey"
        assert data["email"] == "someone@example.com", "unrelated fields preserved"
        assert data["org_name"] == "Acme"
        assert data["base_url"] == "https://b"
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    def test_the_mdm_config_write_refuses_a_symlink(self, pi_mdm_setup, tmp_path):
        """Root writing into another user's home must not follow a planted link, even though
        the user installer deliberately DOES follow one in the user's own home."""
        mod = pi_mdm_setup
        outside = tmp_path / "outside.json"
        outside.write_text("untouched")
        link = tmp_path / "config.json"
        link.symlink_to(outside)

        assert mod._atomic_write_text(link, '{"api_key": "k"}', 0o600) is False
        assert outside.read_text() == "untouched"
    def test_the_source_does_not_mention_the_module_at_all(self, pi_mdm_setup):
        """Not even in a comment. The scanner's rule is name-based, so a mitigation comment
        that names the module keeps the finding firing forever on the fix itself -- which is
        how a closed finding turns into permanent review noise nobody reads."""
        src = Path(pi_mdm_setup.__file__).read_text(encoding="utf-8")
        hits = [f"{i}: {ln.strip()}" for i, ln in enumerate(src.splitlines(), 1)
                if "pickle" in ln.lower()]
        assert hits == [], f"the module is still named in the source: {hits}"

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
