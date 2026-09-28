"""The privileged drop: one verified artifact, fanned out into every enumerated home.

Root is about to write into directories the target user controls, so the three primitives
from RESEARCH C2 are what these tests are really about:

  * `_run_as_user` -- fork + setgroups/setgid/setuid, so a symlink in the home cannot
    escalate. The *logic* is asserted by monkeypatching the fork/uid calls; a real drop
    needs real root and is skipped, not faked.
  * `_repair_user_ownership` -- O_NOFOLLOW + fchown on the file descriptor, refusing a
    regular file with extra hard links. The symlink and hardlink refusals are asserted for
    real, with real symlinks and real hardlinks in a tmp tree.
  * the in-home write itself -- O_NOFOLLOW, 0644, shadow-guarded, per home.
"""

import os
import platform
import stat

import pytest

from tests.pi.mdm.test_user_homes import FakePwd, _pw

WINDOWS = platform.system().lower() == "windows"
NOT_ROOT = os.geteuid() != 0 if hasattr(os, "geteuid") else True

PAYLOAD = b"// the unbound pi extension\nmodule.exports = {};\n"


@pytest.fixture
def digest(pi_mdm_setup):
    import hashlib
    return hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def passthrough(pi_mdm_setup, monkeypatch):
    """Run the in-home function in-process instead of behind a real privilege drop.

    Every test that uses this is asserting what the dropped function DOES. That the drop
    itself happens is asserted separately (test_every_in_home_write_goes_through_the_drop),
    and the real fork+setuid can only be exercised as root (skipped below).
    """
    calls = []

    def _fake(username, fn, *args, **kwargs):
        calls.append(username)
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None

    monkeypatch.setattr(pi_mdm_setup, "_run_as_user", _fake)
    return calls


# --- _repair_user_ownership: the fd-based, symlink- and hardlink-safe repair -------------


@pytest.fixture
def repair_probe(pi_mdm_setup, monkeypatch):
    """Point the repair at a synthetic user whose uid is nobody's, and record fchown.

    The uid is deliberately not ours, so every path we hand it looks "owned by someone
    else" and the repair's decision to chown or not is the only thing under test. fchown
    is recorded rather than performed: a real chown to another uid needs root.
    """
    mod = pi_mdm_setup
    fake_uid, fake_gid = 4242, 4242
    monkeypatch.setattr(mod, "pwd", FakePwd([_pw("target", fake_uid, "/nonexistent")]))
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    chowned = []
    monkeypatch.setattr(mod.os, "fchown",
                        lambda fd, uid, gid: chowned.append((os.fstat(fd).st_ino, uid, gid)))
    return chowned, fake_uid, fake_gid


@pytest.mark.skipif(WINDOWS, reason="O_NOFOLLOW/fchown are Unix-only")
def test_a_plain_file_is_repaired_by_fd(pi_mdm_setup, repair_probe, tmp_path):
    """The ordinary case: a root-owned leftover handed back to the user, by fd."""
    chowned, uid, gid = repair_probe
    target = tmp_path / "index.js"
    target.write_bytes(PAYLOAD)
    pi_mdm_setup._repair_user_ownership("target", tmp_path, [target])
    assert chowned == [(target.stat().st_ino, uid, gid)]


@pytest.mark.skipif(WINDOWS, reason="hard links behave differently on Windows")
def test_a_hardlinked_regular_file_is_refused(pi_mdm_setup, repair_probe, tmp_path):
    """The escalation this refusal exists for: a hard link to a root-owned file planted
    where we are about to repair ownership would hand that file to the user outright.
    st_nlink != 1 is the only reliable tell, and it is checked on the fstat of the fd."""
    chowned, _, _ = repair_probe
    sensitive = tmp_path / "pretend-shadow"
    sensitive.write_text("root:!:1::::::\n")
    planted = tmp_path / "index.js"
    os.link(sensitive, planted)
    assert planted.stat().st_nlink == 2

    pi_mdm_setup._repair_user_ownership("target", tmp_path, [planted])
    assert chowned == [], "a hardlinked regular file was chowned to the target user"


@pytest.mark.skipif(WINDOWS, reason="O_NOFOLLOW is Unix-only")
def test_a_symlink_is_refused_by_o_nofollow(pi_mdm_setup, repair_probe, tmp_path):
    """A symlink pointing at a root-only path is the classic version of the same attack.
    O_NOFOLLOW turns the open into ELOOP, so the repair never sees the target's inode."""
    chowned, _, _ = repair_probe
    outside = tmp_path / "outside"
    outside.write_text("root-owned in the real attack\n")
    link = tmp_path / "index.js"
    link.symlink_to(outside)

    pi_mdm_setup._repair_user_ownership("target", tmp_path, [link])
    assert chowned == []
    # And the same for a symlinked *directory*, which the O_DIRECTORY branch opens first.
    dir_outside = tmp_path / "dir-outside"
    dir_outside.mkdir()
    dir_link = tmp_path / "extensions"
    dir_link.symlink_to(dir_outside, target_is_directory=True)
    pi_mdm_setup._repair_user_ownership("target", tmp_path, [dir_link])
    assert chowned == []


@pytest.fixture
def as_root_owned(pi_mdm_setup, monkeypatch):
    """Report every fstat'd inode as root-owned, so the chown DECISION is what is under test.

    Creating a genuinely root-owned directory needs root; the open, the descriptor and the
    decision are all the real code path. st_mode is untouched, so the directory/regular-file
    classification is the real one.
    """
    real_fstat = os.fstat

    def _root_owned(fd):
        fields = list(real_fstat(fd))
        fields[4] = 0  # st_uid: pretend root created this
        return os.stat_result(tuple(fields))

    monkeypatch.setattr(pi_mdm_setup.os, "fstat", _root_owned)


@pytest.mark.skipif(WINDOWS, reason="O_NOFOLLOW is Unix-only")
def test_a_symlinked_parent_cannot_redirect_the_repair_outside_the_home(
        pi_mdm_setup, repair_probe, as_root_owned, tmp_path):
    """The escalation a whole-path O_NOFOLLOW never covered: it guards the LAST component
    only. A user who replaced ~/.pi/agent/extensions with a symlink to /etc had root open
    /etc/unbound -- a real, root-owned directory that passes every other check here -- and
    hand it over before the privilege drop. Each component is now opened relative to the
    previous one's descriptor, so the planted link is an ELOOP and the walk stops in the home.
    """
    chowned, _, _ = repair_probe
    home = tmp_path / "home"
    (home / ".pi" / "agent").mkdir(parents=True)
    etc = tmp_path / "etc"  # stands in for the root-owned /etc of the real attack
    (etc / "unbound").mkdir(parents=True)
    (home / ".pi" / "agent" / "extensions").symlink_to(etc, target_is_directory=True)

    extdir = home / ".pi" / "agent" / "extensions" / "unbound"
    pi_mdm_setup._repair_user_ownership("target", home, [extdir.parent, extdir])
    assert chowned == [], "a symlinked parent directory redirected the ownership repair"


@pytest.mark.skipif(WINDOWS, reason="Unix ownership semantics")
def test_a_nested_path_under_the_home_is_still_reclaimed(
        pi_mdm_setup, repair_probe, as_root_owned, tmp_path):
    """The positive control for the component-wise walk. The real repair target sits four
    levels below the home, so a walk that refused anything nested would be a silent no-op
    rather than a fix -- and every other repair test here uses a single component."""
    chowned, uid, gid = repair_probe
    home = tmp_path / "home"
    extdir = home / ".pi" / "agent" / "extensions" / "unbound"
    extdir.mkdir(parents=True)

    pi_mdm_setup._repair_user_ownership("target", home, [extdir])
    assert [(u, g) for _, u, g in chowned] == [(uid, gid)]


@pytest.mark.skipif(WINDOWS, reason="Unix ownership semantics")
def test_the_home_directory_itself_is_never_chowned(
        pi_mdm_setup, repair_probe, as_root_owned, tmp_path):
    """A root-owned home is a real configuration, not damage to repair: sshd requires an
    SFTP-only account's ChrootDirectory to be root-owned and refuses the login once it is
    not, and an admin-locked kiosk account is the same shape. The anchor is never a repaired
    path, even when a caller passes it as one."""
    chowned, _, _ = repair_probe
    home = tmp_path / "home"
    home.mkdir()

    pi_mdm_setup._repair_user_ownership("target", home, [home])
    assert chowned == [], "the MDM push changed the ownership of a root-owned home"


@pytest.mark.skipif(WINDOWS, reason="Unix ownership semantics")
def test_a_path_outside_the_home_is_refused(
        pi_mdm_setup, repair_probe, as_root_owned, tmp_path):
    """Nothing above or beside the anchor is repairable, however it was reached."""
    chowned, _, _ = repair_probe
    home = tmp_path / "home"
    home.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    pi_mdm_setup._repair_user_ownership("target", home, [elsewhere, home / ".." / "elsewhere"])
    assert chowned == []


@pytest.mark.skipif(WINDOWS, reason="Unix ownership semantics")
def test_a_directory_owned_by_another_non_root_user_is_not_reclaimed(
        pi_mdm_setup, repair_probe, tmp_path):
    """Directories are reclaimed only when root- or self-owned. Ours is owned by the test
    runner's uid, which is neither 0 nor the synthetic target uid, so handing it over
    would be an over-reach rather than a repair."""
    chowned, _, _ = repair_probe
    extdir = tmp_path / "unbound"
    extdir.mkdir()
    pi_mdm_setup._repair_user_ownership("target", tmp_path, [extdir])
    assert chowned == []


@pytest.mark.skipif(WINDOWS, reason="Unix ownership semantics")
def test_a_root_owned_directory_is_reclaimed(pi_mdm_setup, repair_probe, as_root_owned, tmp_path):
    """The case the function exists for: a previous root-context run left ~/.pi root-owned
    and the dropped user now cannot write into it. Creating a genuinely root-owned dir
    needs root, so only the fstat is synthesised -- the open, the fd and the fchown
    decision are all the real code path."""
    mod = pi_mdm_setup
    chowned, uid, gid = repair_probe
    extdir = tmp_path / "unbound"
    extdir.mkdir()

    mod._repair_user_ownership("target", tmp_path, [extdir])
    assert [(u, g) for _, u, g in chowned] == [(uid, gid)]


@pytest.mark.skipif(WINDOWS, reason="Unix-only branch")
def test_a_missing_path_and_an_unknown_user_are_non_events(pi_mdm_setup, repair_probe, tmp_path):
    chowned, _, _ = repair_probe
    pi_mdm_setup._repair_user_ownership("target", tmp_path, [tmp_path / "never-existed"])
    pi_mdm_setup._repair_user_ownership("nosuchuser", tmp_path, [tmp_path])
    assert chowned == []


def test_the_repair_is_a_no_op_on_windows(pi_mdm_setup, repair_probe, monkeypatch, tmp_path):
    """Windows has no fork, no setuid and no O_NOFOLLOW; the analog returns early rather
    than degrading the guard, and so does this."""
    mod = pi_mdm_setup
    chowned, _, _ = repair_probe
    monkeypatch.setattr(mod.platform, "system", lambda: "Windows")
    target = tmp_path / "index.js"
    target.write_bytes(PAYLOAD)
    mod._repair_user_ownership("target", tmp_path, [target])
    assert chowned == []


# --- _run_as_user ------------------------------------------------------------------------


def test_run_as_user_drops_groups_then_gid_then_uid(pi_mdm_setup, monkeypatch):
    """Order matters: setuid first would make setgid/setgroups fail, silently leaving the
    child in root's groups. The fork is intercepted so this runs unprivileged, which is
    why the assertion is on the call ORDER rather than on a real dropped process."""
    mod = pi_mdm_setup
    if mod.platform.system().lower() == "windows":
        pytest.skip("no fork on Windows")
    monkeypatch.setattr(mod, "pwd", FakePwd([_pw("target", 4242, "/nonexistent")]))
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")

    order = []
    monkeypatch.setattr(mod.os, "setgroups", lambda g: order.append(("setgroups", tuple(g))))
    monkeypatch.setattr(mod.os, "setgid", lambda g: order.append(("setgid", g)))
    monkeypatch.setattr(mod.os, "setuid", lambda u: order.append(("setuid", u)))
    monkeypatch.setattr(mod.os, "fork", lambda: 0)          # pretend to be the child
    monkeypatch.setattr(mod.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr(mod.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(mod.os, "close", lambda fd: None)
    monkeypatch.setenv("HOME", "/var/root")

    with pytest.raises(SystemExit):
        mod._run_as_user("target", lambda: "ran")
    assert order == [("setgroups", ()), ("setgid", 4242), ("setuid", 4242)]
    # setuid leaves $HOME at root's, so the child repoints it before running fn.
    assert os.environ["HOME"] == "/nonexistent"


def test_run_as_user_returns_none_for_an_unknown_user(pi_mdm_setup, monkeypatch):
    mod = pi_mdm_setup
    if mod.platform.system().lower() == "windows":
        pytest.skip("no fork on Windows")
    monkeypatch.setattr(mod, "pwd", FakePwd([]))
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "fork", lambda: pytest.fail("forked for a user that does not exist"))
    assert mod._run_as_user("ghost", lambda: "ran") is None


def test_run_as_user_executes_directly_on_windows(pi_mdm_setup, monkeypatch):
    mod = pi_mdm_setup
    monkeypatch.setattr(mod.platform, "system", lambda: "Windows")
    monkeypatch.setattr(mod.os, "fork", lambda: pytest.fail("forked on Windows"))
    assert mod._run_as_user(None, lambda: "ran") == "ran"


@pytest.mark.skipif(NOT_ROOT, reason="a real fork+setuid privilege drop needs root")
def test_run_as_user_really_drops_privileges(pi_mdm_setup):
    """The only assertion in this file that needs real root. Recorded as SKIPPED in the
    SUMMARY rather than pretended: everything above asserts the logic, not the syscall."""
    import getpass
    mod = pi_mdm_setup
    assert mod._run_as_user(getpass.getuser(), os.geteuid) != 0


# --- the per-home drop -------------------------------------------------------------------


@pytest.fixture
def homes(tmp_path):
    """Two real user homes under a tmp tree, shaped like an enumerated device."""
    made = []
    for name in ("alice", "bob"):
        home = tmp_path / "Users" / name
        home.mkdir(parents=True)
        made.append((name, home))
    return made


def test_a_drop_lands_index_js_at_0644_in_every_home(
        pi_mdm_setup, passthrough, homes, digest):
    mod = pi_mdm_setup
    for username, home in homes:
        assert mod.install_for_user(username, home, PAYLOAD, digest) == "installed"
        target = home / ".pi" / "agent" / "extensions" / "unbound" / "index.js"
        assert target.read_bytes() == PAYLOAD
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
        # The sidecar goes down beside it so an operator can verify the install by hand.
        assert (target.parent / "index.js.sha256").read_text().split()[0] == digest
    assert passthrough == ["alice", "bob"]


def test_install_for_user_never_offers_the_home_itself_for_repair(
        pi_mdm_setup, passthrough, homes, digest, monkeypatch):
    """The call site as well as the primitive: install_for_user used to pass the home in its
    repair list, and the home is the one path whose ownership an MDM push must not change.
    The home is the anchor instead, which is never a repaired path."""
    mod = pi_mdm_setup
    seen = {}
    monkeypatch.setattr(mod, "_repair_user_ownership",
                        lambda username, base, paths: seen.update(
                            base=str(base), paths=[str(p) for p in paths]))
    username, home = homes[0]

    mod.install_for_user(username, home, PAYLOAD, digest)
    assert seen["base"] == str(home)
    assert str(home) not in seen["paths"]


def test_every_in_home_write_goes_through_the_drop(pi_mdm_setup, monkeypatch, homes, digest):
    """With the privilege drop refusing to run, NOTHING may appear in the home: a code path
    that wrote directly as root would still produce the file and pass every other test here."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod, "_run_as_user", lambda username, fn, *a, **k: None)
    username, home = homes[0]
    status = mod.install_for_user(username, home, PAYLOAD, digest)
    assert status.startswith("failed")
    assert not (home / ".pi").exists()


def test_a_second_pass_reports_persisted_and_rewrites_the_same_bytes(
        pi_mdm_setup, passthrough, homes, digest):
    """Idempotence per home, and the state is read before the write or every run would
    look like a first one."""
    mod = pi_mdm_setup
    username, home = homes[0]
    assert mod.install_for_user(username, home, PAYLOAD, digest) == "installed"
    assert mod.install_for_user(username, home, PAYLOAD, digest) == "persisted"
    target = home / ".pi" / "agent" / "extensions" / "unbound" / "index.js"
    assert target.read_bytes() == PAYLOAD


def test_a_planted_index_ts_is_moved_aside_per_home(
        pi_mdm_setup, passthrough, homes, digest, capsys):
    """pi resolves index.ts BEFORE index.js, so one user's leftover .ts silently defeats
    enforcement for that user only. The guard runs per home, inside the drop, and moves
    the developer's file rather than deleting it."""
    mod = pi_mdm_setup
    username, home = homes[0]
    extdir = home / ".pi" / "agent" / "extensions" / "unbound"
    extdir.mkdir(parents=True)
    planted = extdir / "index.ts"
    planted.write_text("// alice's own extension\n")

    assert mod.install_for_user(username, home, PAYLOAD, digest) == "installed"
    assert not planted.exists()
    assert (extdir / "index.ts.unbound-disabled").read_text() == "// alice's own extension\n"
    assert (extdir / "index.js").read_bytes() == PAYLOAD
    assert "would shadow" in capsys.readouterr().out

    # The other home never had one, so nothing is moved there and nothing is warned about.
    other_user, other_home = homes[1]
    mod.install_for_user(other_user, other_home, PAYLOAD, digest)
    other_ext = other_home / ".pi" / "agent" / "extensions" / "unbound"
    assert not list(other_ext.glob("*.unbound-disabled"))


@pytest.mark.skipif(WINDOWS, reason="O_NOFOLLOW is Unix-only")
def test_a_symlinked_index_js_is_refused_not_followed(
        pi_mdm_setup, passthrough, homes, digest, tmp_path):
    """The drop opens the target with O_NOFOLLOW, so a symlink planted at index.js by the
    user (pointing anywhere) fails the write instead of writing through it."""
    mod = pi_mdm_setup
    username, home = homes[0]
    extdir = home / ".pi" / "agent" / "extensions" / "unbound"
    extdir.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere.js"
    elsewhere.write_text("untouched\n")
    (extdir / "index.js").symlink_to(elsewhere)

    assert mod.install_for_user(username, home, PAYLOAD, digest).startswith("failed")
    assert elsewhere.read_text() == "untouched\n"


def test_one_bad_home_never_aborts_the_device_run(pi_mdm_setup, passthrough, homes, digest):
    """A device with one unwritable home must still cover every other user; a raise or an
    early return here is the difference between 1 protected user and 40."""
    mod = pi_mdm_setup
    (alice, alice_home), (bob, bob_home) = homes
    # alice's .pi is a regular file, so mkdir -p cannot succeed under it.
    (alice_home / ".pi").write_text("not a directory\n")

    rows = [(user, mod.install_for_user(user, home, PAYLOAD, digest))
            for user, home in homes]
    assert rows[0][1].startswith("failed")
    assert rows[1][1] == "installed"
    assert (bob_home / ".pi" / "agent" / "extensions" / "unbound" / "index.js").exists()


def test_a_home_with_no_absolute_path_is_a_recorded_failure(pi_mdm_setup, passthrough, digest):
    mod = pi_mdm_setup
    assert mod.install_for_user("alice", "relative/home", PAYLOAD, digest).startswith("failed")


def test_a_payload_that_does_not_match_the_digest_is_refused(
        pi_mdm_setup, passthrough, homes, digest):
    """The written bytes are re-read and compared, so `hook_hash` is provably the sha256
    of what is on disk in the home rather than of what was downloaded."""
    mod = pi_mdm_setup
    username, home = homes[0]
    status = mod.install_for_user(username, home, PAYLOAD, "f" * 64)
    assert status.startswith("failed")


# --- the artifact is fetched and verified ONCE, before the loop ---------------------------


def test_the_artifact_is_fetched_and_verified_once_for_the_whole_device(
        pi_mdm_setup, fake_fetch, digest):
    """A per-home download would mean N chances for a corrupt artifact to reach one home
    and not another, and N× the traffic on a fleet-wide push."""
    mod = pi_mdm_setup
    fetch = fake_fetch({mod.ARTIFACT_URL: PAYLOAD,
                        mod.SHA_URL: f"{digest}  pi/index.js\n"}, module=mod)
    got = mod.fetch_artifact()
    assert got == (PAYLOAD, digest)
    assert sorted(fetch.calls) == sorted([mod.ARTIFACT_URL, mod.SHA_URL])


def test_a_digest_mismatch_refuses_the_whole_run(pi_mdm_setup, fake_fetch, capsys):
    """Refused before the loop, so a bad artifact reaches zero homes rather than all of them."""
    mod = pi_mdm_setup
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD, mod.SHA_URL: "b" * 64 + "  pi/index.js\n"}, module=mod)
    assert mod.fetch_artifact() is None
    assert "Integrity check failed" in capsys.readouterr().out


def test_a_missing_sidecar_refuses_the_whole_run(pi_mdm_setup, fake_fetch, capsys):
    mod = pi_mdm_setup
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD}, module=mod)  # sidecar deliberately unmapped
    assert mod.fetch_artifact() is None
    assert "sidecar" in capsys.readouterr().out


def test_a_malformed_sidecar_refuses_the_whole_run(pi_mdm_setup, fake_fetch, capsys):
    mod = pi_mdm_setup
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD, mod.SHA_URL: "not a digest\n"}, module=mod)
    assert mod.fetch_artifact() is None
    out = capsys.readouterr().out
    assert "not a sha256 sidecar" in out
    assert "expects None" not in out


def test_a_missing_artifact_refuses_the_whole_run(pi_mdm_setup, fake_fetch, digest, capsys):
    mod = pi_mdm_setup
    fake_fetch({mod.SHA_URL: f"{digest}  pi/index.js\n"}, module=mod)
    assert mod.fetch_artifact() is None
    assert mod.ARTIFACT_URL in capsys.readouterr().out


def test_the_staging_directory_is_always_removed(pi_mdm_setup, fake_fetch, digest, monkeypatch):
    """Root downloads into a 0700 temp dir; leaving it behind on a managed fleet would
    accumulate world-visible copies of the artifact under /tmp."""
    mod = pi_mdm_setup
    made = []
    real_mkdtemp = mod.tempfile.mkdtemp
    monkeypatch.setattr(mod.tempfile, "mkdtemp",
                        lambda *a, **k: made.append(real_mkdtemp(*a, **k)) or made[-1])
    fake_fetch({mod.ARTIFACT_URL: PAYLOAD, mod.SHA_URL: f"{digest}  pi/index.js\n"}, module=mod)
    assert mod.fetch_artifact() is not None
    assert made and not os.path.exists(made[0])


def test_the_installed_names_are_exactly_the_two_files_we_write(pi_mdm_setup):
    """--clear may remove only these, so the tuple is the contract between install and clear."""
    assert pi_mdm_setup.INSTALLED_NAMES == ("index.js", "index.js.sha256")
