"""The privileged per-home drop: one verified artifact fanned out into every home.

The privilege-drop and ownership-repair primitives are pi's, unchanged; they are
re-asserted here because this file is a standalone copy. The opencode-specific parts --
plugins/unbound.js, stray copies, the ESM package.json rule -- run per home, inside the drop.
"""

import hashlib
import json
import os
import platform
import stat

import pytest

from tests.opencode.conftest import UNBOUND_BANNER, FakePwd, pw_row

WINDOWS = platform.system().lower() == "windows"
PAYLOAD = UNBOUND_BANNER + b"export default {};\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def _plugins(home):
    return home / ".config" / "opencode" / "plugins"


# --- the primitives, unchanged ----------------------------------------------------------


@pytest.fixture
def repair_probe(oc_mdm_setup, monkeypatch):
    mod = oc_mdm_setup
    monkeypatch.setattr(mod, "pwd", FakePwd([pw_row("target", 4242, "/nonexistent")]))
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    chowned = []
    monkeypatch.setattr(mod.os, "fchown",
                        lambda fd, uid, gid: chowned.append(os.fstat(fd).st_ino))
    return chowned


@pytest.mark.skipif(WINDOWS, reason="Unix-only")
def test_repair_chowns_a_plain_file_by_fd(oc_mdm_setup, repair_probe, tmp_path):
    target = tmp_path / "unbound.js"
    target.write_bytes(PAYLOAD)
    oc_mdm_setup._repair_user_ownership("target", tmp_path, [target])
    assert repair_probe == [target.stat().st_ino]


@pytest.mark.skipif(WINDOWS, reason="Unix-only")
def test_repair_refuses_a_hardlink_and_a_symlink(oc_mdm_setup, repair_probe, tmp_path):
    sensitive = tmp_path / "shadow"
    sensitive.write_text("x")
    os.link(sensitive, tmp_path / "unbound.js")
    (tmp_path / "plugins").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    oc_mdm_setup._repair_user_ownership("target", tmp_path,
                                        [tmp_path / "unbound.js", tmp_path / "plugins" / "x"])
    assert repair_probe == []


def test_run_as_user_drops_groups_then_gid_then_uid(oc_mdm_setup, monkeypatch):
    mod = oc_mdm_setup
    if WINDOWS:
        pytest.skip("no fork on Windows")
    monkeypatch.setattr(mod, "pwd", FakePwd([pw_row("target", 4242, "/nonexistent")]))
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    order = []
    monkeypatch.setattr(mod.os, "setgroups", lambda g: order.append(("setgroups", tuple(g))))
    monkeypatch.setattr(mod.os, "setgid", lambda g: order.append(("setgid", g)))
    monkeypatch.setattr(mod.os, "setuid", lambda u: order.append(("setuid", u)))
    monkeypatch.setattr(mod.os, "fork", lambda: 0)
    monkeypatch.setattr(mod.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr(mod.os, "write", lambda fd, data: len(data))
    monkeypatch.setattr(mod.os, "close", lambda fd: None)
    with pytest.raises(SystemExit):
        mod._run_as_user("target", lambda: "ran")
    assert order == [("setgroups", ()), ("setgid", 4242), ("setuid", 4242)]


# --- the per-home drop ------------------------------------------------------------------


def test_a_drop_lands_unbound_js_at_0644_in_every_home(oc_mdm_setup, passthrough, fake_homes):
    mod = oc_mdm_setup
    for username, home in fake_homes:
        assert mod.install_for_user(username, home, PAYLOAD, DIGEST) == "installed"
        target = _plugins(home) / "unbound.js"
        assert target.read_bytes() == PAYLOAD
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
        assert (_plugins(home) / "unbound.js.sha256").read_text() == f"{DIGEST}  unbound.js\n"
    assert passthrough == ["alice", "bob"]


def test_ownership_repair_covers_the_plugin_dir_file_and_sidecar(
        oc_mdm_setup, passthrough, fake_homes, monkeypatch):
    mod = oc_mdm_setup
    seen = {}
    monkeypatch.setattr(mod, "_repair_user_ownership",
                        lambda username, base, paths: seen.update(
                            user=username, base=str(base), paths=[str(p) for p in paths]))
    username, home = fake_homes[0]
    mod.install_for_user(username, home, PAYLOAD, DIGEST)
    plugins = _plugins(home)
    assert seen["user"] == "alice" and seen["base"] == str(home)
    for p in (plugins, plugins / "unbound.js", plugins / "unbound.js.sha256"):
        assert str(p) in seen["paths"]
    assert str(home) not in seen["paths"], "the home itself is never offered for repair"


def test_every_in_home_write_goes_through_the_drop(oc_mdm_setup, monkeypatch, fake_homes):
    mod = oc_mdm_setup
    monkeypatch.setattr(mod, "_run_as_user", lambda username, fn, *a, **k: None)
    username, home = fake_homes[0]
    assert mod.install_for_user(username, home, PAYLOAD, DIGEST).startswith("failed")
    assert not (home / ".config").exists()


def test_a_second_pass_is_persisted(oc_mdm_setup, passthrough, fake_homes):
    username, home = fake_homes[0]
    assert oc_mdm_setup.install_for_user(username, home, PAYLOAD, DIGEST) == "installed"
    assert oc_mdm_setup.install_for_user(username, home, PAYLOAD, DIGEST) == "persisted"


@pytest.mark.skipif(WINDOWS, reason="O_NOFOLLOW is Unix-only")
def test_a_symlinked_plugin_is_refused_and_other_homes_still_install(
        oc_mdm_setup, passthrough, fake_homes, tmp_path):
    mod = oc_mdm_setup
    (alice, alice_home), (bob, bob_home) = fake_homes
    _plugins(alice_home).mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere.js"
    elsewhere.write_text("untouched\n")
    (_plugins(alice_home) / "unbound.js").symlink_to(elsewhere)
    assert mod.install_for_user(alice, alice_home, PAYLOAD, DIGEST).startswith("failed")
    assert elsewhere.read_text() == "untouched\n"
    assert mod.install_for_user(bob, bob_home, PAYLOAD, DIGEST) == "installed"


def test_one_bad_home_never_aborts_the_others(oc_mdm_setup, passthrough, fake_homes):
    (alice, alice_home), (bob, bob_home) = fake_homes
    (alice_home / ".config").write_text("not a directory\n")
    rows = [oc_mdm_setup.install_for_user(u, h, PAYLOAD, DIGEST) for u, h in fake_homes]
    assert rows[0].startswith("failed") and rows[1] == "installed"


def test_a_relative_home_is_a_recorded_failure(oc_mdm_setup, passthrough):
    assert oc_mdm_setup.install_for_user("alice", "relative/home", PAYLOAD, DIGEST).startswith("failed")


def test_a_payload_that_does_not_match_the_digest_is_refused(oc_mdm_setup, passthrough, fake_homes):
    username, home = fake_homes[0]
    assert oc_mdm_setup.install_for_user(username, home, PAYLOAD, "f" * 64).startswith("failed")


# --- strays and the ESM rule, per home ----------------------------------------------------


def test_a_recognised_stray_is_removed_in_that_home_only(
        oc_mdm_setup, passthrough, fake_homes, capsys):
    (alice, alice_home), (bob, bob_home) = fake_homes
    legacy = alice_home / ".config" / "opencode" / "plugin"
    legacy.mkdir(parents=True)
    (legacy / "unbound.js").write_bytes(UNBOUND_BANNER)
    unrecognised = _plugins(alice_home) / "unbound.ts"
    unrecognised.parent.mkdir(parents=True)
    unrecognised.write_bytes(b"// alice's own\n")
    assert oc_mdm_setup.install_for_user(alice, alice_home, PAYLOAD, DIGEST) == "installed"
    assert not (legacy / "unbound.js").exists()
    assert unrecognised.read_bytes() == b"// alice's own\n"
    out = capsys.readouterr().out
    assert "stray" in out.lower() and "left in place" in out
    oc_mdm_setup.install_for_user(bob, bob_home, PAYLOAD, DIGEST)
    assert "left in place" not in capsys.readouterr().out


def test_the_esm_rule_applies_per_home(oc_mdm_setup, passthrough, fake_homes):
    (alice, alice_home), (bob, bob_home) = fake_homes
    _plugins(bob_home).mkdir(parents=True)
    (_plugins(bob_home) / "other.js").write_text("// bob's\n")
    for u, h in fake_homes:
        oc_mdm_setup.install_for_user(u, h, PAYLOAD, DIGEST)
    assert json.loads((_plugins(alice_home) / "package.json").read_text()) == {"type": "module"}
    assert json.loads((_plugins(alice_home) / ".unbound-installed.json").read_text()) == \
        {"created": ["package.json"]}
    assert not (_plugins(bob_home) / "package.json").exists()
    assert not (_plugins(bob_home) / ".unbound-installed.json").exists()


def test_an_existing_package_json_is_never_modified(oc_mdm_setup, passthrough, fake_homes):
    username, home = fake_homes[0]
    _plugins(home).mkdir(parents=True)
    pkg = _plugins(home) / "package.json"
    pkg.write_text('{"type":"commonjs"}')
    oc_mdm_setup.install_for_user(username, home, PAYLOAD, DIGEST)
    assert pkg.read_text() == '{"type":"commonjs"}'


def test_no_opencode_config_file_is_written_in_any_home(oc_mdm_setup, passthrough, fake_homes):
    for u, h in fake_homes:
        oc_mdm_setup.install_for_user(u, h, PAYLOAD, DIGEST)
        cfg = h / ".config" / "opencode"
        assert sorted(os.listdir(cfg)) == ["plugins"]


# --- the artifact: fetched and verified once ---------------------------------------------


def test_fetch_artifact_accepts_the_committed_sidecar(oc_mdm_setup, fake_fetch):
    mod = oc_mdm_setup
    fetch = fake_fetch({mod.ARTIFACT_URL: PAYLOAD,
                        mod.SHA_URL: f"{DIGEST}  opencode/index.js\n"}, module=mod)
    assert mod.fetch_artifact() == (PAYLOAD, DIGEST)
    assert sorted(fetch.calls) == sorted([mod.ARTIFACT_URL, mod.SHA_URL])


@pytest.mark.parametrize("sidecar", ["b" * 64 + "  opencode/index.js\n", "nope\n", None])
def test_a_bad_or_missing_sidecar_refuses_the_whole_run(oc_mdm_setup, fake_fetch, sidecar):
    mod = oc_mdm_setup
    mapping = {mod.ARTIFACT_URL: PAYLOAD}
    if sidecar is not None:
        mapping[mod.SHA_URL] = sidecar
    fake_fetch(mapping, module=mod)
    assert mod.fetch_artifact() is None
