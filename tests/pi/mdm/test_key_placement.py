"""Where the device key lands, and the two places this installer deliberately differs.

Tier 1 is `UNBOUND_PI_API_KEY` in each user's rc files. Tier 3 is `api_key` in that user's
`~/.unbound/config.json`. Both are written, because an rc export is invisible to a shell
that is already open and to a GUI-launched pi -- but:

  * an rc file is EXECUTED by the user's login shell, so the value passes a charset gate
    before any append (`_is_safe_env_value`, an addition to the Augment analog); and
  * `config.json` `api_key` is written with `setdefault`, where Augment assigns
    unconditionally -- that file is the shared identity store for unbound-cli, Cursor,
    Claude Code, Codex, Copilot and Augment, and clobbering it would repoint all of them at
    this device key.
"""

import json
import os
import stat

import pytest

KEY = "pi-app-key-AbC123._:-"


@pytest.fixture
def unix(pi_mdm_setup, monkeypatch):
    """Pin darwin, so the rc file set and the ownership branch are deterministic."""
    monkeypatch.setattr(pi_mdm_setup.platform, "system", lambda: "Darwin")
    return pi_mdm_setup


@pytest.fixture
def passthrough(pi_mdm_setup, monkeypatch):
    """Run the in-home function in-process; the real drop needs root (see test_drop.py)."""
    seen = []

    def _fake(username, fn, *args, **kwargs):
        seen.append(username)
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None

    monkeypatch.setattr(pi_mdm_setup, "_run_as_user", _fake)
    return seen


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "Users" / "alice"
    h.mkdir(parents=True)
    return h


# --- the charset gate ----------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "abcDEF123", "key_with_underscore", "key.with.dots", "key-with-dashes",
    "key:with:colons", "0123456789",
])
def test_safe_values_pass(unix, value):
    assert unix._is_safe_env_value(value) is True


@pytest.mark.parametrize("value", [
    'key"quote', "key'quote", "key$(whoami)", "key`id`", "key;rm -rf /", "key with space",
    "key\nexport EVIL=1", "key\\backslash", "key|pipe", "key&amp", "key>redirect",
    "key#comment", "key*glob", "", None, 123, "a" * 513,
])
def test_unsafe_values_are_refused(unix, value):
    """Each of these would be CODE in an rc file, not data. The newline case is the worst:
    it appends a second, entirely attacker-chosen line to every account on the device."""
    assert unix._is_safe_env_value(value) is False


def test_an_unsafe_value_is_refused_before_any_file_is_touched(
        unix, passthrough, home, capsys):
    """The gate has to come first. A per-file check after the mkdir would still have created
    the rc file, and a check after the append would already have written the injection."""
    injected = 'k"\nexport ANTHROPIC_BASE_URL="https://attacker.test'
    ok, changed = unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, injected)
    assert (ok, changed) == (False, False)
    assert not (home / ".zprofile").exists()
    assert not (home / ".bash_profile").exists()
    assert "Refusing to write" in capsys.readouterr().out


# --- the rc append -------------------------------------------------------------------------


def test_the_export_lands_in_both_rc_files_quoted(unix, passthrough, home):
    ok, changed = unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY)
    assert (ok, changed) == (True, True)
    for name in (".zprofile", ".bash_profile"):
        assert (home / name).read_text().rstrip().endswith(
            f'export UNBOUND_PI_API_KEY="{KEY}"')
    assert passthrough == ["alice"]


def test_a_second_run_appends_nothing(unix, passthrough, home):
    """Asserted by LINE COUNT, not by substring presence: an implementation that appended
    every time would keep the substring assertion green while growing the file on every
    MDM push until the shell took a noticeable time to start."""
    unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY)
    counts = {n: len((home / n).read_text().splitlines()) for n in (".zprofile", ".bash_profile")}
    ok, changed = unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY)
    assert ok is True and changed is False
    for name, before in counts.items():
        assert len((home / name).read_text().splitlines()) == before


def test_a_rotated_key_replaces_the_line_rather_than_adding_one(unix, passthrough, home):
    """A second MDM push with a new key must leave exactly one export, or the shell's
    last-wins ordering decides which key the extension uses."""
    unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY)
    unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, "rotated-key-2")
    body = (home / ".zprofile").read_text()
    assert body.count("export UNBOUND_PI_API_KEY=") == 1
    assert 'export UNBOUND_PI_API_KEY="rotated-key-2"' in body
    assert KEY not in body


def test_a_foreign_rc_file_is_preserved(unix, passthrough, home):
    """The rule the whole repo turns on: an rc file belongs to its user, and we add one line."""
    rc = home / ".zprofile"
    rc.write_text('export ANTHROPIC_BASE_URL="https://llm.acme-corp.internal"\n'
                  'alias ll="ls -la"\n')
    unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY)
    body = rc.read_text()
    assert "llm.acme-corp.internal" in body
    assert 'alias ll="ls -la"' in body
    assert f'export UNBOUND_PI_API_KEY="{KEY}"' in body


def test_the_export_is_written_with_privileges_dropped(unix, monkeypatch, home):
    """With the drop refusing to run, the rc file must not appear: a code path that appended
    as root would leave a root-owned rc file the user can no longer edit."""
    monkeypatch.setattr(unix, "_run_as_user", lambda username, fn, *a, **k: None)
    assert unix.set_env_var_for_user("alice", home, unix.ENV_API_KEY_PI, KEY) == (False, False)
    assert not (home / ".zprofile").exists()


def test_the_variable_is_the_pi_specific_tier(unix):
    """The generic UNBOUND_API_KEY is read by six other tools; writing the device key there
    would hand it to all of them, which is the same mistake as clobbering config.json."""
    assert unix.ENV_API_KEY_PI == "UNBOUND_PI_API_KEY"
    src = open(unix.__file__, encoding="utf-8").read()
    for line in src.splitlines():
        if "UNBOUND_API_KEY" in line and "UNBOUND_PI_API_KEY" not in line:
            assert line.lstrip().startswith("#"), line.strip()[:90]


def test_linux_uses_the_shell_rc_files_not_the_profiles(pi_mdm_setup, monkeypatch, home):
    """macOS login shells read .zprofile/.bash_profile; Linux desktop sessions read
    .zshrc/.bashrc. Writing the wrong pair means the export is never sourced."""
    monkeypatch.setattr(pi_mdm_setup.platform, "system", lambda: "Linux")
    assert [p.name for p in pi_mdm_setup.rc_files_for(home)] == [".zshrc", ".bashrc"]
    monkeypatch.setattr(pi_mdm_setup.platform, "system", lambda: "Darwin")
    assert [p.name for p in pi_mdm_setup.rc_files_for(home)] == [".zprofile", ".bash_profile"]


# --- config.json: the deliberate divergence ------------------------------------------------


def test_an_absent_api_key_is_written(unix, passthrough, home):
    assert unix.write_unbound_config_for_user("alice", home, KEY,
                                              urls={"base_url": "https://b.test"}) is True
    config = json.loads((home / ".unbound" / "config.json").read_text())
    assert config["api_key"] == KEY
    assert config["base_url"] == "https://b.test"


def test_an_existing_different_api_key_is_left_byte_identical(unix, passthrough, home):
    """The whole reason this file diverges from the Augment analog. A user who ran
    `unbound login` has their own org key here, and it is what Cursor, Claude Code, Codex,
    Copilot and Augment all authenticate with."""
    unbound_dir = home / ".unbound"
    unbound_dir.mkdir()
    config_path = unbound_dir / "config.json"
    config_path.write_text(json.dumps({
        "api_key": "the-users-own-key-do-not-touch",
        "email": "alice@acme.test",
        "org_name": "Acme",
        "base_url": "https://old.test",
    }, indent=2))

    assert unix.write_unbound_config_for_user("alice", home, KEY, urls={
        "base_url": "https://new.test", "gateway_url": "https://gw.test",
        "frontend_url": "https://app.test"}) is True

    config = json.loads(config_path.read_text())
    assert config["api_key"] == "the-users-own-key-do-not-touch"
    assert KEY not in config_path.read_text()
    # URLs are tenant configuration, not identity, so they DO update.
    assert config["base_url"] == "https://new.test"
    assert config["gateway_url"] == "https://gw.test"
    assert config["frontend_url"] == "https://app.test"
    # And the merge preserves everything else in the file.
    assert config["email"] == "alice@acme.test"
    assert config["org_name"] == "Acme"


def test_a_rotated_key_replaces_the_one_this_installer_wrote(unix, passthrough, home):
    """The failure a blanket "never overwrite" left behind. Push one writes the key; the org
    revokes it; push two obtained the replacement, updated the rc exports and left the dead
    key in config.json -- the one tier a GUI-launched pi and every already-open shell read. So
    the extension kept authenticating with a revoked key after a redeployment that reported
    success. A key we wrote is ours to rotate; the digest beside it is how we know."""
    config_path = home / ".unbound" / "config.json"

    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v1") is True
    assert json.loads(config_path.read_text())["api_key"] == "pi-key-v1"

    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v2") is True
    config = json.loads(config_path.read_text())
    assert config["api_key"] == "pi-key-v2"
    assert "pi-key-v1" not in config_path.read_text(), "the revoked key survived the push"


def test_a_key_the_user_manages_is_still_never_rotated(unix, passthrough, home):
    """The other half, asserted after a push of ours so the provenance field is present: a
    value that does not match what we recorded belongs to `unbound login`, and the five other
    tools authenticate with it."""
    config_path = home / ".unbound" / "config.json"
    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v1") is True

    config = json.loads(config_path.read_text())
    config["api_key"] = "the-users-own-key-do-not-touch"
    config_path.write_text(json.dumps(config, indent=2))

    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v2") is True
    assert json.loads(config_path.read_text())["api_key"] == "the-users-own-key-do-not-touch"
    assert "pi-key-v2" not in config_path.read_text()


def test_the_provenance_field_is_a_digest_not_the_key(unix, passthrough, home):
    """It answers "is this still the value we wrote?", so a second copy of the secret would be
    a gratuitous one. And it must track the key it is written beside, or the next rotation
    would either refuse or fire on the wrong value."""
    import hashlib

    unix.write_unbound_config_for_user("alice", home, "pi-key-v1")
    config = json.loads((home / ".unbound" / "config.json").read_text())
    recorded = config[unix.MDM_KEY_PROVENANCE_FIELD]
    assert recorded == hashlib.sha256(b"pi-key-v1").hexdigest()
    assert "pi-key-v1" not in recorded


def test_a_pre_existing_identical_key_is_adopted_rather_than_orphaned(unix, passthrough, home):
    """The upgrade path off the old behaviour, and the idempotent re-push. A config carrying
    the key we are about to write, with no provenance recorded (an older installer wrote it),
    is claimed -- otherwise the very first rotation after this change would still be stuck."""
    unbound_dir = home / ".unbound"
    unbound_dir.mkdir()
    config_path = unbound_dir / "config.json"
    config_path.write_text(json.dumps({"api_key": "pi-key-v1", "email": "alice@acme.test"}))

    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v1") is True
    assert unix.MDM_KEY_PROVENANCE_FIELD in json.loads(config_path.read_text())

    assert unix.write_unbound_config_for_user("alice", home, "pi-key-v2") is True
    config = json.loads(config_path.read_text())
    assert config["api_key"] == "pi-key-v2"
    assert config["email"] == "alice@acme.test", "the merge still preserves everything else"


def test_empty_url_values_do_not_blank_existing_ones(unix, passthrough, home):
    """--frontend-url is optional, and None must not be written over a good value."""
    unbound_dir = home / ".unbound"
    unbound_dir.mkdir()
    (unbound_dir / "config.json").write_text(json.dumps({"frontend_url": "https://app.test"}))
    unix.write_unbound_config_for_user("alice", home, KEY,
                                       urls={"base_url": "https://b.test", "frontend_url": None})
    config = json.loads((unbound_dir / "config.json").read_text())
    assert config["frontend_url"] == "https://app.test"


def test_a_corrupt_config_is_replaced_rather_than_fatal(unix, passthrough, home):
    unbound_dir = home / ".unbound"
    unbound_dir.mkdir()
    (unbound_dir / "config.json").write_text("{ this is not json")
    assert unix.write_unbound_config_for_user("alice", home, KEY) is True
    assert json.loads((unbound_dir / "config.json").read_text())["api_key"] == KEY


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_the_config_is_0600_inside_a_0700_directory(unix, passthrough, home):
    """It holds an API key, so neither other local users nor a stray group may read it."""
    unix.write_unbound_config_for_user("alice", home, KEY)
    unbound_dir = home / ".unbound"
    assert stat.S_IMODE(unbound_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((unbound_dir / "config.json").stat().st_mode) == 0o600


def test_the_config_write_goes_through_the_privilege_drop(unix, monkeypatch, home):
    """Root writing this file directly would leave it root-owned, and the user's next
    `unbound login` would fail with EACCES on their own config."""
    monkeypatch.setattr(unix, "_run_as_user", lambda username, fn, *a, **k: None)
    assert unix.write_unbound_config_for_user("alice", home, KEY) is False
    assert not (home / ".unbound" / "config.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="O_NOFOLLOW is Unix-only")
def test_a_symlinked_config_is_refused_not_written_through(
        unix, passthrough, home, tmp_path):
    """A symlink at ~/.unbound/config.json is how a user would try to get us to write a key
    somewhere else; O_NOFOLLOW turns that into ELOOP."""
    unbound_dir = home / ".unbound"
    unbound_dir.mkdir()
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("untouched\n")
    (unbound_dir / "config.json").symlink_to(elsewhere)
    unix.write_unbound_config_for_user("alice", home, KEY)
    assert elsewhere.read_text() == "untouched\n"


def test_the_divergence_is_stated_at_the_write_site(unix):
    """A conditional write reads like a typo next to the analog's plain assignment. The next
    person to "fix" it into one has to walk past both halves of the reason -- why a user's own
    key is never overwritten, AND why ours must be."""
    src = open(unix.__file__, encoding="utf-8").read()
    body = src.split("def write_unbound_config_for_user")[1].split("\ndef ")[0]
    assert "DELIBERATE DIVERGENCE" in body
    assert "augment/hooks/mdm/setup.py" in body
    for tool in ("Cursor", "Claude Code", "Codex", "Copilot", "Augment"):
        assert tool in body, tool
    assert "MDM_KEY_PROVENANCE_FIELD" in body, "the ownership check is what makes this safe"
    assert "revoked" in body, "the rotation half of the reason is stated too"


def test_the_env_gate_is_stated_as_an_addition(unix):
    """It is not in the analog, so the PR body and the next reader both need to know why."""
    src = open(unix.__file__, encoding="utf-8").read()
    body = src.split("def _is_safe_env_value")[1].split("\ndef ")[0]
    assert "EXECUTED" in body or "executed" in body
    assert "allow-list" in body
