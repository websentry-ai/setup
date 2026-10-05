"""Home enumeration for the opencode MDM installer: the same rules as pi's, asserted again
because this file is a standalone clone and could drift on its own."""

import pytest

from tests.opencode.conftest import FakePwd, pw_row


def _force(monkeypatch, mod, system, pwd_module=None):
    monkeypatch.setattr(mod.platform, "system", lambda: system)
    if pwd_module is not None:
        monkeypatch.setattr(mod, "pwd", pwd_module)


def test_the_shipped_prefixes_and_floors_match_pi(oc_mdm_setup):
    mod = oc_mdm_setup
    assert mod.MACOS_HOME_PREFIX == '/Users/'
    assert mod.LINUX_HOME_PREFIX == '/home/'
    assert mod.MACOS_UID_FLOOR == 500
    assert mod.LINUX_UID_FLOOR == 1000
    assert set(mod.MACOS_SKIP_USERS) == {"Shared", "Guest"}
    assert set(mod.WINDOWS_SKIP_PROFILES) == {
        "Public", "Default", "Default User", "Administrator", "All Users"}


def test_darwin_returns_only_real_user_homes(oc_mdm_setup, monkeypatch, tmp_path):
    mod = oc_mdm_setup
    users = tmp_path / "Users"
    users.mkdir()
    monkeypatch.setattr(mod, "MACOS_HOME_PREFIX", str(users) + "/")
    for name in ("alice", "bob", "Shared", "Guest", "belowfloor"):
        (users / name).mkdir()
    (users / "afile").write_text("x\n")
    outside = tmp_path / "opt" / "svc"
    outside.mkdir(parents=True)
    entries = [
        pw_row("root", 0, "/var/root"),
        pw_row("belowfloor", 499, users / "belowfloor"),
        pw_row("alice", 501, users / "alice"),
        pw_row("bob", 502, users / "bob"),
        pw_row("Shared", 503, users / "Shared"),
        pw_row("Guest", 504, users / "Guest"),
        pw_row("gone", 505, users / "nope"),
        pw_row("afile", 506, users / "afile"),
        pw_row("svc", 507, outside),
    ]
    _force(monkeypatch, mod, "Darwin", FakePwd(entries))
    assert [n for n, _ in mod.get_all_user_homes()] == ["alice", "bob"]


def test_linux_uses_its_floor_and_prefix(oc_mdm_setup, monkeypatch, tmp_path):
    mod = oc_mdm_setup
    home = tmp_path / "linux-home"
    home.mkdir()
    monkeypatch.setattr(mod, "LINUX_HOME_PREFIX", str(home) + "/")
    for name in ("carol", "low", "Shared"):
        (home / name).mkdir()
    entries = [pw_row("carol", 1000, home / "carol"), pw_row("low", 999, home / "low"),
               pw_row("Shared", 1001, home / "Shared")]
    _force(monkeypatch, mod, "Linux", FakePwd(entries))
    assert [n for n, _ in mod.get_all_user_homes()] == ["carol", "Shared"]


def test_a_broken_directory_service_is_an_empty_list(oc_mdm_setup, monkeypatch):
    _force(monkeypatch, oc_mdm_setup, "Darwin", FakePwd(raises=OSError("opendirectoryd down")))
    assert oc_mdm_setup.get_all_user_homes() == []


def test_an_unknown_platform_is_an_empty_list(oc_mdm_setup, monkeypatch):
    _force(monkeypatch, oc_mdm_setup, "Plan9")
    assert oc_mdm_setup.get_all_user_homes() == []


class TestResolveConfigDir:
    def test_it_is_dot_config_opencode_under_the_home(self, oc_mdm_setup, tmp_path):
        assert oc_mdm_setup.resolve_config_dir(tmp_path) == tmp_path / ".config" / "opencode"

    @pytest.mark.parametrize("home", ["", None, "relative/home"])
    def test_a_non_absolute_home_is_none(self, oc_mdm_setup, home):
        assert oc_mdm_setup.resolve_config_dir(home) is None

    def test_root_env_is_never_consulted(self, oc_mdm_setup, tmp_path, monkeypatch):
        """Root cannot see the target user's OPENCODE_CONFIG_DIR / XDG_CONFIG_HOME, and
        honouring root's own copy would send every user's plugin to one directory."""
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "evil"))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "evil2"))
        assert oc_mdm_setup.resolve_config_dir(tmp_path) == tmp_path / ".config" / "opencode"

    def test_paths(self, oc_mdm_setup, tmp_path):
        cfg = tmp_path / ".config" / "opencode"
        assert oc_mdm_setup.plugin_path(cfg) == cfg / "plugins" / "unbound.js"
        assert oc_mdm_setup.sidecar_path(cfg) == cfg / "plugins" / "unbound.js.sha256"
        assert oc_mdm_setup.marker_path(cfg) == cfg / "plugins" / ".unbound-installed.json"


class TestSourceShape:
    def test_no_pi_path_survives_the_clone(self, oc_mdm_setup):
        src = open(oc_mdm_setup.__file__, encoding="utf-8").read()
        code = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
        # A `.pi` PATH (`~/.pi/agent`); `os.pipe()` in the verbatim _run_as_user is not one.
        assert not [ln for ln in code if "/.pi" in ln or ".pi/" in ln or '".pi"' in ln]
        assert "UNBOUND_PI_API_KEY" not in src and "app_type\", \"pi\"" not in src

    def test_the_renamed_constants(self, oc_mdm_setup):
        mod = oc_mdm_setup
        assert mod.ENV_API_KEY == "UNBOUND_OPENCODE_API_KEY"
        assert mod.MDM_KEY_PROVENANCE_FIELD == "opencode_mdm_api_key_sha256"
        assert mod.INSTALLED_NAMES == ("unbound.js", "unbound.js.sha256")
        assert mod.CONFIG_DIR_SEGMENTS == (".config", "opencode")
        assert mod.ARTIFACT_URL.endswith("refs/heads/main/opencode/index.js")
