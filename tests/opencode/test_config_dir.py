"""Where the opencode installer puts the plugin, and the preflight/args around it.

resolve_config_dir must answer exactly what the plugin's resolveOpencodeConfigDir
(hooks-ts/packages/opencode/src/profile.ts) answers. A mismatch installs the plugin
somewhere opencode never looks, or caches policy somewhere the plugin never reads.
"""

from pathlib import Path

import pytest


class TestResolveConfigDir:
    def test_no_env_is_dot_config_opencode(self, oc_setup, oc_home):
        assert oc_setup.resolve_config_dir(oc_home.home, {}) == oc_home.home / ".config" / "opencode"

    def test_the_default_ignores_the_platform(self, oc_setup, oc_home, monkeypatch):
        """xdg-basedir answers ~/.config on macOS too, never ~/Library/..."""
        monkeypatch.setattr(oc_setup.platform, "system", lambda: "Darwin")
        assert oc_setup.resolve_config_dir(oc_home.home, {}) == oc_home.home / ".config" / "opencode"

    def test_opencode_config_dir_absolute_wins(self, oc_setup, oc_home, tmp_path):
        target = tmp_path / "oc-abs"
        env = {"OPENCODE_CONFIG_DIR": str(target), "XDG_CONFIG_HOME": str(tmp_path / "x")}
        assert oc_setup.resolve_config_dir(oc_home.home, env) == target

    def test_opencode_config_dir_tilde_expands_against_the_passed_home(self, oc_setup, oc_home, monkeypatch):
        monkeypatch.setenv("HOME", "/nonexistent-real-home")
        got = oc_setup.resolve_config_dir(oc_home.home, {"OPENCODE_CONFIG_DIR": "~/oc"})
        assert got == oc_home.home / "oc"

    def test_a_bare_tilde_is_home(self, oc_setup, oc_home):
        assert oc_setup.resolve_config_dir(oc_home.home, {"OPENCODE_CONFIG_DIR": "~"}) == oc_home.home

    @pytest.mark.parametrize("value", ["rel/dir", "./oc", "../oc", "oc"])
    def test_a_relative_override_falls_through_to_xdg(self, oc_setup, oc_home, tmp_path, monkeypatch, value):
        monkeypatch.chdir(tmp_path)
        env = {"OPENCODE_CONFIG_DIR": value, "XDG_CONFIG_HOME": str(tmp_path / "x")}
        assert oc_setup.resolve_config_dir(oc_home.home, env) == tmp_path / "x" / "opencode"

    def test_a_relative_override_falls_through_to_the_default(self, oc_setup, oc_home, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        got = oc_setup.resolve_config_dir(oc_home.home, {"OPENCODE_CONFIG_DIR": "rel/dir"})
        assert got == oc_home.home / ".config" / "opencode"
        assert str(tmp_path / "rel") not in str(got)

    @pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
    def test_a_blank_override_falls_through(self, oc_setup, oc_home, blank):
        got = oc_setup.resolve_config_dir(oc_home.home, {"OPENCODE_CONFIG_DIR": blank})
        assert got == oc_home.home / ".config" / "opencode"

    def test_absolute_xdg_config_home(self, oc_setup, oc_home):
        assert oc_setup.resolve_config_dir(oc_home.home, {"XDG_CONFIG_HOME": "/x"}) == Path("/x/opencode")

    @pytest.mark.parametrize("value", ["rel", "", "~/xdg"])
    def test_a_non_absolute_xdg_is_the_default(self, oc_setup, oc_home, value):
        """profile.ts does not tilde-expand XDG_CONFIG_HOME, so neither do we."""
        got = oc_setup.resolve_config_dir(oc_home.home, {"XDG_CONFIG_HOME": value})
        assert got == oc_home.home / ".config" / "opencode"

    def test_no_absolute_home_and_no_absolute_env_is_none(self, oc_setup):
        assert oc_setup.resolve_config_dir("", {}) is None
        assert oc_setup.resolve_config_dir("not/absolute", {}) is None
        assert oc_setup.resolve_config_dir(None, {}) is None
        assert oc_setup.resolve_config_dir("rel", {"OPENCODE_CONFIG_DIR": "~/oc"}) is None

    def test_an_absolute_env_still_answers_without_a_home(self, oc_setup):
        assert oc_setup.resolve_config_dir(None, {"XDG_CONFIG_HOME": "/x"}) == Path("/x/opencode")
        assert oc_setup.resolve_config_dir("", {"OPENCODE_CONFIG_DIR": "/oc"}) == Path("/oc")

    def test_the_process_env_is_the_default_source(self, oc_setup, oc_home, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "from-env"))
        assert oc_setup.resolve_config_dir(oc_home.home) == tmp_path / "from-env"


class TestPaths:
    def test_plugin_path_is_plugins_unbound_js(self, oc_setup, oc_home):
        cfg = oc_home.config_dir
        assert oc_setup.plugin_dir(cfg) == cfg / "plugins"
        assert oc_setup.plugin_path(cfg) == cfg / "plugins" / "unbound.js"
        assert oc_setup.sidecar_path(cfg) == cfg / "plugins" / "unbound.js.sha256"
        assert oc_setup.marker_path(cfg) == cfg / "plugins" / ".unbound-installed.json"

    def test_the_artifact_url_is_the_committed_opencode_bundle(self, oc_setup):
        assert oc_setup.ARTIFACT_URL.endswith("refs/heads/main/opencode/index.js")
        assert oc_setup.SHA_URL == oc_setup.ARTIFACT_URL + ".sha256"


class TestPreflight:
    def test_a_missing_opencode_binary_warns_and_never_blocks(self, oc_setup, monkeypatch, capsys):
        monkeypatch.setattr(oc_setup.shutil, "which", lambda name: None)
        assert oc_setup.preflight() is True
        out = capsys.readouterr().out
        assert "opencode" in out and "PATH" in out

    def test_a_present_binary_is_reported(self, oc_setup, monkeypatch, capsys):
        monkeypatch.setattr(oc_setup.shutil, "which", lambda name: "/somewhere/bin/opencode")
        assert oc_setup.preflight() is True
        assert "/somewhere/bin/opencode" in capsys.readouterr().out

    def test_an_old_python_is_refused(self, oc_setup, monkeypatch, capsys):
        monkeypatch.setattr(oc_setup.sys, "version_info", (3, 7, 9))
        monkeypatch.setattr(oc_setup.shutil, "which", lambda name: None)
        assert oc_setup.preflight() is False
        assert "3.8" in capsys.readouterr().out


class TestArgParsing:
    def test_every_flag_the_cli_passes_is_understood(self, oc_setup):
        argv = ["setup.py", "--api-key", "k-123", "--backend-url", "backend.example.com",
                "--gateway-url", "https://gw.example.com/", "--domain", "app.example.com", "--debug"]
        args = oc_setup.parse_args(argv)
        assert args["api_key"] == "k-123"
        assert args["backend_url"] == "https://backend.example.com"
        assert args["gateway_url"] == "https://gw.example.com"
        assert args["domain"] == "app.example.com"
        assert args["debug"] is True
        assert args["clear"] is False

    def test_clear_needs_no_key(self, oc_setup):
        args = oc_setup.parse_args(["setup.py", "--clear"])
        assert args["clear"] is True and args["api_key"] is None

    def test_a_flag_with_no_value_does_not_crash(self, oc_setup):
        assert oc_setup.parse_args(["setup.py", "--api-key"])["api_key"] is None


class TestSourceShape:
    def test_the_callback_mints_an_opencode_key(self, oc_setup):
        src = Path(oc_setup.__file__).read_text()
        assert src.count("app_type=opencode") == 1
        assert "app_type=pi" not in src

    def test_no_pi_variable_survives_the_clone(self, oc_setup):
        code = [ln for ln in Path(oc_setup.__file__).read_text().splitlines()
                if not ln.lstrip().startswith("#")]
        assert not any("PI_CODING_AGENT_DIR" in ln for ln in code)
