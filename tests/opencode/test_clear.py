"""`--clear` removes what the opencode installer wrote, and provably nothing else (INST-08).

The shared contract test already runs a pristine-HOME clear for every installer. These
add the opencode half: the package.json rule (removed only when the marker says we
created it AND it is still exactly {"type":"module"}), no network, no config.json.
"""

import json

import pytest


@pytest.fixture
def clear_env(oc_setup, oc_home, monkeypatch):
    """clear_setup() against the fake HOME, with any subprocess call a test failure."""

    def no_subprocess(*args, **kwargs):
        raise AssertionError("clear_setup made a subprocess call: %r" % (args,))

    monkeypatch.setattr(oc_setup.subprocess, "run", no_subprocess)
    return oc_home


def _plant_install(home, base=None):
    plugins = home.plugins(base)
    plugins.mkdir(parents=True, exist_ok=True)
    (plugins / "unbound.js").write_text("// unbound\n")
    (plugins / "unbound.js.sha256").write_text("d" * 64 + "  unbound.js\n")
    return plugins


class TestPristineMachine:
    def test_it_returns_true_and_says_not_found(self, oc_setup, clear_env, capsys):
        assert oc_setup.clear_setup() is True
        out = capsys.readouterr().out
        assert "OpenCode Plugin - Clearing Setup" in out
        assert "not_found" in out

    def test_it_creates_nothing(self, oc_setup, clear_env):
        oc_setup.clear_setup()
        assert not clear_env.config_dir.exists()
        assert not clear_env.plugins().exists()
        assert not clear_env.config_path.exists()


class TestWhatItRemoves:
    def test_it_removes_the_plugin_and_sidecar(self, oc_setup, clear_env):
        plugins = _plant_install(clear_env)
        assert oc_setup.clear_setup() is True
        assert not (plugins / "unbound.js").exists()
        assert not (plugins / "unbound.js.sha256").exists()
        assert plugins.is_dir(), "the plugins directory is never removed"

    def test_foreign_plugin_and_shared_config_are_byte_identical(self, oc_setup, clear_env):
        plugins = _plant_install(clear_env)
        other = plugins / "other.js"
        other.write_bytes(b"export const Other = async () => ({})\n")
        cfg = clear_env.write_config({"api_key": "shared", "email": "a@b.c"})
        before = cfg.read_bytes()
        oc_setup.clear_setup()
        assert other.read_bytes() == b"export const Other = async () => ({})\n"
        assert cfg.read_bytes() == before

    def test_it_never_opens_the_shared_config(self, oc_setup, clear_env, monkeypatch):
        _plant_install(clear_env)
        clear_env.write_config({"api_key": "shared"})
        real_open = open

        def guarded(path, *a, **k):
            assert "config.json" not in str(path), "clear opened ~/.unbound/config.json"
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", guarded)
        assert oc_setup.clear_setup() is True

    def test_our_package_json_is_removed_when_the_marker_lists_it(self, oc_setup, clear_env):
        plugins = _plant_install(clear_env)
        (plugins / "package.json").write_text('{ "type" : "module" }\n')
        (plugins / ".unbound-installed.json").write_text(json.dumps({"created": ["package.json"]}))
        assert oc_setup.clear_setup() is True
        assert not (plugins / "package.json").exists()
        assert not (plugins / ".unbound-installed.json").exists()

    def test_a_user_package_json_without_a_marker_survives(self, oc_setup, clear_env):
        plugins = _plant_install(clear_env)
        (plugins / "package.json").write_text('{"type":"module"}')
        oc_setup.clear_setup()
        assert (plugins / "package.json").read_text() == '{"type":"module"}'

    def test_an_edited_package_json_survives_even_with_the_marker(self, oc_setup, clear_env, capsys):
        plugins = _plant_install(clear_env)
        body = '{"type":"module","dependencies":{"x":"1"}}'
        (plugins / "package.json").write_text(body)
        (plugins / ".unbound-installed.json").write_text(json.dumps({"created": ["package.json"]}))
        assert oc_setup.clear_setup() is True
        assert (plugins / "package.json").read_text() == body
        assert "package.json" in capsys.readouterr().out
        assert not (plugins / ".unbound-installed.json").exists(), "the marker is ours either way"

    @pytest.mark.parametrize("marker", ["{not json", "[]", '{"created": "package.json"}', ""])
    def test_a_corrupt_marker_means_nothing_extra_is_removed(self, oc_setup, clear_env, marker):
        plugins = _plant_install(clear_env)
        (plugins / "package.json").write_text('{"type":"module"}')
        (plugins / ".unbound-installed.json").write_text(marker)
        assert oc_setup.clear_setup() is True
        assert (plugins / "package.json").exists()
        assert not (plugins / ".unbound-installed.json").exists()

    def test_the_marker_never_names_anything_but_package_json(self, oc_setup, clear_env):
        plugins = _plant_install(clear_env)
        other = plugins / "other.js"
        other.write_text("// mine\n")
        (plugins / ".unbound-installed.json").write_text(
            json.dumps({"created": ["other.js", "../../../.zshrc"]}))
        oc_setup.clear_setup()
        assert other.exists()


class TestEnvAwareness:
    def test_it_clears_the_opencode_config_dir_target(self, oc_setup, clear_env, monkeypatch, tmp_path):
        base = tmp_path / "custom-oc"
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(base))
        plugins = _plant_install(clear_env, base=base)
        default = _plant_install(clear_env)
        assert oc_setup.clear_setup() is True
        assert not (plugins / "unbound.js").exists()
        assert (default / "unbound.js").exists(), "only the resolved dir is cleared"

    def test_it_honours_xdg_config_home(self, oc_setup, clear_env, monkeypatch, tmp_path):
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        plugins = _plant_install(clear_env, base=xdg / "opencode")
        assert oc_setup.clear_setup() is True
        assert not (plugins / "unbound.js").exists()


class TestClearPathPrimitive:
    def test_statuses(self, oc_setup, tmp_path):
        target = tmp_path / "unbound.js"
        assert oc_setup._clear_path(target, "x") == "not_found"
        target.write_text("x")
        assert oc_setup._clear_path(target, "x") == "cleared"

    def test_a_dangling_symlink_is_still_ours_to_remove(self, oc_setup, tmp_path):
        target = tmp_path / "unbound.js"
        target.symlink_to(tmp_path / "gone")
        assert oc_setup._clear_path(target, "x") == "cleared"
        assert not target.is_symlink()

    def test_an_undeletable_path_is_failed(self, oc_setup, tmp_path, monkeypatch):
        target = tmp_path / "unbound.js"
        target.write_text("x")

        def deny(self, *a, **k):
            raise PermissionError("ro")

        monkeypatch.setattr(oc_setup.Path, "unlink", deny)
        assert oc_setup._clear_path(target, "x") == "failed"

    def test_main_takes_no_arguments(self, oc_setup):
        assert oc_setup.main.__code__.co_argcount == 0
