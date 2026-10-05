"""Stray Unbound copies, the ESM package.json rule, and config plugin entries.

opencode loads every *.{js,ts} in `plugins/` AND in the legacy `plugin/`, so an old
Unbound copy at any of those names loads beside ours (double checks, double signals).
Only files recognised as Unbound's bundle are removed; anything else is left in place
with a warning. The package.json rule comes from spike V1-4: plain Node refuses the
ESM bundle under a commonjs parent, and a nested {"type":"module"} fixes it.
"""

import hashlib
import json
import os

import pytest

from tests.opencode.conftest import UNBOUND_BANNER

ARTIFACT = UNBOUND_BANNER + b"export default {};\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()
STRAYS = ("plugin/unbound.js", "plugins/unbound.ts", "plugin/unbound.ts")


@pytest.fixture
def good_fetch(oc_setup, fake_fetch):
    return fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT,
                       oc_setup.SHA_URL: f"{DIGEST}  opencode/index.js\n"}, module=oc_setup)


def _plant(home, rel, body):
    path = home.config_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


class TestStrays:
    @pytest.mark.parametrize("rel", STRAYS)
    def test_a_recognised_copy_is_removed_and_reported(self, oc_setup, oc_home, rel, capsys):
        path = _plant(oc_home, rel, UNBOUND_BANNER + b"// old unbound\n")
        assert oc_setup.remove_stray_copies(oc_home.config_dir) is True
        assert not path.exists()
        assert rel.split("/")[-1] in capsys.readouterr().out

    def test_the_short_marker_is_recognised_too(self, oc_setup, oc_home):
        path = _plant(oc_home, "plugin/unbound.js", b"// built by unbound-hooks-ts\n")
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert not path.exists()

    def test_the_banner_must_be_in_the_first_4_kib(self, oc_setup, oc_home, capsys):
        body = b"// " + b"x" * 5000 + b"\n// unbound-hooks-ts\n"
        path = _plant(oc_home, "plugins/unbound.ts", body)
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert path.read_bytes() == body

    @pytest.mark.parametrize("rel", STRAYS)
    def test_an_unrecognised_file_is_left_byte_identical_with_a_warning(self, oc_setup, oc_home, rel, capsys):
        body = b"// my own plugin that happens to be named unbound\nexport const X = 1\n"
        path = _plant(oc_home, rel, body)
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert path.read_bytes() == body
        out = capsys.readouterr().out
        assert "left" in out.lower() and str(path) in out

    def test_a_symlink_is_never_followed_or_removed(self, oc_setup, oc_home, tmp_path, capsys):
        real = tmp_path / "elsewhere.js"
        real.write_bytes(UNBOUND_BANNER)
        link = oc_home.config_dir / "plugin" / "unbound.js"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert link.is_symlink() and real.read_bytes() == UNBOUND_BANNER
        assert "symlink" in capsys.readouterr().out.lower()

    def test_other_plugins_are_never_touched(self, oc_setup, oc_home):
        other = _plant(oc_home, "plugins/other.js", UNBOUND_BANNER)
        legacy_other = _plant(oc_home, "plugin/other.ts", b"// x\n")
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert other.read_bytes() == UNBOUND_BANNER
        assert legacy_other.exists()

    def test_our_own_plugins_unbound_js_is_not_a_stray(self, oc_setup, oc_home):
        ours = _plant(oc_home, "plugins/unbound.js", UNBOUND_BANNER)
        oc_setup.remove_stray_copies(oc_home.config_dir)
        assert ours.exists()

    def test_install_removes_strays(self, oc_setup, oc_home, good_fetch):
        stray = _plant(oc_home, "plugin/unbound.js", UNBOUND_BANNER)
        assert oc_setup.install_plugin(oc_home.config_dir) == DIGEST
        assert not stray.exists()


class TestEsmRule:
    def test_an_empty_plugins_dir_gets_type_module_and_a_marker(self, oc_setup, oc_home, good_fetch):
        oc_setup.install_plugin(oc_home.config_dir)
        plugins = oc_home.plugins()
        assert json.loads((plugins / "package.json").read_text()) == {"type": "module"}
        assert json.loads((plugins / ".unbound-installed.json").read_text())["created"] == ["package.json"]

    def test_another_plugin_present_means_no_package_json_and_a_note(
            self, oc_setup, oc_home, good_fetch, capsys):
        _plant(oc_home, "plugins/other.js", b"// someone else's\n")
        oc_setup.install_plugin(oc_home.config_dir)
        assert not (oc_home.plugins() / "package.json").exists()
        assert not (oc_home.plugins() / ".unbound-installed.json").exists()
        assert "package.json" in capsys.readouterr().out

    def test_another_ts_plugin_counts_too(self, oc_setup, oc_home):
        _plant(oc_home, "plugins/mine.ts", b"// mine\n")
        oc_setup.ensure_esm_marker(oc_home.config_dir)
        assert not (oc_home.plugins() / "package.json").exists()

    def test_our_previous_install_does_not_count_as_another_plugin(self, oc_setup, oc_home):
        _plant(oc_home, "plugins/unbound.js", UNBOUND_BANNER)
        _plant(oc_home, "plugins/unbound.js.sha256", b"x\n")
        oc_setup.ensure_esm_marker(oc_home.config_dir)
        assert (oc_home.plugins() / "package.json").exists()

    @pytest.mark.parametrize("body", ['{"type":"commonjs"}', '{"type":"module"}', '{"name":"x"}'])
    def test_an_existing_package_json_is_never_modified(self, oc_setup, oc_home, good_fetch, body):
        pkg = _plant(oc_home, "plugins/package.json", body.encode())
        oc_setup.install_plugin(oc_home.config_dir)
        assert pkg.read_text() == body
        assert not (oc_home.plugins() / ".unbound-installed.json").exists(), \
            "a package.json we did not create is never recorded as ours"

    def test_a_reinstall_keeps_the_marker(self, oc_setup, oc_home, good_fetch):
        oc_setup.install_plugin(oc_home.config_dir)
        oc_setup.install_plugin(oc_home.config_dir)
        plugins = oc_home.plugins()
        assert json.loads((plugins / ".unbound-installed.json").read_text())["created"] == ["package.json"]

    def test_install_then_clear_round_trips_to_an_empty_plugins_dir(
            self, oc_setup, oc_home, good_fetch, monkeypatch):
        oc_setup.install_plugin(oc_home.config_dir)
        assert oc_setup.clear_setup() is True
        assert os.listdir(oc_home.plugins()) == []

    def test_install_then_clear_leaves_a_foreign_plugin(self, oc_setup, oc_home, good_fetch):
        other = _plant(oc_home, "plugins/other.js", b"// keep\n")
        oc_setup.install_plugin(oc_home.config_dir)
        oc_setup.clear_setup()
        assert sorted(os.listdir(oc_home.plugins())) == ["other.js"]
        assert other.read_bytes() == b"// keep\n"


class TestConfigPluginEntries:
    @pytest.mark.parametrize("name", ["opencode.json", "opencode.jsonc"])
    def test_a_stale_unbound_entry_warns_and_is_not_modified(self, oc_setup, oc_home, name, capsys):
        body = ('{\n  // mine\n  "plugin": ["file:///old/unbound.js", "opencode-foo"],\n'
                '  "model": "x"\n}\n')
        path = _plant(oc_home, name, body.encode())
        assert oc_setup.warn_on_config_plugin_entries(oc_home.config_dir) == [path]
        assert path.read_text() == body
        out = capsys.readouterr().out
        assert "twice" in out.lower() and name in out

    def test_a_plugin_list_without_unbound_is_quiet(self, oc_setup, oc_home, capsys):
        _plant(oc_home, "opencode.json", b'{"plugin": ["opencode-foo"], "unbound": 1}')
        assert oc_setup.warn_on_config_plugin_entries(oc_home.config_dir) == []
        assert "twice" not in capsys.readouterr().out.lower()

    def test_no_config_is_quiet(self, oc_setup, oc_home):
        assert oc_setup.warn_on_config_plugin_entries(oc_home.config_dir) == []
        assert not oc_home.config_dir.exists()
