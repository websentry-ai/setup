"""The managed reference (INST-09, spike V1-8 PROVEN on opencode-ai 1.18.34; 15-SPIKES.md).

Root installs one root-owned copy at `<managed>/unbound/unbound.js` and references it by an
absolute `file://` URL from the managed `opencode.json` `plugin` array. opencode 1.x reads that
file for every user and does not scan the managed dir for plugin files, so the reference is
the only way in. Existing managed keys and plugin entries are never lost; a managed
`opencode.jsonc` or an unparseable `opencode.json` is never modified.

Every test runs with OPENCODE_TEST_MANAGED_CONFIG_DIR pointing at a tmp dir (the autouse
`_no_system_managed_dir` fixture in tests/opencode/conftest.py), which also makes the real
system managed dirs unreachable for the whole suite.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from tests.opencode.conftest import SYSTEM_MANAGED_DIRS, UNBOUND_BANNER
from tests.opencode.mdm.test_report_and_clear import _run_install, device  # noqa: F401

WINDOWS = os.name == "nt"
PAYLOAD = UNBOUND_BANNER + b"export default {};\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def managed(_no_system_managed_dir):
    return Path(_no_system_managed_dir)


def _uri(managed):
    return (managed / "unbound" / "unbound.js").as_uri()


def _config(managed):
    return json.loads((managed / "opencode.json").read_text())


class TestTheGuard:
    @pytest.mark.parametrize("path", [
        "/Library/Application Support/opencode/opencode.json",
        "/etc/opencode/unbound/unbound.js",
    ])
    def test_the_suite_cannot_reach_the_system_managed_dirs(self, path):
        with pytest.raises(AssertionError):
            open(path, "rb")
        with pytest.raises(AssertionError):
            os.makedirs(os.path.dirname(path), exist_ok=True)

    def test_the_test_variable_is_set_for_every_test(self, managed):
        assert os.environ["OPENCODE_TEST_MANAGED_CONFIG_DIR"] == str(managed)
        assert not any(str(managed).startswith(d) for d in SYSTEM_MANAGED_DIRS)


class TestManagedConfigDir:
    def test_the_test_variable_wins_as_opencode_does(self, oc_mdm_setup, tmp_path):
        env = {"OPENCODE_TEST_MANAGED_CONFIG_DIR": str(tmp_path / "m")}
        assert oc_mdm_setup.managed_config_dir(env, "Darwin") == tmp_path / "m"

    def test_darwin_default(self, oc_mdm_setup):
        assert oc_mdm_setup.managed_config_dir({}, "Darwin") == Path("/Library/Application Support/opencode")

    def test_linux_default(self, oc_mdm_setup):
        assert oc_mdm_setup.managed_config_dir({}, "Linux") == Path("/etc/opencode")

    def test_windows_is_skipped(self, oc_mdm_setup):
        assert oc_mdm_setup.managed_config_dir({}, "Windows") is None

    @pytest.mark.parametrize("value", ["relative/dir", "   "])
    def test_a_non_absolute_override_is_refused_not_resolved_against_cwd(self, oc_mdm_setup, value):
        assert oc_mdm_setup.managed_config_dir({"OPENCODE_TEST_MANAGED_CONFIG_DIR": value}, "Darwin") is None

    def test_the_process_env_is_the_default_source(self, oc_mdm_setup, managed):
        assert oc_mdm_setup.managed_config_dir() == managed

    def test_the_uri_percent_encodes_the_space_in_application_support(self, oc_mdm_setup):
        uri = oc_mdm_setup.managed_plugin_uri(Path("/Library/Application Support/opencode"))
        assert uri == "file:///Library/Application%20Support/opencode/unbound/unbound.js"


@pytest.mark.skipif(WINDOWS, reason="Unix-only")
class TestInstall:
    def test_a_fresh_install_writes_the_copy_and_a_new_config(self, oc_mdm_setup, managed):
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST) == "installed"
        copy = managed / "unbound" / "unbound.js"
        assert copy.read_bytes() == PAYLOAD
        assert stat.S_IMODE(copy.stat().st_mode) == 0o644
        assert (managed / "unbound" / "unbound.js.sha256").read_text() == f"{DIGEST}  unbound.js\n"
        assert json.loads((managed / "unbound" / "package.json").read_text()) == {"type": "module"}
        assert _config(managed) == {"plugin": [_uri(managed)]}
        assert stat.S_IMODE((managed / "opencode.json").stat().st_mode) == 0o644

    def test_existing_keys_and_plugins_are_preserved(self, oc_mdm_setup, managed):
        managed.mkdir(parents=True)
        (managed / "opencode.json").write_text(json.dumps(
            {"$schema": "https://opencode.ai/config.json", "share": "disabled",
             "plugin": ["corp-audit@1.2.3"], "permission": {"bash": "ask"}}))
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST) == "installed"
        cfg = _config(managed)
        assert cfg["plugin"] == ["corp-audit@1.2.3", _uri(managed)]
        assert cfg["share"] == "disabled" and cfg["permission"] == {"bash": "ask"}
        assert list(cfg)[0] == "$schema", "key order is kept"

    def test_a_rerun_is_idempotent(self, oc_mdm_setup, managed):
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        before = (managed / "opencode.json").read_bytes()
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST) == "persisted"
        assert (managed / "opencode.json").read_bytes() == before
        assert _config(managed)["plugin"].count(_uri(managed)) == 1

    def test_a_managed_jsonc_is_never_touched(self, oc_mdm_setup, managed):
        managed.mkdir(parents=True)
        (managed / "opencode.jsonc").write_text('{\n  // corp\n  "share": "disabled"\n}\n')
        status = oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        assert status.startswith("skipped") and "jsonc" in status
        assert sorted(p.name for p in managed.iterdir()) == ["opencode.jsonc"]

    @pytest.mark.parametrize("text", ['{"share": "disabled",}', "[1, 2]", '{"plugin": "one"}', ""])
    def test_an_unparseable_or_odd_config_is_never_touched(self, oc_mdm_setup, managed, text):
        managed.mkdir(parents=True)
        (managed / "opencode.json").write_text(text)
        status = oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        assert status.startswith("skipped")
        assert (managed / "opencode.json").read_text() == text
        assert not (managed / "unbound").exists()

    def test_a_symlinked_unbound_dir_is_refused(self, oc_mdm_setup, managed, tmp_path):
        managed.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (managed / "unbound").symlink_to(elsewhere, target_is_directory=True)
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST).startswith("failed")
        assert list(elsewhere.iterdir()) == []
        assert not (managed / "opencode.json").exists()

    def test_a_digest_mismatch_adds_no_reference(self, oc_mdm_setup, managed):
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, "0" * 64).startswith("failed")
        assert not (managed / "opencode.json").exists()

    def test_no_temp_debris_is_left(self, oc_mdm_setup, managed):
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        names = [p.name for p in managed.rglob("*")]
        assert not [n for n in names if ".unbound-tmp" in n]

    def test_an_unsupported_platform_is_skipped(self, oc_mdm_setup, monkeypatch):
        monkeypatch.delenv("OPENCODE_TEST_MANAGED_CONFIG_DIR")
        monkeypatch.setattr(oc_mdm_setup.platform, "system", lambda: "Windows")
        assert oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST).startswith("skipped")


@pytest.mark.skipif(WINDOWS, reason="Unix-only")
class TestClear:
    def test_a_config_we_created_is_removed_with_everything_else(self, oc_mdm_setup, managed):
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        assert oc_mdm_setup.clear_managed_reference() == "cleared"
        assert not (managed / "opencode.json").exists()
        assert not (managed / "unbound").exists()
        assert managed.is_dir(), "the managed dir itself is left in place"

    def test_only_our_entry_leaves_a_config_we_did_not_create(self, oc_mdm_setup, managed):
        managed.mkdir(parents=True)
        original = {"share": "disabled", "plugin": ["corp-audit@1.2.3"]}
        (managed / "opencode.json").write_text(json.dumps(original))
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        assert oc_mdm_setup.clear_managed_reference() == "cleared"
        assert _config(managed) == original

    def test_a_plugin_key_we_added_is_removed_again(self, oc_mdm_setup, managed):
        managed.mkdir(parents=True)
        (managed / "opencode.json").write_text(json.dumps({"share": "disabled"}))
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        oc_mdm_setup.clear_managed_reference()
        assert _config(managed) == {"share": "disabled"}

    def test_keys_added_after_install_keep_a_config_we_created(self, oc_mdm_setup, managed):
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        cfg = _config(managed)
        cfg["share"] = "disabled"
        (managed / "opencode.json").write_text(json.dumps(cfg))
        oc_mdm_setup.clear_managed_reference()
        assert _config(managed) == {"share": "disabled"}

    def test_a_config_turned_jsonc_keeps_our_entry_and_says_so(self, oc_mdm_setup, managed):
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        cfg = managed / "opencode.json"
        text = "// edited by hand\n" + cfg.read_text()
        cfg.write_text(text)
        status = oc_mdm_setup.clear_managed_reference()
        assert "kept" in status or "failed" in status
        assert cfg.read_text() == text

    def test_nothing_installed_is_not_found_and_creates_nothing(self, oc_mdm_setup, managed):
        assert oc_mdm_setup.clear_managed_reference() == "not_found"
        assert not managed.exists()

    def test_other_files_in_the_managed_dir_survive(self, oc_mdm_setup, managed):
        managed.mkdir(parents=True)
        (managed / "AGENTS.md").write_text("corp rules\n")
        oc_mdm_setup.install_managed_reference(PAYLOAD, DIGEST)
        oc_mdm_setup.clear_managed_reference()
        assert (managed / "AGENTS.md").read_text() == "corp rules\n"


@pytest.mark.skipif(WINDOWS, reason="Unix-only")
class TestTheDeviceRun:
    def test_the_run_adds_the_reference_and_keeps_the_per_home_drop(
            self, oc_mdm_setup, device, managed, capsys):  # noqa: F811
        assert _run_install(device) is True
        assert _config(managed)["plugin"] == [_uri(managed)]
        for _, h in device["homes"]:
            assert (h / ".config" / "opencode" / "plugins" / "unbound.js").exists()
        assert "managed opencode.json: installed" in capsys.readouterr().out

    def test_a_failed_managed_step_does_not_fail_the_run(
            self, oc_mdm_setup, device, managed, monkeypatch):  # noqa: F811
        def boom(*a, **k):
            raise RuntimeError("managed step exploded")
        monkeypatch.setattr(oc_mdm_setup, "install_managed_reference", boom)
        assert _run_install(device) is True

    def test_clear_removes_the_reference(self, oc_mdm_setup, device, managed, capsys):  # noqa: F811
        _run_install(device)
        assert device["run"]("--clear") is True
        assert not (managed / "opencode.json").exists()
        assert "managed opencode.json: cleared" in capsys.readouterr().out
