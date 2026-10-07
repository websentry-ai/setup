"""The drop: fetch, verify, publish (INST-07).

Nothing is written under the opencode config dir until the downloaded bytes match the
downloaded sidecar, and the publish is a sibling temp + os.replace -- never a truncate
in place -- so a previously working plugin is either the old bytes or all the new ones.
"""

import hashlib
import os
import stat

import pytest

from tests.opencode.conftest import UNBOUND_BANNER

ARTIFACT = UNBOUND_BANNER + b"export default { id: 'unbound', server() {}, setup() {} };\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@pytest.fixture
def good_fetch(oc_setup, fake_fetch):
    """The committed sidecar names `opencode/index.js`; it must still be accepted."""
    return fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT,
                       oc_setup.SHA_URL: f"{DIGEST}  opencode/index.js\n"}, module=oc_setup)


class TestTheDrop:
    def test_it_writes_the_payload_and_returns_the_digest(self, oc_setup, oc_home, good_fetch):
        digest = oc_setup.install_plugin(oc_home.config_dir)
        target = oc_home.plugins() / "unbound.js"
        assert target.read_bytes() == ARTIFACT
        assert digest == DIGEST

    def test_mode_is_0644(self, oc_setup, oc_home, good_fetch):
        oc_setup.install_plugin(oc_home.config_dir)
        assert stat.S_IMODE((oc_home.plugins() / "unbound.js").stat().st_mode) == 0o644

    def test_the_local_sidecar_names_unbound_js(self, oc_setup, oc_home, good_fetch):
        oc_setup.install_plugin(oc_home.config_dir)
        assert (oc_home.plugins() / "unbound.js.sha256").read_text() == f"{DIGEST}  unbound.js\n"

    def test_a_missing_config_dir_is_created(self, oc_setup, oc_home, good_fetch):
        assert not oc_home.config_dir.exists()
        assert oc_setup.install_plugin(oc_home.config_dir) == DIGEST

    def test_a_bare_digest_sidecar_is_accepted(self, oc_setup, oc_home, fake_fetch):
        fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT, oc_setup.SHA_URL: DIGEST + "\n"}, module=oc_setup)
        assert oc_setup.install_plugin(oc_home.config_dir) == DIGEST

    def test_none_config_dir_installs_nothing(self, oc_setup, good_fetch):
        assert oc_setup.install_plugin(None) is None
        assert good_fetch.calls == []


class TestRefusals:
    @pytest.mark.parametrize("sidecar", [
        "0" * 64 + "  opencode/index.js\n",   # mismatch
        "not-a-digest\n",                      # not a sha line
        "",                                    # empty
        DIGEST + "  a  b\n",                   # too many fields
    ])
    def test_a_bad_sidecar_writes_nothing(self, oc_setup, oc_home, fake_fetch, sidecar):
        fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT, oc_setup.SHA_URL: sidecar}, module=oc_setup)
        assert oc_setup.install_plugin(oc_home.config_dir) is None
        assert not oc_home.config_dir.exists()

    def test_a_missing_sidecar_writes_nothing(self, oc_setup, oc_home, fake_fetch):
        fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT}, module=oc_setup)
        assert oc_setup.install_plugin(oc_home.config_dir) is None
        assert not oc_home.config_dir.exists()

    def test_a_failed_download_writes_nothing(self, oc_setup, oc_home, fake_fetch):
        fake_fetch({}, module=oc_setup)
        assert oc_setup.install_plugin(oc_home.config_dir) is None
        assert not oc_home.config_dir.exists()

    def test_a_mismatch_leaves_the_existing_plugin_untouched(self, oc_setup, oc_home, fake_fetch):
        plugins = oc_home.plugins()
        plugins.mkdir(parents=True)
        (plugins / "unbound.js").write_bytes(b"// previous good install\n")
        before = oc_home.snapshot()
        fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT,
                    oc_setup.SHA_URL: "f" * 64 + "  opencode/index.js\n"}, module=oc_setup)
        assert oc_setup.install_plugin(oc_home.config_dir) is None
        assert oc_home.snapshot() == before


class TestAtomicPublish:
    def test_a_failed_replace_keeps_the_old_bytes_and_leaves_no_temp(
            self, oc_setup, oc_home, good_fetch, monkeypatch):
        plugins = oc_home.plugins()
        plugins.mkdir(parents=True)
        (plugins / "unbound.js").write_bytes(b"// previous\n")
        real_replace = os.replace

        def boom(src, dst):
            if str(dst).endswith("unbound.js"):
                raise OSError(28, "No space left on device")
            return real_replace(src, dst)

        monkeypatch.setattr(oc_setup.os, "replace", boom)
        assert oc_setup.install_plugin(oc_home.config_dir) is None
        assert (plugins / "unbound.js").read_bytes() == b"// previous\n"
        assert not [p for p in os.listdir(plugins) if ".unbound-tmp" in p]

    def test_the_source_never_truncates_in_place(self, oc_setup):
        from pathlib import Path
        src = Path(oc_setup.__file__).read_text()
        assert "O_TRUNC" not in src
        assert "os.replace" in src


class TestNoOpencodeConfigIsWritten:
    @pytest.mark.parametrize("preexisting", [None, "opencode.json", "opencode.jsonc", "config.json"])
    def test_no_config_file_appears_or_changes(self, oc_setup, oc_home, good_fetch, preexisting):
        oc_home.config_dir.mkdir(parents=True)
        if preexisting:
            (oc_home.config_dir / preexisting).write_text('{"$schema": "https://opencode.ai/config.json"}\n')
        before = {n: (oc_home.config_dir / n).read_bytes()
                  for n in ("opencode.json", "opencode.jsonc", "config.json")
                  if (oc_home.config_dir / n).exists()}
        assert oc_setup.install_plugin(oc_home.config_dir) == DIGEST
        after = {n: (oc_home.config_dir / n).read_bytes()
                 for n in ("opencode.json", "opencode.jsonc", "config.json")
                 if (oc_home.config_dir / n).exists()}
        assert after == before

    def test_the_only_new_files_are_ours(self, oc_setup, oc_home, good_fetch):
        oc_setup.install_plugin(oc_home.config_dir)
        assert set(oc_home.snapshot()) == {"plugins/unbound.js", "plugins/unbound.js.sha256",
                                            "plugins/package.json", "plugins/.unbound-installed.json"}

    def test_no_code_path_opens_an_opencode_config_for_writing(self, oc_setup):
        import re
        from pathlib import Path
        for line in Path(oc_setup.__file__).read_text().splitlines():
            if re.search(r"open\([^)]*opencode\.json", line):
                assert not re.search(r"['\"]w|O_WRONLY|O_RDWR", line), line
