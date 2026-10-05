"""main(): key first, then the drop, the key write, one setup_complete, and the notes (INST-06).

All network is faked: download_file serves the artifact offline, subprocess.run is the
captured_reports poster, and shutil.which never finds a real opencode.
"""

import hashlib
import json
import os

import pytest

from tests.opencode.conftest import UNBOUND_BANNER

ARTIFACT = UNBOUND_BANNER + b"export default {};\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@pytest.fixture
def run_main(oc_setup, oc_home, fake_fetch, captured_reports, monkeypatch):
    fetch = fake_fetch({oc_setup.ARTIFACT_URL: ARTIFACT,
                        oc_setup.SHA_URL: f"{DIGEST}  opencode/index.js\n"}, module=oc_setup)
    captured_reports.attach(oc_setup)
    monkeypatch.setattr(oc_setup.shutil, "which", lambda name: None)
    monkeypatch.setattr(oc_setup, "get_device_identifier", lambda: "SERIAL-1")
    monkeypatch.setattr(oc_setup, "run_callback_server",
                        lambda url: pytest.fail("no browser in tests"))

    def _run(*argv):
        monkeypatch.setattr(oc_setup.sys, "argv", ["setup.py", *argv])
        return oc_setup.main()

    _run.fetch = fetch
    _run.reports = captured_reports
    return _run


class TestHappyPath:
    def test_one_report_with_the_opencode_fields(self, oc_setup, oc_home, run_main):
        assert run_main("--api-key", "k-1") is True
        assert run_main.reports == [{"tool_type": "opencode", "install_state": "fresh",
                                     "serial_number": "SERIAL-1", "hook_hash": DIGEST,
                                     "install_mode": "user"}]

    def test_a_second_run_is_persisted(self, oc_setup, oc_home, run_main):
        run_main("--api-key", "k-1")
        run_main("--api-key", "k-1")
        assert run_main.reports[-1]["install_state"] == "persisted"

    def test_the_key_and_urls_land_in_config_json(self, oc_setup, oc_home, run_main):
        oc_home.write_config({"email": "a@b.c"})
        run_main("--api-key", "k-2", "--backend-url", "b.example.com")
        cfg = json.loads(oc_home.config_path.read_text())
        assert cfg["api_key"] == "k-2" and cfg["email"] == "a@b.c"
        assert cfg["base_url"] == "https://b.example.com"

    def test_the_plugin_is_installed(self, oc_setup, oc_home, run_main):
        run_main("--api-key", "k")
        assert (oc_home.plugins() / "unbound.js").read_bytes() == ARTIFACT

    def test_the_closing_notes(self, oc_setup, oc_home, run_main, capsys):
        run_main("--api-key", "k")
        out = capsys.readouterr().out
        assert "Restart opencode" in out and "desktop app" in out
        assert "opencode serve" in out and "opencode attach" in out
        assert "--pure" in out and "OPENCODE_PURE" in out
        assert oc_setup.V2_STATUS_NOTE in out
        assert "OpenCode 2.x" in oc_setup.V2_STATUS_NOTE

    def test_no_proxy_note_without_a_proxy(self, oc_setup, oc_home, run_main, capsys):
        run_main("--api-key", "k")
        assert "HTTPS_PROXY" not in capsys.readouterr().out

    def test_a_proxy_gets_the_ca_note(self, oc_setup, oc_home, run_main, monkeypatch, capsys):
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp:3128")
        run_main("--api-key", "k")
        out = capsys.readouterr().out
        assert "HTTPS_PROXY" in out and "CA" in out


class TestRelocatedConfigDir:
    def test_opencode_config_dir_is_named_in_the_output(self, oc_setup, oc_home, run_main,
                                                         monkeypatch, tmp_path, capsys):
        base = tmp_path / "custom-oc"
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(base))
        assert run_main("--api-key", "k") is True
        assert (base / "plugins" / "unbound.js").exists()
        assert not oc_home.config_dir.exists()
        out = capsys.readouterr().out
        assert "OPENCODE_CONFIG_DIR" in out and str(base) in out
        assert "same" in out

    def test_a_stale_config_entry_warns(self, oc_setup, oc_home, run_main, capsys):
        oc_home.config_dir.mkdir(parents=True)
        cfg = oc_home.config_dir / "opencode.json"
        cfg.write_text('{"plugin": ["unbound-old"]}')
        run_main("--api-key", "k")
        assert cfg.read_text() == '{"plugin": ["unbound-old"]}'
        assert "twice" in capsys.readouterr().out.lower()


class TestFailures:
    def test_no_key_and_no_domain_writes_nothing(self, oc_setup, oc_home, run_main):
        assert run_main() is False
        assert not oc_home.config_dir.exists()
        assert not oc_home.config_path.exists()
        assert run_main.fetch.calls == []
        assert run_main.reports == []

    def test_a_failed_install_does_not_report(self, oc_setup, oc_home, run_main, fake_fetch):
        fake_fetch({}, module=oc_setup)
        assert run_main("--api-key", "k") is False
        assert run_main.reports == []
        assert not oc_home.config_path.exists(), "no key is written for a plugin that is not there"

    def test_a_config_write_failure_fails_setup_and_names_the_env_var(
            self, oc_setup, oc_home, run_main, tmp_path, capsys):
        oc_home.unbound_dir.mkdir()
        (tmp_path / "dotfiles.json").write_text("{}")
        oc_home.config_path.symlink_to(tmp_path / "dotfiles.json")
        assert run_main("--api-key", "k") is False
        assert (oc_home.plugins() / "unbound.js").exists()
        assert "UNBOUND_OPENCODE_API_KEY" in capsys.readouterr().out
        assert run_main.reports == []

    def test_a_report_failure_does_not_fail_setup(self, oc_setup, oc_home, run_main, capsys):
        run_main.reports.fail = True
        assert run_main("--api-key", "k") is True
        assert len(run_main.reports) == 1
        assert "best-effort" in capsys.readouterr().out

    def test_an_old_python_refuses_before_anything(self, oc_setup, oc_home, run_main, monkeypatch):
        monkeypatch.setattr(oc_setup.sys, "version_info", (3, 7, 0))
        assert run_main("--api-key", "k") is False
        assert not oc_home.config_dir.exists()


class TestNotifyContract:
    def test_the_shared_contract_body_has_no_extra_keys(self, oc_setup, captured_reports):
        captured_reports.attach(oc_setup)
        oc_setup.notify_setup_complete("k", "claude-code", backend_url="https://b")
        assert captured_reports == [{"tool_type": "claude-code"}]

    def test_the_key_is_never_on_argv(self, oc_setup, monkeypatch):
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd)

            class R:
                returncode = 0
            return R()

        monkeypatch.setattr(oc_setup.subprocess, "run", fake_run)
        oc_setup.notify_setup_complete("secret-key", "opencode", backend_url="https://b")
        assert seen and all("secret-key" not in " ".join(c) for c in seen)

    def test_the_source_reports_opencode_user(self, oc_setup):
        from pathlib import Path
        src = Path(oc_setup.__file__).read_text()
        assert src.count('install_mode="user"') == 1
        assert '"opencode", backend_url' in src

    def test_clear_via_main_posts_nothing(self, oc_setup, oc_home, run_main):
        run_main("--api-key", "k")
        n = len(run_main.reports)
        assert run_main("--clear") is True
        assert len(run_main.reports) == n
        assert not os.path.exists(oc_home.plugins() / "unbound.js")
