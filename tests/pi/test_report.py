"""The key write and the install report -- what the backend is told, and what it is not.

The report is best-effort by design: POST /api/v1/setup/complete/ 4xxs on any staging
that has not deployed Phase 7's handler yet (RESEARCH E6), and an extension that is
installed and working must not be reported as a failed install because of it.
"""

import hashlib
import json
import re

import pytest

DIGEST = hashlib.sha256(b"// extension\n").hexdigest()
ARTIFACT = b"// GENERATED FILE - DO NOT EDIT\nexport default {};\n"
ARTIFACT_DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@pytest.fixture
def fake_home(pi_setup, pi_home, monkeypatch):
    """Points Path.home() at the throwaway HOME, with PI_CODING_AGENT_DIR unset."""
    monkeypatch.setenv("HOME", str(pi_home.home))
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    return pi_home


class TestWriteUnboundConfig:
    def test_it_creates_the_dir_0700_and_the_file_0600(self, pi_setup, fake_home):
        import stat
        assert pi_setup.write_unbound_config("k-1", {}) is True
        assert stat.S_IMODE(fake_home.unbound_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(fake_home.config_path.stat().st_mode) == 0o600

    def test_it_sets_the_api_key(self, pi_setup, fake_home):
        """The user path writes unconditionally: unbound-cli already handed us this
        user's own key (the MDM path in 10-02 is the one that must not clobber)."""
        pi_setup.write_unbound_config("k-1", {})
        assert json.loads(fake_home.config_path.read_text())["api_key"] == "k-1"

    def test_it_merges_rather_than_truncating_other_keys(self, pi_setup, fake_home):
        """~/.unbound/config.json is shared with unbound-cli and five other tools."""
        fake_home.write_config({"api_key": "old", "email": "a@b.c", "org_name": "Acme"})
        pi_setup.write_unbound_config("k-2", {"base_url": "https://backend.example.com"})
        config = json.loads(fake_home.config_path.read_text())
        assert config["email"] == "a@b.c"
        assert config["org_name"] == "Acme"
        assert config["api_key"] == "k-2"
        assert config["base_url"] == "https://backend.example.com"

    def test_it_sets_only_non_empty_urls(self, pi_setup, fake_home):
        pi_setup.write_unbound_config("k", {"base_url": "https://b.example.com",
                                            "frontend_url": None, "gateway_url": ""})
        config = json.loads(fake_home.config_path.read_text())
        assert config["base_url"] == "https://b.example.com"
        assert "frontend_url" not in config
        assert "gateway_url" not in config

    def test_a_corrupt_existing_file_is_replaced_not_fatal(self, pi_setup, fake_home):
        fake_home.unbound_dir.mkdir(parents=True, exist_ok=True)
        fake_home.config_path.write_text("{not json")
        assert pi_setup.write_unbound_config("k-3", {}) is True
        assert json.loads(fake_home.config_path.read_text())["api_key"] == "k-3"

    def test_an_unwritable_config_returns_false_rather_than_raising(self, pi_setup, monkeypatch):
        def deny(*a, **k):
            raise PermissionError("read-only")

        monkeypatch.setattr(pi_setup.os, "open", deny)
        assert pi_setup.write_unbound_config("k", {}) is False


class TestNotifySetupComplete:
    def test_the_shared_contract_body_has_no_extra_keys(self, pi_setup, captured_reports):
        """The exact call tests/test_setup_contract.py makes against every installer."""
        captured_reports.attach(pi_setup)
        pi_setup.notify_setup_complete("k", "claude-code", backend_url="https://b")
        assert captured_reports == [{"tool_type": "claude-code"}]

    def test_a_full_call_carries_the_five_fields(self, pi_setup, captured_reports):
        captured_reports.attach(pi_setup)
        pi_setup.notify_setup_complete("k", "pi", backend_url="https://b",
                                       install_state="fresh", serial_number="C02XYZ",
                                       hook_hash=DIGEST, install_mode="user")
        body = captured_reports[0]
        assert body["tool_type"] == "pi"
        assert body["install_mode"] == "user"
        assert body["install_state"] == "fresh"
        assert body["serial_number"] == "C02XYZ"
        assert re.fullmatch(r"[0-9a-f]{64}", body["hook_hash"])

    def test_it_never_sends_managed(self, pi_setup, captured_reports):
        """`managed` gates tamper counting on the backend; no MDM-less installer sends it."""
        captured_reports.attach(pi_setup)
        pi_setup.notify_setup_complete("k", "pi", backend_url="https://b", install_mode="user")
        assert "managed" not in captured_reports[0]

    def test_an_absent_serial_is_omitted_not_null(self, pi_setup, captured_reports):
        captured_reports.attach(pi_setup)
        pi_setup.notify_setup_complete("k", "pi", backend_url="https://b", serial_number=None)
        assert "serial_number" not in captured_reports[0]

    def test_the_key_is_never_on_the_argv(self, pi_setup, monkeypatch):
        """curl's argv is world-readable via ps and /proc/<pid>/cmdline."""
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = list(cmd)
            seen["input"] = kw.get("input")

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            return _R()

        monkeypatch.setattr(pi_setup.subprocess, "run", fake_run)
        pi_setup.notify_setup_complete("super-secret-key", "pi", backend_url="https://b",
                                       hook_hash=DIGEST, install_mode="user")
        assert "super-secret-key" not in " ".join(seen["cmd"])
        assert isinstance(seen["input"], bytes), "the body reaches curl as input=, as bytes"
        assert "super-secret-key" not in seen["input"].decode()

    def test_the_url_is_the_setup_complete_endpoint(self, pi_setup, monkeypatch):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = list(cmd)

            class _R:
                returncode = 0

            return _R()

        monkeypatch.setattr(pi_setup.subprocess, "run", fake_run)
        pi_setup.notify_setup_complete("k", "pi", backend_url="https://b/")
        assert "https://b/api/v1/setup/complete/" in seen["cmd"]

    def test_a_raising_transport_is_swallowed(self, pi_setup, monkeypatch):
        """A report that cannot be sent is never worth failing an install over."""
        def boom(*a, **k):
            raise OSError("network unreachable")

        monkeypatch.setattr(pi_setup.subprocess, "run", boom)
        assert pi_setup.notify_setup_complete("k", "pi", backend_url="https://b") is None


class TestMainHappyPath:
    @pytest.fixture
    def wired(self, pi_setup, fake_home, fake_fetch, captured_reports, monkeypatch):
        fake_fetch({pi_setup.ARTIFACT_URL: ARTIFACT,
                    pi_setup.SHA_URL: f"{ARTIFACT_DIGEST}  pi/index.js\n"}, module=pi_setup)
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        monkeypatch.setattr(pi_setup, "get_device_identifier", lambda: "C02SERIAL")
        captured_reports.attach(pi_setup)
        return captured_reports

    def test_it_installs_reports_and_prints_the_next_step(
            self, pi_setup, fake_home, wired, monkeypatch, capsys):
        monkeypatch.setattr(pi_setup.sys, "argv",
                            ["setup.py", "--api-key", "k-user", "--backend-url", "https://b.example.com"])
        assert pi_setup.main() is True
        assert pi_setup.artifact_path(fake_home.agent_dir).read_bytes() == ARTIFACT
        assert json.loads(fake_home.config_path.read_text())["api_key"] == "k-user"
        body = wired[0]
        assert body["tool_type"] == "pi"
        assert body["install_mode"] == "user"
        assert body["install_state"] in ("fresh", "persisted")
        assert body["hook_hash"] == ARTIFACT_DIGEST
        assert "new pi session" in capsys.readouterr().out

    def test_the_reported_hash_is_of_the_bytes_on_disk(self, pi_setup, fake_home, wired, monkeypatch):
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--api-key", "k"])
        pi_setup.main()
        on_disk = pi_setup.artifact_sha256(pi_setup.artifact_path(fake_home.agent_dir))
        assert wired[0]["hook_hash"] == on_disk

    def test_a_second_run_reports_persisted(self, pi_setup, fake_home, wired, monkeypatch):
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--api-key", "k"])
        assert pi_setup.main() is True
        assert wired[0]["install_state"] == "fresh"
        assert pi_setup.main() is True
        assert wired[1]["install_state"] == "persisted"

    def test_the_urls_land_in_the_config(self, pi_setup, fake_home, wired, monkeypatch):
        monkeypatch.setattr(pi_setup.sys, "argv", [
            "setup.py", "--api-key", "k", "--backend-url", "b.example.com",
            "--gateway-url", "gw.example.com", "--domain", "app.example.com"])
        pi_setup.main()
        config = json.loads(fake_home.config_path.read_text())
        assert config["base_url"] == "https://b.example.com"
        assert config["gateway_url"] == "https://gw.example.com"
        assert config["frontend_url"] == "https://app.example.com"


class TestMainToleratesAFailedReport:
    def test_a_4xx_does_not_fail_the_install(self, pi_setup, fake_home, fake_fetch,
                                             monkeypatch, capsys):
        """Phase 7's handler is not deployed on every backend yet; the extension is
        installed either way and main() must say so plainly."""
        fake_fetch({pi_setup.ARTIFACT_URL: ARTIFACT,
                    pi_setup.SHA_URL: ARTIFACT_DIGEST}, module=pi_setup)
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        monkeypatch.setattr(pi_setup, "get_device_identifier", lambda: None)

        def boom(*a, **k):
            raise OSError("400 Invalid tool_type")

        monkeypatch.setattr(pi_setup.subprocess, "run", boom)
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--api-key", "k"])
        assert pi_setup.main() is True
        assert pi_setup.artifact_path(fake_home.agent_dir).exists()
        assert "new pi session" in capsys.readouterr().out

    def test_a_refused_artifact_does_fail_the_install(self, pi_setup, fake_home, fake_fetch,
                                                     captured_reports, monkeypatch):
        """An integrity refusal is a real failure -- and nothing is reported for it."""
        fake_fetch({pi_setup.ARTIFACT_URL: ARTIFACT, pi_setup.SHA_URL: "e" * 64}, module=pi_setup)
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        captured_reports.attach(pi_setup)
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--api-key", "k"])
        assert pi_setup.main() is False
        assert not pi_setup.artifact_path(fake_home.agent_dir).exists()
        assert captured_reports == []
        assert not fake_home.config_path.exists(), "no key is stored for an install that refused"


class TestKeyResolution:
    def test_no_key_and_no_domain_writes_nothing_and_returns_false(
            self, pi_setup, fake_home, captured_reports, monkeypatch, capsys):
        def no_fetch(*a, **k):
            raise AssertionError("nothing should be downloaded without a key")

        monkeypatch.setattr(pi_setup, "download_file", no_fetch)
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        captured_reports.attach(pi_setup)
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py"])
        assert pi_setup.main() is False
        assert not fake_home.config_path.exists()
        assert not pi_setup.artifact_path(fake_home.agent_dir).exists()
        assert captured_reports == []
        assert "unbound login" in capsys.readouterr().out

    def test_a_domain_without_a_key_uses_the_browser_callback(
            self, pi_setup, fake_home, fake_fetch, captured_reports, monkeypatch):
        """unbound-cli appends --domain and omits --api-key when none resolved
        (setup.js:259,262); 10-04 adds "pi" to the FE's VALID_APP_TYPES for this flow."""
        fake_fetch({pi_setup.ARTIFACT_URL: ARTIFACT,
                    pi_setup.SHA_URL: ARTIFACT_DIGEST}, module=pi_setup)
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        monkeypatch.setattr(pi_setup, "get_device_identifier", lambda: None)
        seen = {}

        def fake_callback(frontend_url):
            seen["url"] = frontend_url
            return {"query": {"api_key": "minted-by-callback"}}

        monkeypatch.setattr(pi_setup, "run_callback_server", fake_callback)
        captured_reports.attach(pi_setup)
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--domain", "app.example.com"])
        assert pi_setup.main() is True
        assert seen["url"] == "https://app.example.com"
        assert json.loads(fake_home.config_path.read_text())["api_key"] == "minted-by-callback"
        assert captured_reports[0]["tool_type"] == "pi"

    def test_a_failed_callback_returns_false(self, pi_setup, fake_home, monkeypatch):
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        monkeypatch.setattr(pi_setup, "run_callback_server", lambda url: None)
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--domain", "app.example.com"])
        assert pi_setup.main() is False
        assert not fake_home.config_path.exists()

    def test_a_callback_error_response_returns_false(self, pi_setup, fake_home, monkeypatch):
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        monkeypatch.setattr(pi_setup, "run_callback_server",
                            lambda url: {"query": {"error": "access_denied"}})
        monkeypatch.setattr(pi_setup.sys, "argv", ["setup.py", "--domain", "app.example.com"])
        assert pi_setup.main() is False

    def test_the_callback_asks_for_the_pi_app_type(self, pi_setup):
        """A wrong app_type mints a `default` key rather than a pi one (RESEARCH D)."""
        src = open(pi_setup.__file__, encoding="utf-8").read()
        assert "app_type=pi" in src


class TestTheCommittedSidecar:
    def test_it_matches_the_committed_artifact(self, pi_setup):
        from tests.conftest import REPO
        artifact = REPO / "pi" / "index.js"
        sidecar = REPO / "pi" / "index.js.sha256"
        assert sidecar.exists(), "pi/index.js.sha256 is committed next to the artifact"
        expected = pi_setup.parse_sha256_sidecar(sidecar.read_text())
        assert expected is not None, "the committed sidecar parses with our own parser"
        assert expected == pi_setup.artifact_sha256(artifact)

    def test_it_names_the_path_shasum_c_needs_from_the_repo_root(self, pi_setup):
        from tests.conftest import REPO
        text = (REPO / "pi" / "index.js.sha256").read_text()
        assert text.split()[1] == "pi/index.js", (
            "shasum -a 256 -c must work from the repo root, so the path is pi/index.js")
