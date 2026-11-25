"""WEB-6392: the python MDM scripts (mdm/onboard.py on Linux and Windows) report every tool every run.

Each script's real main() runs with only the root-only and network primitives stubbed: every run sends
one setup/complete with status configured (and where its config went), skipped "<Tool> is not installed"
(the config still written, the exit code unchanged), or deferred with the reason the script prints."""

import sys
from pathlib import Path

import pytest

from tests.conftest import load_module

MODULES = {
    "claude-code": "claude-code/hooks/mdm/setup.py",
    "cursor": "cursor/mdm/setup.py",
    "codex": "codex/hooks/mdm/setup.py",
    "copilot": "copilot/hooks/mdm/setup.py",
    "augment": "augment/hooks/mdm/setup.py",
}
TOOL_TYPES = {"claude-code": "claude-code", "cursor": "cursor", "codex": "codex", "copilot": "copilot",
              "augment": "augment_code"}


class Run:
    """One tool's main() over a sandbox: a home, a managed folder, recorded reports and writes."""

    def __init__(self, tool, tmp_path, monkeypatch):
        self.tool, self.m = tool, load_module(MODULES[tool])
        self.home, self.managed = tmp_path / "home", tmp_path / "managed"
        self.home.mkdir()
        self.managed.mkdir()
        self.reports, self.writes, self.installed = [], [], True
        self.mp = monkeypatch
        m = self.m
        monkeypatch.setattr(sys, "argv", ["setup.py", "--api-key", "admin-key"])
        monkeypatch.setattr(m.platform, "system", lambda: "Linux")
        self.stub("check_admin_privileges", True)
        self.stub("get_device_identifier", "SERIAL1")
        self.stub("fetch_api_key_from_mdm", "device-key")
        self.stub("get_all_user_homes", [("u", self.home)])
        self.stub("write_unbound_config_for_user", True)
        self.stub("remove_legacy_key_env", None)
        self.stub("detect_install_state", "fresh")
        self.stub("hook_script_hash", "h" * 64)
        monkeypatch.setattr(m, "notify_setup_complete", lambda key, tool_type, **k: self.reports.append(
            dict(k, api_key=key, tool_type=tool_type)))
        monkeypatch.setattr(m, "tool_installed", lambda homes, *a, **k: self.installed)
        for name in ("set_env_var_system_wide",):
            if hasattr(m, name):
                self.stub(name, (True, False))
        for name in ("remove_env_var_from_user", "remove_gateway_artifacts_for_user", "remove_user_level_hooks",
                     "remove_user_level_hooks_for_user", "_freeze_ownership_evidence", "clear_otel_export_for_user",
                     "enable_codex_hooks_feature_for_user", "restart_cursor", "run_visual_studio_sweep"):
            if hasattr(m, name):
                self.stub(name, None)
        for name in ("get_managed_settings_dir", "get_enterprise_hooks_dir"):
            if hasattr(m, name):
                self.stub(name, self.managed)
        getattr(self, "_" + tool.replace("-", "_"))()

    def stub(self, name, result):
        self.mp.setattr(self.m, name, lambda *a, _r=result, **k: _r)

    def writer(self, name, result=True):
        self.mp.setattr(self.m, name, lambda *a, _n=name, _r=result, **k: self.writes.append(_n) or _r)

    def _claude_code(self):
        self.writer("setup_managed_hooks")
        self.stub("_unbound_base_url_matcher", None)

    def _cursor(self):
        self.stub("set_env_var", (True, False, "ok"))
        self.writer("setup_hooks", (True, False))

    def _codex(self):
        self.writer("setup_managed_hooks")
        self.writer("configure_codex_hooks_for_user")
        self.stub("_installed_hook_script", None)

    def _copilot(self):
        self.stub("_fetch_hook_script", "# hook")
        self.writer("install_hooks_for_user")
        self.stub("configure_managed_telemetry", True)

    def _augment(self):
        self.writer("setup_managed_hooks")
        self.stub("verify_managed_hooks_installed", True)

    def __call__(self):
        return self.m.main()

    @property
    def report(self):
        assert len(self.reports) == 1, self.reports
        return self.reports[0]


@pytest.fixture
def run(tmp_path, monkeypatch):
    return lambda tool: Run(tool, tmp_path, monkeypatch)


WRITTEN_TO = {
    "claude-code": lambda r: str(r.managed / "managed-settings.json"),
    "cursor": lambda r: str(r.managed / "hooks.json"),
    "codex": lambda r: str(r.managed / "hooks.json"),
    "copilot": lambda r: "~/.copilot/hooks/unbound.json",
    "augment": lambda r: str(r.managed / "settings.json"),
}


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_an_installed_tool_reports_configured_and_where_its_config_went(run, tool):
    r = run(tool)
    assert r() is True
    report = r.report
    assert (report["tool_type"], report["status"], report["reason"]) == (TOOL_TYPES[tool], "configured", None)
    assert report["written_to"] == WRITTEN_TO[tool](r)
    assert (report["install_state"], report["serial_number"], report["api_key"]) == ("fresh", "SERIAL1", "device-key")


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_a_tool_that_is_not_installed_is_reported_skipped_and_still_set_up(run, tool):
    r = run(tool)
    r.installed = False
    assert r() is True  # the exit code doesn't change
    report = r.report
    assert (report["status"], report["reason"]) == ("skipped", f"{r.m.TOOL_NAME} is not installed")
    assert r.writes, "reporting only: everything is still written"


DEFERRED = [
    ("claude-code", "set_env_var_system_wide", (False, False), "Failed to set UNBOUND_BACKEND_URL"),
    ("claude-code", "setup_managed_hooks", False, "Failed to configure managed hooks"),
    ("claude-code", "write_unbound_config_for_user", False, "Could not write ~/.unbound/config.json for every user"),
    ("cursor", "set_env_var", (False, False, "denied"), "Failed to set UNBOUND_BACKEND_URL: denied"),
    ("cursor", "setup_hooks", (False, False), "Failed to setup hooks"),
    ("cursor", "write_unbound_config_for_user", False, "Could not write ~/.unbound/config.json for every user"),
    ("codex", "set_env_var_system_wide", (False, False), "Failed to set UNBOUND_BACKEND_URL"),
    ("codex", "setup_managed_hooks", False, "Failed to set up codex managed hooks"),
    ("codex", "get_all_user_homes", [], "No user home directories found"),
    ("codex", "write_unbound_config_for_user", False, "Could not write ~/.unbound/config.json for every user"),
    ("copilot", "set_env_var_system_wide", (False, False), "Failed to set UNBOUND_BACKEND_URL"),
    ("copilot", "_fetch_hook_script", None, "Failed to download unbound.py"),
    ("copilot", "get_all_user_homes", [], "No user home directories found"),
    ("copilot", "write_unbound_config_for_user", False, "Could not write ~/.unbound/config.json for every user"),
    ("augment", "set_env_var_system_wide", (False, False), "Failed to set UNBOUND_BACKEND_URL"),
    ("augment", "setup_managed_hooks", False, "Failed to configure managed hooks"),
    ("augment", "write_unbound_config_for_user", False, "Could not write ~/.unbound/config.json for every user"),
]


@pytest.mark.parametrize("tool,name,result,reason", DEFERRED)
def test_a_failure_after_the_key_is_reported_deferred_with_its_reason(run, tool, name, result, reason):
    r = run(tool)
    r.stub(name, result)
    assert r() is False  # the exit code doesn't change
    report = r.report
    assert (report["status"], report["reason"]) == ("deferred", reason)


def test_codex_on_windows_reports_the_per_user_hooks_file(run):
    r = run("codex")
    r.mp.setattr(r.m.platform, "system", lambda: "Windows")
    assert r() is True
    assert r.report["written_to"] == "~/.codex/hooks.json"


def test_codex_on_windows_reports_a_failed_per_user_install(run):
    r = run("codex")
    r.mp.setattr(r.m.platform, "system", lambda: "Windows")
    r.writer("configure_codex_hooks_for_user", False)
    assert r() is False
    assert (r.report["status"], r.report["reason"]) == ("deferred", "Registered codex hooks for 0 of 1 user(s) — 1 failed")


def test_claude_code_without_managed_settings_reports_the_hook_script(run):
    r = run("claude-code")
    r.mp.setattr(sys, "argv", ["setup.py", "--api-key", "admin-key", "--skip-managed-settings"])
    assert r() is True
    assert (r.report["written_to"], r.report["install_mode"]) == (str(r.managed / "hooks" / "unbound.py"), "mdm-skip")


def test_copilot_with_every_install_failed_sends_one_deferred_report_with_the_tamper(run):
    r = run("copilot")
    r.stub("detect_install_state", "tampered")
    r.writer("install_hooks_for_user", False)
    assert r() is False
    report = r.report
    assert (report["status"], report["reason"], report["install_state"]) == (
        "deferred", "Installed Copilot hooks for 0 of 1 user(s) — 1 failed", "tampered")


def test_copilot_with_some_installs_failed_reports_how_many(run):
    r = run("copilot")
    other = r.home.parent / "other"
    other.mkdir()
    r.stub("get_all_user_homes", [("u", r.home), ("v", other)])
    answers = iter([True, False])
    r.mp.setattr(r.m, "install_hooks_for_user", lambda *a, **k: next(answers))
    assert r() is False
    assert (r.report["status"], r.report["reason"]) == ("deferred", "Installed Copilot hooks for 1 of 2 user(s) — 1 failed")
    # As in the binary, the tamper state rides only on a run where every install failed.
    assert "install_state" not in r.report


@pytest.mark.parametrize("tool", sorted(MODULES))
def test_a_failure_before_the_key_sends_nothing(run, tool):
    """Without the device key there is nothing to report with; the exit code says it."""
    r = run(tool)
    r.stub("fetch_api_key_from_mdm", None)
    assert r() is False
    assert r.reports == []
