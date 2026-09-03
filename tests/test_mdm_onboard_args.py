"""The discovery key is retired, but orgs that set one up long ago still have it
in MDM policies and crons. Every form of it must parse and be ignored — and it
must never reach the per-tool MDM scripts, which reject unknown arguments."""

import pytest

from tests.conftest import load_module

onboard = load_module("mdm/onboard.py")


@pytest.mark.parametrize("argv", [
    ["--api-key", "K", "--discovery-key", "STALE"],
    ["--api-key", "K", "--discovery-key"],
    ["--discovery-key", "--api-key", "K"],
    ["--discovery-key", "STALE", "--api-key", "K", "--backfill"],
])
def test_discovery_key_is_consumed_and_never_forwarded(argv):
    api_key, discovery_key, mdm_args, _backend, _clear, _skip = onboard.parse_args(argv)
    assert api_key == "K"
    assert discovery_key is not None
    assert "--discovery-key" not in mdm_args
    assert "STALE" not in mdm_args


def test_clear_still_works_with_a_stale_discovery_key():
    _api, discovery_key, mdm_args, _backend, is_clear, _skip = onboard.parse_args(
        ["--clear", "--discovery-key", "STALE"])
    assert is_clear
    assert discovery_key == "STALE"
    assert mdm_args == ["--clear"]


def test_api_key_and_backend_url_still_pass_through():
    api_key, discovery_key, mdm_args, backend, _clear, skip = onboard.parse_args(
        ["--api-key", "K", "--backend-url", "https://b", "--skip-managed-settings"])
    assert (api_key, backend, skip, discovery_key) == ("K", "https://b", True, None)
    assert mdm_args == ["--api-key", "K", "--backend-url", "https://b"]


def test_device_identity_matches_the_per_tool_mdm_scripts():
    """Steps 1-5 enroll the device under the per-tool scripts' identifier; step 6
    must resolve the same one or the backend mints a second owner for one machine."""
    per_tool = load_module("claude-code/hooks/mdm/setup.py")
    assert onboard.get_device_identifier() == per_tool.get_device_identifier()


def test_unresolvable_owner_skips_discovery_without_failing_the_enrollment(monkeypatch, capsys):
    """Five clean tool installs must not be reported as a failed enrollment just
    because the owner key could not be resolved. `unbound-hook setup` returns
    ("skipped", ...) here; this path has to agree."""
    monkeypatch.setattr(onboard, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(onboard, "run_tool", lambda name, url, args: True)
    monkeypatch.setattr(onboard, "fetch_device_owner_key", lambda key, url: None)
    monkeypatch.setattr(onboard, "run_discovery", lambda *a: pytest.fail("no key, no scan"))
    monkeypatch.setattr(onboard.sys, "argv", ["onboard.py", "--api-key", "K"])

    assert onboard.main() == 0
    out = capsys.readouterr().out
    assert "Discovery (skipped)" in out
    assert "MDM onboarding complete" in out


def test_a_scan_that_actually_fails_is_still_a_failure(monkeypatch, capsys):
    monkeypatch.setattr(onboard, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(onboard, "run_tool", lambda name, url, args: True)
    monkeypatch.setattr(onboard, "fetch_device_owner_key", lambda key, url: "owner-key")
    monkeypatch.setattr(onboard, "run_discovery", lambda *a: False)
    monkeypatch.setattr(onboard.sys, "argv", ["onboard.py", "--api-key", "K"])

    assert onboard.main() == 1
    assert "failure(s): Discovery" in capsys.readouterr().out
