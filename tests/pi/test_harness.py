"""Assertions about the fixtures themselves.

Waves 1-2 assert pi's behaviour *through* these fixtures, so a fixture that quietly
lies -- a fake_fetch that answers every URL, a captured_reports that never fills --
would turn a red behaviour green. These tests are the only thing standing between a
test double and a false claim, so each negative case is asserted explicitly.
"""

import json

import pytest

from tests.pi.conftest import MINIMAL_ENV_KEYS

ARTIFACT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/pi/index.js"
SHA_URL = ARTIFACT_URL + ".sha256"


def test_the_fake_home_looks_like_a_machine_with_pi_and_unbound(pi_home):
    assert pi_home.agent_dir.is_dir(), pi_home.agent_dir
    assert pi_home.agent_dir == pi_home.home / ".pi" / "agent"
    assert pi_home.unbound_dir.is_dir(), pi_home.unbound_dir
    # The drop target every install path has to compute.
    assert pi_home.extension_dir() == pi_home.agent_dir / "extensions" / "unbound"


def test_the_env_carries_exactly_the_three_allowed_keys(pi_home):
    """More than these three and a pi test could pass off the developer's own shell."""
    assert sorted(pi_home.env) == sorted(MINIMAL_ENV_KEYS)
    assert pi_home.env["HOME"] == str(pi_home.home)
    assert "PI_CODING_AGENT_DIR" not in pi_home.env


def test_the_four_agent_dir_cases_are_four_distinct_states(pi_home, agent_dir_cases):
    assert len(agent_dir_cases) == 4
    assert sorted(c.name for c in agent_dir_cases) == [
        "absolute", "relative", "tilde", "unset",
    ]
    values = [c.env_value for c in agent_dir_cases]
    assert len(set(values)) == 4, values
    # unset means absent, not empty -- an empty string is a different code path.
    unset = [c for c in agent_dir_cases if c.name == "unset"][0]
    assert "PI_CODING_AGENT_DIR" not in unset.env(pi_home.env)
    absolute = [c for c in agent_dir_cases if c.name == "absolute"][0]
    assert absolute.env(pi_home.env)["PI_CODING_AGENT_DIR"] == str(pi_home.home / "abs-agent")


def test_the_relative_case_falls_back_to_the_home_default(pi_home, agent_dir_cases):
    """cache.ts:68-95: a relative value is never resolved against cwd."""
    relative = [c for c in agent_dir_cases if c.name == "relative"][0]
    assert relative.expected_base == pi_home.agent_dir
    assert str(relative.expected_base).startswith(str(pi_home.home))
    assert not relative.env_value.startswith(("/", "~"))
    tilde = [c for c in agent_dir_cases if c.name == "tilde"][0]
    assert tilde.expected_base == pi_home.home / "tilde-agent"


def test_plant_shadow_really_creates_the_shadowing_file(pi_home, plant_shadow):
    extdir = pi_home.extension_dir()
    ts = plant_shadow(extdir)
    assert ts.is_file() and ts.name == "index.ts"
    assert ts.read_text()
    pkg = plant_shadow(extdir, "package.json", "{}\n")
    assert pkg.is_file() and pkg.read_text() == "{}\n"


def test_fake_fetch_writes_a_mapped_url_and_refuses_an_unmapped_one(tmp_path, fake_fetch):
    """The sidecar case INST-01 depends on: index.js present, index.js.sha256 missing."""
    download = fake_fetch({ARTIFACT_URL: b"export const x = 1;\n"})
    artifact = tmp_path / "nested" / "index.js"
    assert download(ARTIFACT_URL, artifact) is True
    assert artifact.read_bytes() == b"export const x = 1;\n"
    sidecar = tmp_path / "index.js.sha256"
    assert download(SHA_URL, sidecar) is False
    assert not sidecar.exists()
    assert download.calls == [ARTIFACT_URL, SHA_URL]


def test_captured_reports_starts_empty_and_collects_a_posted_body(captured_reports):
    assert captured_reports == []
    post = captured_reports.poster()
    body = {"tool_type": "pi", "install_mode": "user", "install_state": "fresh"}
    post(["curl", "-X", "POST"], input=json.dumps(body).encode())
    assert len(captured_reports) == 1
    assert captured_reports[0]["tool_type"] == "pi"
    # A run with no stdin is not a report and must not add a phantom entry.
    post(["curl", "--version"])
    assert len(captured_reports) == 1


def test_the_installer_fixtures_skip_until_their_wave_writes_them(pi_setup):
    """Reached only once pi/setup.py exists; until then the fixture skips, which is
    how this package collects cleanly before Wave 1."""
    assert hasattr(pi_setup, "main"), "pi/setup.py must expose main()"


def test_the_mdm_installer_fixture_skips_until_its_wave_writes_it(pi_mdm_setup):
    assert hasattr(pi_mdm_setup, "main"), "pi/mdm/setup.py must expose main()"


def test_a_pi_behaviour_assertion_is_deferred_to_its_own_wave():
    """Named so a reader does not mistake the harness for pi coverage."""
    pytest.skip("pi/setup.py lands in 10-01")
