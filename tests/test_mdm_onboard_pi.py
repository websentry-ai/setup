"""Pi is the one onboarding step that runs only where its tool is present:
pi/mdm/setup.py installs into every user home without checking, so the gate lives
in mdm/onboard.py. Every detection test passes all four overrides, so the machine
running the suite is never consulted."""

import os

import pytest

from tests.conftest import load_module

onboard = load_module("mdm/onboard.py")

FIVE_TOOLS = ["Claude Code", "Cursor", "Codex", "GitHub Copilot", "Augment"]


def _touch(path):
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(str(path), "w") as f:
        f.write("")
    return path


def _detect(homes, path_dirs=(), machine_bin_dirs=(), system="darwin"):
    return onboard.pi_detected(homes=[str(h) for h in homes],
                               path_dirs=[str(d) for d in path_dirs],
                               machine_bin_dirs=[str(d) for d in machine_bin_dirs],
                               system=system)


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "alice"
    h.mkdir()
    return h


def test_an_empty_home_and_empty_bin_dirs_is_not_pi(home, tmp_path):
    empty = tmp_path / "bin"
    empty.mkdir()
    assert _detect([home], path_dirs=[empty], machine_bin_dirs=[empty]) is False


def test_no_homes_and_no_bin_dirs_is_not_pi():
    assert _detect([]) is False


def test_auth_json_is_a_signal(home):
    _touch(home / ".pi" / "agent" / "auth.json")
    assert _detect([home]) is True


def test_a_sessions_directory_is_a_signal(home):
    (home / ".pi" / "agent" / "sessions").mkdir(parents=True)
    assert _detect([home]) is True


@pytest.mark.parametrize("rel", [
    ".local/bin/pi",
    ".bun/bin/pi",
    ".npm-global/bin/pi",
    ".volta/bin/pi",
    ".yarn/bin/pi",
    ".nvm/versions/node/v22.1.0/bin/pi",
])
def test_the_binary_in_a_users_own_bin_dir_is_a_signal(home, rel):
    _touch(home.joinpath(*rel.split("/")))
    assert _detect([home]) is True


def test_the_binary_on_path_is_a_signal(home, tmp_path):
    _touch(tmp_path / "pathbin" / "pi")
    assert _detect([home], path_dirs=[tmp_path / "pathbin"]) is True


def test_the_binary_in_a_machine_bin_dir_is_a_signal(home, tmp_path):
    _touch(tmp_path / "homebrew" / "pi")
    assert _detect([home], machine_bin_dirs=[tmp_path / "homebrew"]) is True


def test_unbounds_own_extension_is_never_a_signal(home):
    """What pi/mdm/setup.py itself writes. Counting it would make every device that
    was ever onboarded look like it has pi."""
    ext = home / ".pi" / "agent" / "extensions" / "unbound"
    _touch(ext / "index.js")
    _touch(ext / "index.js.sha256")
    assert _detect([home]) is False


@pytest.mark.parametrize("name", ["pi.cmd", "pi.exe", "pi.ps1"])
def test_windows_launcher_names_count_only_on_windows(home, name):
    _touch(home / "AppData" / "Roaming" / "npm" / name)
    assert _detect([home], system="darwin") is False
    assert _detect([home], system="windows") is True


def test_another_binary_that_merely_starts_with_pi_is_not_pi(home):
    _touch(home / ".local" / "bin" / "pip")
    _touch(home / ".local" / "bin" / "pi-hole")
    assert _detect([home]) is False


def test_every_home_is_checked_not_just_the_first(home, tmp_path):
    bob = tmp_path / "bob"
    _touch(bob / ".pi" / "agent" / "auth.json")
    assert _detect([home]) is False
    assert _detect([home, bob]) is True


def test_machine_bin_dirs_are_not_consulted_on_windows(monkeypatch, home):
    """The default is empty there; a POSIX path that happened to exist must not count."""
    seen = []
    real_exists = os.path.exists

    def _exists(path):
        seen.append(path)
        return real_exists(path)

    monkeypatch.setattr(onboard.os.path, "exists", _exists)
    assert onboard.pi_detected(homes=[str(home)], path_dirs=[], system="windows") is False
    assert not any(str(p).startswith("/opt/homebrew") for p in seen)


def test_all_user_homes_lists_real_accounts_only(tmp_path):
    root = tmp_path / "Users"
    for name in ("alice", "bob", "Shared", "Guest", ".hidden"):
        (root / name).mkdir(parents=True)
    _touch(root / "a-plain-file")

    homes = onboard.all_user_homes(system="darwin", users_root=str(root))

    assert str(root / "alice") in homes
    assert str(root / "bob") in homes
    for excluded in ("Shared", "Guest", ".hidden", "a-plain-file"):
        assert str(root / excluded) not in homes
    assert len(homes) == len(set(homes))


def test_all_user_homes_survives_a_missing_users_root(tmp_path):
    homes = onboard.all_user_homes(system="linux", users_root=str(tmp_path / "nope"))
    assert homes == [os.path.expanduser("~")]


def test_a_broken_detector_leans_towards_installing(monkeypatch, capsys):
    def _boom():
        raise OSError("directory service is down")

    monkeypatch.setattr(onboard, "pi_detected", _boom)
    assert onboard.should_install_pi() is True
    assert "setting up the Pi Coding Agent anyway" in capsys.readouterr().err


# ---- main() ----

def _run_main(monkeypatch, argv, detected, tool_result=lambda name: True):
    """Run onboard.main() with every download, child and scan faked. `detected` is
    True/False, or a callable installed as onboard.pi_detected."""
    calls = []

    def _run_tool(name, url, args):
        calls.append((name, url, list(args)))
        return tool_result(name)

    monkeypatch.setattr(onboard, "check_admin_privileges", lambda: True)
    monkeypatch.setattr(onboard, "run_tool", _run_tool)
    monkeypatch.setattr(onboard, "fetch_device_owner_key", lambda key, url: None)
    monkeypatch.setattr(onboard, "pi_detected",
                        detected if callable(detected) else (lambda: detected))
    monkeypatch.setattr(onboard.sys, "argv", ["onboard.py"] + argv)
    return onboard.main(), calls


def test_pi_step_runs_when_pi_is_detected(monkeypatch, capsys):
    code, calls = _run_main(
        monkeypatch, ["--api-key", "K", "--backfill", "--skip-managed-settings"], True)

    assert code == 0
    assert [name for name, _url, _args in calls] == FIVE_TOOLS + ["Pi Coding Agent"]
    name, url, args = calls[-1]
    assert url.endswith("/pi/mdm/setup.py")
    # pi has no transcript store and no managed-settings file.
    assert args == ["--api-key", "K"]
    out = capsys.readouterr().out
    assert "MDM onboarding complete" in out
    assert "Pi Coding Agent" in out
    assert "Pi Coding Agent (skipped)" not in out


def test_pi_step_is_skipped_when_pi_is_not_detected(monkeypatch, capsys):
    code, calls = _run_main(monkeypatch, ["--api-key", "K"], False)

    assert code == 0
    assert [name for name, _url, _args in calls] == FIVE_TOOLS
    out = capsys.readouterr().out
    assert "not detected" in out
    assert "Pi Coding Agent (skipped)" in out
    assert "MDM onboarding complete" in out


def test_pi_step_runs_when_detection_raises(monkeypatch):
    def _boom():
        raise RuntimeError("boom")

    code, calls = _run_main(monkeypatch, ["--api-key", "K"], _boom)

    assert code == 0
    assert calls[-1][0] == "Pi Coding Agent"


def test_clear_always_runs_the_pi_step_without_asking_detection(monkeypatch, capsys):
    """A device whose pi was uninstalled still carries the extension and the rc export."""
    code, calls = _run_main(
        monkeypatch, ["--clear"], lambda: pytest.fail("--clear must not consult detection"))

    assert code == 0
    assert [name for name, _url, _args in calls] == FIVE_TOOLS + ["Pi Coding Agent"]
    assert calls[-1][2] == ["--clear"]
    out = capsys.readouterr().out
    assert "Pi Coding Agent" in out
    assert "(skipped)" not in out


def test_a_failed_pi_step_fails_the_enrollment(monkeypatch, capsys):
    code, _calls = _run_main(monkeypatch, ["--api-key", "K"], True,
                             tool_result=lambda name: name != "Pi Coding Agent")

    assert code == 1
    assert "failure(s): Pi Coding Agent" in capsys.readouterr().out


def test_a_skipped_pi_step_does_not_hide_another_tools_failure(monkeypatch, capsys):
    code, _calls = _run_main(monkeypatch, ["--api-key", "K"], False,
                             tool_result=lambda name: name != "Cursor")

    assert code == 1
    assert "failure(s): Cursor" in capsys.readouterr().out


def test_pi_is_not_a_row_in_the_tool_table():
    assert [name for name, *_ in onboard.TOOLS] == FIVE_TOOLS
    assert onboard.PI_TOOL[0] == "Pi Coding Agent"
    assert onboard.PI_TOOL[2:] == (False, False)
