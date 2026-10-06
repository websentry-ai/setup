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


def _link(path, target):
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    os.symlink(str(target), str(path))
    return path


def _stat_failing_under(monkeypatch, blocked, error=PermissionError):
    """Make every os.stat under `blocked` fail the way an unreadable home does."""
    real_stat = os.stat

    def _stat(path, *args, **kwargs):
        if str(path).startswith(str(blocked)):
            raise error(13, "Permission denied", str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(onboard.os, "stat", _stat)


def _detect(homes, path_dirs=(), machine_bin_dirs=(), system="darwin", os_package_bin_dirs=()):
    return onboard.pi_detected(homes=[str(h) for h in homes],
                               path_dirs=[str(d) for d in path_dirs],
                               machine_bin_dirs=[str(d) for d in machine_bin_dirs],
                               system=system,
                               os_package_bin_dirs=[str(d) for d in os_package_bin_dirs])


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
    ".pi/agent/bin/pi",   # where pi's own installer puts it
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
    _touch(tmp_path / "local-bin" / "pi")
    assert _detect([home], machine_bin_dirs=[tmp_path / "local-bin"]) is True


def test_a_plain_file_named_pi_in_an_os_package_dir_is_not_the_agent(home, tmp_path):
    """Debian and Ubuntu ship a digits-of-pi calculator at /usr/bin/pi. A regular file
    in a dir the OS package manager owns is the OS's own program."""
    usr_bin = tmp_path / "usr-bin"
    _touch(usr_bin / "pi")
    assert _detect([home], machine_bin_dirs=[usr_bin], os_package_bin_dirs=[usr_bin]) is False
    assert _detect([home], path_dirs=[usr_bin], os_package_bin_dirs=[usr_bin]) is False


def test_the_agent_linked_into_an_os_package_dir_is_a_signal(home, tmp_path):
    """npm with its prefix at /usr links the agent into /usr/bin."""
    usr_bin = tmp_path / "usr-bin"
    cli = _touch(tmp_path / "usr-lib" / "node_modules" / "pi-coding-agent" / "dist" / "cli.js")
    _link(usr_bin / "pi", cli)
    assert _detect([home], machine_bin_dirs=[usr_bin], os_package_bin_dirs=[usr_bin]) is True


def test_an_os_package_dir_reached_through_a_link_is_still_one(home, tmp_path):
    """/bin is a link to /usr/bin on a merged-usr system."""
    usr_bin = tmp_path / "usr-bin"
    _touch(usr_bin / "pi")
    _link(tmp_path / "bin", usr_bin)
    assert _detect([home], path_dirs=[tmp_path / "bin"], os_package_bin_dirs=[usr_bin]) is False


def test_a_link_whose_target_is_gone_is_not_a_signal(home, tmp_path):
    _link(tmp_path / "local-bin" / "pi", tmp_path / "uninstalled" / "cli.js")
    assert _detect([home], machine_bin_dirs=[tmp_path / "local-bin"]) is False


def test_the_real_os_package_dirs_are_the_default():
    assert onboard.PI_OS_PACKAGE_BIN_DIRS == ("/usr/bin", "/bin")
    assert set(onboard.PI_OS_PACKAGE_BIN_DIRS) & set(onboard.PI_MACHINE_BIN_DIRS) == {"/usr/bin"}


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
    real_stat = os.stat

    def _stat(path, *args, **kwargs):
        seen.append(str(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(onboard.os, "stat", _stat)
    assert onboard.pi_detected(homes=[str(home)], path_dirs=[], system="windows") is False
    assert seen and not any(p.startswith("/opt/homebrew") for p in seen)


# ---- a place that could not be inspected ----

def test_an_unreadable_home_is_not_reported_as_a_device_without_pi(monkeypatch, home, tmp_path):
    """Absent and unreadable are different answers. Reporting the second as the first
    skipped the install on exactly the devices where nothing could be ruled out."""
    locked = tmp_path / "locked"
    locked.mkdir()
    _stat_failing_under(monkeypatch, locked)

    with pytest.raises(PermissionError):
        _detect([home, locked])


def test_an_io_error_is_treated_like_an_unreadable_home(monkeypatch, home, tmp_path):
    broken = tmp_path / "broken"
    broken.mkdir()
    _stat_failing_under(monkeypatch, broken, error=OSError)

    with pytest.raises(OSError):
        _detect([home, broken])


def test_a_signal_found_elsewhere_wins_over_an_unreadable_home(monkeypatch, home, tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    _touch(home / ".pi" / "agent" / "auth.json")
    _stat_failing_under(monkeypatch, locked)

    assert _detect([home, locked]) is True


def test_an_unreadable_home_makes_the_pi_step_run(monkeypatch, capsys, home, tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    _stat_failing_under(monkeypatch, locked)
    monkeypatch.setattr(onboard, "all_user_homes", lambda *a, **k: [str(home), str(locked)])
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(onboard, "PI_MACHINE_BIN_DIRS", ())

    assert onboard.should_install_pi() is True
    assert "setting up the Pi Coding Agent anyway" in capsys.readouterr().err


def test_an_unlistable_nvm_dir_is_not_reported_as_absent(monkeypatch, home):
    nvm = home / ".nvm" / "versions" / "node"
    nvm.mkdir(parents=True)
    real_listdir = os.listdir

    def _listdir(path):
        if str(path) == str(nvm):
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)

    monkeypatch.setattr(onboard.os, "listdir", _listdir)
    with pytest.raises(PermissionError):
        _detect([home])


def test_all_user_homes_lists_real_accounts_only(tmp_path):
    root = tmp_path / "Users"
    for name in ("alice", "bob", "Shared", "Guest", ".hidden"):
        (root / name).mkdir(parents=True)
    _touch(root / "a-plain-file")

    homes = onboard.all_user_homes(system="darwin", users_root=str(root), account_homes=[])

    assert str(root / "alice") in homes
    assert str(root / "bob") in homes
    for excluded in ("Shared", "Guest", ".hidden", "a-plain-file"):
        assert str(root / excluded) not in homes
    assert len(homes) == len(set(homes))


def test_all_user_homes_survives_a_missing_users_root(tmp_path):
    homes = onboard.all_user_homes(system="linux", users_root=str(tmp_path / "nope"),
                                   account_homes=[])
    assert homes == [os.path.expanduser("~")]


def test_a_home_that_is_not_a_direct_child_of_the_users_root_is_found(tmp_path):
    """/home/DOMAIN/alice: pi/mdm/setup.py installs for that account, so detection
    has to look there too. A listing of /home sees only DOMAIN."""
    root = tmp_path / "home"
    alice = root / "DOMAIN" / "alice"
    _touch(alice / ".pi" / "agent" / "auth.json")

    listed_only = onboard.all_user_homes(system="linux", users_root=str(root), account_homes=[])
    assert str(alice) not in listed_only
    assert _detect(listed_only[1:]) is False

    homes = onboard.all_user_homes(system="linux", users_root=str(root),
                                   account_homes=[str(alice)])
    assert str(alice) in homes
    assert _detect(homes[1:]) is True


def test_linux_users_named_shared_or_guest_are_real_accounts(tmp_path):
    """pi/mdm/setup.py skips those names on macOS only."""
    root = tmp_path / "home"
    for name in ("Shared", "Guest", "alice"):
        (root / name).mkdir(parents=True)

    linux = onboard.all_user_homes(system="linux", users_root=str(root), account_homes=[])
    assert {str(root / "Shared"), str(root / "Guest"), str(root / "alice")} <= set(linux)

    mac = onboard.all_user_homes(system="darwin", users_root=str(root),
                                 account_homes=[str(root / "Guest")])
    assert str(root / "alice") in mac
    assert str(root / "Shared") not in mac and str(root / "Guest") not in mac


def test_an_account_home_that_does_not_exist_is_dropped(tmp_path):
    homes = onboard.all_user_homes(system="linux", users_root=str(tmp_path / "home"),
                                   account_homes=[str(tmp_path / "home" / "ghost")])
    assert homes == [os.path.expanduser("~")]


def test_account_homes_come_from_under_the_platform_prefix_only(monkeypatch):
    """The same rule pi/mdm/setup.py applies before it installs into a home."""
    import pwd
    import types

    entries = [types.SimpleNamespace(pw_dir=d) for d in
               ("/home/alice", "/home/DOMAIN/bob", "/var/lib/postgres", "/root", "")]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)

    assert onboard._account_homes("linux", []) == ["/home/alice", "/home/DOMAIN/bob"]
    assert onboard._account_homes("darwin", []) == []
    assert onboard._account_homes("windows", []) == []


def test_an_account_database_that_cannot_be_read_is_not_a_device_without_pi(monkeypatch, tmp_path):
    """Homes may have gone unseen, so "nothing found" is not an answer."""
    import pwd

    def _broken():
        raise OSError("directory service is down")

    monkeypatch.setattr(pwd, "getpwall", _broken)
    monkeypatch.setattr(onboard.os, "listdir", lambda path: [])
    monkeypatch.setattr(onboard.os.path, "expanduser", lambda path: str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(onboard, "PI_MACHINE_BIN_DIRS", ())

    errors = []
    assert onboard._account_homes("linux", errors) == []
    assert len(errors) == 1
    with pytest.raises(OSError):
        onboard.pi_detected(system="linux")


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
