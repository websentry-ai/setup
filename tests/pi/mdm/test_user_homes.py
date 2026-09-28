"""Home enumeration for the MDM installer, and the two guards that wrap it.

The enumeration decides which directories root is about to write into, so it is tested
per platform against the analog's exact rules (augment/hooks/mdm/setup.py:356-398): a uid
floor, a home-prefix check, a skip list, and a whole-body try/except that degrades to an
empty list rather than raising.

The home prefixes are read from module constants (MACOS_HOME_PREFIX / LINUX_HOME_PREFIX)
so a test can point them at a tmp tree. The shipped values are asserted here too, because
a seam nothing pins is a seam that can drift.
"""

import ast
import io
import os
import pwd as real_pwd

import pytest


def _pw(name, uid, home):
    """A pwd.getpwall() row, shaped exactly like the real thing."""
    return real_pwd.struct_passwd((name, "*", uid, uid, "", str(home), "/bin/zsh"))


class FakePwd:
    """Stands in for the `pwd` module so a test controls the machine's user list."""

    def __init__(self, entries=(), raises=None):
        self._entries = list(entries)
        self._raises = raises

    def getpwall(self):
        if self._raises is not None:
            raise self._raises
        return list(self._entries)

    def getpwnam(self, name):
        for entry in self._entries:
            if entry.pw_name == name:
                return entry
        raise KeyError(name)


def _force(monkeypatch, mod, system, pwd_module=None):
    """Pin platform.system() and, optionally, the module's `pwd` handle."""
    monkeypatch.setattr(mod.platform, "system", lambda: system)
    if pwd_module is not None:
        monkeypatch.setattr(mod, "pwd", pwd_module)


# --- the shipped constants ---------------------------------------------------------------


def test_the_shipped_prefixes_and_floors_match_the_analog(pi_mdm_setup):
    """These four values are the whole difference between "every real user" and
    "every system account", so they are pinned rather than assumed."""
    mod = pi_mdm_setup
    assert mod.MACOS_HOME_PREFIX == '/Users/'
    assert mod.LINUX_HOME_PREFIX == '/home/'
    assert mod.MACOS_UID_FLOOR == 500
    assert mod.LINUX_UID_FLOOR == 1000
    assert set(mod.MACOS_SKIP_USERS) == {"Shared", "Guest"}
    assert set(mod.WINDOWS_SKIP_PROFILES) == {
        "Public", "Default", "Default User", "Administrator", "All Users"}


def test_the_users_prefix_is_never_double_quoted_in_the_source(pi_mdm_setup):
    """tests/test_setup_contract.py fails a line whose two characters before a /Users/
    prefix contain a double quote. Asserted here too so the failure names this file."""
    src = (pi_mdm_setup.__file__ and open(pi_mdm_setup.__file__, encoding="utf-8").read())
    for line in src.splitlines():
        if '/Users/' in line and not line.lstrip().startswith("#"):
            assert '"' not in line.split('/Users/')[0][-2:], line.strip()[:80]


# --- macOS -------------------------------------------------------------------------------


def test_darwin_returns_only_real_user_homes(pi_mdm_setup, monkeypatch, tmp_path):
    """Every exclusion the analog makes, asserted in one pass: the uid floor, the home
    prefix, Shared and Guest by name, a missing home, and a home that is a file."""
    mod = pi_mdm_setup
    users = tmp_path / "Users"
    users.mkdir()
    prefix = str(users) + "/"
    monkeypatch.setattr(mod, "MACOS_HOME_PREFIX", prefix)

    for name in ("alice", "bob", "Shared", "Guest", "belowfloor"):
        (users / name).mkdir()
    (users / "afile").write_text("not a directory\n")
    outside = tmp_path / "opt" / "svcacct"
    outside.mkdir(parents=True)

    entries = [
        _pw("root", 0, "/var/root"),                  # system account, under the floor
        _pw("belowfloor", 499, users / "belowfloor"),  # one below the floor
        _pw("alice", 501, users / "alice"),            # a real user
        _pw("bob", 502, users / "bob"),                # a real user
        _pw("Shared", 503, users / "Shared"),          # skipped by name
        _pw("Guest", 504, users / "Guest"),            # skipped by name
        _pw("gone", 505, users / "does-not-exist"),    # home absent
        _pw("afile", 506, users / "afile"),            # home is a regular file
        _pw("svcacct", 507, outside),                  # home outside the prefix
    ]
    _force(monkeypatch, mod, "Darwin", FakePwd(entries))

    found = mod.get_all_user_homes()
    assert [name for name, _ in found] == ["alice", "bob"]
    assert [str(home) for _, home in found] == [str(users / "alice"), str(users / "bob")]


def test_darwin_accepts_the_floor_itself(pi_mdm_setup, monkeypatch, tmp_path):
    """`uid >= 500`, not `> 500`: the first real macOS account is exactly 501 today, but
    the comparison is the analog's and a flipped operator would be invisible otherwise."""
    mod = pi_mdm_setup
    users = tmp_path / "Users"
    (users / "edge").mkdir(parents=True)
    monkeypatch.setattr(mod, "MACOS_HOME_PREFIX", str(users) + "/")
    _force(monkeypatch, mod, "Darwin", FakePwd([_pw("edge", 500, users / "edge")]))
    assert [n for n, _ in mod.get_all_user_homes()] == ["edge"]


# --- Linux -------------------------------------------------------------------------------


def test_linux_uses_the_1000_floor_and_the_home_prefix(pi_mdm_setup, monkeypatch, tmp_path):
    """Linux has no Shared/Guest names to skip; the floor is 1000 and the prefix differs."""
    mod = pi_mdm_setup
    homes = tmp_path / "home"
    homes.mkdir()
    for name in ("dev", "daemonish"):
        (homes / name).mkdir()
    srv = tmp_path / "srv" / "app"
    srv.mkdir(parents=True)
    monkeypatch.setattr(mod, "LINUX_HOME_PREFIX", str(homes) + "/")

    entries = [
        _pw("daemonish", 999, homes / "daemonish"),  # one below the floor
        _pw("dev", 1000, homes / "dev"),             # the floor itself
        _pw("app", 1001, srv),                       # outside the prefix
    ]
    _force(monkeypatch, mod, "Linux", FakePwd(entries))
    assert [n for n, _ in mod.get_all_user_homes()] == ["dev"]


def test_linux_does_not_apply_the_macos_skip_list(pi_mdm_setup, monkeypatch, tmp_path):
    """A user genuinely called `Guest` on Linux is a real user; the analog only skips
    those names on darwin, and copying the skip list across would silently lose them."""
    mod = pi_mdm_setup
    homes = tmp_path / "home"
    (homes / "Guest").mkdir(parents=True)
    monkeypatch.setattr(mod, "LINUX_HOME_PREFIX", str(homes) + "/")
    _force(monkeypatch, mod, "Linux", FakePwd([_pw("Guest", 1001, homes / "Guest")]))
    assert [n for n, _ in mod.get_all_user_homes()] == ["Guest"]


# --- Windows -----------------------------------------------------------------------------


def test_windows_walks_the_users_directory_minus_the_system_profiles(
        pi_mdm_setup, monkeypatch, tmp_path):
    """No pwd on Windows: the profile directories under %SystemDrive%\\Users ARE the list.
    The path is built with os.sep so this is exercisable from a POSIX test runner."""
    mod = pi_mdm_setup
    drive = tmp_path / "C-drive"
    users = drive / "Users"
    users.mkdir(parents=True)
    for name in ("Carol", "Public", "Default", "Default User", "Administrator", "All Users"):
        (users / name).mkdir()
    (users / "desktop.ini").write_text("[.ShellClassInfo]\n")  # a file, not a profile
    monkeypatch.setenv("SystemDrive", str(drive))
    _force(monkeypatch, mod, "Windows", FakePwd())

    found = mod.get_all_user_homes()
    assert [n for n, _ in found] == ["Carol"]


def test_windows_with_no_users_directory_is_empty_not_an_error(
        pi_mdm_setup, monkeypatch, tmp_path):
    mod = pi_mdm_setup
    monkeypatch.setenv("SystemDrive", str(tmp_path / "nothing-here"))
    _force(monkeypatch, mod, "Windows", FakePwd())
    assert mod.get_all_user_homes() == []


# --- degradation -------------------------------------------------------------------------


def test_any_failure_inside_the_enumeration_yields_an_empty_list(pi_mdm_setup, monkeypatch):
    """A raise here would abort the whole device run before a single home was considered."""
    mod = pi_mdm_setup
    _force(monkeypatch, mod, "Darwin", FakePwd(raises=OSError("nss is down")))
    assert mod.get_all_user_homes() == []


def test_a_missing_pwd_module_yields_an_empty_list(pi_mdm_setup, monkeypatch):
    """`pwd` is absent on Windows and the import is guarded, so the darwin branch has to
    survive `pwd is None` rather than raising AttributeError out of the loop."""
    mod = pi_mdm_setup
    _force(monkeypatch, mod, "Darwin", None)
    monkeypatch.setattr(mod, "pwd", None)
    assert mod.get_all_user_homes() == []


def test_an_unknown_platform_yields_an_empty_list(pi_mdm_setup, monkeypatch):
    mod = pi_mdm_setup
    _force(monkeypatch, mod, "SunOS", FakePwd())
    assert mod.get_all_user_homes() == []


# --- the stdout guard --------------------------------------------------------------------


def test_the_stdout_guard_reconfigures_both_streams(pi_mdm_setup, monkeypatch):
    """MDM hands this a pipe; on Windows that pipe is cp1252 and the first status line
    with a check mark in it takes down the run. stdout and stderr get separate wrappers
    so a guard that stopped reconfiguring one of them cannot pass."""
    mod = pi_mdm_setup
    line = "status ✅ and dash —\n"

    def narrow():
        raw = io.BytesIO()
        return raw, io.TextIOWrapper(raw, encoding="cp1252", newline="")

    out_raw, out = narrow()
    err_raw, err = narrow()
    for stream in (out, err):
        with pytest.raises(UnicodeEncodeError):
            stream.write(line)
            stream.flush()

    monkeypatch.setattr(mod.sys, "stdout", out)
    monkeypatch.setattr(mod.sys, "stderr", err)
    mod._stdout_never_raises()
    for stream, raw in ((out, out_raw), (err, err_raw)):
        stream.write(line)
        stream.flush()
        assert raw.getvalue().endswith(line.encode("utf-8"))


def test_the_stdout_guard_swallows_a_stream_that_cannot_reconfigure(pi_mdm_setup, monkeypatch):
    """A stream object with no reconfigure (AttributeError), a detached one (ValueError)
    and a closed pipe (OSError) must all be non-events -- the guard's whole job is to
    never be the thing that fails the install."""
    mod = pi_mdm_setup

    class NoReconfigure:
        pass

    for boom in (ValueError("underlying buffer detached"), OSError("closed pipe")):
        class Raiser:
            def reconfigure(self, **kw):
                raise boom
        monkeypatch.setattr(mod.sys, "stdout", Raiser())
        monkeypatch.setattr(mod.sys, "stderr", NoReconfigure())
        mod._stdout_never_raises()  # no raise is the assertion


def test_main_calls_the_stdout_guard_as_its_first_statement(pi_mdm_setup):
    """The shared contract asserts this for every MDM entry point; asserted here too so a
    regression fails in the pi suite, next to the code, rather than only in the shared one."""
    tree = ast.parse(open(pi_mdm_setup.__file__, encoding="utf-8").read())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = main.body
    first = body[1] if (isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)) else body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
    assert first.value.func.id == "_stdout_never_raises"


# --- the root gate -----------------------------------------------------------------------


def test_check_admin_privileges_is_euid_zero_on_unix(pi_mdm_setup, monkeypatch):
    mod = pi_mdm_setup
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    assert mod.check_admin_privileges() is True
    monkeypatch.setattr(mod.os, "geteuid", lambda: 501)
    assert mod.check_admin_privileges() is False


def test_main_without_root_refuses_before_touching_any_home(
        pi_mdm_setup, monkeypatch, capsys):
    """The refusal has to come BEFORE enumeration: an unprivileged run that walked the
    homes and failed per-user would print a wall of noise instead of one clear line."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 501)
    monkeypatch.setattr(mod.sys, "argv", ["setup.py", "--api-key", "admin-key"])

    touched = []
    monkeypatch.setattr(mod, "get_all_user_homes", lambda: touched.append("enumerated") or [])
    monkeypatch.setattr(mod, "install_for_user", lambda *a, **k: touched.append("installed"))
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *a, **k: pytest.fail("an unprivileged run reached the network"))

    assert mod.main() is False
    assert touched == []
    out = capsys.readouterr().out
    assert "root" in out or "sudo" in out


def test_clear_without_root_refuses_cleanly(pi_mdm_setup, monkeypatch, capsys):
    """The shared TestEveryTeardown case, asserted directly: refusing is fine, a
    traceback or a silent partial clear is not."""
    mod = pi_mdm_setup
    monkeypatch.setattr(mod.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 501)
    monkeypatch.setattr(mod, "get_all_user_homes",
                        lambda: pytest.fail("clear enumerated homes without root"))
    monkeypatch.setattr(mod.subprocess, "run",
                        lambda *a, **k: pytest.fail("clear reached the network"))
    assert mod.clear_setup() is False
    assert "sudo" in capsys.readouterr().out


def test_the_installer_never_reads_the_agent_dir_env_var(pi_mdm_setup, monkeypatch, tmp_path):
    """PI_CODING_AGENT_DIR is the TARGET user's variable and root cannot read it, so the
    MDM installer must resolve the default path only -- and must not be fooled by the
    variable happening to be set in root's own environment."""
    mod = pi_mdm_setup
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "hijacked"))
    assert mod.resolve_agent_dir(home) == home / ".pi" / "agent"
    # One parameter, the home: there is deliberately no `env` seam to pass root's
    # environment in through, so the hijack above cannot reach the resolver at all.
    assert mod.resolve_agent_dir.__code__.co_argcount == 1
    src = open(pi_mdm_setup.__file__, encoding="utf-8").read()
    for line in src.splitlines():
        if "PI_CODING_AGENT_DIR" in line:
            assert line.lstrip().startswith("#") or "environ" not in line, line.strip()[:90]


def test_resolve_agent_dir_refuses_a_relative_or_empty_home(pi_mdm_setup):
    """No absolute base means no safe place to write; guessing one would drop the
    extension into whatever directory the Jamf runner happened to start in."""
    mod = pi_mdm_setup
    assert mod.resolve_agent_dir(None) is None
    assert mod.resolve_agent_dir("") is None
    assert mod.resolve_agent_dir("relative/home") is None
    assert mod.extension_dir(os.sep + "abs") == \
        mod.Path(os.sep + "abs") / "extensions" / "unbound"
