"""`--clear` removes what we wrote, and provably nothing else (INST-02).

The shared tests/test_setup_contract.py::TestEveryTeardown already proves a pristine
HOME clear does not traceback and leaves a foreign ~/.zprofile and ~/.claude/settings.json
alone. These add the pi-specific half: no network, no key, no config.json, and the
directory plus a developer's own files survive.
"""

import json

import pytest


@pytest.fixture
def clear_env(pi_setup, pi_home, monkeypatch):
    """Runs clear_setup() against the fake HOME, with curl wired to explode.

    clear_setup derives everything from HOME (the contract test passes nothing else),
    so the env is the only input, and a subprocess call is a test failure rather than
    a mocked no-op -- the claim is that the teardown path makes none at all.
    """

    def no_subprocess(*args, **kwargs):
        raise AssertionError("clear_setup made a subprocess call: %r" % (args,))

    monkeypatch.setenv("HOME", str(pi_home.home))
    monkeypatch.delenv("PI_CODING_AGENT_DIR", raising=False)
    monkeypatch.setattr(pi_setup.subprocess, "run", no_subprocess)
    return pi_home


class TestPristineMachine:
    def test_it_reports_not_found_and_returns_a_bool(self, pi_setup, clear_env, capsys):
        ok = pi_setup.clear_setup()
        assert isinstance(ok, bool)
        assert ok is True, "nothing to remove is success, not failure"
        assert "not_found" in capsys.readouterr().out

    def test_it_creates_nothing(self, pi_setup, clear_env):
        """A teardown that mkdirs its way to an answer would fail the contract's
        pristine-HOME run on a machine where the agent dir does not exist."""
        pi_setup.clear_setup()
        assert not clear_env.extension_dir().exists()
        assert not clear_env.config_path.exists()


class TestWhatItRemoves:
    def test_it_removes_index_js_and_the_sidecar_we_wrote(self, pi_setup, clear_env):
        extdir = clear_env.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        (extdir / "index.js.sha256").write_text("d" * 64 + "  index.js\n")
        assert pi_setup.clear_setup() is True
        assert not (extdir / "index.js").exists()
        assert not (extdir / "index.js.sha256").exists()

    def test_it_leaves_the_directory_and_a_siblings_file(self, pi_setup, clear_env):
        extdir = clear_env.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        notes = extdir / "notes.md"
        notes.write_text("# my own notes\n")
        pi_setup.clear_setup()
        assert extdir.is_dir(), "the directory is never removed"
        assert notes.read_text() == "# my own notes\n"

    def test_it_leaves_a_disabled_shadow_file_alone(self, pi_setup, clear_env, plant_shadow):
        """We moved that .ts aside; it was the developer's file before and after."""
        extdir = clear_env.extension_dir()
        disabled = plant_shadow(extdir, name="index.ts.unbound-disabled", body="// mine\n")
        (extdir / "index.js").write_text("// unbound\n")
        pi_setup.clear_setup()
        assert disabled.read_text() == "// mine\n"

    def test_it_leaves_a_live_index_ts_alone(self, pi_setup, clear_env, plant_shadow):
        extdir = clear_env.extension_dir()
        shadow = plant_shadow(extdir, name="index.ts")
        pi_setup.clear_setup()
        assert shadow.exists(), "clear never wrote a .ts, so it never removes one"

    def test_it_never_touches_a_sibling_extension(self, pi_setup, clear_env):
        other = clear_env.agent_dir / "extensions" / "somebody-else"
        other.mkdir(parents=True)
        (other / "index.js").write_text("// not ours\n")
        pi_setup.clear_setup()
        assert (other / "index.js").read_text() == "// not ours\n"


class TestWhatItNeverTouches:
    def test_it_leaves_the_shared_config_byte_identical(self, pi_setup, clear_env):
        """~/.unbound/config.json holds the key six tools read; --clear must not
        so much as rewrite it (CONTEXT-locked, RESEARCH E3)."""
        original = {"api_key": "shared-key", "base_url": "https://backend.getunbound.ai"}
        path = clear_env.write_config(original)
        before = path.read_bytes()
        extdir = clear_env.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        pi_setup.clear_setup()
        assert path.read_bytes() == before
        assert json.loads(path.read_text())["api_key"] == "shared-key"

    def test_it_needs_no_api_key(self, pi_setup, clear_env):
        """The CLI omits --api-key on a clear run (setup.js:258-259)."""
        assert pi_setup.main.__code__.co_argcount == 0
        assert pi_setup.parse_args(["setup.py", "--clear"])["api_key"] is None
        assert pi_setup.clear_setup() is True

    def test_it_makes_no_network_call(self, pi_setup, clear_env):
        """clear_env wires subprocess.run to raise, so reaching curl fails the test."""
        extdir = clear_env.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        assert pi_setup.clear_setup() is True


class TestEnvAwareness:
    def test_it_honours_pi_coding_agent_dir(self, pi_setup, clear_env, monkeypatch, tmp_path):
        """A clear that ignored the env var would leave the real install in place
        while printing success -- the mirror image of RESEARCH E2."""
        base = tmp_path / "custom-agent"
        monkeypatch.setenv("PI_CODING_AGENT_DIR", str(base))
        extdir = clear_env.extension_dir(base=base)
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        default_extdir = clear_env.extension_dir()
        default_extdir.mkdir(parents=True)
        (default_extdir / "index.js").write_text("// stale default\n")
        assert pi_setup.clear_setup() is True
        assert not (extdir / "index.js").exists()
        assert (default_extdir / "index.js").exists(), "only the resolved dir is cleared"

    def test_a_relative_env_value_clears_the_home_default(self, pi_setup, clear_env, monkeypatch):
        monkeypatch.setenv("PI_CODING_AGENT_DIR", "relative-agent")
        extdir = clear_env.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_text("// unbound\n")
        assert pi_setup.clear_setup() is True
        assert not (extdir / "index.js").exists()


class TestClearPathPrimitive:
    def test_it_returns_a_status_and_never_raises(self, pi_setup, tmp_path):
        target = tmp_path / "index.js"
        assert pi_setup._clear_path(target, "pi extension") == "not_found"
        target.write_text("x")
        assert pi_setup._clear_path(target, "pi extension") == "cleared"
        assert pi_setup._clear_path(target, "pi extension") == "not_found"

    def test_an_undeletable_path_is_failed_not_an_exception(self, pi_setup, tmp_path, monkeypatch):
        target = tmp_path / "index.js"
        target.write_text("x")

        def deny(self, *a, **k):
            raise PermissionError("read-only filesystem")

        monkeypatch.setattr(pi_setup.Path, "unlink", deny)
        assert pi_setup._clear_path(target, "pi extension") == "failed"
