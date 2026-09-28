"""The drop: where the file lands, what mode it gets, and what it must not disturb.

The highest-value assertion in this module is the index.ts shadow guard. pi resolves
index.ts BEFORE index.js, so a stale .ts left in place means pi loads the wrong file,
logs nothing, and the installer still says success (RESEARCH B4/E1).
"""

import hashlib
import stat
from pathlib import Path

import pytest

ARTIFACT = b"// GENERATED FILE - DO NOT EDIT\nexport default { name: 'unbound' };\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@pytest.fixture
def good_fetch(pi_setup, fake_fetch):
    """A fetch where the artifact and the sidecar agree -- the happy path."""
    return fake_fetch(
        {pi_setup.ARTIFACT_URL: ARTIFACT,
         pi_setup.SHA_URL: f"{DIGEST}  pi/index.js\n"},
        module=pi_setup,
    )


class TestTheDrop:
    def test_it_writes_index_js_and_returns_the_digest(self, pi_setup, pi_home, good_fetch):
        digest = pi_setup.install_extension(pi_home.agent_dir)
        target = pi_setup.artifact_path(pi_home.agent_dir)
        assert target.read_bytes() == ARTIFACT
        assert digest == DIGEST, "the returned digest is of the bytes actually written"

    def test_the_written_bytes_are_byte_identical_to_the_fetched_artifact(
            self, pi_setup, pi_home, good_fetch):
        pi_setup.install_extension(pi_home.agent_dir)
        target = pi_setup.artifact_path(pi_home.agent_dir)
        assert pi_setup.artifact_sha256(target) == DIGEST

    def test_the_file_mode_is_exactly_0644(self, pi_setup, pi_home, good_fetch):
        """World-readable so pi can load it, not writable so nothing else can edit it."""
        pi_setup.install_extension(pi_home.agent_dir)
        target = pi_setup.artifact_path(pi_home.agent_dir)
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_it_creates_the_extension_dir_at_0755(self, pi_setup, pi_home, good_fetch):
        pi_setup.install_extension(pi_home.agent_dir)
        extdir = pi_setup.extension_dir(pi_home.agent_dir)
        assert extdir.is_dir()
        assert stat.S_IMODE(extdir.stat().st_mode) == 0o755

    def test_it_creates_a_missing_agent_dir_too(self, pi_setup, pi_home, good_fetch, tmp_path):
        """A machine where pi has never run has no ~/.pi/agent yet."""
        base = tmp_path / "never-run" / "agent"
        assert pi_setup.install_extension(base) == DIGEST
        assert pi_setup.artifact_path(base).exists()

    def test_it_writes_the_sidecar_next_to_the_artifact(self, pi_setup, pi_home, good_fetch):
        """--clear removes this file, so it has to be one we actually wrote."""
        pi_setup.install_extension(pi_home.agent_dir)
        sidecar = pi_setup.sidecar_path(pi_home.agent_dir)
        assert DIGEST in sidecar.read_text()

    def test_it_never_touches_a_sibling_extension(self, pi_setup, pi_home, good_fetch):
        other = pi_home.agent_dir / "extensions" / "somebody-else"
        other.mkdir(parents=True)
        (other / "index.js").write_bytes(b"// not ours\n")
        pi_setup.install_extension(pi_home.agent_dir)
        assert (other / "index.js").read_bytes() == b"// not ours\n"

    def test_it_leaves_a_sibling_file_in_our_own_dir_alone(self, pi_setup, pi_home, good_fetch):
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        notes = extdir / "notes.md"
        notes.write_text("# mine\n")
        pi_setup.install_extension(pi_home.agent_dir)
        assert notes.read_text() == "# mine\n"


class TestIdempotence:
    def test_rerunning_over_an_identical_file_is_clean(self, pi_setup, pi_home, good_fetch, capsys):
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        capsys.readouterr()
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        out = capsys.readouterr().out
        assert "❌" not in out
        target = pi_setup.artifact_path(pi_home.agent_dir)
        assert target.read_bytes() == ARTIFACT
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_it_overwrites_a_stale_build(self, pi_setup, pi_home, good_fetch):
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        (extdir / "index.js").write_bytes(b"// a much older build\n")
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        assert (extdir / "index.js").read_bytes() == ARTIFACT

    def test_it_repairs_a_wrong_mode(self, pi_setup, pi_home, good_fetch):
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        target = extdir / "index.js"
        target.write_bytes(b"// old\n")
        target.chmod(0o600)
        pi_setup.install_extension(pi_home.agent_dir)
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


class TestInstallState:
    def test_an_absent_target_is_fresh(self, pi_setup, pi_home):
        assert pi_setup.detect_install_state(pi_setup.artifact_path(pi_home.agent_dir)) == "fresh"

    def test_an_existing_target_is_persisted(self, pi_setup, pi_home):
        target = pi_setup.artifact_path(pi_home.agent_dir)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"// already here\n")
        assert pi_setup.detect_install_state(target) == "persisted"

    def test_it_never_reports_tampered(self, pi_setup, pi_home):
        """A user-level install is not tamper-eligible; the backend's third enum value
        belongs to the managed path only."""
        for path in (pi_setup.artifact_path(pi_home.agent_dir), None, "/nonexistent/x/index.js"):
            assert pi_setup.detect_install_state(path) in ("fresh", "persisted")

    def test_an_unstattable_path_degrades_to_fresh(self, pi_setup, monkeypatch):
        def deny(self):
            raise PermissionError("nope")

        monkeypatch.setattr(pi_setup.Path, "exists", deny)
        assert pi_setup.detect_install_state("/somewhere/index.js") == "fresh"


class TestShadowGuard:
    def test_an_index_ts_is_moved_aside_with_a_loud_warning(
            self, pi_setup, pi_home, good_fetch, plant_shadow, capsys):
        extdir = pi_home.extension_dir()
        shadow = plant_shadow(extdir, body="// a developer's own extension\n")
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        assert not shadow.exists(), "index.ts would have won resolution over index.js"
        moved = extdir / ("index.ts" + pi_setup.DISABLED_SUFFIX)
        assert moved.read_text() == "// a developer's own extension\n"
        out = capsys.readouterr().out
        assert "would shadow" in out.lower()
        assert "index.ts" in out

    def test_index_js_is_written_after_the_move(self, pi_setup, pi_home, good_fetch, plant_shadow):
        extdir = pi_home.extension_dir()
        plant_shadow(extdir)
        pi_setup.install_extension(pi_home.agent_dir)
        assert (extdir / "index.js").read_bytes() == ARTIFACT

    def test_a_second_shadow_does_not_clobber_the_first_disabled_file(
            self, pi_setup, pi_home, good_fetch, plant_shadow):
        """A developer's file is moved, never overwritten and never deleted."""
        extdir = pi_home.extension_dir()
        plant_shadow(extdir, body="// first\n")
        pi_setup.install_extension(pi_home.agent_dir)
        plant_shadow(extdir, body="// second\n")
        pi_setup.install_extension(pi_home.agent_dir)
        first = extdir / ("index.ts" + pi_setup.DISABLED_SUFFIX)
        assert first.read_text() == "// first\n"
        bodies = sorted(p.read_text() for p in extdir.glob("index.ts" + pi_setup.DISABLED_SUFFIX + "*"))
        assert bodies == ["// first\n", "// second\n"]

    def test_a_sibling_package_json_warns_but_does_not_stop_the_install(
            self, pi_setup, pi_home, good_fetch, plant_shadow, capsys):
        extdir = pi_home.extension_dir()
        pkg = plant_shadow(extdir, name="package.json", body='{"type":"module"}')
        assert pi_setup.install_extension(pi_home.agent_dir) == DIGEST
        assert pkg.read_text() == '{"type":"module"}', "a warn-only file is left untouched"
        assert "package.json" in capsys.readouterr().out

    def test_no_shadow_means_no_warning_and_no_stray_file(
            self, pi_setup, pi_home, good_fetch, capsys):
        pi_setup.install_extension(pi_home.agent_dir)
        extdir = pi_home.extension_dir()
        assert list(extdir.glob("*" + pi_setup.DISABLED_SUFFIX)) == []
        # Matched on the warning's wording, not the bare word: pytest's tmp_path carries
        # this test's own name, which contains "shadow", into every path we print.
        assert "would shadow" not in capsys.readouterr().out.lower()

    def test_next_free_name_never_returns_an_existing_path(self, pi_setup, tmp_path):
        first = tmp_path / "index.ts.unbound-disabled"
        assert Path(pi_setup._next_free_name(first)) == first
        first.write_text("a")
        second = Path(pi_setup._next_free_name(first))
        assert second != first and not second.exists()
        second.write_text("b")
        third = Path(pi_setup._next_free_name(first))
        assert third not in (first, second) and not third.exists()


class TestAgentDirIsHonoured:
    def test_an_absolute_env_value_puts_everything_under_it(
            self, pi_setup, pi_home, good_fetch, tmp_path):
        base = tmp_path / "abs" / "pitest"
        assert pi_setup.install_extension(base) == DIGEST
        assert (base / "extensions" / "unbound" / "index.js").read_bytes() == ARTIFACT
        assert not pi_home.extension_dir().joinpath("index.js").exists()

    def test_all_four_env_cases_install_where_the_extension_would_look(
            self, pi_setup, pi_home, good_fetch, agent_dir_cases):
        for case in agent_dir_cases:
            resolved = pi_setup.resolve_agent_dir(pi_home.home, case.env(pi_home.env))
            assert pi_setup.install_extension(resolved) == DIGEST, case.name
            assert (case.expected_base / "extensions" / "unbound" / "index.js").read_bytes() == ARTIFACT
