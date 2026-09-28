"""The artifact is only written when its bytes match the committed sidecar.

Three ways verification can fail -- a digest that disagrees, a sidecar that never
arrived, and a sidecar that is not a digest -- and all three must be a refusal, not a
soft pass. A corrupt or truncated download that becomes an installed extension is worse
than no install: pi would load it and the installer would report success.
"""

import hashlib

import pytest

ARTIFACT = b"// GENERATED FILE - DO NOT EDIT\nexport default {};\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@pytest.fixture
def urls(pi_setup):
    return pi_setup.ARTIFACT_URL, pi_setup.SHA_URL


class TestArtifactSha256:
    def test_it_is_the_sha256_of_the_bytes_on_disk(self, pi_setup, tmp_path):
        target = tmp_path / "index.js"
        target.write_bytes(ARTIFACT)
        assert pi_setup.artifact_sha256(target) == DIGEST

    def test_a_missing_or_unreadable_file_is_none_not_a_raise(self, pi_setup, tmp_path):
        """A digest is never worth a traceback; the caller turns None into a refusal."""
        assert pi_setup.artifact_sha256(tmp_path / "gone.js") is None
        assert pi_setup.artifact_sha256(None) is None

    def test_it_is_lowercase_hex_of_length_64(self, pi_setup, tmp_path):
        """The backend drops hook_hash unless it is exactly 64 lowercase hex chars."""
        target = tmp_path / "index.js"
        target.write_bytes(ARTIFACT)
        digest = pi_setup.artifact_sha256(target)
        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)

    def test_the_helper_is_not_named_hook_script_hash(self, pi_setup):
        """tests/test_setup_contract.py asserts exactly 10 installers define that name,
        and pi ships no unbound.py hook script to hash. Do not "fix" this name."""
        assert not hasattr(pi_setup, "hook_script_hash")
        assert callable(pi_setup.artifact_sha256)


class TestParseSidecar:
    def test_a_bare_digest_line(self, pi_setup):
        assert pi_setup.parse_sha256_sidecar(DIGEST + "\n") == DIGEST

    def test_the_shasum_two_field_form(self, pi_setup):
        """`shasum -a 256 pi/index.js` emits "<digest>  pi/index.js"."""
        assert pi_setup.parse_sha256_sidecar(f"{DIGEST}  pi/index.js\n") == DIGEST

    def test_an_uppercase_digest_is_normalized(self, pi_setup):
        assert pi_setup.parse_sha256_sidecar(DIGEST.upper()) == DIGEST

    @pytest.mark.parametrize("text", [
        "", "   \n", "not a digest\n", "z" * 64, DIGEST[:63], DIGEST + "ab",
        "  pi/index.js\n", None,
    ])
    def test_anything_that_is_not_a_digest_is_none(self, pi_setup, text):
        assert pi_setup.parse_sha256_sidecar(text) is None


class TestVerifyArtifact:
    def test_matching_bytes_verify(self, pi_setup, tmp_path):
        target = tmp_path / "index.js"
        target.write_bytes(ARTIFACT)
        ok, computed, expected = pi_setup.verify_artifact(target, DIGEST + "  pi/index.js\n")
        assert ok is True
        assert computed == expected == DIGEST

    def test_disagreeing_bytes_do_not_verify_and_both_digests_come_back(self, pi_setup, tmp_path):
        target = tmp_path / "index.js"
        target.write_bytes(ARTIFACT + b"// truncated differently\n")
        other = "a" * 64
        ok, computed, expected = pi_setup.verify_artifact(target, other)
        assert ok is False
        assert expected == other
        assert computed not in (None, other)

    def test_a_malformed_sidecar_does_not_verify(self, pi_setup, tmp_path):
        target = tmp_path / "index.js"
        target.write_bytes(ARTIFACT)
        ok, computed, expected = pi_setup.verify_artifact(target, "not a digest")
        assert ok is False
        assert expected is None
        assert computed == DIGEST


class TestInstallRefuses:
    """Every refusal leaves <extdir>/index.js absent -- nothing half-written."""

    def _run(self, pi_setup, pi_home, fake_fetch, mapping):
        fetch = fake_fetch(mapping, module=pi_setup)
        digest = pi_setup.install_extension(pi_home.agent_dir)
        return digest, fetch

    def test_a_digest_mismatch_refuses_and_names_both_digests(
            self, pi_setup, pi_home, fake_fetch, urls, capsys):
        artifact_url, sha_url = urls
        wrong = "b" * 64
        digest, _ = self._run(pi_setup, pi_home, fake_fetch,
                              {artifact_url: ARTIFACT, sha_url: wrong + "  pi/index.js\n"})
        assert digest is None
        assert not pi_setup.artifact_path(pi_home.agent_dir).exists()
        out = capsys.readouterr().out
        assert artifact_url in out
        assert wrong[:16] in out
        assert DIGEST[:16] in out

    def test_a_missing_sidecar_refuses_rather_than_soft_passing(
            self, pi_setup, pi_home, fake_fetch, urls, capsys):
        """The artifact and its sidecar are committed together; the sidecar not being
        there means the ref is inconsistent, which is exactly when not to install."""
        artifact_url, sha_url = urls
        digest, fetch = self._run(pi_setup, pi_home, fake_fetch, {artifact_url: ARTIFACT})
        assert digest is None
        assert not pi_setup.artifact_path(pi_home.agent_dir).exists()
        assert sha_url in fetch.calls
        out = capsys.readouterr().out
        assert sha_url in out
        assert "sidecar" in out.lower()

    def test_a_missing_artifact_refuses(self, pi_setup, pi_home, fake_fetch, urls, capsys):
        artifact_url, sha_url = urls
        digest, _ = self._run(pi_setup, pi_home, fake_fetch, {sha_url: DIGEST})
        assert digest is None
        assert not pi_setup.artifact_path(pi_home.agent_dir).exists()
        assert artifact_url in capsys.readouterr().out

    @pytest.mark.parametrize("body", ["", "   \n", "deadbeef\n", "zz" * 32 + "\n",
                                      f"{DIGEST}  some-other-file.js\n"])
    def test_a_malformed_sidecar_refuses(self, pi_setup, pi_home, fake_fetch, urls, capsys, body):
        artifact_url, sha_url = urls
        digest, _ = self._run(pi_setup, pi_home, fake_fetch,
                              {artifact_url: ARTIFACT, sha_url: body})
        assert digest is None
        assert not pi_setup.artifact_path(pi_home.agent_dir).exists()
        out = capsys.readouterr().out
        # A malformed sidecar says so, rather than printing "expected None" and reading
        # like a digest mismatch.
        assert "not a sha256 sidecar" in out
        assert "expects None" not in out

    def test_a_refusal_leaves_an_earlier_good_install_in_place(
            self, pi_setup, pi_home, fake_fetch, urls):
        """Re-running against a broken ref must not take a working extension away."""
        artifact_url, sha_url = urls
        extdir = pi_home.extension_dir()
        extdir.mkdir(parents=True)
        existing = extdir / "index.js"
        existing.write_bytes(b"// yesterday's good build\n")
        self._run(pi_setup, pi_home, fake_fetch,
                  {artifact_url: ARTIFACT, sha_url: "c" * 64})
        assert existing.read_bytes() == b"// yesterday's good build\n"

    def test_a_refusal_writes_no_sidecar_either(self, pi_setup, pi_home, fake_fetch, urls):
        artifact_url, sha_url = urls
        self._run(pi_setup, pi_home, fake_fetch, {artifact_url: ARTIFACT, sha_url: "c" * 64})
        assert not pi_setup.sidecar_path(pi_home.agent_dir).exists()


class TestFetchShape:
    def test_both_urls_come_from_the_same_ref_as_this_installer(self, pi_setup):
        assert pi_setup.SHA_URL == pi_setup.ARTIFACT_URL + ".sha256"
        assert "refs/heads/main/pi/index.js" in pi_setup.ARTIFACT_URL
        assert pi_setup.ARTIFACT_URL.startswith("https://raw.githubusercontent.com/websentry-ai/setup/")

    def test_there_is_no_env_override_for_the_artifact_url(self, pi_setup):
        """An env-settable artifact URL would be a redirect primitive for anyone who can
        set a variable in the user's shell. Tests monkeypatch download_file instead."""
        src = (pi_setup.__file__ and open(pi_setup.__file__, encoding="utf-8").read()) or ""
        for needle in ("UNBOUND_PI_ARTIFACT_URL", "PI_ARTIFACT_URL", "--artifact-url"):
            assert needle not in src, needle

    def test_it_fetches_both_urls(self, pi_setup, pi_home, fake_fetch, urls):
        artifact_url, sha_url = urls
        fetch = fake_fetch({artifact_url: ARTIFACT, sha_url: DIGEST}, module=pi_setup)
        pi_setup.install_extension(pi_home.agent_dir)
        assert artifact_url in fetch.calls
        assert sha_url in fetch.calls

    def test_download_file_returns_false_rather_than_raising(self, pi_setup, tmp_path, monkeypatch):
        def boom(*a, **k):
            raise FileNotFoundError("curl")

        monkeypatch.setattr(pi_setup.subprocess, "run", boom)
        assert pi_setup.download_file("https://example.invalid/x", tmp_path / "x") is False
