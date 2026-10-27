"""The link guards across many shapes of history: which reparse tags count as links, generated trees of
folders, links and junctions, loops, the refusal of a linked profile, and the callers that already used the
check before the backfill did.

Junctions can't be created off Windows. A junction is simulated by reporting a reparse tag from os.lstat for
chosen paths, which is what the uploader reads on Python 3.11. A junction that loops back is a real symlink
that os.path.islink and Path.is_symlink are told is not one, as Windows reports for a junction, so os.walk
would follow it.
"""

import io
import json
import os
import pathlib
import random
import shutil
import stat
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.conftest import tool_module

mdm = tool_module("claude-code/hooks/mdm", "setup")
setup = tool_module("claude-code/hooks", "setup")
uploaders = (mdm, setup)

LINK_TAGS = (0xA0000003, 0xA000000C, 0xA000001D)  # junction, symlink, WSL link
NOT_LINK_TAGS = (0x9000701A, 0x8000001B, 0x80000013, 0)  # OneDrive placeholder, AppExecLink, dedup, none
SEEDS = range(200)


def _reparse(tags, dir_mode=None):
    """os.lstat reports tags[path] as that path's reparse tag. dir_mode(path) marks loop junctions, which also
    read as plain folders, at any depth the walk reaches them."""
    real_lstat, tags = os.lstat, {str(p): t for p, t in tags.items()}

    def lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        key = os.fspath(path)
        if dir_mode is not None and dir_mode(key):
            return mock.Mock(wraps=result, st_reparse_tag=dir_mode.tag, st_mode=stat.S_IFDIR | 0o755)
        if key in tags:
            return mock.Mock(wraps=result, st_reparse_tag=tags[key], st_mode=result.st_mode)
        return result
    return mock.patch("os.lstat", side_effect=lstat)


def _identity(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _as_windows_junction(stack, link: Path, tag=LINK_TAGS[0]):
    """A real symlink that reads as a junction does on Windows: not a link to islink, but carrying a reparse
    tag. It is recognised wherever the walk meets it again, as each pass round a loop is a new path."""
    real_islink, real_is_symlink = os.path.islink, pathlib.Path.is_symlink
    # By the parent folder's identity, not realpath, which consults the patched islink.
    parent = _identity(link.parent)

    def marked(path):
        path = os.fspath(path)
        return os.path.basename(path) == link.name and _identity(os.path.dirname(path)) == parent
    marked.tag = tag
    stack.enter_context(mock.patch("os.path.islink", side_effect=lambda p: False if marked(p) else real_islink(p)))
    stack.enter_context(mock.patch.object(pathlib.Path, "is_symlink", autospec=True, side_effect=lambda self: (
        False if marked(self) else real_is_symlink(self))))
    stack.enter_context(_reparse({}, dir_mode=marked))


class _Tree:
    """A seeded random history tree, and the transcripts each walk must find in it, worked out from the spec."""

    def __init__(self, seed: int, base: Path):
        self.rng, self.n = random.Random(seed), 0
        self.root, self.outside = base / "projects", base / "outside"
        self.root.mkdir(parents=True)
        self.outside.mkdir()
        self.tags, self.walked, self.transcripts = {}, set(), set()
        self._grow(self.root, 1, linked=False, in_subagents=False)

    def _name(self, prefix="n"):
        self.n += 1
        return f"{prefix}{self.n}"

    def _outside_target(self):
        target = self.outside / self._name("t")
        target.mkdir()
        (target / "elsewhere.jsonl").write_text("{}\n")
        return target

    def _grow(self, folder: Path, depth: int, linked: bool, in_subagents: bool):
        kinds = ["jsonl", "jsonl", "other", "hidden", "symlink_file", "junction_file"]
        if depth < 4:
            kinds += ["dir", "dir", "hidden_dir", "subagents", "symlink_dir", "junction", "placeholder_dir"]
        for _ in range(self.rng.randint(1, 4)):
            self._node(self.rng.choice(kinds), folder, depth, linked, in_subagents)

    def _transcript(self, path: Path, linked: bool, in_subagents: bool):
        path.write_text(json.dumps({"sessionId": path.stem}) + "\n")
        if not linked:
            self.walked.add(path)
            if not in_subagents and not path.name.startswith("."):
                self.transcripts.add(path)

    def _node(self, kind, folder, depth, linked, in_subagents):
        if kind in ("jsonl", "hidden"):
            self._transcript(folder / (self._name("." if kind == "hidden" else "n") + ".jsonl"), linked, in_subagents)
        elif kind == "other":
            (folder / (self._name() + ".txt")).write_text("{}\n")
        elif kind == "junction_file":
            path = folder / (self._name() + ".jsonl")
            path.write_text("{}\n")
            self.tags[path] = self.rng.choice(LINK_TAGS)
        elif kind == "symlink_file":
            (folder / (self._name() + ".jsonl")).symlink_to(self._outside_target() / "elsewhere.jsonl")
        elif kind == "symlink_dir":
            (folder / self._name()).symlink_to(self._outside_target(), target_is_directory=True)
        else:
            self._folder(kind, folder, depth, linked, in_subagents)

    def _folder(self, kind, folder, depth, linked, in_subagents):
        name = {"subagents": "subagents", "hidden_dir": self._name(".d")}.get(kind) or self._name()
        child = folder / name
        if child.exists():
            child = folder / self._name()
        child.mkdir()
        if kind == "junction":
            self.tags[child] = self.rng.choice(LINK_TAGS)
            linked = True
        elif kind == "placeholder_dir":
            # A reparse point that is not a link (OneDrive, dedup): still walked.
            self.tags[child] = self.rng.choice(NOT_LINK_TAGS[:-1])
        self._grow(child, depth + 1, linked, in_subagents or child.name == "subagents")


class LinkTagsTestCase(unittest.TestCase):
    """A1: which paths _is_reparse_point calls a link."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        (self.base / "dir").mkdir()
        (self.base / "file.jsonl").write_text("{}\n")

    def test_redirecting_tags_are_links_and_other_reparse_points_are_not(self):
        for up in uploaders:
            for tag in LINK_TAGS + NOT_LINK_TAGS:
                for path in (self.base / "dir", self.base / "file.jsonl"):
                    with self.subTest(up.__name__, tag=hex(tag), path=path.name), _reparse({path: tag}):
                        self.assertIs(up._is_reparse_point(path), tag in LINK_TAGS)

    def test_a_missing_path_is_not_a_link(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertFalse(up._is_reparse_point(self.base / "missing.json"))
                self.assertFalse(up._is_reparse_point(self.base / "missing" / "deeper.json"))

    def test_a_path_that_cannot_be_inspected_is_suspect(self):
        target, real_lstat = str(self.base / "dir"), os.lstat

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == target:
                raise PermissionError(13, "Access is denied", target)
            return real_lstat(path, *args, **kwargs)
        for up in uploaders:
            with self.subTest(up.__name__), mock.patch("os.lstat", side_effect=lstat):
                self.assertTrue(up._is_reparse_point(self.base / "dir"))

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a non-root POSIX user")
    def test_a_path_in_a_folder_the_user_cannot_enter_is_suspect(self):
        locked = self.base / "locked"
        (locked / "inner").mkdir(parents=True)
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertTrue(up._is_reparse_point(locked / "inner"))

    def test_real_symlinks_are_links_and_plain_paths_are_not(self):
        (self.base / "dir-link").symlink_to(self.base / "dir", target_is_directory=True)
        (self.base / "file-link.jsonl").symlink_to(self.base / "file.jsonl")
        (self.base / "dangling").symlink_to(self.base / "gone")
        for up in uploaders:
            with self.subTest(up.__name__):
                for name, linked in (("dir-link", True), ("file-link.jsonl", True), ("dangling", True),
                                     ("dir", False), ("file.jsonl", False)):
                    self.assertIs(up._is_reparse_point(self.base / name), linked, name)


class GeneratedTreesTestCase(unittest.TestCase):
    """A2: over 200 seeded trees, a walk finds exactly the transcripts the spec says, each once."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.trees = [_Tree(seed, Path(cls._tmp.name) / str(seed)) for seed in SEEDS]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_trees_cover_every_kind_of_node(self):
        # Guards the generator: a seed range that never made a junction would make the walks vacuous.
        self.assertTrue(any(t.tags.get(p) in LINK_TAGS for t in self.trees for p in t.tags))
        self.assertTrue(any(t.tags.get(p) in NOT_LINK_TAGS for t in self.trees for p in t.tags))
        self.assertTrue(any(t.walked - t.transcripts for t in self.trees))
        self.assertGreater(sum(len(t.transcripts) for t in self.trees), 200)

    def test_the_jsonl_walk_yields_every_unlinked_transcript_once(self):
        for up in uploaders:
            for seed, tree in zip(SEEDS, self.trees):
                with self.subTest(up.__name__, seed=seed), _reparse(tree.tags):
                    walked = list(up._backfill_jsonl_files(tree.root))
                    self.assertEqual(len(walked), len(set(walked)))
                    self.assertEqual(set(walked), tree.walked)

    def test_the_transcript_walk_also_leaves_out_hidden_files_and_subagents(self):
        for up in uploaders:
            for seed, tree in zip(SEEDS, self.trees):
                with self.subTest(up.__name__, seed=seed), _reparse(tree.tags):
                    walked = list(up._backfill_iter_transcripts(tree.root, 0))
                    self.assertEqual(len(walked), len(set(walked)))
                    self.assertEqual(set(walked), tree.transcripts)


class LinkedProfileRootTestCase(unittest.TestCase):
    """A3: the MDM uploader refuses a profile whose .claude, projects or hooks folder is linked, on Windows only."""

    def test_only_windows_refuses_a_linked_profile_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            claude = home / ".claude"
            folders = (claude, claude / "projects", claude / "hooks")
            for folder in folders:
                folder.mkdir(exist_ok=True)
            for linked in folders + (None,):
                for system in ("Windows", "Darwin", "Linux"):
                    tags = {linked: LINK_TAGS[0]} if linked else {}
                    with self.subTest(getattr(linked, "name", "none"), system=system), _reparse(tags), \
                            mock.patch.object(mdm.platform, "system", return_value=system):
                        self.assertIs(mdm._backfill_root_is_linked(*folders), bool(linked) and system == "Windows")


class LinkLoopTestCase(unittest.TestCase):
    """D3: a link back to an ancestor ends the walk instead of looping, and nothing is read through it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "projects"
        inner = self.root / "a" / "b"
        inner.mkdir(parents=True)
        (self.root / "top.jsonl").write_text("{}\n")
        (inner / "deep.jsonl").write_text("{}\n")
        self.real = {self.root / "top.jsonl", inner / "deep.jsonl"}
        self.loop = inner / "loop"
        self.loop.symlink_to(self.root, target_is_directory=True)

    def test_a_symlink_to_an_ancestor_is_not_followed(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertEqual(sorted(up._backfill_iter_transcripts(self.root, 0)), sorted(self.real))
                self.assertEqual(sorted(up._backfill_jsonl_files(self.root)), sorted(self.real))

    def test_a_junction_to_an_ancestor_is_not_followed(self):
        for up in uploaders:
            with self.subTest(up.__name__), ExitStack() as stack:
                _as_windows_junction(stack, self.loop)
                self.assertEqual(sorted(up._backfill_iter_transcripts(self.root, 0)), sorted(self.real))
                self.assertEqual(sorted(up._backfill_jsonl_files(self.root)), sorted(self.real))

    def test_without_its_reparse_tag_the_simulated_junction_is_a_real_loop(self):
        # Proves the simulation: with nothing to recognise it by, os.walk follows it round until the OS stops it.
        with ExitStack() as stack:
            _as_windows_junction(stack, self.loop, tag=0)
            walked = list(os.walk(self.root))
        self.assertGreater(len(walked), 10)


class CallersOutsideTheBackfillTestCase(unittest.TestCase):
    """E2: the settings writers and the email readers that used _is_reparse_point first behave as on staging
    for plain, missing and linked paths."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.managed = self.base / "ClaudeCode"
        self.home = self.base / "home"
        self.home.mkdir()

    def _install(self):
        def download(url, dest):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("# hook\n")
            return True
        with mock.patch.object(mdm, "get_managed_settings_dir", return_value=self.managed), \
                mock.patch.object(mdm, "download_file", side_effect=download), \
                mock.patch.object(mdm, "_freeze_ownership_evidence"), \
                mock.patch.dict(mdm._OWNERSHIP_EVIDENCE, {}, clear=True), \
                redirect_stdout(io.StringIO()):
            return mdm.setup_managed_hooks()

    def _settings(self):
        return self.managed / "managed-settings.json"

    def test_install_writes_a_missing_or_plain_settings_file(self):
        self.assertTrue(self._install())
        self.assertIn("hooks", json.loads(self._settings().read_text()))
        self._settings().write_text(json.dumps({"forceLoginOrgUUID": "org"}))
        self.assertTrue(self._install())
        written = json.loads(self._settings().read_text())
        self.assertEqual((written["forceLoginOrgUUID"], "hooks" in written), ("org", True))

    def test_install_refuses_a_linked_settings_file(self):
        self.managed.mkdir()
        target = self.base / "org.json"
        target.write_text('{"forceLoginOrgUUID": "org"}')
        self._settings().symlink_to(target)
        self.assertFalse(self._install())
        self.assertTrue(self._settings().is_symlink())
        self.assertEqual(target.read_text(), '{"forceLoginOrgUUID": "org"}')

    def test_strip_leaves_a_missing_file_alone_and_refuses_a_link(self):
        self.managed.mkdir()
        script = self.managed / "hooks" / "unbound.py"
        self.assertEqual(mdm._strip_unbound_hooks_from_settings(self.managed, script), (False, False))
        target = self.base / "org.json"
        target.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": f'"{script}"'}]}]}}))
        self._settings().symlink_to(target)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(mdm._strip_unbound_hooks_from_settings(self.managed, script), (False, True))

    def _account(self, path: Path, email: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"oauthAccount": {"emailAddress": email}}))

    def _email(self, up, home):
        with mock.patch.object(up.platform, "system", return_value="Darwin"):
            return up._backfill_account_email(home)

    def test_account_email_reads_plain_and_contained_links_but_not_escaping_ones(self):
        for up in uploaders:
            with self.subTest(up.__name__):
                account = self.home / ".claude.json"
                self.assertIsNone(self._email(up, self.home))
                self._account(account, "plain@example.com")
                self.assertEqual(self._email(up, self.home), "plain@example.com")
                account.unlink()
                self._account(self.home / "dotfiles" / "claude.json", "inside@example.com")
                account.symlink_to(self.home / "dotfiles" / "claude.json")
                self.assertEqual(self._email(up, self.home), "inside@example.com")
                account.unlink()
                self._account(self.base / "other" / ".claude.json", "other@example.com")
                account.symlink_to(self.base / "other" / ".claude.json")
                self.assertIsNone(self._email(up, self.home))
                account.unlink()
                # A home that is a file: every path under it fails with ENOTDIR.
                not_a_folder = self.base / "not-a-folder"
                not_a_folder.write_text("x")
                self.assertIsNone(self._email(up, not_a_folder))

    def _session(self, base: Path, n: int, email: str) -> Path:
        path = base / "local-agent-mode-sessions" / "o" / f"s{n}" / f"local_{n}" / ".claude" / ".claude.json"
        self._account(path, email)
        return path

    def _desktop_email(self, up):
        with mock.patch.object(up.platform, "system", return_value="Darwin"):
            return up._desktop_session_email(self.home)

    def test_desktop_email_skips_linked_bases_and_sessions(self):
        base = self.home / "Library" / "Application Support" / "Claude"
        for up in uploaders:
            with self.subTest(up.__name__):
                self.assertIsNone(self._desktop_email(up))
                self._session(base, 1, "desk@example.com")
                self.assertEqual(self._desktop_email(up), "desk@example.com")
                # A linked session file, then a linked session folder, each naming another account.
                foreign = self._session(self.base / "foreign", 2, "foreign@example.com")
                link = base / "local-agent-mode-sessions" / "o" / "s3" / "local_3" / ".claude" / ".claude.json"
                link.parent.mkdir(parents=True)
                link.symlink_to(foreign)
                self.assertEqual(self._desktop_email(up), "desk@example.com")
                (base / "local-agent-mode-sessions" / "o" / "s4").symlink_to(
                    foreign.parents[2], target_is_directory=True)
                self.assertEqual(self._desktop_email(up), "desk@example.com")
                moved = self.base / "moved-claude"
                shutil.move(str(base), str(moved))
                base.symlink_to(moved, target_is_directory=True)
                self.assertIsNone(self._desktop_email(up))
                base.unlink()
                shutil.rmtree(moved)


def _fake_http(bodies):
    def http(url, method, headers, body=None, timeout=30):
        if url.endswith("/upload-url/"):
            return 200, json.dumps({"upload_url": "https://s3/put", "object_key": "k"}).encode()
        if method == "PUT":
            bodies.append(json.loads(body.decode("utf-8")))
        return 200, b"{}"
    return http


class UnlinkedProfileProgressTestCase(unittest.TestCase):
    """C3: a profile with ordinary folders still saves its progress, resumes after a capped batch and writes its
    cutoff, byte for byte as before the link guards, on Windows as elsewhere."""

    NOW = 1_900_000_000.0

    def _home(self, base: Path) -> Path:
        projects = base / "home" / ".claude" / "projects" / "p"
        projects.mkdir(parents=True)
        for i in range(5):
            path = projects / f"f{i}.jsonl"
            path.write_text(json.dumps({"type": "user", "sessionId": f"s{i}"}) + "\n")
            os.utime(path, (self.NOW - 5000 + i * 100,) * 2)
        return base / "home"

    def _run(self, home: Path, system: str):
        bodies = []
        with mock.patch.object(mdm, "_backfill_http_request", side_effect=_fake_http(bodies)), \
                mock.patch.object(mdm, "_backfill_force_config", return_value=(None, None)), \
                mock.patch.object(mdm, "_backfill_account_email", return_value=None), \
                mock.patch.object(mdm, "get_device_identifier", return_value="SERIAL"), \
                mock.patch.object(mdm, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)), \
                mock.patch.object(mdm._BackfillRun, "has_time_for_a_batch", return_value=True), \
                mock.patch.object(mdm, "BACKFILL_MAX_SESSIONS_PER_RUN", 2), \
                mock.patch.object(mdm, "BACKFILL_MAX_BATCHES_PER_HOME", 1), \
                mock.patch.object(mdm.platform, "system", return_value=system), \
                mock.patch("time.time", return_value=self.NOW), \
                redirect_stdout(io.StringIO()):
            mdm.run_backfill("key", "https://backend", [("alice", home)])
        state = (home / ".claude" / "hooks" / mdm.BACKFILL_STATE_FILE).read_text()
        return [s["session_id"] for b in bodies for s in b["sessions"]], state

    def _progress(self, home: Path, i: int) -> str:
        path = home / ".claude" / "projects" / "p" / f"f{i}.jsonl"
        return json.dumps({"cursor": self.NOW - 5000 + i * 100, "cursor_path": str(path),
                           "force_epoch": None, "completed_at": None})

    def test_progress_resume_and_cutoff_are_unchanged(self):
        for system in ("Windows", "Darwin", "Linux"):
            with self.subTest(system), tempfile.TemporaryDirectory() as tmp:
                home = self._home(Path(tmp))
                runs = [self._run(home, system) for _ in range(4)]
                self.assertEqual(runs, [
                    (["s0", "s1"], self._progress(home, 1)),
                    (["s2", "s3"], self._progress(home, 3)),
                    (["s4"], str(self.NOW)),
                    ([], str(self.NOW)),
                ])


if __name__ == "__main__":
    unittest.main()
