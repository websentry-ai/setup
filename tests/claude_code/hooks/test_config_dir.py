"""Runtime path resolution in unbound.py, checked against what Claude Code does.

Every constant here is a path Claude Code also computes. If the two disagree the
hook reads or writes somewhere Claude never looks, which fails silently — so
these assertions mirror the resolver in the shipped Claude Code bundle.
"""

import importlib.util
import itertools
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO, tool_module

_UNBOUND = REPO / "claude-code" / "hooks" / "unbound.py"
_seq = itertools.count()
hooks_setup = tool_module("claude-code/hooks", "setup")


def _abs(p):
    """The absolute form of a test path. Windows prepends the current drive to a
    root-relative path, which is what the code under test stores, so expectations
    have to go through the same call to compare on either platform."""
    return Path(os.path.abspath(p))


def _reload(**env):
    """Import unbound afresh with `env` applied. Every path resolves at import, so
    each case needs its own module rather than a reload of the shared one."""
    base = {k: v for k, v in os.environ.items()
            if k not in ('CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_PLUGIN_CACHE_DIR')}
    base.update({k: v for k, v in env.items() if v is not None})
    # expanduser reads USERPROFILE on Windows and HOME on POSIX; set both so a
    # fake home takes effect either way.
    if 'HOME' in base:
        base.setdefault('USERPROFILE', base['HOME'])
        base['USERPROFILE'] = base['HOME']
    with patch.dict(os.environ, base, clear=True):
        name = "unbound_cfgdir_%d" % next(_seq)
        spec = importlib.util.spec_from_file_location(name, _UNBOUND)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(name, None)
        return module


class TestConfigDirResolution(unittest.TestCase):
    def test_default_when_env_unset(self):
        m = _reload(HOME='/home/jane')
        self.assertEqual(m._CONFIG_DIR, Path('/home/jane/.claude'))

    def test_relocated_when_env_set(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m._CONFIG_DIR, _abs('/opt/cc'))

    def test_leading_tilde_is_not_expanded(self):
        # Claude Code reads the value verbatim and makes a literal "~" directory.
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='~/cc')
        self.assertNotEqual(m._CONFIG_DIR, Path('/home/jane/cc'))
        self.assertEqual(m._CONFIG_DIR, Path(os.path.abspath('~/cc')))

    def test_blank_env_falls_back_to_home(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='   ')
        self.assertEqual(m._CONFIG_DIR, Path('/home/jane/.claude'))

    def test_empty_env_also_falls_back_to_home(self):
        # Claude Code would use the cwd here; we deliberately do not follow it
        # there, and the installer warns instead. See the note in setup.py main().
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='')
        self.assertEqual(m._CONFIG_DIR, Path('/home/jane/.claude'))

    def test_enforcement_paths_follow_the_relocated_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.AUDIT_LOG, _abs('/opt/cc/hooks/agent-audit.log'))
        self.assertEqual(m.POLICY_CACHE_FILE, _abs('/opt/cc/hooks/.policy_cache.json'))
        self.assertEqual(m.SELF_SCRIPT_PATH, _abs('/opt/cc/hooks/unbound.py'))
        self.assertEqual(m.CLAUDE_SKILLS_ROOT, _abs('/opt/cc/skills'))


class TestClaudeJsonLocation(unittest.TestCase):
    """Claude resolves it as (CLAUDE_CONFIG_DIR or homedir) + '/.claude.json' —
    beside the config dir when relocated, never nested under ~/.claude."""

    def tearDown(self):
        _reload()

    def test_sits_in_home_not_under_dot_claude_by_default(self):
        m = _reload(HOME='/home/jane')
        self.assertEqual(m.CLAUDE_MCP_CONFIG_PATH, Path('/home/jane/.claude.json'))

    def test_moves_into_the_relocated_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.CLAUDE_MCP_CONFIG_PATH, _abs('/opt/cc/.claude.json'))


class TestPluginCacheDir(unittest.TestCase):
    def tearDown(self):
        _reload()

    def test_defaults_under_the_config_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, _abs('/opt/cc/plugins/cache'))

    def test_env_override_wins_over_the_config_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc',
                    CLAUDE_CODE_PLUGIN_CACHE_DIR='/var/pcache')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, _abs('/var/pcache/cache'))

    def test_blank_override_is_ignored(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc',
                    CLAUDE_CODE_PLUGIN_CACHE_DIR='  ')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, _abs('/opt/cc/plugins/cache'))




class TestGatewayHelperRemovedUnderCustomDir(unittest.TestCase):
    """Installing hooks must drop the gateway's apiKeyHelper, including the absolute
    form it writes for a relocated dir — otherwise both drive Claude at once."""

    def test_absolute_helper_setting_is_recognised(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            cc.mkdir(parents=True)
            (cc / "anthropic_key.sh").write_text(hooks_setup.UNBOUND_KEY_HELPER_BODY)
            self.assertTrue(hooks_setup._is_unbound_key_helper_setting(
                str(cc / "anthropic_key.sh"), cc))

    def test_portable_form_is_judged_against_the_default_dir(self):
        # A ~ form left over from a default install names ~/.claude, so the script
        # there decides — not whatever sits in the relocated dir.
        with tempfile.TemporaryDirectory() as home:
            with patch.object(hooks_setup.Path, "home", staticmethod(lambda: Path(home))):
                default = Path(home) / ".claude"
                default.mkdir(parents=True)
                (default / "anthropic_key.sh").write_text("echo $SOMEONE_ELSES_KEY")
                cc = Path(home) / "cc"
                cc.mkdir(parents=True)
                (cc / "anthropic_key.sh").write_text(hooks_setup.UNBOUND_KEY_HELPER_BODY)
                self.assertFalse(
                    hooks_setup._is_unbound_key_helper_setting(
                        hooks_setup.UNBOUND_KEY_HELPER_SETTING, cc),
                    "the relocated dir's helper must not vouch for the default one")

    def test_a_foreign_helper_setting_is_not_ours(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            cc.mkdir(parents=True)
            self.assertFalse(hooks_setup._is_unbound_key_helper_setting(
                str(cc / "somebody_else.sh"), cc))


class TestSkillResolutionFollowsConfigDir(unittest.TestCase):
    """The sync writes managed skills to <config dir>/skills, so resolution has to
    look there — otherwise every Unbound skill silently fails to resolve on a
    relocated install."""

    def test_user_skill_resolves_under_a_relocated_dir(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            skill = cc / "skills" / "unbound-review" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("# review")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertEqual(m._resolve_skill_path("unbound-review", None), str(skill))

    def test_a_stale_copy_in_the_old_home_dir_does_not_win(self):
        """After a move the sync stops refreshing ~/.claude/skills, so anything left
        there is frozen at whatever it last held. Resolution must not prefer it."""
        with tempfile.TemporaryDirectory() as home:
            stale = Path(home) / ".claude" / "skills" / "unbound-review" / "SKILL.md"
            stale.parent.mkdir(parents=True)
            stale.write_text("# stale")
            cc = Path(home) / "cc"
            fresh = cc / "skills" / "unbound-review" / "SKILL.md"
            fresh.parent.mkdir(parents=True)
            fresh.write_text("# fresh")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertEqual(m._resolve_skill_path("unbound-review", None), str(fresh))

    def test_default_dir_resolution_is_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            skill = Path(home) / ".claude" / "skills" / "unbound-review" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("# review")
            m = _reload(HOME=home)
            self.assertEqual(m._resolve_skill_path("unbound-review", None), str(skill))


class TestSyncedSkillResolution(unittest.TestCase):
    """Skills synced from claude.ai live under <config dir>/skills/synced/<bucket>/
    <name>/ — one level deeper than a bundle. Resolution has to reach the bucket,
    or every synced skill run reports no path and can never be tied to a body."""

    def _make_synced(self, cc, name, bucket="org_set", body="# synced"):
        f = cc / "skills" / "synced" / bucket / name / "SKILL.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
        return f

    def test_bare_synced_name_resolves(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            f = self._make_synced(cc, "docx")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertEqual(m._resolve_skill_path("docx", None), str(f))

    def test_set_namespaced_synced_name_resolves(self):
        # A synced skill is often invoked under its set name
        # ("anthropic-skills:docx"). The set maps to the opaque bucket, not a
        # folder, so the bare name has to resolve inside it.
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            f = self._make_synced(cc, "docx")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertEqual(m._resolve_skill_path("anthropic-skills:docx", None), str(f))

    def test_two_buckets_with_the_same_name_resolve_nothing(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            self._make_synced(cc, "docx", bucket="orgA_set1")
            self._make_synced(cc, "docx", bucket="orgB_set2")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertIsNone(m._resolve_skill_path("docx", None))

    def test_a_directly_installed_skill_wins_over_a_synced_one(self):
        # The synced glob is a last-resort fallback: a skill installed directly
        # under skills/<name> must still resolve to itself, not the synced copy.
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            local = cc / "skills" / "docx" / "SKILL.md"
            local.parent.mkdir(parents=True)
            local.write_text("# local")
            self._make_synced(cc, "docx")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))
            self.assertEqual(m._resolve_skill_path("docx", None), str(local))


class TestSyncedSkillReachesInvocationPayload(unittest.TestCase):
    """The real entrypoint. build_llm_exchange — not the resolver in isolation — is
    what ships; it must emit both skill_path and content_hash for a synced Skill
    invocation, or the backend has nothing to join on."""

    def test_synced_invocation_carries_path_and_hash(self):
        with tempfile.TemporaryDirectory() as home:
            cc = Path(home) / "cc"
            skill = cc / "skills" / "synced" / "org_set" / "docx" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("---\nname: docx\n---\n# docx body\n")
            m = _reload(HOME=home, CLAUDE_CONFIG_DIR=str(cc))

            events = [
                {"hook_event_name": "UserPromptSubmit", "prompt": "make a doc", "session_id": "s"},
                {"hook_event_name": "PostToolUse", "tool_name": "Skill",
                 "tool_input": {"skill": "docx"}, "tool_response": {}, "session_id": "s"},
            ]
            exchange = m.build_llm_exchange(events, stop_assistant_message="done")
            uses = [u for msg in (exchange or {}).get("messages", [])
                    if msg.get("role") == "assistant"
                    for u in msg.get("tool_use", [])]
            docx = [u for u in uses if u.get("skill_name") == "docx"]
            self.assertTrue(docx, "synced docx invocation not emitted through build_llm_exchange")
            self.assertEqual(docx[0].get("skill_path"), str(skill))
            self.assertTrue(docx[0].get("content_hash"),
                            "no content_hash emitted for the synced skill")


if __name__ == '__main__':
    unittest.main()
