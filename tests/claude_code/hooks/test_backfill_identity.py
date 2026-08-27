"""Backfill carries the device serial and signed-in email with each session.

Without them the server attributes replayed history to whichever application owns
the upload key. Under MDM that is one admin key for the whole device, so every
profile's history would land on the admin instead of the person who ran it.
"""

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from tests.conftest import tool_module

setup = tool_module("claude-code/hooks", "setup")
mdm = tool_module("claude-code/hooks/mdm", "setup")


def _write_claude_json(home, email):
    home.mkdir(parents=True, exist_ok=True)
    payload = {'oauthAccount': {'emailAddress': email}} if email is not None else {}
    (home / '.claude.json').write_text(json.dumps(payload), encoding='utf-8')


class AccountEmailTestCase(unittest.TestCase):
    """Same source of truth as read_account_identity in unbound.py."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'alice'

    def test_reads_the_signed_in_email(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                _write_claude_json(self.home, 'alice@example.com')
                self.assertEqual(mod._backfill_account_email(self.home), 'alice@example.com')

    def test_whitespace_is_trimmed_and_blank_is_none(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                _write_claude_json(self.home, '  alice@example.com  ')
                self.assertEqual(mod._backfill_account_email(self.home), 'alice@example.com')
                _write_claude_json(self.home, '   ')
                self.assertIsNone(mod._backfill_account_email(self.home))

    def test_missing_file_or_key_never_raises(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                missing = Path(self.tmp.name) / 'nobody'
                self.assertIsNone(mod._backfill_account_email(missing))
                _write_claude_json(self.home, None)
                self.assertIsNone(mod._backfill_account_email(self.home))

    def test_malformed_json_never_raises(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                self.home.mkdir(parents=True, exist_ok=True)
                (self.home / '.claude.json').write_text('{not json', encoding='utf-8')
                self.assertIsNone(mod._backfill_account_email(self.home))


class DesktopSessionFallbackTestCase(unittest.TestCase):
    """Team/SSO Claude Desktop never hydrates oauthAccount into ~/.claude.json,
    so without this fallback exactly those users stay unattributed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'alice'

    def _session(self, mod, email, name='s1'):
        base = mod._claude_desktop_support_dirs(self.home)[0]
        path = base / 'local-agent-mode-sessions' / name / 'x' / 'local_1' / '.claude' / '.claude.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'oauthAccount': {'emailAddress': email}}), encoding='utf-8')
        return path

    def test_falls_back_when_claude_json_has_no_oauth_account(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                self.tmp.cleanup(); self.tmp = tempfile.TemporaryDirectory()
                self.home = Path(self.tmp.name) / 'alice'
                _write_claude_json(self.home, None)
                self._session(mod, 'alice@example.com')
                self.assertEqual(mod._backfill_account_email(self.home), 'alice@example.com')

    def test_claude_json_wins_when_both_exist(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                self.tmp.cleanup(); self.tmp = tempfile.TemporaryDirectory()
                self.home = Path(self.tmp.name) / 'alice'
                _write_claude_json(self.home, 'primary@example.com')
                self._session(mod, 'session@example.com')
                self.assertEqual(mod._backfill_account_email(self.home), 'primary@example.com')

    def test_disagreeing_sessions_yield_blank_over_wrong(self):
        # These configs are sandbox-writable, so a disagreement could be a forged
        # one. Blank is safer than attributing a device to the wrong person.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                self.tmp.cleanup(); self.tmp = tempfile.TemporaryDirectory()
                self.home = Path(self.tmp.name) / 'alice'
                _write_claude_json(self.home, None)
                self._session(mod, 'alice@example.com', name='s1')
                self._session(mod, 'mallory@example.com', name='s2')
                self.assertIsNone(mod._backfill_account_email(self.home))

    def test_support_dir_is_keyed_off_the_home_not_the_process(self):
        # The MDM trap again: a process-scoped path would resolve to the admin's
        # for every profile it walks.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                for home in (Path('/tmp/h1'), Path('/tmp/h2')):
                    dirs = mod._claude_desktop_support_dirs(home)
                    self.assertTrue(all(str(d).startswith(str(home)) for d in dirs), dirs)


class AttachIdentityTestCase(unittest.TestCase):
    def test_both_fields_are_stamped_on_every_session(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                sessions = [{'session_id': 'a'}, {'session_id': 'b'}]
                mod._backfill_attach_identity(sessions, 'FCQFM54', 'alice@example.com')
                for s in sessions:
                    self.assertEqual(s['device_serial'], 'FCQFM54')
                    self.assertEqual(s['user_email'], 'alice@example.com')

    def test_absent_halves_are_omitted_not_written_as_none(self):
        # A null would travel to the server and be dropped there anyway; leaving the
        # key out keeps the payload identical to what older agents send.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                sessions = [{'session_id': 'a'}]
                mod._backfill_attach_identity(sessions, None, None)
                self.assertNotIn('device_serial', sessions[0])
                self.assertNotIn('user_email', sessions[0])

    def test_an_empty_session_list_is_a_no_op(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                mod._backfill_attach_identity([], 'FCQFM54', 'alice@example.com')


class MdmPerHomeEmailTestCase(unittest.TestCase):
    """The MDM trap: one email for the whole run would be the same bug again."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_each_home_gets_its_own_email(self):
        homes = {}
        for name, email in (('alice', 'alice@example.com'), ('bob', 'bob@example.com')):
            home = Path(self.tmp.name) / name
            _write_claude_json(home, email)
            homes[name] = home

        collected = []
        for name, home in homes.items():
            sessions = [{'session_id': f'{name}-1'}, {'session_id': f'{name}-2'}]
            mdm._backfill_attach_identity(sessions, 'SHARED-SERIAL', mdm._backfill_account_email(home))
            collected.extend(sessions)

        by_email = {s['user_email'] for s in collected}
        self.assertEqual(by_email, {'alice@example.com', 'bob@example.com'})
        # The serial is a property of the machine, so it is the same for everyone.
        self.assertEqual({s['device_serial'] for s in collected}, {'SHARED-SERIAL'})


if __name__ == '__main__':
    unittest.main()


class NeverFailsTestCase(unittest.TestCase):
    """Backfill must degrade to sending nothing, never to an exception. A failure
    here would take down the whole onboarding run for a nice-to-have field."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_every_hostile_home_returns_none_without_raising(self):
        homes = {
            'missing': Path(self.tmp.name) / 'does-not-exist',
            'empty-dir': Path(self.tmp.name) / 'empty',
            'claude-json-is-a-dir': Path(self.tmp.name) / 'isdir',
            'malformed-json': Path(self.tmp.name) / 'bad',
            'oauth-not-a-dict': Path(self.tmp.name) / 'notdict',
            'email-not-a-string': Path(self.tmp.name) / 'notstr',
            'binary-garbage': Path(self.tmp.name) / 'binary',
        }
        homes['empty-dir'].mkdir(parents=True)
        (homes['claude-json-is-a-dir'] / '.claude.json').mkdir(parents=True)
        homes['malformed-json'].mkdir(parents=True)
        (homes['malformed-json'] / '.claude.json').write_text('{oh no', encoding='utf-8')
        homes['oauth-not-a-dict'].mkdir(parents=True)
        (homes['oauth-not-a-dict'] / '.claude.json').write_text('{"oauthAccount": "nope"}', encoding='utf-8')
        homes['email-not-a-string'].mkdir(parents=True)
        (homes['email-not-a-string'] / '.claude.json').write_text('{"oauthAccount": {"emailAddress": 42}}', encoding='utf-8')
        homes['binary-garbage'].mkdir(parents=True)
        (homes['binary-garbage'] / '.claude.json').write_bytes(b'\x00\xff\xfe binary')

        for mod in (setup, mdm):
            for label, home in homes.items():
                with self.subTest(module=mod.__name__, home=label):
                    self.assertIsNone(mod._backfill_account_email(home))

    def test_windows_lists_both_the_roaming_and_msix_locations(self):
        # MSIX/Store installs never populate %APPDATA%\Claude; verified on a real
        # Windows box where only the LocalCache path existed.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                with patch.object(mod.platform, 'system', return_value='Windows'):
                    dirs = [str(d) for d in mod._claude_desktop_support_dirs(Path('/h'))]
                self.assertEqual(len(dirs), 2)
                self.assertTrue(any('Roaming' in d and 'Packages' not in d for d in dirs), dirs)
                self.assertTrue(any('Claude_pzs8sxrjxfjjc' in d for d in dirs), dirs)
                self.assertTrue(all(d.startswith(str(Path('/h'))) for d in dirs), dirs)

    def test_unsupported_platform_still_returns_a_list(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                with patch.object(mod.platform, 'system', return_value='Plan9'):
                    self.assertIsInstance(mod._claude_desktop_support_dirs(Path('/h')), list)

    def test_attach_is_a_no_op_when_nothing_resolved(self):
        # The end state that matters: no key on the wire, so the server sees the
        # same payload older agents send.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                sessions = [{'session_id': 'a'}]
                mod._backfill_attach_identity(sessions, None, None)
                self.assertEqual(sessions[0], {'session_id': 'a'})


class SliceKeepsIdentityTestCase(unittest.TestCase):
    """An oversized session is re-emitted as fresh dicts. Identity has to survive
    that or long MDM sessions stay attributed to the upload key's owner."""

    def _big_session(self):
        # Two exchanges, each big enough that the pair cannot fit in one chunk.
        entries = []
        for i in range(2):
            entries.append({'type': 'user', 'message': {'role': 'user', 'content': 'x' * 4000}})
            entries.append({'type': 'assistant', 'message': {'role': 'assistant', 'content': 'y' * 4000}})
        return {
            'session_id': 'SESS-BIG',
            'entries': entries,
            'device_serial': 'FCQFM54',
            'user_email': 'alice@example.com',
        }

    def test_every_slice_of_an_oversized_session_keeps_the_identity(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                session = self._big_session()
                slices = list(mod._backfill_slice_session(session, 9000))
                self.assertGreater(len(slices), 1, "expected the session to be split")
                for s in slices:
                    self.assertEqual(s['device_serial'], 'FCQFM54')
                    self.assertEqual(s['user_email'], 'alice@example.com')

    def test_a_session_that_fits_is_passed_through_untouched(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                session = {'session_id': 'S', 'entries': [{'a': 1}],
                           'device_serial': 'FCQFM54', 'user_email': 'alice@example.com'}
                slices = list(mod._backfill_slice_session(session, 10 * 1024 * 1024))
                self.assertEqual(slices, [session])

    def test_a_session_without_identity_gains_no_empty_keys(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                session = {'session_id': 'S', 'entries': [{'a': 1}]}
                for s in mod._backfill_slice_session(session, 10 * 1024 * 1024):
                    self.assertNotIn('device_serial', s)
                    self.assertNotIn('user_email', s)


class ReparsePointTestCase(unittest.TestCase):
    """On Windows _run_as_user cannot fork, so the MDM script globs every profile's
    user-writable AppData while still elevated. A planted junction must not walk it
    out of the profile."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_symlinked_support_dir_is_skipped(self):
        outside = Path(self.tmp.name) / 'outside'
        (outside / 'local-agent-mode-sessions' / 'a' / 'b' / 'local_1' / '.claude').mkdir(parents=True)
        (outside / 'local-agent-mode-sessions' / 'a' / 'b' / 'local_1' / '.claude' / '.claude.json').write_text(
            json.dumps({'oauthAccount': {'emailAddress': 'planted@evil.com'}}), encoding='utf-8')

        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'home-{mod.__name__}'
                base = mod._claude_desktop_support_dirs(home)[0]
                base.parent.mkdir(parents=True, exist_ok=True)
                base.symlink_to(outside, target_is_directory=True)
                self.assertIsNone(mod._desktop_session_email(home))

    def test_a_symlinked_session_file_is_skipped(self):
        planted = Path(self.tmp.name) / 'planted.json'
        planted.write_text(json.dumps({'oauthAccount': {'emailAddress': 'planted@evil.com'}}), encoding='utf-8')

        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'h2-{mod.__name__}'
                leaf = mod._claude_desktop_support_dirs(home)[0] / 'local-agent-mode-sessions' / 'a' / 'b' / 'local_1' / '.claude'
                leaf.mkdir(parents=True)
                (leaf / '.claude.json').symlink_to(planted)
                self.assertIsNone(mod._desktop_session_email(home))

    def test_a_real_file_inside_the_base_is_still_read(self):
        # The guard must not break the normal case.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'h3-{mod.__name__}'
                leaf = mod._claude_desktop_support_dirs(home)[0] / 'local-agent-mode-sessions' / 'a' / 'b' / 'local_1' / '.claude'
                leaf.mkdir(parents=True)
                (leaf / '.claude.json').write_text(
                    json.dumps({'oauthAccount': {'emailAddress': 'real@example.com'}}), encoding='utf-8')
                self.assertEqual(mod._desktop_session_email(home), 'real@example.com')


class PrimaryReadContainmentTestCase(unittest.TestCase):
    """On Windows _run_as_user cannot fork, so this read happens as SYSTEM across
    every profile. A link planted at .claude.json must not pull another user's
    address into this profile's sessions."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_link_pointing_outside_the_home_is_refused(self):
        victim = Path(self.tmp.name) / 'victim'
        victim.mkdir(parents=True)
        (victim / '.claude.json').write_text(
            json.dumps({'oauthAccount': {'emailAddress': 'victim@example.com'}}), encoding='utf-8')

        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                attacker = Path(self.tmp.name) / f'attacker-{mod.__name__}'
                attacker.mkdir(parents=True)
                (attacker / '.claude.json').symlink_to(victim / '.claude.json')
                # No desktop sessions either, so nothing is resolved at all.
                self.assertIsNone(mod._backfill_account_email(attacker))

    def test_a_dotfiles_link_inside_the_same_home_still_resolves(self):
        # Containment rather than blanket refusal: a link into the user's own home
        # is their own config and must keep working.
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'dotfiles-{mod.__name__}'
                (home / 'dotfiles').mkdir(parents=True)
                real = home / 'dotfiles' / 'claude.json'
                real.write_text(
                    json.dumps({'oauthAccount': {'emailAddress': 'owner@example.com'}}), encoding='utf-8')
                (home / '.claude.json').symlink_to(real)
                self.assertEqual(mod._backfill_account_email(home), 'owner@example.com')

    def test_a_plain_file_is_unaffected(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'plain-{mod.__name__}'
                home.mkdir(parents=True)
                (home / '.claude.json').write_text(
                    json.dumps({'oauthAccount': {'emailAddress': 'plain@example.com'}}), encoding='utf-8')
                self.assertEqual(mod._backfill_account_email(home), 'plain@example.com')

    def test_a_dangling_link_does_not_raise(self):
        for mod in (setup, mdm):
            with self.subTest(module=mod.__name__):
                home = Path(self.tmp.name) / f'dangling-{mod.__name__}'
                home.mkdir(parents=True)
                (home / '.claude.json').symlink_to(home / 'nope.json')
                self.assertIsNone(mod._backfill_account_email(home))
