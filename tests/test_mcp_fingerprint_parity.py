import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.conftest import load_module


HOOKS = [
    load_module('claude-code/hooks/unbound.py'),
    load_module('codex/hooks/unbound.py'),
    load_module('copilot/hooks/unbound.py'),
    load_module('augment/hooks/unbound.py'),
    load_module('cursor/unbound.py'),
]

# Only the hooks whose targeted MCP scan uploads the script body for the backend
# to re-hash; the rest carry the hash alone.
BODY_HOOKS = [h for h in HOOKS if hasattr(h, '_read_script_body_b64')]


class TestMcpFingerprintParity(unittest.TestCase):
    def test_redaction_placeholder_is_not_a_binary_identity(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key('redacted', '***', None, [])
                )

    def test_vscode_provider_identity_does_not_override_launch_details(self):
        additional_data = {
            'providerId': 'eamodio.gitlens/gitlens.gkMcpProvider',
            'providerServerId': 'eamodio.gitlens/GitKraken',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'GitKraken', 'gk', None, ['mcp'], additional_data,
                    ),
                    'bin:gk',
                )

    def test_bare_vscode_provider_is_not_a_fingerprint(self):
        additional_data = {
            'providerId': 'eamodio.gitlens/gitlens.gkMcpProvider',
            'providerServerId': 'eamodio.gitlens/GitKraken',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key(
                        'GitKraken', None, None, [], additional_data,
                    )
                )

    def test_cached_vscode_provider_keeps_launch_identity(self):
        additional_data = {
            'scope': 'vscode-provider-cache',
            'providerId': 'eamodio.gitlens/gitlens.gkMcpProvider',
            'providerServerId': 'eamodio.gitlens/GitKraken',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'GitKraken', 'gk', None, ['mcp'], additional_data,
                    ),
                    'bin:gk',
                )

    def test_http_provider_keeps_url_bound_identity(self):
        additional_data = {
            'providerId': 'publisher.extension/provider',
            'providerServerId': 'publisher.extension/server',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'provider', None, 'https://mcp.example.com/api', [],
                        additional_data,
                    ),
                    'url:mcp.example.com/api',
                )

    def test_smithery_wrapper_uses_run_target(self):
        args = ['-y', '@smithery/cli@latest', 'run', '@vendor/server', '--key', 'secret']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'smithery:vendor/server',
                )

    def test_smithery_supported_package_and_command_forms(self):
        vectors = [
            ('npx', ['-y', 'smithery@latest', 'mcp', 'run', 'vendor/server'], 'smithery:vendor/server'),
            ('npm', ['exec', '--', '@smithery/cli@latest', 'run', 'vendor/server'], 'smithery:vendor/server'),
            ('cmd', ['/c', 'npx.cmd', '-y', '@smithery/cli@latest', 'run', 'vendor/server'], 'smithery:vendor/server'),
            (
                'npx',
                [
                    '-y', '@smithery/cli@latest', 'run', '--config', '{}',
                    '@vendor/server',
                ],
                'smithery:vendor/server',
            ),
            (
                'cmd.exe',
                ['/d', '/c', 'npx', '-y', 'smithery@latest', 'run', 'vendor/server'],
                'smithery:vendor/server',
            ),
        ]
        for hook in HOOKS:
            for command, args, expected in vectors:
                with self.subTest(hook=hook.__file__, command=command, args=args):
                    self.assertEqual(
                        hook.compute_mcp_cache_key('alias', command, None, args),
                        expected,
                    )

    def test_invalid_standalone_smithery_command_fails_closed(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key(
                        'alias', 'smithery', None, ['list', 'vendor/server']
                    )
                )

    def test_smithery_argument_does_not_override_another_launcher(self):
        args = ['@vendor/wrapper', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'npm:@vendor/wrapper',
                )

    def test_smithery_argument_preserves_bare_launcher(self):
        args = ['wrapper-mcp', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'npm:wrapper-mcp',
                )

    def test_smithery_argument_preserves_wrapped_npm_launchers(self):
        vectors = [
            ('bun', ['x', 'wrapper-mcp', '@smithery/cli', 'run', '@vendor/server']),
            ('cmd', ['/d', '/c', 'npx', 'wrapper-mcp', '@smithery/cli', 'run', '@vendor/server']),
        ]
        for hook in HOOKS:
            for command, args in vectors:
                with self.subTest(hook=hook.__file__, command=command):
                    self.assertEqual(
                        hook.compute_mcp_cache_key('alias', command, None, args),
                        'npm:wrapper-mcp',
                    )

    def test_smithery_argument_does_not_turn_bun_script_into_package(self):
        args = ['wrapper-mcp', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key('alias', 'bun', None, args)
                )

    def test_smithery_rejects_execution_changing_inputs(self):
        vectors = [
            ('npx', ['--registry=https://packages.example', '@smithery/cli', 'run', '@vendor/server']),
            ('npx', ['-y', '@smithery/cli@npm:evil', 'run', '@vendor/server']),
            ('npx', ['-y', '@smithery/cli@.', 'run', '@vendor/server']),
            ('npx', ['-y', '@smithery/cli@...', 'run', '@vendor/server']),
            ('npx', ['-y', '@smithery/cli@.hidden', 'run', '@vendor/server']),
            ('npx', ['-y', 'smithery@..', 'mcp', 'run', 'vendor/server']),
            ('npx', ['-y', '@smithery/cli', 'run', '@vendor/server@npm:evil']),
            ('npm', ['exec', '@smithery/cli', 'run', '@vendor/server']),
            ('npx', ['-y', '@smithery/cli', 'run', '@vendor/server', '--package=evil']),
            ('npm', ['exec', '--', '@smithery/cli', 'run', '@vendor/server', '--call=evil']),
            ('cmd', ['/c', 'npx', '@smithery/cli', 'run', '@vendor/server', '&', 'evil']),
            ('npx', ['--workspace', 'decoy', '@smithery/cli', 'run', '@vendor/server']),
            ('bunx', ['--cwd', 'decoy', '@smithery/cli', 'run', '@vendor/server']),
        ]
        for hook in HOOKS:
            for command, args in vectors:
                with self.subTest(hook=hook.__file__, command=command, args=args):
                    self.assertIsNone(
                        hook.compute_mcp_cache_key('alias', command, None, args)
                    )

    def test_unverified_smithery_launchers_fail_closed(self):
        vectors = [
            ('smithery', ['run', '@vendor/server']),
            ('smithery.cmd', ['--verbose', 'run', '@vendor/server']),
            ('bunx', ['--bun', '@smithery/cli@latest', 'run', 'vendor/server']),
            ('bun', ['x', '--bun', '@smithery/cli@latest', 'run', 'vendor/server']),
            ('npx', ['-y', '@smithery/cli', 'run', 'vendor/server']),
            ('./smithery', ['run', '@vendor/server']),
            ('/tmp/evil/smithery', ['run', '@vendor/server']),
            (r'C:\evil\smithery.exe', ['run', '@vendor/server']),
            ('./npx', ['-y', '@smithery/cli@latest', 'run', '@vendor/server']),
        ]
        for hook in HOOKS:
            for command, args in vectors:
                with self.subTest(hook=hook.__file__, command=command):
                    self.assertIsNone(
                        hook.compute_mcp_cache_key('alias', command, None, args)
                    )

    def test_runtime_argument_does_not_claim_smithery_identity(self):
        args = ['-c', 'npx', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key('alias', 'python', None, args)
                )

    def test_nested_npm_runner_does_not_claim_smithery_identity(self):
        for hook in HOOKS:
            for nested_runner in ['npm', 'npx.cmd', 'bun']:
                with self.subTest(hook=hook.__file__, nested_runner=nested_runner):
                    args = [nested_runner, '@smithery/cli', 'run', '@vendor/server']
                    self.assertIsNone(
                        hook.compute_mcp_cache_key('alias', 'npx', None, args)
                    )

    def test_smithery_argument_does_not_erase_non_npm_launcher(self):
        vectors = [
            ('uvx', ['real-package', '@smithery/cli'], 'pypi:real-package'),
            ('docker', ['run', 'vendor/image', '@smithery/cli'], 'docker:vendor/image'),
            ('custom-server', ['@smithery/cli'], 'bin:custom-server'),
        ]
        for hook in HOOKS:
            for command, args, expected in vectors:
                with self.subTest(hook=hook.__file__, command=command):
                    self.assertEqual(
                        hook.compute_mcp_cache_key('alias', command, None, args),
                        expected,
                    )

    def test_nuget_launchers_use_package_identity(self):
        vectors = [
            ('dnx', ['Vendor.Server@1.2.3', 'serve'], None),
            (
                'dnx',
                [
                    '--framework', 'net10.0', '-y', 'Example.Server@2.0.0',
                    '--source', 'https://api.nuget.org/v3/index.json',
                ],
                'nuget:example.server',
            ),
            (
                'dnx',
                ['--configfile', 'Vendor.Config', '-y', 'Example.Server@2.0.0'],
                None,
            ),
            (
                'dotnet',
                ['tool', 'execute', 'Example.Server@2.0.0', '--source',
                 'https://api.nuget.org/v3/index.json'],
                'nuget:example.server',
            ),
            (
                'dotnet',
                ['tool', 'exec', '--source',
                 'https://api.nuget.org/v3/index.json', 'Example.Server@2.0.0'],
                'nuget:example.server',
            ),
            (
                'dotnet',
                ['tool', 'exec', '--version', '2.0.0', '--source',
                 'https://api.nuget.org/v3/index.json', 'Example.Server'],
                'nuget:example.server',
            ),
            (
                'dotnet',
                ['tool', 'exec', '--source',
                 'https://api.nuget.org/v3/index.json', 'Example.Server'],
                'url-arg:api.nuget.org/v3/index.json',
            ),
            (
                '/tmp/dotnet',
                ['tool', 'exec', 'Example.Server@2.0.0', '--source',
                 'https://api.nuget.org/v3/index.json'],
                'url-arg:api.nuget.org/v3/index.json',
            ),
            (
                'dotnet',
                [
                    'dnx', '--arch', 'x64', '--verbosity', 'diag',
                    '--disable-parallel', '--no-cache', '--no-http-cache',
                    '--source', 'https://api.nuget.org/v3/index.json',
                    'Example.Server@2.0.0',
                ],
                'nuget:example.server',
            ),
            (
                'dotnet',
                [
                    'tool', 'exec', 'Example.Server@2.0.0', '--source',
                    'https://api.nuget.org/v3/index.json', '--', '--listen',
                ],
                'nuget:example.server',
            ),
            (
                'dotnet',
                ['tool', 'exec', 'Example.Server@2.0.0'],
                None,
            ),
            (
                'dnx',
                ['Example.Server@2.0.0', '--add-source',
                 'https://api.nuget.org/v3/index.json'],
                'url-arg:api.nuget.org/v3/index.json',
            ),
            (
                'dotnet',
                ['tool', 'exec', 'Example.Server@2.0.0', '--source',
                 'https://packages.example.com/v3/index.json'],
                'url-arg:packages.example.com/v3/index.json',
            ),
            (
                'dotnet',
                ['tool', 'exec', 'Example.Server@2.0.0', '--source', 'private'],
                None,
            ),
        ]
        for hook in HOOKS:
            for command, args, expected in vectors:
                with self.subTest(hook=hook.__file__, command=command):
                    self.assertEqual(
                        hook.compute_mcp_cache_key('alias', command, None, args),
                        expected,
                    )

    def test_attached_nuget_source_cannot_hide_the_real_host(self):
        args = [
            'Example.Server@2.0.0',
            '--source=https://api.nuget.org=@evil.com/v3/index.json',
        ]
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertNotEqual(
                    hook.compute_mcp_cache_key('alias', 'dnx', None, args),
                    'nuget:example.server',
                )

    def test_colon_attached_nuget_source(self):
        args = [
            'tool', 'exec', 'Example.Server@2.0.0',
            '--source:https://api.nuget.org/v3/index.json',
        ]
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'dotnet', None, args),
                    'nuget:example.server',
                )

    def test_nuget_restore_options_after_package_fail_closed(self):
        vectors = [
            '--add-source:https://packages.example/v3/index.json',
            '--configfile:NuGet.Config',
            '--unknown-option',
        ]
        for hook in HOOKS:
            for extra in vectors:
                with self.subTest(hook=hook.__file__, extra=extra):
                    self.assertNotEqual(
                        hook.compute_mcp_cache_key(
                            'alias', 'dotnet', None,
                            [
                                'tool', 'exec', 'Example.Server@2.0.0',
                                '--source',
                                'https://api.nuget.org/v3/index.json',
                                extra,
                            ],
                        ),
                        'nuget:example.server',
                    )


class TestScriptHashParity(unittest.TestCase):
    """Every hook must derive the same `script:<hash>` identity from the same
    local script, and the same non-answer from the same non-script config."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.body = b"console.log('hi')\n"
        self.script = self.dir / 'index.js'
        self.script.write_bytes(self.body)
        self.sha = hashlib.sha256(self.body).hexdigest()

    def tearDown(self):
        self._tmp.cleanup()

    def _hashes(self, command, args, cwd=None):
        return {h.__file__: h._compute_script_hash(command, args, cwd) for h in HOOKS}

    def _assert_all(self, expected, command, args, cwd=None):
        for path, got in self._hashes(command, args, cwd).items():
            self.assertEqual(got, expected, path)

    def test_runtime_with_absolute_script_hashes_the_file(self):
        self._assert_all(self.sha, 'node', [str(self.script)])

    def test_command_is_the_script(self):
        sh = self.dir / 'server.sh'
        sh.write_bytes(self.body)
        self._assert_all(self.sha, str(sh), [])

    def test_relative_script_needs_cwd(self):
        self._assert_all(None, 'node', ['index.js'])
        self._assert_all(self.sha, 'node', ['index.js'], str(self.dir))

    def test_runner_subtoken_is_skipped(self):
        ts = self.dir / 'server.ts'
        ts.write_bytes(self.body)
        self._assert_all(self.sha, 'node', ['--loader', 'tsx', str(ts)])

    def test_non_script_extension_is_never_read(self):
        # Security control: a '/'-only match let a crafted config point a runtime
        # at any readable file. The extension check is what stops it.
        secret = self.dir / 'passwd'
        secret.write_bytes(b'root:x:0:0\n')
        self._assert_all(None, 'python3', [str(secret)])

    def test_unexpanded_env_var_is_not_resolved(self):
        self._assert_all(None, 'node', ['${WORKSPACE}/index.js'], str(self.dir))

    def test_missing_file_and_package_configs_yield_no_hash(self):
        self._assert_all(None, 'node', [str(self.dir / 'absent.js')])
        self._assert_all(None, 'npx', ['-y', 'pg-mcp'])
        self._assert_all(None, 'uvx', ['markitdown-mcp@latest'])

    def test_url_and_package_args_are_not_paths(self):
        for hook in HOOKS:
            for value in ('https://example.com/index.js', '@vendor/server.js',
                          'git+https://example.com/repo.js'):
                with self.subTest(hook=hook.__file__, value=value):
                    self.assertFalse(hook._hook_looks_like_path(value))

    def test_hash_is_capped_at_the_shared_byte_limit(self):
        cap = HOOKS[0]._HOOK_MAX_SCRIPT_BYTES
        for hook in HOOKS:
            self.assertEqual(hook._HOOK_MAX_SCRIPT_BYTES, cap, hook.__file__)
        big = self.dir / 'big.js'
        big.write_bytes(b'a' * (cap + 1024))
        expected = hashlib.sha256(b'a' * cap).hexdigest()
        self._assert_all(expected, 'node', [str(big)])

    def test_script_hash_drives_the_fingerprint(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key('local', 'node', None, [str(self.script)])
                )
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'local', 'node', None, [str(self.script)],
                        script_hash=hook._compute_script_hash('node', [str(self.script)], None),
                    ),
                    'script:%s' % self.sha,
                )

    def test_uploaded_body_re_hashes_to_the_reported_hash(self):
        # The backend recomputes sha256 over the decoded body, so a hook that
        # sends both must send bytes that agree.
        self.assertTrue(BODY_HOOKS)
        big = self.dir / 'big.js'
        big.write_bytes(b'a' * (HOOKS[0]._HOOK_MAX_SCRIPT_BYTES + 1024))
        for hook in BODY_HOOKS:
            for script in (self.script, big):
                with self.subTest(hook=hook.__file__, script=script.name):
                    body = hook._read_script_body_b64('node', [str(script)], None)
                    self.assertEqual(
                        hashlib.sha256(base64.b64decode(body)).hexdigest(),
                        hook._compute_script_hash('node', [str(script)], None),
                    )
