import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

from tests.conftest import load_module


COPILOT = load_module('copilot/hooks/unbound.py')
HOOKS = [
    load_module('claude-code/hooks/unbound.py'),
    load_module('codex/hooks/unbound.py'),
    COPILOT,
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

    def test_pylance_loopback_has_one_provider_fingerprint(self):
        additional_data = {
            'scope': 'vscode-provider-cache',
            'providerId': 'ms-python.vscode-pylance/pylanceMcp',
            'providerServerId': (
                'ms-python.vscode-pylance/pylance mcp server'
            ),
        }
        expected = (
            'vscode-provider:ms-python.vscode-pylance/pylancemcp:'
            'ms-python.vscode-pylance/pylance mcp server'
        )
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'pylance mcp server',
                        None,
                        'http://localhost:51983/stream',
                        [],
                        additional_data,
                    ),
                    expected,
                )
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'pylance mcp server',
                        None,
                        'http://127.0.0.1:51983/stream',
                        [],
                        additional_data,
                    ),
                    expected,
                )

    def test_provider_identity_is_not_extension_allowlisted(self):
        additional_data = {
            'scope': 'vscode-provider-cache',
            'providerId': 'publisher.extension/provider',
            'providerServerId': 'publisher.extension/server',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'server',
                        None,
                        'http://localhost:51983/stream',
                        [],
                        additional_data,
                    ),
                    'vscode-provider:publisher.extension/provider:'
                    'publisher.extension/server',
                )

    def test_port_above_65535_is_not_a_provider_url(self):
        """urlparse().port raises on these, so they must not reach the rebuild."""
        additional_data = {
            'scope': 'vscode-provider-cache',
            'providerId': 'publisher.extension/provider',
            'providerServerId': 'publisher.extension/server',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'server',
                        None,
                        'http://localhost:99999/mcp',
                        [],
                        additional_data,
                    ),
                    None,
                )

    def test_provider_identity_only_applies_to_loopback_urls(self):
        additional_data = {
            'scope': 'vscode-provider-cache',
            'providerId': 'publisher.extension/provider',
            'providerServerId': 'publisher.extension/server',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'server',
                        None,
                        'https://api.githubcopilot.com/mcp/',
                        [],
                        additional_data,
                    ),
                    'url:api.githubcopilot.com/mcp',
                )
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'server',
                        'prompt_security_mcp',
                        None,
                        ['__args__', 'http://localhost:51983/stream'],
                        additional_data,
                    ),
                    'url:localhost:51983/stream',
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
        self._assert_all(self.sha, 'bun', ['run', str(ts)])

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


class TestMcpScanDispatchCommand(unittest.TestCase):
    """The targeted scan has to launch natively on Windows: a stock box has neither
    bash nor install.sh, which is what `[WinError 2]` on the dispatch was."""

    DOMAIN = 'https://backend.example.com'
    API_KEY = 'secret-api-key'
    SERVER = {'command': 'npx', 'args': ['-y', 'pg-mcp']}
    SYSTEM_ROOT = r'C:\Windows'

    def _dispatch(self, hook, windows):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'unbound.json'
            config.write_text(json.dumps(
                {'api_key': self.API_KEY, 'base_url': self.DOMAIN}))
            with patch.object(hook, 'UNBOUND_CONFIG_PATH', config), \
                    patch.object(hook, 'RUNNING_FROZEN', False), \
                    patch.object(hook, '_is_windows', return_value=windows), \
                    patch.object(hook, '_ensure_discovery_installer', return_value=True), \
                    patch.dict(os.environ, {'SystemRoot': self.SYSTEM_ROOT}), \
                    patch.object(hook.subprocess, 'Popen') as popen:
                hook._dispatch_mcp_server_scan('ctx', dict(self.SERVER))
        self.assertEqual(popen.call_count, 1, hook.__file__)
        return popen.call_args

    def test_windows_scan_runs_the_powershell_installer(self):
        powershell = str(PureWindowsPath(self.SYSTEM_ROOT).joinpath(
            'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'))
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(self._dispatch(hook, windows=True).args[0], [
                    powershell,
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(hook.DISCOVERY_INSTALL_PS1),
                    '-McpScan', '-McpServerName', 'ctx', '-Domain', self.DOMAIN,
                ])

    def test_unix_scan_keeps_its_bash_invocation(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                argv = self._dispatch(hook, windows=False).args[0]
                if hook is COPILOT:
                    self.assertEqual(argv, [
                        'bash', str(hook.DISCOVERY_INSTALL_SH), 'mcp-scan',
                        '--name', 'ctx', '--domain', self.DOMAIN,
                    ])
                    continue
                self.assertEqual(argv[:2], ['bash', '-c'])
                self.assertIn(hook.DISCOVERY_INSTALL_SH.as_posix(), argv[2])
                self.assertIn(hook.DISCOVERY_INSTALL_URL, argv[2])
                self.assertIn(
                    'exec bash "$SH" mcp-scan --name "$UNBOUND_MCP_SERVER_NAME"'
                    ' --domain "$UNBOUND_MCP_DOMAIN"', argv[2])

    def test_neither_path_puts_the_api_key_in_argv(self):
        for hook in HOOKS:
            for windows in (True, False):
                with self.subTest(hook=hook.__file__, windows=windows):
                    call = self._dispatch(hook, windows=windows)
                    self.assertNotIn(self.API_KEY, ' '.join(call.args[0]))
                    self.assertEqual(
                        call.kwargs['env']['UNBOUND_API_KEY'], self.API_KEY)
                    self.assertEqual(
                        json.loads(call.kwargs['env']['UNBOUND_MCP_SERVER_JSON']),
                        self.SERVER)


class TestScriptEntrypointSelection(unittest.TestCase):
    """A crafted MCP config must not be able to name a file the runtime would never
    execute: `python -m package C:\\private\\notes.py` runs a module, not notes.py."""

    def _candidates(self, command, args):
        return {h.__file__: h._hook_candidate_script(command, args)
                for h in HOOKS}

    def _assert_all(self, expected, command, args):
        for path, got in self._candidates(command, args).items():
            self.assertEqual(got, expected, path)

    def test_module_flag_leaves_a_trailing_path_alone(self):
        self._assert_all(None, 'python', ['-m', 'package', r'C:\private\notes.py'])

    def test_inline_code_flags_have_no_entrypoint(self):
        for command, args in (
            ('python3', ['-c', 'import runpy']),
            ('python3', ['-uc', 'import runpy']),      # bundled short options
            ('node', ['-e', 'require("./server.js")']),
            ('node', ['--eval', 'x']),
            ('node', ['-p', './server.js']),
            ('bun', ['--eval', './server.ts']),
            ('deno', ['eval', './server.ts']),
            ('ruby', ['-e', 'load "./server.rb"']),
            ('perl', ['-ne', 'print', './server.py']),  # bundled -n -e
            ('php', ['-r', 'include "x.php";', './server.php']),
            ('rscript', ['-e', 'source("x.sh")']),
        ):
            with self.subTest(command=command, args=args):
                self._assert_all(None, command, args)

    def test_any_flag_before_the_entrypoint_yields_nothing(self):
        # Deliberately conservative: without per-runtime flag tables we cannot tell
        # an entrypoint from a module name or a value a flag consumes, so we read
        # nothing rather than risk reading the wrong file.
        for command, args in (
            ('node', ['-r', './preload.js', 'server.js']),
            ('node', ['--require', './preload.js', 'server.js']),
            ('node', ['--require=./preload.js', 'server.js']),
            ('node', ['--experimental-loader', './loader.mjs', 'server.js']),
            ('node', ['--loader', 'tsx', 'server.ts']),
            ('bun', ['--preload', './preload.js', 'server.js']),
            ('deno', ['run', '--allow-net', 'server.ts']),
            ('python3', ['-X', 'importtime', 'app.py']),
            ('python3', ['-uX', 'importtime', 'app.py']),
            ('ruby', ['-I', './lib', 'main.rb']),
            ('ruby', ['-Ilib', 'main.rb']),
            ('php', ['-f', 'server.php']),
        ):
            with self.subTest(command=command, args=args):
                self._assert_all(None, command, args)

    def test_only_the_first_positional_can_be_the_entrypoint(self):
        self._assert_all('server.js', 'node', ['server.js', './notes.py'])

    def test_runner_subtokens_still_resolve(self):
        self._assert_all('server.ts', 'bun', ['run', 'server.ts'])
        self._assert_all('server.ts', 'deno', ['run', 'server.ts'])
        self._assert_all('server.ts', 'dart', ['run', 'server.ts'])

    def test_run_is_not_skipped_for_other_runtimes(self):
        for runtime in ('node', 'python3', 'ruby'):
            with self.subTest(runtime=runtime):
                self._assert_all(None, runtime, ['run', 'private.py'])

    def test_command_that_is_itself_a_script_still_resolves(self):
        self._assert_all('./server.py', './server.py', [])

    def test_non_string_args_are_not_parsed(self):
        self._assert_all(None, 'node', [{'path': 'server.js'}, 'server.js'])


class TestScriptSymlinkResolution(unittest.TestCase):
    """The extension gate has to hold for the bytes actually read, so a `.py`
    symlink pointing at a secret is rejected rather than followed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.body = b"print('hi')\n"
        for hook in HOOKS:
            if hasattr(hook, '_HOOK_SCRIPT_SNAPSHOT'):
                hook._HOOK_SCRIPT_SNAPSHOT.clear()

    def tearDown(self):
        self._tmp.cleanup()

    def _assert_all(self, expected, command, args, cwd=None):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(hook._compute_script_hash(command, args, cwd), expected)

    def test_script_symlink_to_a_non_script_is_rejected(self):
        secret = self.dir / 'credentials'
        secret.write_bytes(b'aws_secret_access_key = 1\n')
        link = self.dir / 'server.py'
        link.symlink_to(secret)
        self._assert_all(None, 'python3', [str(link)])

    def test_symlink_to_a_real_script_still_resolves(self):
        target = self.dir / 'real.py'
        target.write_bytes(self.body)
        link = self.dir / 'server.py'
        link.symlink_to(target)
        self._assert_all(hashlib.sha256(self.body).hexdigest(), 'python3', [str(link)])

    def test_directory_named_like_a_script_is_not_read(self):
        (self.dir / 'server.py').mkdir()
        self._assert_all(None, 'python3', [str(self.dir / 'server.py')])

    def test_fifo_named_like_a_script_is_not_read(self):
        fifo = self.dir / 'server.sh'
        os.mkfifo(fifo)
        self._assert_all(None, 'bash', [str(fifo)])
        self._assert_all(None, str(fifo), [])


class TestScriptFailureDiagnostics(unittest.TestCase):
    """A script we resolve but cannot use has to leave a breadcrumb; a silent
    `except Exception: return None` is indistinguishable from 'not a local script'."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        for hook in HOOKS:
            if hasattr(hook, '_HOOK_SCRIPT_SNAPSHOT'):
                hook._HOOK_SCRIPT_SNAPSHOT.clear()

    def tearDown(self):
        self._tmp.cleanup()

    def _logged(self, hook, command, args):
        with patch.object(hook, 'log_error') as log_error:
            self.assertIsNone(hook._compute_script_hash(command, args, None))
        self.assertTrue(log_error.called, hook.__file__)
        message, category = log_error.call_args.args[:2]
        self.assertEqual(category, 'mcp_config', hook.__file__)
        return message

    def test_non_script_symlink_target_is_logged(self):
        secret = self.dir / 'credentials'
        secret.write_bytes(b'aws_secret_access_key = 1\n')
        link = self.dir / 'server.py'
        link.symlink_to(secret)
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                message = self._logged(hook, 'python3', [str(link)])
                self.assertIn(str(link), message)
                self.assertNotIn('aws_secret_access_key', message)

    def test_unreadable_script_is_logged(self):
        script = self.dir / 'server.py'
        script.write_bytes(b"print('secret-body')\n")
        script.chmod(0o000)
        try:
            for hook in HOOKS:
                with self.subTest(hook=hook.__file__):
                    message = self._logged(hook, 'python3', [str(script)])
                    self.assertIn(str(script), message)
                    self.assertIn('PermissionError', message)
                    self.assertNotIn('secret-body', message)
        finally:
            script.chmod(0o600)
