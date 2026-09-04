import unittest

from tests.conftest import load_module


HOOKS = [
    load_module('claude-code/hooks/unbound.py'),
    load_module('codex/hooks/unbound.py'),
    load_module('copilot/hooks/unbound.py'),
    load_module('augment/hooks/unbound.py'),
    load_module('cursor/unbound.py'),
]


class TestMcpFingerprintParity(unittest.TestCase):
    def test_vscode_provider_identity_wins_over_launch_details(self):
        additional_data = {
            'providerId': 'eamodio.gitlens/gitlens.gkMcpProvider',
            'providerServerId': 'eamodio.gitlens/GitKraken',
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key(
                        'GitKraken', 'node', None, ['extension.js'], additional_data,
                    ),
                    'vscode-provider:eamodio.gitlens/gitlens.gkmcpprovider:'
                    'eamodio.gitlens/gitkraken',
                )

    def test_vscode_provider_identity_respects_fingerprint_column_limit(self):
        provider_id = f"{'a' * 128}/{'b' * 128}"
        additional_data = {
            'providerId': provider_id,
            'providerServerId': provider_id,
        }
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertIsNone(
                    hook.compute_mcp_cache_key(
                        'provider', 'node', None, [], additional_data,
                    )
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
                    'smithery:@vendor/server',
                )

    def test_smithery_argument_does_not_override_another_launcher(self):
        args = ['@vendor/wrapper', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'npm:@vendor/wrapper',
                )

    def test_runtime_argument_does_not_claim_smithery_identity(self):
        args = ['-c', 'npx', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'python', None, args),
                    'npm:@smithery/cli',
                )

    def test_nested_npm_runner_does_not_claim_smithery_identity(self):
        args = ['npm', '@smithery/cli', 'run', '@vendor/server']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'npm:@smithery/cli',
                )

    def test_nuget_launchers_use_package_identity(self):
        vectors = [
            ('dnx', ['Vendor.Server@1.2.3', 'serve'], 'nuget:vendor.server'),
            (
                'dnx',
                ['--framework', 'net10.0', '-y', 'Example.Server@2.0.0'],
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
                ['tool', 'exec', 'Example.Server@2.0.0'],
                'nuget:example.server',
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
