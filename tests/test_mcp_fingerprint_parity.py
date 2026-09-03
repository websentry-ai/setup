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
    def test_smithery_wrapper_uses_run_target(self):
        args = ['-y', '@smithery/cli@latest', 'run', '@vendor/server', '--key', 'secret']
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(
                    hook.compute_mcp_cache_key('alias', 'npx', None, args),
                    'smithery:@vendor/server',
                )

    def test_nuget_launchers_use_package_identity(self):
        vectors = [
            ('dnx', ['Vendor.Server@1.2.3', 'serve'], 'nuget:vendor.server'),
            (
                'dotnet',
                ['tool', 'execute', 'Example.Server@2.0.0', '--source',
                 'https://api.nuget.org/v3/index.json'],
                'nuget:example.server',
            ),
        ]
        for hook in HOOKS:
            for command, args, expected in vectors:
                with self.subTest(hook=hook.__file__, command=command):
                    self.assertEqual(
                        hook.compute_mcp_cache_key('alias', command, None, args),
                        expected,
                    )
