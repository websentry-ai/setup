"""Every hook records where each shell transfer went (tool, host as written, host ssh resolves it to, address kind),
checked on all five Python hooks with a fake `ssh` on PATH, a patched resolver and each hook's exchange builder."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import load_module

HOOK_PATHS = [
    'claude-code/hooks/unbound.py',
    'codex/hooks/unbound.py',
    'copilot/hooks/unbound.py',
    'augment/hooks/unbound.py',
    'cursor/unbound.py',
]
HOOKS = [load_module(p) for p in HOOK_PATHS]
REPO_ROOT = Path(__file__).resolve().parents[1]
# The ssh on PATH before the tests put their stand-in first; ssh -G runs a Match exec command, which they never must.
REAL_SSH = shutil.which('ssh')
START = '# KEEP IN SYNC: transfer resolution'
END = '# --- end transfer resolution ---'
# The cursor-plugin repo's hooks/unbound.py carries the same block and pins the same digest in its own test, so a
# change made in one repo and not the other fails there. Update both together.
BLOCK_SHA256 = '397bdf8077a6c8c926c88cfa9055f8c7c2fb343031a390493c7a1f5af8281199'
# Not a real credential; it only has to sit where a login goes.
FAKE_TOKEN = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'  # gitleaks:allow

ADDRESSES = {
    'files.acme-infra.net': ['10.20.30.40'],
    'example.com': ['93.184.216.34'],
    'api.example.com': ['93.184.216.35'],
    'vpn.acme.internal': ['fd12:3456:789a::1'],
    'cgnat.example': ['100.64.10.1'],
    'split.example': ['10.0.0.9', '8.8.8.8'],
    'metadata.example': ['169.254.169.254'],
    'localhost': ['127.0.0.1', '::1'],
    'never.example': ['198.51.100.1'],
    'actual.example': ['198.51.100.2'],
}
FAKE_SSH = '''#!{python}
"""ssh -G stand-in: HostName from -F (or ~/.ssh/config), -o and -p; logs each call."""
import json, os, re, sys, time
args = sys.argv[1:]
with open(os.environ['FAKE_SSH_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': args, 'cwd': os.getcwd()}}) + '\\n')
time.sleep(float(os.environ.get('FAKE_SSH_SLEEP') or 0))
if args[:1] != ['-G']:
    sys.exit(2)
config, overrides, port, destination, i = None, {{}}, '22', None, 1
while i < len(args):
    arg, i = args[i], i + 1
    if arg == '--':
        destination = args[i]
        break
    if arg in ('-F', '-o', '-p', '-J', '-l'):
        value, i = args[i], i + 1
        if arg == '-F':
            config = value
        elif arg == '-p':
            port = value
        elif arg == '-o':
            key, value = re.split(r'[ =]', value, maxsplit=1)
            overrides[key.lower()] = value
    else:
        destination = arg
host = destination.rsplit('@', 1)[-1]
hostname, current = host, []
config = config or os.path.join(os.environ['HOME'], '.ssh', 'config')


def lines_of(path, depth=0):
    # Each Include is read in place, and its Host blocks end with it, as ssh does.
    out = []
    for line in (open(path) if depth < 8 and os.path.exists(path) else []):
        words = line.split()
        if words and words[0].lower() == 'include':
            for target in words[1:]:
                out += lines_of(target.strip('"'), depth + 1) + ['Host \\0end']
        else:
            out.append(line)
    return out


for line in (lines_of(config) if config != 'none' else []):
    words = line.split()
    if words and words[0].lower() == 'host':
        current = words[1:]
    elif words and words[0].lower() == 'hostname' and host in current and hostname == host:
        hostname = words[1]  # the first value wins, as in ssh
    elif words and words[0].lower() in ('proxyjump', 'proxycommand') and host in current:
        overrides.setdefault(words[0].lower(), ' '.join(words[1:]))
print('hostname ' + overrides.get('hostname', hostname).lower())
print('port ' + overrides.get('port', port))
for key in ('proxyjump', 'proxycommand'):
    print(key + ' ' + overrides.get(key, 'none'))  # as some ssh versions print it for a host with neither
'''


def _getaddrinfo(host, *args, **kwargs):
    if host not in ADDRESSES:
        raise socket.gaierror(socket.EAI_NONAME, 'unknown host')
    return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
            for ip in ADDRESSES[host]]


def _entries(obj):
    """Every dict nested anywhere in a hook's output."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _entries(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _entries(value)


def _tool_entries(output):
    return [e for e in _entries(output) if 'tool_use_id' in e]


@unittest.skipIf(os.name == 'nt', 'the fake ssh is a POSIX script')
class TransferTestCase(unittest.TestCase):
    """A throwaway home whose ssh config maps `prod` to 10.0.4.12, a repo with a frontend folder whose own `cfg`
    maps it elsewhere, a fake ssh first on PATH, and a resolver that knows only ADDRESSES."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, '.ssh'))
        Path(self.home, '.ssh', 'config').write_text('Host prod\n  HostName 10.0.4.12\n  User deploy\n')
        self.repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.repo, 'frontend'))
        Path(self.repo, 'cfg').write_text('Host prod\n  HostName 203.0.113.9\n')
        Path(self.repo, 'frontend', 'cfg').write_text('Host prod\n  HostName 10.0.4.12\n')
        bin_dir = tempfile.mkdtemp()
        ssh = Path(bin_dir, 'ssh')
        ssh.write_text(FAKE_SSH.format(python=sys.executable))
        ssh.chmod(0o755)
        self.ssh_log = os.path.join(bin_dir, 'calls.jsonl')
        Path(self.ssh_log).touch()
        env = {'PATH': bin_dir + os.pathsep + os.environ.get('PATH', ''), 'HOME': self.home,
               'FAKE_SSH_LOG': self.ssh_log, 'FAKE_SSH_SLEEP': '0'}
        for patcher in [patch.dict(os.environ, env), patch('socket.getaddrinfo', _getaddrinfo)] + \
                [patch.object(hook, '_transfer_home', lambda home=self.home: home) for hook in HOOKS]:
            patcher.start()
            self.addCleanup(patcher.stop)
        # A proxy this machine's shell sets would change what is looked up; the dict patch above puts it back.
        for key in [k for k in os.environ if k.lower() in ('http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy',
                                                           'no_proxy')]:
            del os.environ[key]

    def ssh_calls(self):
        """Each ssh -G call, with the vetted config copy it was handed shown as <vetted>."""
        calls = [json.loads(line) for line in Path(self.ssh_log).read_text().splitlines()]
        for call in calls:
            call['argv'] = ['<vetted>' if 'unbound-ssh-' in arg else arg for arg in call['argv']]
        return calls

    def each(self, command, cwd=None):
        """(hook file, transfer) for every hook, each with a fresh turn."""
        return [(hook.__file__, hook._transfer(command, cwd or self.repo, {})) for hook in HOOKS]

    def assert_endpoints(self, command, expected, tool=None, cwd=None):
        for hook, transfer in self.each(command, cwd):
            with self.subTest(hook=hook, command=command):
                self.assertIsNotNone(transfer)
                self.assertEqual(transfer['endpoints'], expected)
                if tool:
                    self.assertEqual(transfer['tool'], tool)

    def assert_hosts(self, command, expected, cwd=None):
        """[(direction, host)] for each endpoint, '' for an unknown direction."""
        for hook, transfer in self.each(command, cwd):
            with self.subTest(hook=hook, command=command):
                got = [(e.get('direction', ''), e['host']) for e in (transfer or {}).get('endpoints', [])]
                self.assertEqual(got, expected)


def _endpoint(direction, host, address, resolved=None):
    endpoint = {'direction': direction, 'host': host, 'resolved_host': resolved or host, 'address': address}
    return {k: v for k, v in endpoint.items() if v}


class TheBlockIsSharedTests(unittest.TestCase):
    def _block(self, path):
        text = (REPO_ROOT / path).read_text()
        self.assertEqual(text.count(START), 1, path)
        self.assertEqual(text.count(END), 1, path)
        return text[text.index(START):text.index(END) + len(END)]

    def test_the_block_is_byte_identical_in_every_hook(self):
        self.assertEqual(len({self._block(path) for path in HOOK_PATHS}), 1)

    def test_the_block_matches_the_digest_the_cursor_plugin_pins(self):
        digest = hashlib.sha256(self._block(HOOK_PATHS[0]).encode('utf-8')).hexdigest()
        self.assertEqual(digest, BLOCK_SHA256)


class SharedCorpusTests(TransferTestCase):
    """tests/fixtures/transfer_cases.json is also checked by hooks-ts, so every hook, Pi included, sends the same field
    for the same command."""

    def test_every_command_sends_the_expected_transfer(self):
        fixture = json.loads((REPO_ROOT / 'tests' / 'fixtures' / 'transfer_cases.json').read_text())
        Path(self.home, '.ssh', 'config').write_text(
            ''.join(f'Host {alias}\n  HostName {name}\n' for alias, name in fixture['ssh_hosts'].items()))

        looked_up = []

        def lookup(host, *args, **kwargs):
            looked_up.append(host)
            if host not in fixture['addresses']:
                raise socket.gaierror(socket.EAI_NONAME, 'unknown host')
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
                    for ip in fixture['addresses'][host]]

        # hook_env is the hook's own environment: none of its values may reach a host, a lookup or ssh -G.
        with patch('socket.getaddrinfo', lookup), patch.dict(os.environ, fixture['hook_env']):
            for case in fixture['cases']:
                # env is what the agent's shell passes on, such as a proxy.
                with patch.dict(os.environ, case.get('env', {})):
                    results = self.each(case['command'])
                for hook, transfer in results:
                    with self.subTest(hook=hook, command=case['command'], env=case.get('env')):
                        self.assertEqual(transfer, case['transfer'])
        for value in fixture['hook_env'].values():
            self.assertNotIn(value, json.dumps([looked_up, self.ssh_calls()]))


class CurlTests(TransferTestCase):
    def test_an_upload_a_form_a_body_json_or_a_sending_method_is_out(self):
        for command in ('curl -T build.zip https://files.acme-infra.net/up',
                        'curl --upload-file build.zip https://files.acme-infra.net/up',
                        'curl -F file=@build.zip https://files.acme-infra.net/up',
                        'curl -sSL -d @payload.json https://files.acme-infra.net/up',
                        "curl --data-binary @- https://files.acme-infra.net/up < build.zip",
                        "curl --json '{\"a\": 1}' https://files.acme-infra.net/up",
                        'curl -XPOST https://files.acme-infra.net/up',
                        'curl --request put https://files.acme-infra.net/up',
                        'curl.exe -X PATCH https://files.acme-infra.net/up'):
            self.assert_endpoints(command, [_endpoint('out', 'files.acme-infra.net', 'private')], tool='curl')

    def test_a_fetch_a_get_with_data_and_a_delete_are_in(self):
        for command in ('curl -fsSLo app.tgz https://example.com/app.tgz',
                        'curl -G -d q=term https://example.com/search',
                        'curl -X DELETE https://example.com/item/1',
                        'curl --url https://example.com/x --output x',
                        '/usr/bin/curl -H "Accept: text/plain" example.com/plain'):
            self.assert_endpoints(command, [_endpoint('in', 'example.com', 'public')], tool='curl')

    def test_an_attached_or_expanded_value_is_read_as_curl_reads_it(self):
        for command in ('curl --data=hello https://files.acme-infra.net/up',
                        'curl --upload-file=build.zip https://files.acme-infra.net/up',
                        'curl --json=@payload.json https://files.acme-infra.net/up',
                        'curl --form=file=@a.zip https://files.acme-infra.net/up',
                        'curl --request=PUT https://files.acme-infra.net/up',
                        'curl --url=https://files.acme-infra.net/up --data-binary=@build.zip',
                        "curl --expand-data '{{body}}' https://files.acme-infra.net/up"):
            self.assert_endpoints(command, [_endpoint('out', 'files.acme-infra.net', 'private')], tool='curl')
        self.assert_hosts('curl --output=page.html --proxy=http://proxy.corp:3128 https://example.com/x',
                          [('in', 'example.com')])

    def test_a_non_ascii_host_is_sent_in_the_punycode_form_curl_dials(self):
        # curl (libidn2) and the URL standard keep ß and a final sigma; the older IDNA 2003 rewrites them.
        for url, host in (('https://exämple.com/a', 'xn--exmple-cua.com'), ('https://faß.de/a', 'xn--fa-hia.de'),
                          ('https://βόλος.com/a', 'xn--nxasmm1c.com'), ('https://xn--exmple-cua.com/a', 'xn--exmple-cua.com')):
            self.assert_hosts('curl ' + url, [('in', host)])

    def test_each_next_starts_a_request_with_its_own_options(self):
        self.assert_hosts('curl -T build.zip https://files.acme-infra.net/up --next https://example.com/file',
                          [('out', 'files.acme-infra.net'), ('in', 'example.com')])
        self.assert_hosts('curl https://example.com/a -: -d x https://files.acme-infra.net/up',
                          [('in', 'example.com'), ('out', 'files.acme-infra.net')])
        # A --next or -: that is another option's value is that value, not a new request.
        self.assert_hosts('curl --data --next https://example.com/a', [('out', 'example.com')])
        self.assert_hosts('curl -d -: https://example.com/a', [('out', 'example.com')])

    def test_url_globs_reach_every_host_they_name(self):
        # curl expands {a,b} sets and [1-3] ranges itself unless --globoff is given, and stops at a glob it rejects.
        cases = {
            "curl -T x 'https://{files.acme-infra.net,example.com}/up'":
                [('out', 'files.acme-infra.net'), ('out', 'example.com')],
            "curl 'https://h[1-3].example/x'": [('in', 'h1.example'), ('in', 'h2.example'), ('in', 'h3.example')],
            "curl 'https://h[01-10:9].example/x'": [('in', 'h01.example'), ('in', 'h10.example')],
            "curl 'https://{a,b\\,c}.example/x'": [('in', 'a.example')],
            "curl 'https://[::1]:8080/x'": [('in', '::1')],
            "curl --url 'https://{a,b}.example/x'": [('in', 'a.example'), ('in', 'b.example')],
            "curl -g 'https://{a,b}.example/x'": [],
            "curl 'https://a.example/x' 'https://{{b}}.example/y' https://c.example/z": [('in', 'a.example')],
            "curl 'https://h[3-1].example/x'": [],
            "curl 'https://a.example/x}'": [],
            # With globbing off, brackets or a backslash in the host are a name curl rejects.
            "curl -g 'https://h[1-2].example/x'": [],
            "curl -g 'https://a.example\\b/x'": [],
            "curl -g https://{a,b}.example/x": [('in', 'a.example'), ('in', 'b.example')],
            # Unquoted, bash expands the braces before curl runs; quoted, curl reads {1..2} as one name.
            'curl https://h{1..2}.example/x': [('in', 'h1.example'), ('in', 'h2.example')],
            "curl 'https://h{1..2}.example/x'": [('in', 'h1..2.example')],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)

    def test_connect_to_and_resolve_set_where_a_url_connects(self):
        # As curl applies them: the first matching --connect-to, then the last pin for that host and port, a named
        # host before *; pins carry on past --next and a --connect-to does not.
        cases = {
            'curl --resolve example.com:443:10.0.0.5 https://example.com/x': [('example.com', '10.0.0.5', 'private')],
            'curl --resolve example.com:80:10.0.0.5 https://example.com/x': [('example.com', 'example.com', 'public')],
            "curl --resolve '*:443:10.0.0.5' https://example.com/x": [('example.com', '10.0.0.5', 'private')],
            "curl --resolve example.com:443:8.8.8.8 --resolve '*:443:10.0.0.5' https://example.com/x":
                [('example.com', '8.8.8.8', 'public')],
            'curl --resolve example.com:443:10.0.0.5 --resolve -example.com:443 https://example.com/x':
                [('example.com', 'example.com', 'public')],
            "curl --resolve 'example.com:443:10.0.0.5,8.8.8.8' https://example.com/x":
                [('example.com', '10.0.0.5', 'public')],
            'curl --connect-to example.com:443:cgnat.example:8443 --resolve cgnat.example:8443:[fd00::1] '
            'https://example.com/x': [('example.com', 'fd00::1', 'private')],
            'curl --connect-to example.com:443:cgnat.example: --resolve example.com:443:8.8.8.8 https://example.com/x':
                [('example.com', 'cgnat.example', 'cgnat')],
            'curl --connect-to ::10.1.2.3: --connect-to ::8.8.8.8: https://example.com/x':
                [('example.com', '10.1.2.3', 'private')],
            'curl https://example.com/a --next --resolve example.com:443:10.0.0.5 https://example.com/b':
                [('example.com', 'example.com', 'public'), ('example.com', '10.0.0.5', 'private')],
            'curl --connect-to ::10.1.2.3: https://example.com/a --next https://example.com/b':
                [('example.com', '10.1.2.3', 'private'), ('example.com', 'example.com', 'public')],
        }
        for command, expected in cases.items():
            for hook, transfer in self.each(command):
                with self.subTest(hook=hook, command=command):
                    got = [(e['host'], e['resolved_host'], e['address']) for e in transfer['endpoints']]
                    self.assertEqual(got, expected)

    def test_option_values_are_never_read_as_urls(self):
        self.assert_hosts('curl --cacert ca.pem -x http://proxy.corp:3128 -e https://referer.example '
                          '--resolve api.example.com:443:1.2.3.4 https://api.example.com/v1', [('in', 'api.example.com')])


class WgetTests(TransferTestCase):
    def test_posting_data_or_a_file_is_out_and_anything_else_is_in(self):
        for command, direction in (('wget --post-file=build.zip https://files.acme-infra.net/up', 'out'),
                                   ("wget --post-data 'a=1' https://files.acme-infra.net/up", 'out'),
                                   ('wget --method=PUT --body-file=b.zip https://files.acme-infra.net/up', 'out'),
                                   ('wget --body-data x https://files.acme-infra.net/up', 'out'),
                                   ('wget -qO- https://files.acme-infra.net/install.sh | sh', 'in'),
                                   ('wget -O out.zip -e robots=off https://files.acme-infra.net/a.zip', 'in')):
            self.assert_endpoints(command, [_endpoint(direction, 'files.acme-infra.net', 'private')], tool='wget')


class CopyTests(TransferTestCase):
    def test_scp_to_a_nickname_reports_the_address_ssh_resolves_it_to(self):
        self.assert_endpoints('scp build.zip prod:/srv', [_endpoint('out', 'prod', 'private', '10.0.4.12')], 'scp')
        self.assertEqual(self.ssh_calls()[0]['argv'], ['-G', '-F', '<vetted>', '--', 'prod'])
        # ssh runs from the vetted folder, never the project's, where Windows would look for a planted ssh first.
        self.assertTrue(all('unbound-ssh-' in call['cwd'] for call in self.ssh_calls()))

    def test_scp_and_rsync_copy_directions(self):
        cases = {
            'scp build.zip deploy@prod:/srv': [('out', 'prod')],
            'scp prod:/var/log/app.log .': [('in', 'prod')],
            'scp -r prod:/a example.com:/b': [('in', 'prod'), ('out', 'example.com')],
            'rsync -avz ./dist deploy@prod:/srv/app': [('out', 'prod')],
            'rsync -a prod:/srv/backup/ ./backup': [('in', 'prod')],
            'rsync -a prod:/srv/ example.com:/srv/': [('in', 'prod'), ('out', 'example.com')],
            'rsync -a ./dist backup.example.com::module': [('out', 'backup.example.com')],
            'rsync -a ./dist rsync://backup.example.com/module': [('out', 'backup.example.com')],
            'cp a b': [],
            'rsync -a src/ dst/': [],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)

    def test_sftp_fetches_a_named_path_and_leaves_a_session_direction_unknown(self):
        self.assert_hosts('sftp deploy@prod', [('', 'prod')])
        self.assert_hosts('sftp prod:/etc/hosts ./hosts', [('in', 'prod')])
        self.assert_hosts('sftp -b batch.txt sftp://deploy@prod:2222/srv', [('in', 'prod')])

    def test_ssh_options_that_change_the_host_are_passed_to_ssh_g(self):
        command = 'scp -F cfg -P 2222 -o HostName=10.9.9.9 -o Compression=yes -o ProxyJump=none f prod:/tmp'
        self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.9.9.9')])
        self.assertEqual(self.ssh_calls()[0]['argv'],
                         ['-G', '-F', '<vetted>', '-p', '2222', '-o', 'HostName=10.9.9.9', '-o', 'ProxyJump=none', '--',
                          'prod'])

    def test_a_host_reached_through_a_jump_host_or_proxy_command_is_never_looked_up(self):
        # The jump host or proxy resolves it, so neither ssh -G nor DNS runs here; an address as written still counts.
        for command in ('scp -J jump f prod:/tmp', 'scp -o ProxyJump=jump f prod:/tmp',
                        "scp -o 'ProxyCommand nc %h %p' f prod:/tmp", 'ssh -J jump prod cat < f',
                        'rsync -a -e "ssh -J jump" f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'unresolved')])
        self.assert_endpoints('scp -J jump f 10.0.4.12:/tmp', [_endpoint('out', '10.0.4.12', 'private')])
        self.assertEqual(self.ssh_calls(), [])
        # A jump host the config names, as ssh -G reports it, carries the bytes where it sends them, so neither the
        # config's HostName nor its address is reported.
        Path(self.repo, 'jump_cfg').write_text('Host prod\n  HostName files.acme-infra.net\n')
        self.assert_endpoints('scp -F jump_cfg f prod:/tmp',
                              [_endpoint('out', 'prod', 'private', 'files.acme-infra.net')])
        for jump in ('ProxyJump bastion', 'ProxyCommand nc %h %p'):
            Path(self.repo, 'jump_cfg').write_text(f'Host prod\n  HostName files.acme-infra.net\n  {jump}\n')
            self.assert_endpoints('scp -F jump_cfg f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])

    def test_rsync_reads_its_remote_shell_and_a_daemon_is_never_looked_up(self):
        for command in ('rsync -a -e "ssh -F frontend/cfg -p 2200" src prod:/dest',
                        'RSYNC_RSH="ssh -F frontend/cfg -p 2200" rsync -a src prod:/dest',
                        "rsync -avze 'ssh -F frontend/cfg -p 2200' src prod:/dest --exclude foo:bar"):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assertTrue(all(c['argv'][:5] == ['-G', '-F', '<vetted>', '-p', '2200'] for c in self.ssh_calls()))
        Path(self.ssh_log).write_text('')
        self.assert_hosts('rsync -a src prod::module', [('out', 'prod')])
        self.assert_hosts('rsync -a -e /usr/local/bin/custom-shell src prod:/dest', [('out', 'prod')])
        self.assertEqual(self.ssh_calls(), [])

    def test_the_hooks_own_remote_shell_never_reaches_ssh_g(self):
        # Only text the command wrote may reach a lookup; an RSYNC_RSH the hook inherited stays unknown.
        with patch.dict(os.environ, {'RSYNC_RSH': 'ssh -o HostName=leak.example'}):
            for command in ('rsync -a src prod:/dest', 'export RSYNC_RSH; rsync -a src prod:/dest'):
                self.assert_endpoints(command, [_endpoint('out', 'prod', 'unresolved')])
            self.assert_endpoints('RSYNC_RSH="ssh -o HostName=10.9.9.9" rsync -a src prod:/dest',
                                  [_endpoint('out', 'prod', 'private', '10.9.9.9')])
        self.assertNotIn('leak.example', json.dumps(self.ssh_calls()))

    def test_bracketed_ipv6_and_scp_uris_resolve_without_their_login(self):
        self.assert_endpoints('scp -F none dump.sql deploy@[fd12:3456:789a::1]:/tmp/',
                              [_endpoint('out', 'fd12:3456:789a::1', 'private')])
        self.assert_endpoints(f'scp dump.sql scp://deploy:{FAKE_TOKEN}@prod:2200/tmp/',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assertIn(['-p', '2200'], [c['argv'][3:5] for c in self.ssh_calls()])
        self.assertNotIn(FAKE_TOKEN, json.dumps(self.ssh_calls()))


class SshPipeTests(TransferTestCase):
    def test_feeding_ssh_is_out_and_keeping_its_output_is_in(self):
        cases = {
            "ssh prod 'cat > f' < secrets.env": [('out', 'prod')],
            'tar c . | ssh prod "tar x -C /srv"': [('out', 'prod')],
            "ssh prod 'cat /etc/passwd' > passwd.txt": [('in', 'prod')],
            "ssh prod 'tar c /srv' | tar x": [('in', 'prod')],
            'ssh prod uptime': [],
            'ssh prod uptime > /dev/null': [],
            'ssh -N -L 8080:localhost:80 prod': [],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)
        self.assert_endpoints("ssh prod 'cat > f' < secrets.env", [_endpoint('out', 'prod', 'private', '10.0.4.12')],
                              tool='ssh')


class NetcatAndSocatTests(TransferTestCase):
    def test_netcat_is_out_only_when_fed(self):
        cases = {
            'echo hi | nc example.com 80': [('out', 'example.com')],
            'nc -w 3 example.com 80 < request.txt': [('out', 'example.com')],
            'ncat --proxy proxy.corp:3128 example.com 443 < request.txt': [('out', 'example.com')],
            'netcat example.com 80': [('', 'example.com')],
            'nc -zv example.com 22': [('', 'example.com')],
            'nc -lk 8080': [],
            'nc -U /tmp/socket': [],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)
        self.assert_endpoints('echo hi | nc example.com 80', [_endpoint('out', 'example.com', 'public')], tool='nc')

    def test_socat_reads_host_addresses(self):
        cases = {
            'socat - TCP:example.com:443 < request.txt': [('out', 'example.com')],
            'socat STDIO OPENSSL:example.com:443,verify=0': [('', 'example.com')],
            'socat - PROXY:proxy.corp:example.com:443,proxyport=3128': [('', 'example.com')],
            'socat TCP-LISTEN:8080,fork TCP:localhost:80': [('', 'localhost')],
            'socat - UNIX-CONNECT:/tmp/sock': [],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)
        self.assert_endpoints('socat - TCP:example.com:443 < request.txt',
                              [_endpoint('out', 'example.com', 'public')], tool='socat')


class HttpieTests(TransferTestCase):
    def test_data_items_stdin_and_sending_methods_are_out(self):
        cases = {
            'http POST api.example.com/v1 name=x': 'out',
            'http api.example.com/v1 name=x': 'out',
            'http api.example.com/v1 config:=@cfg.json': 'out',
            'http -f api.example.com/v1 file@report.pdf': 'out',
            'http PUT api.example.com/v1 < body.json': 'out',
            'https --raw "hello" api.example.com/v1': 'out',
            'http api.example.com/v1': 'in',
            'http GET api.example.com/v1 X-Api-Version:2 q==term': 'in',
            'http -a user:pass api.example.com/v1': 'in',
            'http --ignore-stdin api.example.com/v1 < body.json': 'in',
        }
        for command, direction in cases.items():
            self.assert_endpoints(command, [_endpoint(direction, 'api.example.com', 'public')], tool='httpie')
        self.assert_hosts('https :3000/health', [('in', 'localhost')])
        self.assert_hosts('http --offline POST api.example.com/v1 a=1', [])


class PowerShellTests(TransferTestCase):
    def test_web_cmdlets_read_their_uri_body_file_form_and_method(self):
        cases = {
            'Invoke-WebRequest -Uri https://example.com/a.zip -OutFile a.zip': 'in',
            'iwr https://example.com/a.zip -UseBasicParsing': 'in',
            'Invoke-RestMethod -Uri https://example.com/api -Method Post -Body $body': 'out',
            'irm https://example.com/api -Method:Put': 'out',
            'Invoke-WebRequest -Uri https://example.com/up -InFile build.zip -Method Put': 'out',
            'invoke-webrequest -uri https://example.com/up -form $form': 'out',
            'Get-Content a.json | Invoke-RestMethod https://example.com/api': 'out',
        }
        for command, direction in cases.items():
            self.assert_endpoints(command, [_endpoint(direction, 'example.com', 'public')], tool='powershell')

    def test_a_followed_command_string_shares_its_wrappers_pipes_and_redirections(self):
        cases = {
            'tar c . | sh -c "ssh prod \'tar x -C /srv\'"': [('out', 'prod')],
            'sh -c "ssh prod \'tar c /srv\'" > backup.tar': [('in', 'prod')],
            'bash -c "nc example.com 80" < request.txt': [('out', 'example.com')],
            'Get-Content a.json | powershell -Command "Invoke-RestMethod https://example.com/api"': [('out', 'example.com')],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)

    def test_a_compounds_pipes_and_redirections_reach_the_commands_inside(self):
        cases = {
            "tar c . | (ssh prod 'tar x -C /srv')": [('out', 'prod')],
            "(ssh prod 'tar c /srv') > backup.tar": [('in', 'prod')],
            "{ ssh prod 'tar c /srv'; } > backup.tar": [('in', 'prod')],
            "tar c . | { cd /tmp && ssh prod 'tar x'; }": [('out', 'prod')],
            'if true; then nc example.com 80; fi < request.txt': [('out', 'example.com')],
            "case x in *) ssh prod 'tar c /srv';; esac | tar x": [('in', 'prod')],
            "echo $(ssh prod 'cat f') > out.txt": [],
        }
        for command, expected in cases.items():
            self.assert_hosts(command, expected)

    def test_a_powershell_or_sh_command_string_is_followed(self):
        self.assert_endpoints('powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri https://example.com/up '
                              '-InFile b.zip -Method Put"', [_endpoint('out', 'example.com', 'public')], 'powershell')
        self.assert_endpoints("pwsh -c 'irm https://example.com/api'", [_endpoint('in', 'example.com', 'public')])
        self.assert_endpoints("bash -lc 'curl -T b.zip https://files.acme-infra.net/up'",
                              [_endpoint('out', 'files.acme-infra.net', 'private')], 'curl')
        self.assert_hosts('bash deploy.sh', [])


class AddressTests(TransferTestCase):
    def test_a_proxied_or_unsure_call_is_unresolved_whatever_an_earlier_call_found(self):
        # The turn caches each lookup, but a call that must not look up never reads it.
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                state = {}
                self.assertEqual(hook._transfer('curl https://files.acme-infra.net/a', self.repo, state)['endpoints'],
                                 [_endpoint('in', 'files.acme-infra.net', 'private')])
                for command in ('curl --socks5-hostname proxy.example:1080 -T secret https://files.acme-infra.net/up',
                                '[ -f /nope ] && curl -T secret https://files.acme-infra.net/up'):
                    self.assertEqual(hook._transfer(command, self.repo, state)['endpoints'],
                                     [_endpoint('out', 'files.acme-infra.net', 'unresolved')], command)

    def test_a_call_that_may_not_have_run_is_never_looked_up(self):
        # Neither DNS nor ssh -G runs for it; an address as written is still classified, and a sure call looks up.
        looked_up = []

        def lookup(host, *args, **kwargs):
            looked_up.append(host)
            return _getaddrinfo(host, *args, **kwargs)

        with patch('socket.getaddrinfo', lookup):
            self.assert_endpoints('if [ -f /nope ]; then curl https://example.com/up; fi',
                                  [_endpoint('in', 'example.com', 'unresolved')])
            self.assert_endpoints('[ -f /nope ] && scp f prod:/srv', [_endpoint('out', 'prod', 'unresolved')])
            self.assert_endpoints('[ -f /nope ] || curl https://10.0.0.5/up', [_endpoint('in', '10.0.0.5', 'private')])
            self.assertEqual((looked_up, self.ssh_calls()), ([], []))
            self.assert_endpoints('curl https://example.com/up', [_endpoint('in', 'example.com', 'public')])
            self.assertEqual(set(looked_up), {'example.com'})

    def test_each_address_kind(self):
        cases = {
            'https://files.acme-infra.net/x': 'private',
            'https://vpn.acme.internal/x': 'private',
            'https://example.com/x': 'public',
            'https://cgnat.example/x': 'cgnat',
            'https://metadata.example/x': 'link_local',
            'http://localhost:8080/x': 'loopback',
            'http://[::1]:8080/x': 'loopback',
            'http://192.168.1.10/x': 'private',
            'http://172.20.0.5/x': 'private',
            'http://100.100.1.1/x': 'cgnat',
            'http://8.8.8.8/x': 'public',
            'https://split.example/x': 'public',
            'https://nowhere.invalid/x': 'unresolved',
        }
        for url, kind in cases.items():
            for hook, transfer in self.each('curl ' + url):
                with self.subTest(hook=hook, url=url):
                    self.assertEqual(transfer['endpoints'][0]['address'], kind)

    def test_a_host_is_looked_up_once_per_turn(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch('socket.getaddrinfo', side_effect=_getaddrinfo) as lookup:
                state = {}
                hook._transfer('curl https://example.com/a', self.repo, state)
                hook._transfer('curl -T b https://example.com/b && curl https://example.com/c', self.repo, state)
                self.assertEqual(lookup.call_count, 1)


class LoginsNeverLeaveTests(TransferTestCase):
    def test_no_login_password_or_token_reaches_the_field(self):
        for command in (f'curl https://jdoe:{FAKE_TOKEN}@example.com/x',
                        f'curl -u jdoe:{FAKE_TOKEN} https://example.com/x',  # gitleaks:allow
                        f'wget https://jdoe:{FAKE_TOKEN}@example.com/x',
                        'scp f jdoe@example.com:/tmp',
                        f'scp f scp://jdoe:{FAKE_TOKEN}@example.com/tmp',
                        f'rsync -a f jdoe@example.com:/tmp',
                        f"ssh jdoe:{FAKE_TOKEN}@example.com 'cat > f' < f",
                        f'http -a jdoe:{FAKE_TOKEN} example.com/x',
                        f'iwr -Uri https://jdoe:{FAKE_TOKEN}@example.com/x -OutFile x'):
            for hook, transfer in self.each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(transfer['endpoints'][0]['host'], 'example.com')
                    self.assertNotIn(FAKE_TOKEN, json.dumps(transfer))
                    self.assertNotIn('jdoe', json.dumps(transfer))

    def test_only_the_contract_fields_are_sent(self):
        for hook, transfer in self.each('curl -T /etc/secret.env https://files.acme-infra.net/up?token=abc'):
            with self.subTest(hook=hook):
                self.assertEqual(set(transfer), {'tool', 'endpoints'})
                self.assertEqual(set(transfer['endpoints'][0]), {'direction', 'host', 'resolved_host', 'address'})
                self.assertNotIn('secret', json.dumps(transfer))
                self.assertNotIn('token', json.dumps(transfer))

    def test_commands_without_a_transfer_or_a_host_send_nothing(self):
        for command in ('ls -la', 'git push origin main', 'curl --version', 'curl "$URL"', 'scp a b', '',
                        'echo curl https://example.com', 'cat <<EOF\ncurl -T x https://example.com\nEOF', None):
            for hook, transfer in self.each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertIsNone(transfer)


class SshLookupTests(TransferTestCase):
    def test_an_ssh_config_that_could_run_commands_is_never_handed_to_ssh(self):
        Path(self.home, '.ssh', 'config').write_text('Match host * exec "touch /tmp/never"\n  HostName 10.9.9.9\n')
        self.assert_endpoints('scp f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        Path(self.repo, 'canon').write_text('CanonicalizeHostname yes\n')
        self.assert_endpoints('scp -F canon f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(self.ssh_calls(), [])

    def test_match_criteria_are_read_as_ssh_reads_them(self):
        # Only an exec criterion runs a command; a host pattern that starts with exec does not.
        Path(self.repo, 'host').write_text('Match host exec-prod\n  HostName 10.1.1.1\n')
        self.assert_hosts('scp -F host f prod:/tmp', [('out', 'prod')])
        self.assertEqual(len(self.ssh_calls()), len(HOOKS))
        for config in ('Match exec=true\n', 'Match !exec "true"\n', 'Match canonical exec "true"\n'):
            Path(self.repo, 'run').write_text(config)
            self.assert_endpoints('scp -F run f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(len(self.ssh_calls()), len(HOOKS))

    def test_a_system_config_that_could_run_commands_is_never_handed_to_ssh(self):
        system = tempfile.mkdtemp()
        Path(system, 'ssh_config').write_text('Match exec "touch /tmp/never"\n')
        patches = [patch.object(hook, '_transfer_ssh_system_dir', lambda: system) for hook in HOOKS]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assert_endpoints('scp f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(self.ssh_calls(), [])
        # A safe one is read after the user's config, whose value comes first.
        Path(system, 'ssh_config').write_text('Host prod other\n  HostName 10.7.7.7\n')
        self.assert_endpoints('scp f prod:/tmp', [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assert_endpoints('scp f other:/tmp', [_endpoint('out', 'other', 'private', '10.7.7.7')])

    @unittest.skipUnless(REAL_SSH, 'needs a real ssh')
    def test_a_match_exec_never_runs_however_the_config_reaches_ssh(self):
        # Each config is shown to run its command when handed to ssh -G directly, then never runs through the hook.
        sentinel = os.path.join(tempfile.mkdtemp(), 'ran')
        evil = f'Match exec "touch {sentinel}"\n  HostName 10.6.6.6\n'
        safe = 'Host prod\n  HostName 10.0.4.12\n'
        Path(self.repo, 'evil.conf').write_text(evil)
        os.makedirs(os.path.join(self.repo, 'conf.d'))
        Path(self.repo, 'conf.d', 'b.conf').write_text(evil)
        Path(self.home, 'evil.conf').write_text(evil)
        Path(self.home, '.ssh', 'rel.conf').write_text(evil)
        forms = {'direct': evil, 'include': f'Include {self.repo}/evil.conf\n' + safe,
                 'glob': f'Include {self.repo}/conf.d/*.conf\n' + safe, 'tilde': 'Include ~/evil.conf\n' + safe,
                 'relative': 'Include rel.conf\n' + safe, 'nested': f'Include {self.repo}/include\n' + safe}
        env = {'PATH': os.path.dirname(REAL_SSH) + os.pathsep + os.environ['PATH']}
        for name, text in forms.items():
            Path(self.repo, name).write_text(text)
            with self.subTest(form=name):
                if name not in ('tilde', 'relative'):  # ssh puts those under the account's own home
                    subprocess.run([REAL_SSH, '-G', '-F', os.path.join(self.repo, name), '--', 'prod'],
                                   cwd=self.repo, capture_output=True, timeout=10)
                    self.assertTrue(os.path.exists(sentinel), name)
                    os.remove(sentinel)
                with patch.dict(os.environ, env):
                    self.assert_endpoints(f'scp -F {name} f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
                self.assertFalse(os.path.exists(sentinel), name)
        # The account's own config, read when no -F is given.
        Path(self.home, '.ssh', 'config').write_text(evil)
        with patch.dict(os.environ, env):
            self.assert_endpoints('scp f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertFalse(os.path.exists(sentinel))

    @unittest.skipUnless(REAL_SSH, 'needs a real ssh')
    def test_a_match_exec_split_by_a_trailing_backslash_never_runs(self):
        # ssh joins no lines, so the split line is a bad option to it; the check refuses any line ending in a backslash.
        sentinel = os.path.join(tempfile.mkdtemp(), 'ran')
        split = f'Match host prod \\\n  exec "touch {sentinel}"\n  HostName 10.6.6.6\n'
        Path(self.repo, 'split').write_text(split)
        Path(self.repo, 'split.conf').write_text(split)
        Path(self.repo, 'includes').write_text(f'Include {self.repo}/split.conf\nHost prod\n  HostName 10.0.4.12\n')
        Path(self.repo, 'canon').write_text('CanonicalizeHostname \\\nyes\nHost prod\n  HostName 10.0.4.12\n')
        env = {'PATH': os.path.dirname(REAL_SSH) + os.pathsep + os.environ['PATH']}
        for name in ('split', 'includes', 'canon'):
            with self.subTest(config=name), patch.dict(os.environ, env), \
                    patch('subprocess.run', wraps=subprocess.run) as run:
                self.assert_endpoints(f'scp -F {name} f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
                self.assertEqual(run.call_args_list, [])  # refused before ssh -G ever starts
            self.assertFalse(os.path.exists(sentinel), name)

    @unittest.skipUnless(REAL_SSH, 'needs a real ssh')
    def test_ssh_reads_the_copy_that_was_checked_not_the_file_as_it_is_later(self):
        # The config turns into one that runs a command after the check and before ssh starts; ssh never sees it.
        sentinel = os.path.join(tempfile.mkdtemp(), 'ran')
        Path(self.repo, 'swap').write_text('Host prod\n  HostName 10.0.4.12\n')
        real_run = subprocess.run

        def swap_then_run(argv, *args, **kwargs):
            Path(self.repo, 'swap').write_text(f'Match exec "touch {sentinel}"\n  HostName 10.6.6.6\n')
            return real_run(argv, *args, **kwargs)

        env = {'PATH': os.path.dirname(REAL_SSH) + os.pathsep + os.environ['PATH']}
        for hook in HOOKS:
            Path(self.repo, 'swap').write_text('Host prod\n  HostName 10.0.4.12\n')
            with self.subTest(hook=hook.__file__), patch.dict(os.environ, env), \
                    patch.object(hook.subprocess, 'run', swap_then_run):
                self.assertEqual(hook._transfer('scp -F swap f prod:/tmp', self.repo, {})['endpoints'],
                                 [_endpoint('out', 'prod', 'private', '10.0.4.12')])
            self.assertFalse(os.path.exists(sentinel))

    def test_includes_are_checked_under_home_as_well_as_the_account_home(self):
        # ssh reads ~/.ssh/config from the account's home but expands an Include with $HOME.
        elsewhere = tempfile.mkdtemp()
        os.makedirs(os.path.join(elsewhere, '.ssh', 'config.d'))
        Path(elsewhere, '.ssh', 'config.d', 'x.conf').write_text('Match exec "touch /tmp/never"\n')
        Path(elsewhere, '.ssh', 'other.conf').write_text('Match exec "touch /tmp/never"\n')
        Path(self.repo, 'relative_cfg').write_text('Include config.d/*.conf\nHost prod\n  HostName 10.0.4.12\n')
        Path(self.repo, 'tilde_cfg').write_text('Include ~/.ssh/other.conf\nHost prod\n  HostName 10.0.4.12\n')
        with patch.dict(os.environ, {'HOME': elsewhere}):
            for config in ('relative_cfg', 'tilde_cfg'):
                self.assert_endpoints(f'scp -F {config} f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(self.ssh_calls(), [])

    def test_sudo_around_a_command_string_still_skips_ssh_g(self):
        for command in ("sudo -u deploy sh -c 'scp f prod:/tmp'", 'sudo bash -c "tar c . | ssh prod \'tar x\'"'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(self.ssh_calls(), [])

    def test_an_ssh_host_under_sudo_is_never_looked_up_but_a_url_is(self):
        # The other user's config may send the alias elsewhere, so DNS on it would classify the wrong host.
        with patch('socket.getaddrinfo', side_effect=_getaddrinfo) as lookup:
            for command in ("sudo -u deploy scp f example.com:/srv", "sudo -u deploy sh -c 'scp f example.com:/srv'",
                            'doas rsync -a f example.com:/srv', 'sudo ssh example.com < f'):
                self.assert_endpoints(command, [_endpoint('out', 'example.com', 'unresolved')])
            lookup.assert_not_called()
            self.assert_endpoints('sudo curl https://example.com/x', [_endpoint('in', 'example.com', 'public')])
        self.assertEqual(self.ssh_calls(), [])

    def test_a_tilde_config_path_is_expanded_as_the_shell_does(self):
        Path(self.home, 'alt_cfg').write_text('Host prod\n  HostName 10.9.8.7\n')
        self.assert_endpoints('scp -F ~/alt_cfg f prod:/tmp', [_endpoint('out', 'prod', 'private', '10.9.8.7')])

    def test_a_one_letter_host_is_a_drive_only_on_windows(self):
        # Windows OpenSSH reads C:file as a local path; elsewhere scp dials host c.
        self.assert_hosts('scp build.zip a:/srv', [('out', 'a')])
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook, '_TRANSFER_WINDOWS', True):
                for command in ('scp C:file prod:/srv', 'scp c:/dir/file prod:/srv'):
                    found = hook._transfer(command, self.repo, {})
                    self.assertEqual([e['host'] for e in found['endpoints']], ['prod'], command)
                self.assertIsNone(hook._transfer('scp build.zip a:/srv', self.repo, {}))

    def test_sudo_and_dash_led_destinations_are_never_looked_up(self):
        self.assert_hosts('sudo -u deploy scp f prod:/tmp', [('out', 'prod')])
        self.assert_hosts('ssh -- -Fevil:x < f', [])
        self.assertEqual(self.ssh_calls(), [])

    def test_only_allowlisted_lookups_ever_run(self):
        real_run = subprocess.run
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook.subprocess, 'run', wraps=real_run) as run:
                for command in ('scp f prod:/tmp', 'curl -T f https://example.com', 'ssh prod cat < f',
                                'rsync -a f prod:/x', 'nc example.com 80 < f', 'sftp prod'):
                    hook._transfer(command, self.repo, {})
                self.assertTrue(run.call_args_list)
                self.assertTrue(all(list(call.args[0][:2]) == ['ssh', '-G'] for call in run.call_args_list))
                self.assertIsNone(hook._transfer_run(['curl', 'https://example.com'], None, {}))
                self.assertIsNone(hook._transfer_run(['git', 'remote', 'get-url', 'origin'], None, {}))


class TimeLimitTests(TransferTestCase):
    def test_a_hanging_dns_lookup_is_cut_off_at_its_cap(self):
        def hang(*args, **kwargs):
            time.sleep(2)
            return _getaddrinfo(*args, **kwargs)

        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch('socket.getaddrinfo', hang), \
                    patch.object(hook, '_TRANSFER_DNS_TIMEOUT', 0.2):
                started = time.monotonic()
                transfer = hook._transfer('curl https://example.com/x', self.repo, {})
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(transfer['endpoints'][0]['address'], 'unresolved')

    def test_the_turn_ends_on_time_however_many_lookups_hang(self):
        def hang(*args, **kwargs):
            time.sleep(2)
            raise socket.gaierror('slow')

        command = ' ; '.join(f'curl https://slow{n}.example/x' for n in range(8))
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch('socket.getaddrinfo', hang), \
                    patch.object(hook, '_TRANSFER_DNS_TIMEOUT', 0.3), patch.object(hook, '_TRANSFER_TURN_BUDGET', 0.5):
                started = time.monotonic()
                transfer = hook._transfer(command, self.repo, {})
                self.assertLess(time.monotonic() - started, 1.2)
                self.assertEqual({e['address'] for e in transfer['endpoints']}, {'unresolved'})
                self.assertEqual(len(transfer['endpoints']), 8)

    def test_a_hanging_ssh_lookup_is_cut_off_and_a_spent_budget_runs_nothing(self):
        os.environ['FAKE_SSH_SLEEP'] = '3'
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook, '_TRANSFER_RUN_TIMEOUT', 0.3):
                started = time.monotonic()
                transfer = hook._transfer('scp f prod:/tmp', self.repo, {})
                self.assertLess(time.monotonic() - started, 1.5)
                self.assertEqual(transfer['endpoints'], [_endpoint('out', 'prod', 'unresolved')])
            with self.subTest(hook=hook.__file__, budget='spent'), patch.object(hook.subprocess, 'run') as run, \
                    patch('socket.getaddrinfo') as lookup:
                transfer = hook._transfer('scp f prod:/tmp; curl https://example.com', self.repo,
                                          {'deadline': time.monotonic() - 1})
                self.assertEqual({e['address'] for e in transfer['endpoints']}, {'unresolved'})
                run.assert_not_called()
                lookup.assert_not_called()

    def test_a_failed_or_refused_ssh_lookup_never_falls_back_to_dns(self):
        # The config sends example.com elsewhere, so looking up the alias itself would classify the wrong host.
        Path(self.home, '.ssh', 'config').write_text('Host example.com\n  HostName 10.0.4.12\n')
        Path(self.repo, 'exec.cfg').write_text('Match exec "true"\n')
        for command, sleep in (('scp f example.com:/tmp', '3'), ('scp -F exec.cfg f example.com:/tmp', '0'),
                               ("scp -F '~/cfg' f example.com:/tmp", '0')):
            os.environ['FAKE_SSH_SLEEP'] = sleep
            for hook in HOOKS:
                with self.subTest(hook=hook.__file__, command=command), patch.object(hook, '_TRANSFER_RUN_TIMEOUT', 0.3), \
                        patch('socket.getaddrinfo', side_effect=_getaddrinfo) as lookup:
                    transfer = hook._transfer(command, self.repo, {})
                    self.assertEqual(transfer['endpoints'], [_endpoint('out', 'example.com', 'unresolved')])
                    lookup.assert_not_called()

    def test_any_error_leaves_the_call_without_a_transfer(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook, '_transfer_walk', side_effect=RuntimeError):
                self.assertIsNone(hook._transfer('curl -T f https://example.com', self.repo, {}))

    def test_a_command_too_long_or_nested_too_deep_is_skipped_at_once(self):
        for n in (1000, 3000):  # past the nesting cap, and past the length cap too
            command = 'if true; then ' * n + 'scp f prod:/tmp' + '; fi' * n
            for hook in HOOKS:
                with self.subTest(hook=hook.__file__, n=n):
                    start = time.monotonic()
                    self.assertIsNone(hook._transfer(command, self.repo, {}))
                    self.assertIsNone(hook._transfer_next_cwd(command, self.repo))
                    self.assertLess(time.monotonic() - start, 1.0)


class ParserFindingTests(TransferTestCase):
    """Commands the shell reads in ways easy to get wrong. `cfg` in the repo maps prod to a public address and
    `frontend/cfg` to a private one, so the address shows which folder the lookup ran in."""

    def test_a_short_circuited_subshell_is_skipped_whole(self):
        for command in ('false && (echo skipped; curl -T f https://never.example/x); curl https://actual.example/y',
                        'true || (echo skipped; curl -T f https://never.example/x); curl https://actual.example/y',
                        'false && { echo skipped; curl -T f https://never.example/x; }; curl https://actual.example/y'):
            self.assert_hosts(command, [('in', 'actual.example')])

    def test_a_paren_in_a_case_pattern_does_not_end_the_subshell(self):
        self.assert_endpoints('(cd frontend; case x in y) true;; esac; scp -F cfg f prod:/tmp)',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])

    def test_a_substitution_inside_double_quotes_runs(self):
        self.assert_endpoints('echo "$(cd frontend && scp -F cfg f prod:/tmp)"',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assert_endpoints('echo "ip: `curl -s https://example.com/ip`"', [_endpoint('in', 'example.com', 'public')])

    def test_untaken_branches_and_function_bodies_do_not_run(self):
        self.assert_hosts('if false; then curl https://never.example/a; else curl https://actual.example/b; fi',
                          [('in', 'actual.example')])
        self.assert_hosts('f() { curl -T x https://never.example/a; }; curl https://actual.example/b',
                          [('in', 'actual.example')])
        self.assert_hosts('function f { curl -T x https://never.example/a; }; curl https://actual.example/b',
                          [('in', 'actual.example')])
        for command in ('f () { curl -T x https://never.example/a; }; curl https://actual.example/b',
                        'function f () { curl -T x https://never.example/a; }; curl https://actual.example/b',
                        'if true; then f () { curl https://never.example/a; }; fi; curl https://actual.example/b',
                        '{ f() { curl https://never.example/a; }; }; curl https://actual.example/b',
                        'while true; do g () { curl https://never.example/a; }; break; done; curl https://actual.example/b'):
            self.assert_hosts(command, [('in', 'actual.example')])
        for command in ('if false; then cd frontend; fi; scp -F cfg f prod:/tmp',
                        'f() { cd frontend; }; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'public', '203.0.113.9')])

    def test_a_substitution_under_an_untaken_branch_or_a_function_body_does_not_run(self):
        for command in ('if false; then echo $(curl -T x https://never.example/a); fi; curl https://actual.example/b',
                        'if true; then :; else echo "$(curl https://never.example/a)"; fi; curl https://actual.example/b',
                        'f() { echo "$(curl -T x https://never.example/a)"; }; curl https://actual.example/b',
                        'function f { echo `curl https://never.example/a`; }; curl https://actual.example/b',
                        'while false; do echo $(curl https://never.example/a); done; curl https://actual.example/b'):
            self.assert_hosts(command, [('in', 'actual.example')])
        self.assert_hosts('if [ -f x ]; then echo $(curl https://maybe.example/a); fi', [('in', 'maybe.example')])

    def test_a_negated_command_still_obeys_the_and_or_before_it(self):
        for command in ('false && ! curl -T x https://never.example/a; curl https://actual.example/b',
                        'false && ! echo $(curl https://never.example/a); curl https://actual.example/b',
                        'true || ! echo $(curl https://never.example/a); curl https://actual.example/b'):
            self.assert_hosts(command, [('in', 'actual.example')])
        self.assert_hosts('true && ! curl https://ran.example/a', [('in', 'ran.example')])
        # A skipped `!` must not flip the status of the next command.
        for command, expected in (('false && ! true; false && curl https://never.example/a', []),
                                  ('false && ! true; true && curl https://ran.example/a', [('in', 'ran.example')]),
                                  ('true || ! false; true && curl https://ran.example/a', [('in', 'ran.example')]),
                                  ('if false; then ! true; fi; false && curl https://never.example/a', [])):
            self.assert_hosts(command, expected)

    def test_a_backgrounded_cd_does_not_move_the_next_command(self):
        for command in ('cd frontend & scp -F cfg f prod:/tmp', '{ cd frontend; } & scp -F cfg f prod:/tmp',
                        'if true; then cd frontend; fi & scp -F cfg f prod:/tmp',
                        'cd frontend && true & scp -F cfg f prod:/tmp',
                        'cd frontend | true; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'public', '203.0.113.9')])
        self.assert_endpoints('cd frontend && scp -F cfg f prod:/tmp &', [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        # A backgrounded list inside a compound starts where the compound's body does, after the cd before it.
        for command in ('cd frontend && { true & scp -F cfg f prod:/tmp; }',
                        'cd frontend && { for x in a; do true; done & scp -F cfg f prod:/tmp; }',
                        'cd frontend && if true; then true & scp -F cfg f prod:/tmp; fi'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.0.4.12')])

    def test_a_piped_compound_keeps_its_cd_to_itself(self):
        for command in ('{ cd frontend; } | cat; scp -F cfg f prod:/tmp',
                        'if true; then cd frontend; fi | cat; scp -F cfg f prod:/tmp',
                        'cat x | ( cd frontend ); scp -F cfg f prod:/tmp',
                        'cd frontend && { true; } & scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'public', '203.0.113.9')])
        # zsh runs a pipeline's last command in this shell and bash in a subshell, so what it changes is unknown.
        for command in ('cat x | { true; cd frontend; }; scp -F cfg f prod:/tmp',
                        'cat x | cd frontend; scp -F cfg f prod:/tmp',
                        'f() { cd frontend; }; cat x | f; scp -F cfg f prod:/tmp',
                        'cat x | if true; then cd frontend; fi; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'unresolved', 'prod')])
        self.assert_endpoints('cat x | { cd frontend; scp -F cfg f prod:/tmp; }',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])

    def test_a_cd_that_may_not_have_run_leaves_the_folder_unknown(self):
        # Where a cd hangs on an unknown status, a later relative -F config is not read from a guessed folder.
        unknown = [_endpoint('out', 'prod', 'unresolved', 'prod')]
        for command in ('test -f marker && cd frontend; scp -F cfg f prod:/tmp',
                        'mkdir x && cd frontend && scp -F cfg f prod:/tmp',
                        'if [ -d frontend ]; then cd frontend; fi; scp -F cfg f prod:/tmp',
                        'case x in y) cd frontend;; esac; scp -F cfg f prod:/tmp',
                        '[ -d x ] && { cd frontend; }; scp -F cfg f prod:/tmp',
                        'f() { cd frontend; }; [ -d x ] && f; scp -F cfg f prod:/tmp',
                        'for x in a; do [ -f y ] && break; cd frontend; done; scp -F cfg f prod:/tmp',
                        '[ -d x ] && cd frontend; cd ..; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, unknown)
        # A cd that certainly ran, given the command after it runs, still applies; an absolute one is known again.
        private = [_endpoint('out', 'prod', 'private', '10.0.4.12')]
        for command in ('cd frontend && scp -F cfg f prod:/tmp',
                        'cd frontend; scp -F cfg f prod:/tmp',
                        f'[ -d x ] && cd /tmp; cd {self.repo}/frontend; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, private)
        # Inside a branch that may not run, the cd before a call still applies to it, but the call may not have run,
        # so it is never looked up.
        for command in ('if [ -d frontend ]; then cd frontend; scp -F cfg f prod:/tmp; fi',
                        '[ -d x ] && { cd frontend; scp -F cfg f prod:/tmp; }'):
            self.assert_endpoints(command, unknown)
            for hook in HOOKS:
                calls = hook._transfer_walk(hook._TransferLexer(command).read(), self.repo, {}, 0)
                self.assertEqual([(c[3], c[6]) for c in calls if c[0] == 'scp'],
                                 [(os.path.join(self.repo, 'frontend'), True)])

    def test_a_loop_that_may_repeat_or_a_cd_the_command_may_have_made_leaves_the_folder_unknown(self):
        # A body that runs again repeats its cd; a folder another command names may have been made or removed by it,
        # since the folder is read after the command ran. Neither is guessed.
        unknown = [_endpoint('out', 'prod', 'unresolved', 'prod')]
        for command in ('cd frontend; for x in a b; do cd ..; done; scp -F cfg f prod:/tmp',
                        'cd frontend; for x in a b; do cd ..; continue; done; scp -F cfg f prod:/tmp',
                        'cd frontend; while [ -f y ]; do cd ..; done; scp -F cfg f prod:/tmp',
                        'cd frontend; for x in *.txt; do cd ..; done; scp -F cfg f prod:/tmp',
                        'mkdir nowhere; cd nowhere; cd frontend; scp -F cfg f prod:/tmp',
                        'cd nowhere; cd frontend; scp -F cfg f prod:/tmp',
                        'if [ -f y ]; then f() { cd frontend; }; fi; f; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, unknown)
        for command in ('cd -P frontend; scp -F cfg f prod:/tmp', 'cd -- frontend; scp -F cfg f prod:/tmp',
                        'cd -L frontend; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        public = [_endpoint('out', 'prod', 'public', '203.0.113.9')]
        for command in ('cd frontend; for x in a; do cd ..; done; scp -F cfg f prod:/tmp',
                        'cd frontend; for x in a b; do cd ..; break; done; scp -F cfg f prod:/tmp',
                        'cd frontend; while true; do cd ..; break; done; scp -F cfg f prod:/tmp',
                        'for x in a b; do scp -F cfg f prod:/tmp; done'):
            self.assert_endpoints(command, public)

    def test_return_exit_and_break_leave_the_folder_where_bash_does(self):
        private, public = (_endpoint('out', 'prod', 'private', '10.0.4.12'),
                           _endpoint('out', 'prod', 'public', '203.0.113.9'))
        for command, expected in (('f() { return; cd frontend; }; f; scp -F cfg f prod:/tmp', public),
                                  ('f() { cd frontend; return; cd ..; }; f; scp -F cfg f prod:/tmp', private),
                                  ('for x in a; do break; cd frontend; done; scp -F cfg f prod:/tmp', public),
                                  ('for x in; do cd frontend; done; scp -F cfg f prod:/tmp', public),
                                  ('(cd frontend; exit; cd ..); scp -F cfg f prod:/tmp', public),
                                  ('f() { [ -f y ] && return; cd frontend; }; f; scp -F cfg f prod:/tmp',
                                   _endpoint('out', 'prod', 'unresolved', 'prod'))):
            self.assert_endpoints(command, [expected])

    def test_a_cd_lands_where_bash_and_zsh_both_do_or_leaves_the_folder_unknown(self):
        # -P resolves links (bash takes the last of -L and -P, zsh any -P); a cd every shell rejects stays put, and one
        # the shells land differently on (a second folder, -e, -q) is not guessed.
        os.makedirs(os.path.join(self.repo, 'frontend', 'inner'))
        os.symlink(os.path.join(self.repo, 'frontend', 'inner'), os.path.join(self.repo, 'link'))
        Path(self.repo, 'notes').write_text('a file, not a folder')
        private, public, unknown = (_endpoint('out', 'prod', 'private', '10.0.4.12'),
                                    _endpoint('out', 'prod', 'public', '203.0.113.9'),
                                    _endpoint('out', 'prod', 'unresolved', 'prod'))
        for command, expected in (('cd link; cd ..; scp -F cfg f prod:/tmp', public),
                                  ('cd -P link; cd ..; scp -F cfg f prod:/tmp', private),
                                  ('cd link; cd -P ..; scp -F cfg f prod:/tmp', private),
                                  ('cd -L -P link; cd ..; scp -F cfg f prod:/tmp', private),
                                  ('cd -P -L link; cd ..; scp -F cfg f prod:/tmp', unknown),
                                  ('env -C link/.. scp -F cfg f prod:/tmp', private),
                                  ('cd -Z frontend; scp -F cfg f prod:/tmp', public),
                                  ('cd --physical frontend; scp -F cfg f prod:/tmp', public),
                                  ('cd frontend extra; scp -F cfg f prod:/tmp', unknown),
                                  ('cd frontend -P; scp -F cfg f prod:/tmp', unknown),
                                  ('cd -Pe frontend; scp -F cfg f prod:/tmp', unknown),
                                  ('cd -q frontend; scp -F cfg f prod:/tmp', unknown),
                                  ('cd missing/../frontend; scp -F cfg f prod:/tmp', unknown),
                                  # A cd into a folder that is there succeeds, and one into a file fails and stays, so
                                  # && and || after it follow; a missing folder may have been there when it ran.
                                  ('cd frontend || cd ..; scp -F cfg f prod:/tmp', private),
                                  ('cd nowhere || cd frontend; scp -F cfg f prod:/tmp', unknown),
                                  ('cd nowhere && cd frontend; scp -F cfg f prod:/tmp', unknown),
                                  ('cd notes; scp -F cfg f prod:/tmp', public),
                                  # In double quotes a backslash stays unless it escapes $ ` " \ or a newline.
                                  ('cd "\\frontend"; scp -F cfg f prod:/tmp', unknown),
                                  ('cd "\\~/frontend"; scp -F cfg f prod:/tmp', unknown),
                                  ('cd "front\\\nend"; scp -F cfg f prod:/tmp', private),
                                  # Naming the -F file anywhere else in the turn means no lookup, as it may be rewritten.
                                  ('cd cfg; scp -F cfg f prod:/tmp', unknown),
                                  # A command that only reads inside the folder, such as wc, does not name it.
                                  ('wc -c frontend/notes; cd frontend; scp -F cfg f prod:/tmp', private),
                                  # Every shell fails that cd, so the || after it surely runs.
                                  ('cd -Z frontend || cd frontend; scp -F cfg f prod:/tmp', private),
                                  # An arithmetic for that stops after one pass keeps its cd, unless its body
                                  # touches the counter.
                                  ('for ((i=0;i<1;i++)); do cd frontend; done; scp -F cfg f prod:/tmp', private),
                                  ('for ((i=0;i<1;i++)); do cd frontend; [ -f m ] && i=-1; done; scp -F cfg f prod:/tmp',
                                   unknown),
                                  ('for ((i=0;i<1;i++)); do cd frontend; i=0; break; done; scp -F cfg f prod:/tmp',
                                   private),
                                  ('for ((i=0;i<1;i++)); do echo $i; cd frontend; done; scp -F cfg f prod:/tmp', private),
                                  # A bare cd and a leading ~ go to the shell's HOME. A HOME= in front of cd applies to
                                  # a bare cd, but ~ is expanded before it; a VAR= in front of cd leaves it a cd.
                                  (f'HOME={self.repo}/frontend; cd; scp -F cfg f prod:/tmp', private),
                                  (f'HOME={self.repo}/frontend; cd ~; scp -F cfg f prod:/tmp', private),
                                  (f'HOME={self.repo}; HOME={self.repo}/frontend cd; scp -F cfg f prod:/tmp', private),
                                  (f'HOME={self.repo}; HOME={self.repo}/frontend cd ~; scp -F cfg f prod:/tmp', public),
                                  (f'HOME={self.repo}/frontend; scp -F ~/cfg f prod:/tmp', private),
                                  (f'HOME={self.repo}; HOME={self.repo}/frontend scp -F ~/cfg f prod:/tmp', public),
                                  # A quoted or escaped ~ is a folder named ~, which is not there, so where the
                                  # cd went is not known.
                                  (f"HOME={self.repo}; cd '~/frontend'; scp -F cfg f prod:/tmp", unknown),
                                  (f'HOME={self.repo}; cd \\~/frontend; scp -F cfg f prod:/tmp', unknown),
                                  (f'HOME={self.repo}; cd ~/frontend; scp -F cfg f prod:/tmp', private),
                                  (f"HOME={self.repo}; cd '~root'; scp -F cfg f prod:/tmp", unknown),
                                  # After empty quotes bash leaves a ~ and zsh expands it.
                                  (f"HOME={self.repo}; cd ''~/frontend; scp -F cfg f prod:/tmp", unknown),
                                  # An assignment expands the ~ its value starts with.
                                  (f'HOME={self.repo}/frontend; cd; HOME=~/..; cd; scp -F cfg f prod:/tmp', public),
                                  ('FOO=1 cd frontend; scp -F cfg f prod:/tmp', private)):
            self.assert_endpoints(command, [expected])
        # exec replaces the shell even when what it runs is a builtin, so the scp never runs.
        self.assert_hosts('exec cd frontend; scp -F cfg f prod:/tmp', [])

    def test_pushd_lands_as_cd_does_and_any_other_stack_move_leaves_the_folder_unknown(self):
        private, unknown = (_endpoint('out', 'prod', 'private', '10.0.4.12'), _endpoint('out', 'prod', 'unresolved'))
        for command in ('pushd frontend; scp -F cfg build.zip prod:/srv', 'pushd frontend && scp -F cfg f prod:/tmp',
                        'pushd -- frontend; scp -F cfg f prod:/tmp', 'cd -- frontend; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [private])
        for command in ('pushd frontend; popd; scp -F cfg f prod:/tmp', 'pushd frontend; pushd; scp -F cfg f prod:/tmp',
                        'pushd frontend; pushd +1; scp -F cfg f prod:/tmp', 'pushd -n frontend; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [unknown])

    def test_a_builtin_behind_a_wrapper_that_is_a_program_changes_nothing_here(self):
        # env, sudo, nohup and the like run it as a program of its own, or fail; command and builtin run it here.
        public = [_endpoint('out', 'prod', 'public', '203.0.113.9')]
        for command in ('env cd frontend; scp -F cfg f prod:/tmp', 'sudo cd frontend; scp -F cfg f prod:/tmp',
                        'nohup pushd frontend; scp -F cfg f prod:/tmp', 'nice -n 5 cd frontend; scp -F cfg f prod:/tmp',
                        'timeout 5 cd frontend; scp -F cfg f prod:/tmp', 'env exit; scp -F cfg f prod:/tmp',
                        'nohup source f; scp -F cfg f prod:/tmp', 'env eval x; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, public)
        self.assert_endpoints('builtin export H=1; cd frontend; scp -F cfg f prod:/tmp',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])

    def test_eval_and_source_leave_every_function_unknown(self):
        # Their text may redefine a function, so a call after them may no longer run the body seen before.
        frontend = os.path.join(self.repo, 'frontend')
        for command in (f"f() {{ cd {frontend}; }}; eval 'f() {{ cd {self.repo}; }}'; f; scp -F cfg f prod:/tmp",
                        f"f() {{ cd {frontend}; }}; source x.sh; cd {self.repo}; f; scp -F cfg f prod:/tmp"):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'unresolved', 'prod')])

    def test_a_called_function_runs_its_body_in_the_callers_shell(self):
        private = _endpoint('out', 'prod', 'private', '10.0.4.12')
        public = _endpoint('out', 'prod', 'public', '203.0.113.9')
        for command, expected in (('f() { cd frontend; }; f; scp -F cfg f prod:/tmp', private),
                                  ('f() { scp -F cfg f prod:/tmp; }; cd frontend; f', private),
                                  ('f() { cd frontend; }; f | cat; scp -F cfg f prod:/tmp', public),
                                  ('f() ( cd frontend ); f; scp -F cfg f prod:/tmp', public),
                                  (': $(f() { cd frontend; }); f; scp -F cfg f prod:/tmp', public)):
            self.assert_endpoints(command, [expected])
        # A recursive function is followed a bounded number of times, and the command after it is still read.
        started = time.monotonic()
        self.assert_hosts('f() { f; f; f; f; }; f; curl https://actual.example/b', [('in', 'actual.example')])
        self.assertLess(time.monotonic() - started, 5)


class ShellReadingTests(TransferTestCase):
    """The parts of the shell parser kept from the account resolver."""

    def test_wrappers_exports_and_folders_are_followed(self):
        private = [_endpoint('out', 'prod', 'private', '10.0.4.12')]
        for command in ('cd frontend && scp -F cfg f prod:/tmp',
                        '(cd frontend && scp -F cfg f prod:/tmp)',
                        'if cd frontend; then scp -F cfg f prod:/tmp; fi',
                        '{ cd frontend; scp -F cfg f prod:/tmp; }',
                        'env -C frontend scp -F cfg f prod:/tmp',
                        'timeout -s KILL 30 env -C frontend scp -F cfg f prod:/tmp',
                        'nice -n 10 nohup env -C frontend scp -F cfg f prod:/tmp',
                        "env -S 'scp -F frontend/cfg f prod:/tmp'",
                        'export RSYNC_RSH="ssh -F frontend/cfg"; rsync -a f prod:/tmp'):
            self.assert_endpoints(command, private)
        self.assert_endpoints('(cd frontend; true) && scp -F cfg f prod:/tmp', [_endpoint('out', 'prod', 'public', '203.0.113.9')])

    def test_heredocs_comments_continuations_and_redirections_are_read_as_the_shell_does(self):
        self.assert_hosts("cat > up.sh <<'EOF'\ncurl -T x https://never.example\nEOF\ncurl https://actual.example",
                          [('in', 'actual.example')])
        self.assert_hosts('cd frontend # curl https://never.example\ncurl \\\n  https://actual.example',
                          [('in', 'actual.example')])
        self.assert_hosts('curl https://actual.example 2>&1 | tail -5', [('in', 'actual.example')])
        self.assert_hosts('false && curl https://never.example || curl https://actual.example', [('in', 'actual.example')])
        self.assert_hosts('diff <(curl -s https://never.example) <(curl -s https://actual.example)',
                          [('in', 'never.example'), ('in', 'actual.example')])

    def test_a_command_the_shell_cannot_read_sends_nothing(self):
        self.assert_hosts("curl -T x 'https://example.com", [])
        self.assert_hosts('echo $(curl https://example.com', [])


class CallTimeTests(unittest.TestCase):
    def test_every_log_stamp_becomes_utc_to_the_second(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                self.assertEqual(hook._call_ts('2026-10-22T16:40:00.123456Z'), '2026-10-22T16:40:00Z')
                self.assertEqual(hook._call_ts('2026-10-22T22:10:00.5+05:30'), '2026-10-22T16:40:00Z')
                self.assertEqual(hook._call_ts('2026-10-22T16:40:00'), '2026-10-22T16:40:00Z')
                self.assertIsNone(hook._call_ts('yesterday'))
                self.assertIsNone(hook._call_ts(None))
                self.assertEqual(hook._with_call_ts({'a': 1}, None), {'a': 1})


@unittest.skipIf(os.name == 'nt', 'the fake ssh is a POSIX script')
class EachHookCarriesTheTransferTests(TransferTestCase):
    """Each agent's own exchange builder puts the transfer and the call time on the shell call's tool entry, and the
    same command sends the same field under every agent."""

    COMMAND = 'scp build.zip prod:/srv'
    EXPECTED = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}

    def _check(self, output, ts='2026-10-22T16:40:00Z'):
        entries = _tool_entries(output)
        shell = [e for e in entries if e.get('transfer')]
        self.assertEqual(len(shell), 1, entries)
        self.assertEqual(shell[0]['transfer'], self.EXPECTED)
        self.assertEqual(shell[0].get('ts'), ts)
        self.assertTrue(all(e.get('ts') for e in entries if 'skill_name' not in e), entries)

    def test_claude_code(self):
        hook = load_module('claude-code/hooks/unbound.py')
        events = [
            {'timestamp': '2026-10-22T16:39:58.000001Z',
             'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'session_id': 's1'}},
            {'timestamp': '2026-10-22T16:40:00.250000Z',
             'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': self.COMMAND}, 'tool_response': {}}},
            {'timestamp': '2026-10-22T16:40:01.000000Z',
             'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Read',
                       'tool_input': {'file_path': '/tmp/x'}, 'tool_response': {}}},
        ]
        self._check(hook.build_llm_exchange(events, cwd=self.repo))

    def test_cursor(self):
        hook = load_module('cursor/unbound.py')
        roots = {'workspace_roots': [self.repo], 'conversation_id': 'c1', 'generation_id': 'g1'}
        events = [
            {'timestamp': '2026-10-22T22:09:59+05:30',
             'event': {'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'ship it', **roots}},
            {'timestamp': '2026-10-22T22:10:00.700+05:30',
             'event': {'hook_event_name': 'afterShellExecution', 'command': self.COMMAND, 'cwd': self.repo,
                       'output': '', **roots}},
            {'timestamp': '2026-10-22T22:10:01+05:30',
             'event': {'hook_event_name': 'afterFileEdit', 'file_path': '/tmp/x', 'edits': [], **roots}},
            {'timestamp': '2026-10-22T22:10:02+05:30',
             'event': {'hook_event_name': 'afterAgentResponse', 'text': 'shipped', **roots}},
        ]
        self._check(hook.build_llm_exchange(events))

    def test_a_cursor_command_on_windows_is_read_as_powershell(self):
        # Cursor's agent runs commands in PowerShell there, where a ; inside @{ } separates a hashtable's entries.
        hook = load_module('cursor/unbound.py')
        roots = {'workspace_roots': [self.repo], 'conversation_id': 'c1', 'generation_id': 'g1'}
        command = 'Invoke-WebRequest -Method Post -Body @{a=1; b=2} -Uri https://files.acme-infra.net/up'
        events = [{'timestamp': '2026-10-22T22:09:59+05:30',
                   'event': {'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'ship it', **roots}},
                  {'timestamp': '2026-10-22T22:10:00+05:30',
                   'event': {'hook_event_name': 'afterShellExecution', 'command': command, 'cwd': self.repo,
                             'output': '', **roots}},
                  {'timestamp': '2026-10-22T22:10:02+05:30',
                   'event': {'hook_event_name': 'afterAgentResponse', 'text': 'shipped', **roots}}]
        with patch.object(hook.os, 'name', 'nt'):
            transfers = [e.get('transfer') for e in _tool_entries(hook.build_llm_exchange(events))]
        self.assertEqual(transfers, [{'tool': 'powershell',
                                      'endpoints': [_endpoint('out', 'files.acme-infra.net', 'private')]}])

    def test_copilot(self):
        hook = load_module('copilot/hooks/unbound.py')
        path = Path(tempfile.mkdtemp(), 'events.jsonl')
        lines = [
            {'type': 'user.message', 'id': 'u1', 'timestamp': '2026-10-22T16:39:59.000Z', 'data': {'content': 'ship'}},
            {'type': 'tool.execution_start', 'timestamp': '2026-10-22T16:40:00.123Z',
             'data': {'toolCallId': 'call-1', 'toolName': 'bash', 'arguments': {'command': self.COMMAND}}},
            {'type': 'tool.execution_complete', 'timestamp': '2026-10-22T16:40:01.000Z',
             'data': {'toolCallId': 'call-1', 'success': True, 'result': {'content': ''}}},
            {'type': 'assistant.message', 'timestamp': '2026-10-22T16:40:02.000Z', 'data': {'content': 'shipped'}},
        ]
        path.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        exchange = hook.build_exchange_from_transcript(str(path), 's1', cwd=self.repo)[0]
        self._check(exchange)

    def test_copilot_cloud_runner_gets_the_shorter_budget(self):
        hook = load_module('copilot/hooks/unbound.py')
        shell_state = {'dir': self.repo}
        with patch.object(hook, 'RUNNING_CLOUD', True):
            hook.map_copilot_tool('bash', {'command': self.COMMAND}, '', shell_state=shell_state, root_projects={})
        self.assertLessEqual(shell_state['transfers']['deadline'] - time.monotonic(), 3.0)

    def test_the_copilot_setup_backfill_looks_nothing_up(self):
        # The backfill maps past calls only for MCP provenance, so neither setup runs ssh -G or DNS for them.
        hook = load_module('copilot/hooks/unbound.py')
        lines = [{'type': 'tool.execution_start', 'data': {'toolCallId': f'call-{n}', 'toolName': 'bash',
                                                          'arguments': {'command': command}}}
                 for n, command in enumerate([self.COMMAND, 'curl -T f https://example.com/up'])]
        for setup in [load_module('copilot/hooks/setup.py'), load_module('copilot/hooks/mdm/setup.py')]:
            with self.subTest(setup=setup.__file__), patch.object(setup, '_backfill_load_hook_module', return_value=hook), \
                    patch('socket.getaddrinfo', side_effect=_getaddrinfo) as lookup:
                self.assertEqual(setup._backfill_mcp_tool_provenance(lines), {})
                self.assertEqual(self.ssh_calls(), [])
                lookup.assert_not_called()
        # The same calls mapped as a live turn do look up, so the checks above are not vacuous.
        with patch('socket.getaddrinfo', side_effect=_getaddrinfo) as lookup:
            for line in lines:
                hook.map_copilot_tool('bash', line['data']['arguments'], '', shell_state={'dir': self.repo})
        self.assertTrue(self.ssh_calls())
        lookup.assert_called()

    def test_a_copilot_powershell_call_keeps_a_hashtable_whole(self):
        # A ; inside @{ } separates the hashtable's entries, so the cmdlet keeps its -Uri.
        hook = load_module('copilot/hooks/unbound.py')
        command = 'Invoke-WebRequest -Method Post -Body @{a=1; b=2} -Uri https://example.com/up'
        mapped = hook.map_copilot_tool('powershell', {'command': command}, '', shell_state={'dir': self.repo},
                                       root_projects={})
        self.assertEqual(mapped['transfer'],
                         {'tool': 'powershell', 'endpoints': [_endpoint('out', 'example.com', 'public')]})
        # A cd written inside the hashtable is its text, so the next call starts where this one did.
        shell_state = {'dir': self.repo}
        command = 'iwr -Body @{a=1; cd frontend; b=2} -Uri https://example.com/up'
        hook.map_copilot_tool('powershell', {'command': command}, '', shell_state=shell_state, root_projects={})
        mapped = hook.map_copilot_tool('bash', {'command': 'scp -F cfg f prod:/tmp'}, '', shell_state=shell_state,
                                       root_projects={})
        self.assertEqual(mapped['transfer']['endpoints'], [_endpoint('out', 'prod', 'public', '203.0.113.9')])

    def test_a_forwarded_copilot_powershell_call_keeps_a_hashtable_whole(self):
        # A call sent on an earlier Stop is replayed only to follow the folder, read as an unsent one is.
        hook = load_module('copilot/hooks/unbound.py')
        lines = [{'type': 'user.message', 'id': 'u1', 'timestamp': '2026-10-22T16:39:59.000Z', 'data': {'content': 'go'}}]
        calls = [('powershell', 'iwr -Body @{a=1; cd frontend; b=2} -Uri https://example.com/up'),
                 ('bash', 'scp -F cfg f prod:/tmp')]
        for n, (tool, command) in enumerate(calls):
            lines += [{'type': 'tool.execution_start', 'timestamp': f'2026-10-22T16:40:0{n}.000Z',
                       'data': {'toolCallId': f'call-{n}', 'toolName': tool, 'arguments': {'command': command}}},
                      {'type': 'tool.execution_complete', 'timestamp': f'2026-10-22T16:40:0{n}.500Z',
                       'data': {'toolCallId': f'call-{n}', 'success': True, 'result': {'content': ''}}}]
        events = Path(tempfile.mkdtemp(), 'events.jsonl')
        events.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        output = hook.build_exchange_from_transcript(str(events), 's1', cwd=self.repo, already_forwarded={'call-0'})[0]
        self.assertEqual([e.get('transfer') for e in _tool_entries(output)],
                         [{'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'public', '203.0.113.9')]}])

    def test_a_failed_copilot_call_leaves_the_folder_unknown(self):
        # A command that ran and failed may have stopped anywhere, sent on an earlier Stop or not.
        hook = load_module('copilot/hooks/unbound.py')
        lines = [{'type': 'user.message', 'id': 'u1', 'timestamp': '2026-10-22T16:39:59.000Z',
                  'data': {'content': 'go'}}]
        done = [{'success': False, 'error': {'message': 'exit 1', 'code': 'failure'}},
                {'success': True, 'result': {'content': ''}}]
        for n, (command, result) in enumerate(zip(('cd frontend && npm test', 'scp -F cfg f prod:/tmp'), done)):
            lines += [{'type': 'tool.execution_start', 'timestamp': f'2026-10-22T16:40:0{n}.000Z',
                       'data': {'toolCallId': f'call-{n}', 'toolName': 'bash', 'arguments': {'command': command}}},
                      {'type': 'tool.execution_complete', 'timestamp': f'2026-10-22T16:40:0{n}.500Z',
                       'data': {'toolCallId': f'call-{n}', **result}}]
        events = Path(tempfile.mkdtemp(), 'events.jsonl')
        events.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        unknown = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'unresolved')]}
        for forwarded in (set(), {'call-0'}):
            with self.subTest(forwarded=forwarded):
                output = hook.build_exchange_from_transcript(str(events), 's1', cwd=self.repo,
                                                             already_forwarded=forwarded)[0]
                self.assertEqual([e.get('transfer') for e in _tool_entries(output)][-1], unknown)

    def test_augment(self):
        hook = load_module('augment/hooks/unbound.py')
        post = [{'timestamp': '2026-10-22T16:40:00.9Z',
                 'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                           'tool_input': {'command': self.COMMAND}, 'tool_output': ''}}]
        stop = {'hook_event_name': 'Stop', 'cwd': self.repo, 'conversation_id': 'c1',
                'conversation': {'userPrompt': 'ship it', 'agentTextResponse': 'shipped'}}
        self._check(hook.build_llm_exchange(stop, post))

    def test_codex(self):
        hook = load_module('codex/hooks/unbound.py')
        transcript = os.path.join(tempfile.mkdtemp(), 'rollout.jsonl')
        lines = [
            {'type': 'response_item', 'timestamp': '2026-10-22T16:40:00.321Z',
             'payload': {'type': 'function_call', 'call_id': 'c1', 'name': 'exec_command',
                         'arguments': json.dumps({'cmd': self.COMMAND, 'workdir': self.repo})}},
            {'type': 'response_item', 'timestamp': '2026-10-22T16:40:01Z',
             'payload': {'type': 'function_call_output', 'call_id': 'c1', 'output': ''}},
        ]
        Path(transcript).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        self._check(hook.parse_codex_transcript_for_tools(transcript, None, self.repo))

    def _transfers(self, path, commands):
        """Each Bash command, in order, through one hook's own exchange builder; the transfer of each."""
        hook, lines = load_module(path), []
        if path.startswith('codex/'):
            for n, command in enumerate(commands):
                lines += [{'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                           'payload': {'type': 'function_call', 'call_id': f'c{n}', 'name': 'exec_command',
                                       'arguments': json.dumps({'cmd': command})}},
                          {'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                           'payload': {'type': 'function_call_output', 'call_id': f'c{n}', 'output': ''}}]
            transcript = os.path.join(tempfile.mkdtemp(), 'rollout.jsonl')
            Path(transcript).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
            output = hook.parse_codex_transcript_for_tools(transcript, None, self.repo)
        elif path.startswith('copilot/'):
            lines.append({'type': 'user.message', 'id': 'u1', 'timestamp': '2026-10-22T16:39:59.000Z',
                          'data': {'content': 'ship'}})
            for n, command in enumerate(commands):
                lines += [{'type': 'tool.execution_start', 'timestamp': f'2026-10-22T16:40:0{n}.000Z',
                           'data': {'toolCallId': f'call-{n}', 'toolName': 'bash', 'arguments': {'command': command}}},
                          {'type': 'tool.execution_complete', 'timestamp': f'2026-10-22T16:40:0{n}.500Z',
                           'data': {'toolCallId': f'call-{n}', 'success': True, 'result': {'content': ''}}}]
            lines.append({'type': 'assistant.message', 'timestamp': '2026-10-22T16:40:09.000Z',
                          'data': {'content': 'shipped'}})
            events = Path(tempfile.mkdtemp(), 'events.jsonl')
            events.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
            output = hook.build_exchange_from_transcript(str(events), 's1', cwd=self.repo)[0]
        elif path.startswith('augment/'):
            post = [{'timestamp': f'2026-10-22T16:40:0{n}.9Z',
                     'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                               'tool_input': {'command': command}, 'tool_output': ''}}
                    for n, command in enumerate(commands)]
            stop = {'hook_event_name': 'Stop', 'cwd': self.repo, 'conversation_id': 'c1',
                    'conversation': {'userPrompt': 'ship it', 'agentTextResponse': 'shipped'}}
            output = hook.build_llm_exchange(stop, post)
        else:
            events = [{'timestamp': '2026-10-22T16:39:58.000001Z',
                       'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'session_id': 's1'}}]
            events += [{'timestamp': f'2026-10-22T16:40:0{n}.250000Z',
                        'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                                  'tool_input': {'command': command}, 'tool_response': {}}}
                       for n, command in enumerate(commands)]
            output = hook.build_llm_exchange(events, cwd=self.repo)
        return [e.get('transfer') for e in _tool_entries(output)]

    def test_a_later_call_starts_where_the_shell_really_is(self):
        # A persistent shell keeps a cd between calls, so only a cd that surely ran moves the next call's -F lookup.
        public = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'public', '203.0.113.9')]}
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        unknown = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'unresolved', 'prod')]}
        cases = (('false && cd frontend', public), ('cd frontend', private), ('cd frontend &', public),
                 ('(cd frontend)', public), ('test -f marker && cd frontend', unknown), ('exec cd frontend', public))
        for path in ('claude-code/hooks/unbound.py', 'copilot/hooks/unbound.py'):
            for first, expected in cases:
                with self.subTest(hook=path, first=first):
                    transfers = self._transfers(path, [first, 'scp -F cfg build.zip prod:/srv'])
                    self.assertEqual(transfers[-1], expected)

    def test_a_codex_or_augment_call_starts_in_a_new_shell(self):
        # Each Codex exec_command and Augment launch-process is a new shell, so a cd in one call does not move the next.
        public = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'public', '203.0.113.9')]}
        for path in ('codex/hooks/unbound.py', 'augment/hooks/unbound.py'):
            with self.subTest(hook=path):
                transfers = self._transfers(path, ['cd frontend', 'scp -F cfg build.zip prod:/srv'])
                self.assertEqual(transfers[-1], public)

    def test_an_augment_call_starts_in_its_own_cwd(self):
        hook = load_module('augment/hooks/unbound.py')
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        for cwd in ('frontend', os.path.join(self.repo, 'frontend')):
            post = [{'timestamp': '2026-10-22T16:40:00.9Z',
                     'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                               'tool_input': {'command': 'scp -F cfg build.zip prod:/srv', 'cwd': cwd},
                               'tool_output': ''}}]
            stop = {'hook_event_name': 'Stop', 'cwd': self.repo, 'conversation_id': 'c1',
                    'conversation': {'userPrompt': 'ship it', 'agentTextResponse': 'shipped'}}
            with self.subTest(cwd=cwd):
                entries = _tool_entries(hook.build_llm_exchange(stop, post))
                self.assertEqual([e.get('transfer') for e in entries], [private])

    def test_claude_code_starts_the_walk_where_the_turn_started(self):
        # Claude's Stop carries the folder the turn ended in; replaying the turn's cd from there would miss the folder.
        hook = load_module('claude-code/hooks/unbound.py')
        frontend = os.path.join(self.repo, 'frontend')
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        for command in ('cd frontend && scp build.zip prod:/srv', 'cd frontend && scp -F cfg build.zip prod:/srv'):
            events = [
                {'timestamp': '2026-10-22T16:39:58Z',
                 'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'session_id': 's1',
                           'cwd': self.repo}},
                {'timestamp': '2026-10-22T16:40:00Z',
                 'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_input': {'command': command},
                           'tool_response': {}, 'cwd': frontend}},
            ]
            with self.subTest(command=command):
                entries = _tool_entries(hook.build_llm_exchange(events, cwd=frontend))
                self.assertEqual([e.get('transfer') for e in entries], [private])

    def test_a_failed_claude_bash_call_is_read_and_leaves_the_folder_unknown(self):
        # Claude reports a command that exits non-zero as PostToolUseFailure; it ran, so its upload and its cd may have.
        hook = load_module('claude-code/hooks/unbound.py')
        failed = 'cd frontend && curl -T secret https://files.acme-infra.net/up | grep ok'
        events = [{'timestamp': '2026-10-22T16:40:00Z', 'event': {**fields, 'session_id': 's1'}} for fields in (
            {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'cwd': self.repo},
            {'hook_event_name': 'PostToolUseFailure', 'tool_name': 'Bash', 'error': 'Exit code 1',
             'tool_use_id': 't1', 'tool_input': {'command': failed}},
            {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_response': {}, 'tool_use_id': 't2',
             'tool_input': {'command': 'scp -F cfg build.zip prod:/srv'}})]
        entries = _tool_entries(hook.build_llm_exchange(events, cwd=self.repo))
        self.assertEqual([(e['tool_use_id'], e['tool_input'], e['tool_response']) for e in entries],
                         [('t1', {'command': failed}, {'error': 'Exit code 1'}),
                          ('t2', {'command': 'scp -F cfg build.zip prod:/srv'}, {})])
        self.assertEqual([e.get('transfer') for e in entries],
                         [{'tool': 'curl', 'endpoints': [_endpoint('out', 'files.acme-infra.net', 'private')]},
                          {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'unresolved', 'prod')]}])

    def test_a_claude_background_call_keeps_its_cd_to_itself(self):
        # run_in_background runs the command in a shell of its own; its own lookups still start where the walk is.
        hook = load_module('claude-code/hooks/unbound.py')
        events = [{'timestamp': '2026-10-22T16:40:00Z', 'event': {**fields, 'session_id': 's1'}} for fields in (
            {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'cwd': self.repo},
            {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_response': {},
             'tool_input': {'command': 'cd frontend && scp -F cfg build.zip prod:/srv', 'run_in_background': True}},
            {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_response': {},
             'tool_input': {'command': 'scp -F cfg build.zip prod:/srv'}})]
        transfers = [e.get('transfer') for e in _tool_entries(hook.build_llm_exchange(events, cwd=self.repo))]
        self.assertEqual(transfers, [{'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]},
                                     {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'public', '203.0.113.9')]}])

    def test_claude_code_seeds_the_walk_from_a_prompt_that_carries_a_cwd(self):
        hook = load_module('claude-code/hooks/unbound.py')
        frontend = os.path.join(self.repo, 'frontend')
        events = [{'timestamp': '2026-10-22T16:40:00Z', 'event': {**fields, 'session_id': 's1'}} for fields in (
            {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it'},
            {'hook_event_name': 'UserPromptSubmit', 'prompt': 'and the build', 'cwd': self.repo},
            {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_response': {},
             'tool_input': {'command': 'cd frontend && scp -F cfg build.zip prod:/srv'}})]
        transfers = [e.get('transfer') for e in _tool_entries(hook.build_llm_exchange(events, cwd=frontend))]
        self.assertEqual(transfers, [{'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}])

    def test_claude_code_seeds_the_walk_from_the_turns_first_prompt_only(self):
        # The shell keeps its folder across the turn, so a later prompt's cwd does not move it back.
        hook = load_module('claude-code/hooks/unbound.py')
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}

        def event(name, **fields):
            return {'timestamp': '2026-10-22T16:40:00Z', 'event': {'hook_event_name': name, 'session_id': 's1', **fields}}

        def bash(command):
            return event('PostToolUse', tool_name='Bash', tool_input={'command': command}, tool_response={})

        events = [event('UserPromptSubmit', prompt='ship it', cwd=self.repo), bash('cd frontend'),
                  event('UserPromptSubmit', prompt='and the build', cwd=self.repo),
                  bash('scp -F cfg build.zip prod:/srv')]
        transfers = [e.get('transfer') for e in _tool_entries(hook.build_llm_exchange(events, cwd=self.repo))]
        self.assertEqual(transfers[-1], private)

    def _codex(self, calls):
        """Each (arguments, output or None for none) through Codex's builder; the transfer of each call."""
        hook, lines = load_module('codex/hooks/unbound.py'), []
        for n, (arguments, output) in enumerate(calls):
            lines.append({'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                          'payload': {'type': 'function_call', 'call_id': f'c{n}', 'name': 'exec_command',
                                      'arguments': json.dumps(arguments)}})
            if output is not None:
                lines.append({'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                              'payload': {'type': 'function_call_output', 'call_id': f'c{n}', 'output': output}})
        transcript = os.path.join(tempfile.mkdtemp(), 'rollout.jsonl')
        Path(transcript).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        return [e.get('transfer') for e in _tool_entries(hook.parse_codex_transcript_for_tools(transcript, None, self.repo))]

    def test_a_relative_codex_workdir_is_under_the_session_folder(self):
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        self.assertEqual(self._codex([({'cmd': 'scp -F cfg build.zip prod:/srv', 'workdir': 'frontend'}, '')]), [private])

    def test_a_call_that_never_ran_is_not_looked_up(self):
        # Blocked, denied or rejected before it ran, or with no result at all; a command that ran and failed still is.
        command = 'scp build.zip prod:/srv'
        codex = self._codex([({'cmd': command}, 'Command blocked by PreToolUse hook: no'),
                             ({'cmd': command}, 'exec command rejected by user'), ({'cmd': command}, None)])
        self.assertEqual(codex, [None, None, None])

        copilot, lines = load_module('copilot/hooks/unbound.py'), [
            {'type': 'user.message', 'id': 'u1', 'timestamp': '2026-10-22T16:39:59.000Z', 'data': {'content': 'ship'}}]
        for n, done in enumerate(({'success': False, 'error': {'message': 'no', 'code': 'denied'}},
                                  {'success': False, 'error': {'message': 'no', 'code': 'rejected'}}, None)):
            lines.append({'type': 'tool.execution_start', 'timestamp': f'2026-10-22T16:40:0{n}.000Z',
                          'data': {'toolCallId': f'call-{n}', 'toolName': 'bash', 'arguments': {'command': command}}})
            if done is not None:
                lines.append({'type': 'tool.execution_complete', 'timestamp': f'2026-10-22T16:40:0{n}.500Z',
                              'data': {'toolCallId': f'call-{n}', **done}})
        events = Path(tempfile.mkdtemp(), 'events.jsonl')
        events.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        output = copilot.build_exchange_from_transcript(str(events), 's1', cwd=self.repo)[0]
        self.assertEqual([e.get('transfer') for e in _tool_entries(output)], [None, None, None])

        augment = load_module('augment/hooks/unbound.py')
        post = [{'timestamp': '2026-10-22T16:40:00.9Z',
                 'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                           'tool_input': {'command': command}, 'tool_output': error, 'tool_error': error}}
                for error in ('Failed to launch process: no shell', 'Tool call was denied')]
        stop = {'hook_event_name': 'Stop', 'cwd': self.repo, 'conversation_id': 'c1',
                'conversation': {'userPrompt': 'ship it', 'agentTextResponse': 'shipped'}}
        self.assertEqual([e.get('transfer') for e in _tool_entries(augment.build_llm_exchange(stop, post))],
                         [None, None])
        self.assertEqual(self.ssh_calls(), [])

        ran = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        self.assertEqual(self._codex([({'cmd': command}, 'Process exited with code 1\nOutput:\nlost connection')]), [ran])
        failed = 'Here are the results from executing the command.\n<return-code>\n1\n</return-code>'
        post = [{'timestamp': '2026-10-22T16:40:00.9Z',
                 'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                           'tool_input': {'command': command}, 'tool_output': failed, 'tool_error': failed}}]
        self.assertEqual([e.get('transfer') for e in _tool_entries(augment.build_llm_exchange(stop, post))], [ran])
        lines = lines[:1] + [
            {'type': 'tool.execution_start', 'timestamp': '2026-10-22T16:40:00.000Z',
             'data': {'toolCallId': 'call-x', 'toolName': 'bash', 'arguments': {'command': command}}},
            {'type': 'tool.execution_complete', 'timestamp': '2026-10-22T16:40:00.500Z',
             'data': {'toolCallId': 'call-x', 'success': False, 'error': {'message': 'exit 1', 'code': 'failure'}}}]
        events.write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        output = copilot.build_exchange_from_transcript(str(events), 's1', cwd=self.repo)[0]
        self.assertEqual([e.get('transfer') for e in _tool_entries(output)], [ran])

    def test_a_turn_that_names_an_ssh_config_makes_no_ssh_lookup(self):
        # ssh -G reads the configs at the end of the turn, so a later call that may rewrite one leaves the turn's
        # ssh destinations unresolved; a turn that names none still resolves.
        unknown = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'unresolved')]}
        private = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'private', '10.0.4.12')]}
        for path in ('claude-code/hooks/unbound.py', 'codex/hooks/unbound.py', 'copilot/hooks/unbound.py',
                     'augment/hooks/unbound.py'):
            for second, expected in (("sed -i 's/HostName 203.0.113.9/HostName 10.0.4.12/' ~/.ssh/config", unknown),
                                     ('echo done', private)):
                with self.subTest(hook=path, second=second):
                    self.assertEqual(self._transfers(path, ['scp build.zip prod:/srv', second])[0], expected)
        cursor = load_module('cursor/unbound.py')
        roots = {'workspace_roots': [self.repo], 'conversation_id': 'c1', 'generation_id': 'g1'}
        events = [{'timestamp': '2026-10-22T22:09:59+05:30',
                   'event': {'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'ship it', **roots}},
                  {'timestamp': '2026-10-22T22:10:00+05:30',
                   'event': {'hook_event_name': 'afterShellExecution', 'command': 'scp build.zip prod:/srv',
                             'cwd': self.repo, 'output': '', **roots}},
                  {'timestamp': '2026-10-22T22:10:01+05:30',
                   'event': {'hook_event_name': 'afterFileEdit', 'file_path': os.path.join(self.home, '.ssh', 'config'),
                             'edits': [], **roots}},
                  {'timestamp': '2026-10-22T22:10:02+05:30',
                   'event': {'hook_event_name': 'afterAgentResponse', 'text': 'shipped', **roots}}]
        transfers = [e.get('transfer') for e in _tool_entries(cursor.build_llm_exchange(events)) if e.get('transfer')]
        self.assertEqual(transfers, [unknown])

    def test_a_codex_workdir_does_not_move_later_calls(self):
        # A workdir is that call's own; the next call without one still starts in the session folder.
        hook, lines = load_module('codex/hooks/unbound.py'), []
        calls = [{'cmd': 'true', 'workdir': os.path.join(self.repo, 'frontend')},
                 {'cmd': 'scp -F cfg build.zip prod:/srv'}]
        for n, arguments in enumerate(calls):
            lines += [{'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                       'payload': {'type': 'function_call', 'call_id': f'c{n}', 'name': 'exec_command',
                                   'arguments': json.dumps(arguments)}},
                      {'type': 'response_item', 'timestamp': f'2026-10-22T16:40:0{n}Z',
                       'payload': {'type': 'function_call_output', 'call_id': f'c{n}', 'output': ''}}]
        transcript = os.path.join(tempfile.mkdtemp(), 'rollout.jsonl')
        Path(transcript).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        output = hook.parse_codex_transcript_for_tools(transcript, None, self.repo)
        transfers = [entry.get('transfer') for entry in _tool_entries(output)]
        public = {'tool': 'scp', 'endpoints': [_endpoint('out', 'prod', 'public', '203.0.113.9')]}
        self.assertEqual(transfers[-1], public)

    def test_a_failing_resolver_never_breaks_the_exchange(self):
        hook = load_module('claude-code/hooks/unbound.py')
        events = [{'timestamp': '2026-10-22T16:40:00Z',
                   'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'session_id': 's1'}},
                  {'timestamp': '2026-10-22T16:40:00Z',
                   'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                             'tool_input': {'command': self.COMMAND}, 'tool_response': {}}}]
        with patch.object(hook, '_TransferLexer', side_effect=RuntimeError):
            entries = _tool_entries(hook.build_llm_exchange(events, cwd=self.repo))
        self.assertEqual(len(entries), 1)
        self.assertNotIn('transfer', entries[0])
        self.assertEqual(entries[0]['ts'], '2026-10-22T16:40:00Z')


if __name__ == '__main__':
    unittest.main()
