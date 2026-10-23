"""Every hook records where each shell transfer went: the tool, and for each place it sent to or fetched from, the host
as written (no login), the host ssh resolves it to, and the kind of address that host has.

The same checks run on all five Python hook copies. ssh -G is answered by a fake `ssh` on PATH that reads `-F` (or
~/.ssh/config under a throwaway home) and logs every call; DNS is answered by a patched `socket.getaddrinfo`. Each
hook's own exchange builder is then driven once to prove the field and the call time ride on its tool entry.
"""
import hashlib
import json
import os
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
START = '# KEEP IN SYNC: transfer resolution'
END = '# --- end transfer resolution ---'
# The cursor-plugin repo's hooks/unbound.py carries the same block and pins the same digest in its own test, so a
# change made in one repo and not the other fails there. Update both together.
BLOCK_SHA256 = '52f01280736b273d3ee79590411b881ccbc3bdd2e94945d6cb2290f8caf96d90'
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
if config != 'none' and os.path.exists(config):
    for line in open(config):
        words = line.split()
        if words and words[0].lower() == 'host':
            current = words[1:]
        elif words and words[0].lower() == 'hostname' and host in current:
            hostname = words[1]
print('hostname ' + overrides.get('hostname', hostname).lower())
print('port ' + overrides.get('port', port))
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

    def ssh_calls(self):
        return [json.loads(line) for line in Path(self.ssh_log).read_text().splitlines()]

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

        def lookup(host, *args, **kwargs):
            if host not in fixture['addresses']:
                raise socket.gaierror(socket.EAI_NONAME, 'unknown host')
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
                    for ip in fixture['addresses'][host]]

        with patch('socket.getaddrinfo', lookup):
            for case in fixture['cases']:
                for hook, transfer in self.each(case['command']):
                    with self.subTest(hook=hook, command=case['command']):
                        self.assertEqual(transfer, case['transfer'])


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
        self.assertEqual(self.ssh_calls()[0]['argv'], ['-G', '--', 'prod'])

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
        command = 'scp -F cfg -P 2222 -o HostName=10.9.9.9 -o Compression=yes -J jump f prod:/tmp'
        self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.9.9.9')])
        self.assertEqual(self.ssh_calls()[0]['argv'],
                         ['-G', '-F', 'cfg', '-p', '2222', '-o', 'HostName=10.9.9.9', '-J', 'jump', '--', 'prod'])

    def test_rsync_reads_its_remote_shell_and_a_daemon_is_never_looked_up(self):
        for command in ('rsync -a -e "ssh -F frontend/cfg -p 2200" src prod:/dest',
                        'RSYNC_RSH="ssh -F frontend/cfg -p 2200" rsync -a src prod:/dest',
                        "rsync -avze 'ssh -F frontend/cfg -p 2200' src prod:/dest --exclude foo:bar"):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assertTrue(all(c['argv'][:5] == ['-G', '-F', 'frontend/cfg', '-p', '2200'] for c in self.ssh_calls()))
        Path(self.ssh_log).write_text('')
        self.assert_hosts('rsync -a src prod::module', [('out', 'prod')])
        self.assert_hosts('rsync -a -e /usr/local/bin/custom-shell src prod:/dest', [('out', 'prod')])
        self.assertEqual(self.ssh_calls(), [])

    def test_bracketed_ipv6_and_scp_uris_resolve_without_their_login(self):
        self.assert_endpoints('scp -F none dump.sql deploy@[fd12:3456:789a::1]:/tmp/',
                              [_endpoint('out', 'fd12:3456:789a::1', 'private')])
        self.assert_endpoints(f'scp dump.sql scp://deploy:{FAKE_TOKEN}@prod:2200/tmp/',
                              [_endpoint('out', 'prod', 'private', '10.0.4.12')])
        self.assertIn(['-p', '2200'], [c['argv'][1:3] for c in self.ssh_calls()])
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

    def test_a_system_config_that_could_run_commands_is_never_handed_to_ssh(self):
        program_data = tempfile.mkdtemp()
        os.makedirs(os.path.join(program_data, 'ssh'))
        Path(program_data, 'ssh', 'ssh_config').write_text('Match exec "touch /tmp/never"\n')
        with patch.dict(os.environ, {'PROGRAMDATA': program_data}):
            self.assert_endpoints('scp f prod:/tmp', [_endpoint('out', 'prod', 'unresolved')])
        self.assertEqual(self.ssh_calls(), [])

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

    def test_a_tilde_config_path_is_expanded_as_the_shell_does(self):
        Path(self.home, 'alt_cfg').write_text('Host prod\n  HostName 10.9.8.7\n')
        self.assert_endpoints('scp -F ~/alt_cfg f prod:/tmp', [_endpoint('out', 'prod', 'private', '10.9.8.7')])

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

    def test_any_error_leaves_the_call_without_a_transfer(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook, '_transfer_walk', side_effect=RuntimeError):
                self.assertIsNone(hook._transfer('curl -T f https://example.com', self.repo, {}))


class ParserFindingTests(TransferTestCase):
    """Each of these was read wrong before: a command bash never runs was resolved, or one it runs was missed, or a
    command ran in a folder bash never moved to. `cfg` in the repo maps prod to a public address, `frontend/cfg` to a
    private one, so the address shows which folder the lookup ran in."""

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
                        'cat x | { true; cd frontend; }; scp -F cfg f prod:/tmp',
                        'if true; then cd frontend; fi | cat; scp -F cfg f prod:/tmp',
                        'cd frontend && { true; } & scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, [_endpoint('out', 'prod', 'public', '203.0.113.9')])
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
                        'if [ -d frontend ]; then cd frontend; scp -F cfg f prod:/tmp; fi',
                        '[ -d x ] && { cd frontend; scp -F cfg f prod:/tmp; }',
                        f'[ -d x ] && cd /tmp; cd {self.repo}/frontend; scp -F cfg f prod:/tmp'):
            self.assert_endpoints(command, private)

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
