#!/usr/bin/env python3
"""End-to-end proof of skill injection against a real Claude Code process.

Drives the real unbound.py hook against a stub gateway in two phases.

Phase 1 reconciles: the hook posts what it holds to /v1/hooks/skills/sync and writes the
body it gets back. Run explicitly rather than left to the detached SessionStart dispatch,
which would race the first tool call and make this flaky.

Phase 2 injects: the first matching command is denied by identity alone, the agent
invokes the skill, the hook sees that in the transcript and reports the slug loaded, and
the retry is allowed so the original task completes.

Writes to ~/.claude/skills/unbound-<slug>/ because that is what production does. The
directory is removed on exit, and only ever when it carries the .unbound-managed
marker, so a developer's own skill of the same name is never touched.

Usage: python3 run_injection_e2e.py [--model claude-haiku-4-5-20251001] [--keep]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / 'unbound.py'
STUB = Path(__file__).resolve().parent / 'stub_gateway.py'
SLUG = 'e2e-probe-sql'
INSTALL_DIR = Path.home() / '.claude' / 'skills' / ('unbound-' + SLUG)
MARKER = '.unbound-managed'

SKILL_BODY = """---
name: unbound-e2e-probe-sql
description: Organization SQL safety guidance. Use before writing database query code.
---
Use parameterized queries. Never interpolate user input into SQL.
"""


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def cleanup():
    if INSTALL_DIR.exists() and (INSTALL_DIR / MARKER).exists():
        shutil.rmtree(INSTALL_DIR)
    elif INSTALL_DIR.exists():
        print('REFUSING to remove %s: no %s marker, not ours' % (INSTALL_DIR, MARKER))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', default='claude-haiku-4-5-20251001')
    ap.add_argument('--keep', action='store_true')
    args = ap.parse_args()

    if not HOOK.exists():
        sys.exit('hook not found at %s' % HOOK)
    cleanup()

    work = Path(tempfile.mkdtemp(prefix='inject-e2e-'))
    content_file = work / 'skill.md'
    content_file.write_text(SKILL_BODY, encoding='utf-8')
    log = work / 'gateway.json'
    port = free_port()

    # Through the interpreter, not the bare path: setup.py chmods the hook to 0755 when
    # it installs, but the repo copy is not executable and Claude Code would fail to exec it.
    settings = work / 'settings.json'
    settings.write_text(json.dumps({
        'hooks': {
            'PreToolUse': [{
                'matcher': '*',
                'hooks': [{'type': 'command',
                           'command': '%s %s' % (sys.executable, HOOK),
                           'timeout': 30}],
            }],
        },
    }), encoding='utf-8')

    stub = subprocess.Popen([
        sys.executable, str(STUB), '--port', str(port), '--pattern', 'psql',
        '--slug', SLUG, '--content-file', str(content_file), '--log', str(log),
    ])
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        stub.kill()
        sys.exit('stub gateway did not start')

    env = dict(os.environ)
    env['UNBOUND_GATEWAY_URL'] = 'http://127.0.0.1:%d' % port
    env['UNBOUND_CLAUDE_API_KEY'] = 'e2e-stub-key'

    failures = []

    # ── Phase 1: reconcile ────────────────────────────────────────────────────
    sync = subprocess.run([sys.executable, str(HOOK), '--sync-skills'],
                          capture_output=True, text=True, env=env, timeout=60)
    skill_file = INSTALL_DIR / 'SKILL.md'
    if not skill_file.exists():
        failures.append('sync did not install the skill at %s (stderr=%r)'
                        % (skill_file, sync.stderr[-300:]))
    elif skill_file.read_text(encoding='utf-8') != SKILL_BODY:
        failures.append('installed body differs from what the sync endpoint sent')
    if not (INSTALL_DIR / MARKER).exists():
        failures.append('%s marker missing; cleanup cannot claim ownership' % MARKER)
    print('phase 1: installed=%s' % skill_file.exists())

    prompt = ('Run exactly this bash command and report its output: '
              'psql --version || echo PSQL_TASK_DONE')
    try:
        run = subprocess.run(
            ['claude', '-p', '--settings', str(settings), '--model', args.model,
             '--allowed-tools', 'Bash,Skill'],
            input=prompt, capture_output=True, text=True, cwd=str(work),
            env=env, timeout=300,
        )
    finally:
        stub.terminate()
        stub.wait(timeout=10)

    requests = json.loads(log.read_text(encoding='utf-8')) if log.exists() else []
    bash_calls = [r for r in requests
                  if 'psql' in ((r['body'].get('pre_tool_use_data') or {}).get('command') or '')]

    if len(bash_calls) < 2:
        failures.append('expected >=2 matching tool calls, saw %d' % len(bash_calls))
    else:
        first = bash_calls[0]['response']
        if first.get('decision') != 'deny':
            failures.append('first call was not denied: %r' % first)
        # Identity only: a body on this path would mean the gateway is shipping 16KB per
        # matching command again.
        if 'parameterized' in json.dumps(first):
            failures.append('deny carried the skill body: %r' % first)
        for entry in first.get('inject_skills') or []:
            if 'content' in entry:
                failures.append('inject_skills entry carried content: %r' % entry)
        reported = ((bash_calls[0]['body'].get('pre_tool_use_data') or {})
                    .get('metadata') or {}).get('installed_skills') or []
        if SLUG not in [e.get('slug') for e in reported if isinstance(e, dict)]:
            failures.append('device did not report the installed skill: %r' % reported)
        first_loaded = ((bash_calls[0]['body'].get('pre_tool_use_data') or {})
                        .get('metadata') or {}).get('loaded_skills') or []
        if SLUG in first_loaded:
            failures.append('slug reported loaded before injection: %r' % first_loaded)
        last_loaded = ((bash_calls[-1]['body'].get('pre_tool_use_data') or {})
                       .get('metadata') or {}).get('loaded_skills') or []
        if SLUG not in last_loaded:
            failures.append('retry did not report slug as loaded: %r' % last_loaded)
        if bash_calls[-1]['response'].get('decision') == 'deny':
            failures.append('retry was denied; injection did not clear')

    if 'PSQL_TASK_DONE' not in run.stdout and 'psql' not in run.stdout.lower():
        failures.append('original task did not complete; stdout=%r' % run.stdout[-400:])

    print('gateway calls seen: %d (matching: %d)' % (len(requests), len(bash_calls)))
    for i, call in enumerate(bash_calls):
        meta = (call['body'].get('pre_tool_use_data') or {}).get('metadata') or {}
        print('  call %d: decision=%s loaded=%r installed=%r'
              % (i + 1, call['response'].get('decision', 'allow'),
                 meta.get('loaded_skills'), [e.get('slug') for e in
                 (meta.get('installed_skills') or []) if isinstance(e, dict)]))
    print('installed: %s' % skill_file.exists())

    if not args.keep:
        cleanup()
        shutil.rmtree(work, ignore_errors=True)

    if failures:
        print('\nFAIL')
        for f in failures:
            print('  - %s' % f)
        return 1
    print('\nPASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
