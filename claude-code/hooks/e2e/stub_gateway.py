#!/usr/bin/env python3
"""Stub of the two gateway endpoints the device talks to, for the end-to-end harness.

Stands in for ai-gateway so the harness proves the device half, meaning the hook, Claude
Code and the filesystem, without a live backend. The gateway's own matching is unit-tested
in that repo.

The deny text below is copied verbatim from ai-gateway buildInjectionDeny. If that wording
changes, this stub stops proving what the device actually receives.
"""
import argparse
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {'requests': [], 'pattern': None, 'slug': None, 'content': None, 'log': None}
LOCK = threading.Lock()


def _sha256():
    return hashlib.sha256(STATE['content'].encode()).hexdigest()


def _decide_pretool(body):
    """Mirror the gateway's decision order closely enough to drive the device."""
    data = body.get('pre_tool_use_data') or {}
    metadata = data.get('metadata') or {}
    command = data.get('command') or ''
    if body.get('event_name') == 'user_prompt':
        return {}
    if not re.search(STATE['pattern'], command):
        return {}
    if STATE['slug'] in (metadata.get('loaded_skills') or []):
        return {}

    # Never deny toward a skill the device cannot invoke: ask it to reconcile instead.
    installed = {
        e.get('slug'): e.get('sha256')
        for e in (metadata.get('installed_skills') or [])
        if isinstance(e, dict)
    }
    if installed.get(STATE['slug']) != _sha256():
        return {'decision': 'allow', 'sync_skills': True}

    if metadata.get('already_injected_this_turn'):
        return {}

    reason = (
        "This tool call needs guidance loaded first, per your organization's policy.\n"
        'Invoke the skill unbound-%s, then retry this exact tool call.' % STATE['slug']
    )
    return {
        'decision': 'deny',
        'reason': reason,
        'additionalContext': (
            reason + ' '
            'This is not a permanent restriction and not an error to work around: do not '
            'rephrase the command, do not switch to another tool, and do not ask the user '
            'how to proceed. '
            'Policies can change per request; do not save this guidance to memory or any '
            'persistent user or agent config.'
        ),
        'inject_skills': [{'slug': STATE['slug'], 'sha256': _sha256()}],
    }


def _plan_sync(body):
    """The reconcile plan: the body travels here and nowhere else."""
    installed = {
        e.get('slug'): e.get('sha256')
        for e in (body.get('installed') or [])
        if isinstance(e, dict)
    }
    if installed.get(STATE['slug']) == _sha256():
        return {'install': [], 'remove': []}
    return {
        'install': [{
            'slug': STATE['slug'],
            'sha256': _sha256(),
            'content': STATE['content'],
        }],
        'remove': [],
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        try:
            body = json.loads(raw or b'{}')
        except json.JSONDecodeError:
            body = {}
        if self.path.rstrip('/').endswith('/skills/sync'):
            response = _plan_sync(body)
        else:
            response = _decide_pretool(body)
        with LOCK:
            STATE['requests'].append({'body': body, 'response': response})
            # Flushed per request, not at shutdown: the harness kills this process
            # with a signal, so an atexit write would never land.
            with open(STATE['log'], 'w', encoding='utf-8') as fh:
                json.dump(STATE['requests'], fh, indent=1)
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--pattern', required=True)
    ap.add_argument('--slug', required=True)
    ap.add_argument('--content-file', required=True)
    ap.add_argument('--log', required=True)
    args = ap.parse_args()

    STATE['log'] = args.log
    STATE['pattern'] = args.pattern
    STATE['slug'] = args.slug
    with open(args.content_file, encoding='utf-8') as fh:
        STATE['content'] = fh.read()

    server = HTTPServer(('127.0.0.1', args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
