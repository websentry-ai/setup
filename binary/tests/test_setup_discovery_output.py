"""WEB-6392: setup now reads the discovery scan's stdout (for the 'Scan skipped:' line) instead of
letting the scan inherit it. A pipe can stall a child that a shared stdout never could, so these run
_run_discovery against real child processes: a big and noisy scan, a grandchild that keeps the pipe
open, and a scan that hangs past the backstop.
"""

import os
import signal
import sys
import time

import pytest

from unbound_hook import setup_cmd

OPTS = {"backend_url": "http://127.0.0.1:9"}
SKIPPED = ("skipped", "another scan is running")


def _scan(tmp_path, monkeypatch, body):
    """Stand in a discovery binary (a python script) and the owner-key lookup it needs."""
    script = tmp_path / "unbound-discovery"
    script.write_text(f"#!{sys.executable}\nimport os, subprocess, sys, time\n"
                      f"PIDS = {str(tmp_path / 'pids')!r}\n{body}")
    script.chmod(0o755)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_BINARY", script)
    monkeypatch.setattr(setup_cmd, "_fetch_device_owner_key", lambda opts: "owner-key")
    return tmp_path / "pids"


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.fixture
def reap():
    """Kills whatever pids a scan wrote down, so no test leaves a process behind."""
    files = []
    yield files.append
    for path in files:
        for pid in (int(p) for p in path.read_text().split()) if path.exists() else ():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


# A child that writes a pid down and keeps the scan's stdout open, as a helper the scan starts might.
SPAWN_HOLDER = ("holder = subprocess.Popen(['sleep', '30'])\n"
                "open(PIDS, 'a').write(f'{holder.pid}\\n')\n")


def test_a_big_scan_whose_grandchild_keeps_the_pipe_is_read_through_and_not_waited_for(
        tmp_path, monkeypatch, capsys, reap):
    # 20 MB of output, the skipped line (CRLF) at line 500, then a grandchild holding the pipe open.
    reap(_scan(tmp_path, monkeypatch,
               "out = sys.stdout.buffer\nline = b'x' * 99 + b'\\n'\n"
               "for _ in range(499): out.write(line)\n"
               "out.write(b'Scan skipped: another scan is running\\r\\n')\n"
               "for _ in range(200000): out.write(line)\n"
               "out.flush()\n" + SPAWN_HOLDER))
    began = time.monotonic()
    assert setup_cmd._run_discovery(OPTS) == SKIPPED
    # Nowhere near the grandchild's 30 s: setup gives a held pipe 5 s, then moves on.
    assert time.monotonic() - began < 15
    out = capsys.readouterr().out
    assert out.count("x" * 99 + "\n") == 200499  # every line reached the MDM log
    assert "Scan skipped: another scan is running" in out


def test_a_scan_past_the_backstop_is_killed_with_its_whole_group_and_deferred(tmp_path, monkeypatch, reap):
    reap(_scan(tmp_path, monkeypatch,
               SPAWN_HOLDER + "open(PIDS, 'a').write(f'{os.getpid()}\\n')\n"
               "print('detecting', flush=True)\ntime.sleep(60)\n"))
    monkeypatch.setattr(setup_cmd, "DISCOVERY_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(setup_cmd, "DISCOVERY_KILL_GRACE_SECONDS", 0)
    began = time.monotonic()
    assert setup_cmd._run_discovery(OPTS) == ("deferred", "discovery exceeded 1s and was terminated")
    assert time.monotonic() - began < 10
    pids = [int(p) for p in (tmp_path / "pids").read_text().split()]
    deadline = time.monotonic() + 5  # an orphaned grandchild is reaped by launchd/init, not by us
    while any(_alive(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not [pid for pid in pids if _alive(pid)], "a scan process outlived the backstop kill"

