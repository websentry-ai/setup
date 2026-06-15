"""`unbound-hook install-daemon` — register the periodic discovery daemon.

On macOS the ai.getunbound.runtime pkg's postinstall owns the LaunchDaemon, so
this is a no-op there (the pkg is the system of record). On Linux there is no
pkg — onboard.sh extracts a tarball and then calls this to install the systemd
equivalent of the launchd job:

  launchd (macOS)                      systemd (Linux)
  ----------------------------------   ----------------------------------------
  ProgramArguments: discovery scan  -> unbound-discovery.service (Type=oneshot)
  RunAtLoad + StartInterval=43200   -> unbound-discovery.timer (12h, Persistent)
  Nice=10 / LowPriorityIO           -> Nice=10 / IOSchedulingClass=idle
  StandardOut/ErrPath /var/log/...  -> StandardOutput=append:/var/log/unbound/..

Fail-open ethos (matches the rest of the fleet tooling): the daemon only adds
the *periodic* re-scan. The hooks (the actual DLP enforcement) and the one-shot
discovery run during `setup` work regardless. So a host without systemd is a
warning + exit 0, never a hard install failure — it must not block onboarding.
The daemon idles fail-open (exit 0) until `setup` writes config, so scheduling
it before onboarding never crash-loops.

System teardown is owned by onboard.sh --clear (the Linux analog of the pkg
uninstall), mirroring how macOS `unbound-hook clear` leaves the system
LaunchDaemon to the pkg. This command only INSTALLS.
"""

import os
import platform
import subprocess
import sys

from ._resources import DISCOVERY_BINARY, HOOK_BINARY

# Mirrors ai.getunbound.discovery.plist verbatim.
SCAN_INTERVAL_SECONDS = 43200  # 12h, == launchd StartInterval
NICE = 10
LOG_DIR = "/var/log/unbound"
SYSTEMD_DIR = "/etc/systemd/system"
SERVICE_UNIT = "unbound-discovery.service"
TIMER_UNIT = "unbound-discovery.timer"
LOGROTATE_PATH = "/etc/logrotate.d/unbound"

USAGE = "Usage: unbound-hook install-daemon [--debug]\n"


def _log(msg: str) -> None:
    print(f"[install-daemon] {msg}")


def _systemd_available() -> bool:
    # The canonical "is systemd the init / running" probe; present on every
    # systemd host, absent in non-systemd containers and on macOS.
    return os.path.isdir("/run/systemd/system")


def _service_unit() -> str:
    # After network-online so the very first scheduled scan can reach the
    # backend; the daemon itself is fail-open if it can't.
    return f"""[Unit]
Description=Unbound coding-agent discovery scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={DISCOVERY_BINARY} scan
Nice={NICE}
IOSchedulingClass=idle
StandardOutput=append:{LOG_DIR}/discovery.log
StandardError=append:{LOG_DIR}/discovery.err.log
"""


def _timer_unit() -> str:
    # OnBootSec gives the launchd RunAtLoad-ish initial run; OnUnitActiveSec is
    # the 12h cadence; Persistent catches up a scan missed while powered off.
    return f"""[Unit]
Description=Unbound discovery scan schedule (every {SCAN_INTERVAL_SECONDS}s)

[Timer]
OnBootSec=2min
OnUnitActiveSec={SCAN_INTERVAL_SECONDS}
Persistent=true

[Install]
WantedBy=timers.target
"""


def _logrotate_conf() -> str:
    # Linux analog of newsyslog-ai.getunbound.conf: 5MB, keep 5, gzip.
    return f"""{LOG_DIR}/*.log {{
    rotate 5
    size 5M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}}
"""


def _write(path: str, content: str, mode: int = 0o644) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)


def run(argv) -> int:
    for a in argv:
        if a != "--debug":
            print(f"Unknown argument: {a}", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 2

    system = platform.system().lower()
    if system != "linux":
        # macOS: the pkg postinstall owns launchd. Anything else: unsupported.
        # Either way this is a deliberate no-op, never an error — onboard.sh
        # only calls it on Linux, but a stray macOS/dev invocation must not fail.
        _log(f"no-op on {system or 'unknown'} (system daemon owned by the platform installer)")
        return 0

    if os.geteuid() != 0:
        print("install-daemon requires root. Re-run with sudo.", file=sys.stderr)
        return 1

    # Pre-warm / smoke-test both binaries before scheduling anything — same
    # contract as the macOS postinstall: a build that can't even print
    # --version must not become a scheduled daemon.
    for exe in (HOOK_BINARY, DISCOVERY_BINARY):
        if not os.access(str(exe), os.X_OK):
            print(f"ERROR: runtime binary missing or not executable: {exe}", file=sys.stderr)
            return 1
        try:
            subprocess.run([str(exe), "--version"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            print(f"ERROR: {exe} failed pre-warm ({e}); not scheduling daemon", file=sys.stderr)
            return 1

    if not _systemd_available():
        # Fail-open: no systemd -> skip the periodic scan, but onboarding
        # (hooks + the setup-time scan) still proceeds. Loud so it's visible
        # in MDM logs, exit 0 so onboard.sh does not abort the install.
        print("::install-daemon: systemd not detected — skipping periodic "
              "discovery timer (hooks + setup scan still active)", file=sys.stderr)
        return 0

    try:
        os.makedirs(LOG_DIR, mode=0o755, exist_ok=True)
        _write(os.path.join(SYSTEMD_DIR, SERVICE_UNIT), _service_unit())
        _write(os.path.join(SYSTEMD_DIR, TIMER_UNIT), _timer_unit())
        _write(LOGROTATE_PATH, _logrotate_conf())

        subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=60)
        # Enable+start the TIMER (not the service): the timer drives the
        # one-shot service on its schedule. The initial scan is also covered by
        # `setup`'s own discovery run, so we don't start the service inline
        # (keeps onboard.sh non-blocking).
        subprocess.run(["systemctl", "enable", "--now", TIMER_UNIT], check=True, timeout=60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        print(f"ERROR: failed to install systemd daemon: {e}", file=sys.stderr)
        return 1

    _log(f"systemd timer {TIMER_UNIT} installed (scan every {SCAN_INTERVAL_SECONDS}s)")
    return 0
