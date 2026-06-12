"""`unbound-hook hook <tool> [<event>]` — stdin/stdout hook dispatch.

Loads the tool's vendored hook module and runs its main() unchanged: the
module reads the event JSON from stdin and prints its response to stdout,
exactly as the python serving path does. The <event> argument exists because
managed settings register one command per event; the modules dispatch on the
stdin payload's hook_event_name, so argv is routing/diagnostics only.

Fail-open is non-negotiable here: this process sits between the user and
their editor. Any dispatcher-level failure prints neutral JSON and exits 0.
The modules' own main() functions already fail open internally; SystemExit
raised by a module (cursor exits 2 on deny) is propagated untouched.
"""

import sys

from ._resources import TOOLS
from ._loader import load_hook_module


def run(args) -> int:
    if not args or args[0] not in TOOLS:
        # Unknown/missing tool: never block the editor over a bad registration.
        print("{}", flush=True)
        return 0
    tool = args[0]
    try:
        module = load_hook_module(tool)
        module.main()
    except SystemExit:
        # The module decided its own exit code (cursor exits 2 on deny) —
        # that's contract, not failure. Propagate untouched.
        raise
    except Exception:
        print("{}", flush=True)
        return 0
    return 0
