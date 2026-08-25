"""Shared loading for the setup test suite.

Every tool ships its own `unbound.py` and `setup.py`, so a bare `import unbound`
resolves to whichever directory happens to be on sys.path first. Tests load the
module they mean, by repo-relative path, through `load_module` below.
"""

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_CACHE = {}


def load_module(relpath: str):
    """Import a repo file under a name derived from its path, so two tools' modules
    of the same basename can be loaded into one pytest run without colliding."""
    key = str(relpath)
    if key in _CACHE:
        return _CACHE[key]
    path = REPO / relpath
    if not path.exists():
        raise FileNotFoundError(path)
    alias = "unbound_setup_tests." + key.replace("/", "_").replace("-", "_")[:-3]
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec so a module that imports itself by name still resolves.
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    _CACHE[key] = module
    return module


def tool_module(tool: str, kind: str = "unbound"):
    """`tool` is the directory a tool's code lives in, e.g. "claude-code/hooks"."""
    return load_module("%s/%s.py" % (tool, kind))
