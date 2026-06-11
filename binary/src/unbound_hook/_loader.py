"""Load the vendored hook / MDM setup modules from source at runtime.

importlib-from-file keeps a single loading path for dev checkouts and the
frozen bundle, and guarantees the binary executes the exact same module
source as the python serving path.
"""

import importlib.util
import sys

from ._resources import hook_source_path, mdm_setup_source_path

_cache = {}


def _load(path, module_name):
    if module_name in _cache:
        return _cache[module_name]
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Register before exec so any self-referential imports resolve.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    _cache[module_name] = module
    return module


def load_hook_module(tool: str):
    safe = tool.replace("-", "_")
    return _load(hook_source_path(tool), f"_unbound_vendored_hook_{safe}")


def load_mdm_setup_module(tool: str):
    safe = tool.replace("-", "_")
    return _load(mdm_setup_source_path(tool), f"_unbound_vendored_mdm_{safe}")
