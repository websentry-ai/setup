// The opencode plugin module: ONE default export and nothing else.
//
//   * `id` — required for a file plugin by the v1 loader (`resolvePluginId`, 13-SPIKES.md V1-2:
//     without it the load fails, log-only).
//   * `server` — the v1 entry (opencode 1.18.x): the enforcing one.
//   * `setup` — the v2 entry (opencode 2.x): inert on a 1.18 host, active on a v2 host (v2.ts).
//
// No other export: the v1 legacy path rejects a non-function named export, and a module that
// evaluates is all the loader needs. Nothing here performs I/O at module evaluation.

import { PLUGIN_ID } from "./constants.ts";
import { createServerPlugin } from "./plugin.ts";
import { setupV2 } from "./v2.ts";

const plugin = { id: PLUGIN_ID, server: createServerPlugin(), setup: setupV2 };

export default plugin;
