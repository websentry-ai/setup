// Where pi keeps its own files — and therefore where the policy cache and `auth.json` are looked for.
//
// Core asks for this through `AgentProfile.resolveAgentDir` and never names pi's directory itself.
// `setup/pi/setup.py` resolves the same directory in Python (`PI_AGENT_DIR_SEGMENTS`,
// `ENV_PI_AGENT_DIR`, `_resolve_agent_dir`); the two must stay in lockstep.

import { isAbsolute, join } from "node:path";

import { expandTilde } from "../../core/src/cache.ts";

/** `join(homedir(), ...)` — pi's default agent dir, `PI/dist/config.js:405-427`. */
export const PI_AGENT_DIR_SEGMENTS = [".pi", "agent"] as const;
/** pi's own relocation hook, tilde-expanded, takes precedence over the default (§A6). */
export const ENV_PI_AGENT_DIR = "PI_CODING_AGENT_DIR";

/**
 * pi's agent dir — `PI_CODING_AGENT_DIR` (tilde-expanded, absolute only) → `~/.pi/agent` — or
 * `undefined` when no safe absolute base exists. The one resolution both the cache and the
 * account-identity reader (`auth.json`) use, so the two can never look in different places.
 *
 * A **relative** `PI_CODING_AGENT_DIR` falls back to the home default rather than resolving against
 * the process cwd. `os.homedir()` can also fail, and the caller's fallback for that is `""`; joining
 * from `""` would put the cache inside the repository pi was started in, where a hostile repo could
 * plant one. Same reasoning, same guard, as `readUnboundConfig` (PR #348 finding 3).
 */
export function resolvePiAgentDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  try {
    let base = expandTilde(env?.[ENV_PI_AGENT_DIR], typeof homeDir === "string" ? homeDir : "");
    if (base === undefined || !isAbsolute(base)) {
      if (typeof homeDir !== "string" || homeDir.length === 0 || !isAbsolute(homeDir)) return undefined;
      base = join(homeDir, ...PI_AGENT_DIR_SEGMENTS);
    }
    return isAbsolute(base) ? base : undefined;
  } catch {
    return undefined;
  }
}
