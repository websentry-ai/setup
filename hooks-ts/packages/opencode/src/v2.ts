// The v2 `setup` entry: present but INACTIVE in Phase 13. It enforces nothing and says so
// (ROADMAP Phase 13 SC5; Phase 14 owns v2 enforcement).
//
// Two hosts call it (13-SPIKES.md V1-2b, V2-1):
//
//   * opencode 1.18.x embeds the v2 core plugin host and calls `setup(ctx)` once per process, in the
//     SAME process where the v1 `server` entry is the one enforcing. Its ctx has no `tool`,
//     `permission` or `session` key. On that host this function must be a pure no-op: no report
//     (the v1 family IS active there), no I/O, no interaction with the `server` sentinel.
//   * `@opencode/cli` 2.x calls `setup(ctx)` and never calls `server`. Its ctx carries `tool` +
//     `permission` and `session`. There the plugin is loaded but nothing is enforced, so it reports
//     `api_family_inactive` once per process, from a later macrotask, so the seat never looks
//     protected without saying otherwise. No heartbeat is sent from here.
//
// Never raises, never rejects, never awaits I/O; its double-report guard is its own `globalThis`
// slot, separate from the `server` sentinel.

import { homedir } from "node:os";

import { createApiClient } from "../../core/src/client.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { createSignalReporter } from "../../core/src/signals.ts";
import { SENTINEL_KEY, SIGNAL_API_FAMILY_INACTIVE } from "./constants.ts";
import { OPENCODE_PROFILE } from "./profile.ts";

/** The `globalThis` slot key of the v2 report-once guard. */
const SETUP_SENTINEL_KEY = `${SENTINEL_KEY}.v2-setup`;
/** Signal label and detail. */
const SETUP_TOOL_LABEL = "setup";
const SETUP_INACTIVE_DETAIL = "v2_setup_inactive";

export interface SetupDeps {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  /** The report-once slot. Default `Symbol.for("unbound.opencode.v2-setup")`. */
  sentinelKey: symbol;
  timeouts?: { errorsMs?: number };
}

export type SetupEntry = (ctx: unknown) => Promise<undefined>;

/** Does this ctx come from a real v2 host (not 1.18's embedded core host)? Total. */
function isV2Context(ctx: unknown): boolean {
  try {
    if (ctx === null || typeof ctx !== "object") return false;
    return ("tool" in ctx && "permission" in ctx) || "session" in ctx;
  } catch {
    return false;
  }
}

export function createSetupV2(overrides: Partial<SetupDeps> = {}): SetupEntry {
  const source: Partial<SetupDeps> = overrides ?? {};
  const sentinelKey = typeof source.sentinelKey === "symbol" ? source.sentinelKey : Symbol.for(SETUP_SENTINEL_KEY);

  function reportInactive(): void {
    const env: NodeJS.ProcessEnv = source.env ?? process.env;
    let homeDir = "";
    try {
      homeDir = typeof source.homeDir === "string" ? source.homeDir : homedir();
    } catch {
      homeDir = "";
    }
    const apiKey = resolveApiKey(env, homeDir, OPENCODE_PROFILE);
    if (apiKey === undefined) return;
    const baseUrl = resolveGatewayUrl(env, homeDir);
    const errorsMs = source.timeouts?.errorsMs;
    const client = createApiClient({
      baseUrl,
      apiKey,
      profile: OPENCODE_PROFILE,
      ...(errorsMs === undefined ? {} : { errorsTimeoutMs: errorsMs }),
    });
    createSignalReporter({ client, profile: OPENCODE_PROFILE, apiKey }).report(SIGNAL_API_FAMILY_INACTIVE, {
      toolName: SETUP_TOOL_LABEL,
      detail: SETUP_INACTIVE_DETAIL,
    });
  }

  return (ctx: unknown): Promise<undefined> => {
    try {
      if (!isV2Context(ctx)) return Promise.resolve(undefined);
      const slot = globalThis as unknown as Record<symbol, unknown>;
      if (slot[sentinelKey] !== undefined) return Promise.resolve(undefined);
      slot[sentinelKey] = true;
      const timer = setTimeout(() => {
        try {
          reportInactive();
        } catch {
          // A report is never worth an uncaught exception.
        }
      }, 0);
      timer.unref?.();
    } catch {
      // Inert.
    }
    return Promise.resolve(undefined);
  };
}

/** The production entry. */
export const setupV2: SetupEntry = createSetupV2();
