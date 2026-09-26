// The Unbound policy extension for pi. Be honest about what this is:
//
//   * **It is fail-open.** If the Unbound API times out, refuses the connection, answers non-2xx or
//     returns unparseable JSON, the tool call is ALLOWED and the bypass is self-reported. The single
//     exception is an organisation whose last successful response asked for block-on-failure. A
//     policy engine that cannot be reached must not stop a developer working; that trade-off is the
//     product decision, and every bypass leaves an audit trail rather than silence.
//   * **It can never throw.** pi does not guard the handlers it calls: an exception escaping a
//     `tool_call` handler is treated as a decision to BLOCK, and the exception text is handed to the
//     model as the tool result. `user_bash` is worse still — pi rethrows and then declines to run the
//     typed command, rendering nothing. Every handler body below therefore opens `try` before its
//     first statement, with nothing computed, read from `ctx`, or awaited outside it — key resolution
//     and the payload build both touch the filesystem and can fail with EACCES.
//   * **Without a UI it blocks on confirmation.** Under `pi -p` / `--mode json` there is nobody to
//     ask, so a verdict that needs confirmation blocks with an explanatory reason instead of
//     silently allowing or silently denying.
//   * **Without an API key it does nothing at all.** No requests, no verdicts, no blocks — just one
//     notice at session start.
//
// Only the events actually implemented are registered — there is no placeholder handler anywhere,
// because a registered handler is one pi will call and every registration is another way to block or
// hang a session. The tool-result audit, the end-of-turn log and the session heartbeat are still to
// come; a test asserts the registered set, so adding one is a deliberate act.
//
// Built and tested against pi 0.87.1 on Node >= 22.19.0.

import { homedir } from "node:os";

import type { ExtensionAPI, ExtensionFactory } from "@earendil-works/pi-coding-agent";

import { createBreaker } from "../../core/src/breaker.ts";
import { keyFingerprint, readCache, resolveCachePath, writeCache } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import { NO_KEY_NOTICE } from "../../core/src/constants.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { keyState } from "../../core/src/keyState.ts";
import { resolveClientEntrypoint } from "../../core/src/piVersion.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { decideToolCall } from "./decide.ts";
import { notifySafe } from "./ui.ts";
import { decideUserBash } from "./userBash.ts";

/** The injectable seam. Production uses every default; tests replace what they need to observe. */
export interface Deps {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  makeChecker(apiKey: string, baseUrl: string): PolicyChecker;
  /** `undefined` means "resolve the pi version lazily, on first use". */
  entrypoint: string | undefined;
}

interface Resolved {
  apiKey: string | undefined;
  entrypoint: string;
  /** Absent exactly when no key resolved — the inactive state. */
  checker: PolicyChecker | undefined;
}

/**
 * The real composition, and the only place Wave 1's and Wave 2's core mechanisms become reachable
 * from a running extension:
 *
 *   * one client, shared by the policy path and the bypass reporter;
 *   * **one breaker per checker**, i.e. per resolved base URL, so a `UNBOUND_GATEWAY_URL` change (or
 *     a `/reload`) starts clean and one gateway's outage never suppresses another's;
 *   * the **module-scope** `keyState`, handed to both the checker and the reporter — sharing one
 *     instance is the whole point, because "no further HTTP" has to include `/v1/hooks/errors`, which
 *     authenticates with the same rejected key (§F9);
 *   * `onSync` bound to the resolved cache path and identity, so a successful check persists the
 *     policy snapshot for the next session (RES-03).
 *
 * Exported so `compose.test.ts` can assert the per-base-URL breaker directly. `env` / `homeDir`
 * default to values that make `resolveCachePath` refuse, i.e. no cache rather than a cache in the
 * wrong place.
 */
export function defaultMakeChecker(
  apiKey: string,
  baseUrl: string,
  env: NodeJS.ProcessEnv = {},
  homeDir = "",
): PolicyChecker {
  const client = createApiClient({ baseUrl, apiKey });
  const cachePath = resolveCachePath(env, homeDir);
  const fingerprint = keyFingerprint(apiKey);
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
    breaker: createBreaker({ now: Date.now }),
    keyState,
    onSync:
      cachePath === undefined
        ? undefined
        : (snapshot) => {
            // Total by contract: `writeCache` returns false rather than throwing, and `policy.ts`
            // wraps this call anyway — a cache that could not be written is a round trip next
            // session, never a failed tool call.
            void writeCache(cachePath, {
              ...snapshot,
              gateway_url: baseUrl,
              key_fingerprint: fingerprint,
            });
          },
  });
}

/**
 * Warm the in-memory state from disk (RES-03). A missing, unreadable or foreign-identity file is a
 * cold start, never an error — and `policyState.hydrate` refuses to downgrade anything already
 * learned over the network, which is what caps what a planted cache can do (T-09-01/T-09-02).
 */
function hydrateFromCache(
  apiKey: string,
  baseUrl: string,
  env: NodeJS.ProcessEnv,
  homeDir: string,
): void {
  try {
    const cachePath = resolveCachePath(env, homeDir);
    if (cachePath === undefined) return;
    const onDisk = readCache(cachePath, { gatewayUrl: baseUrl, fingerprint: keyFingerprint(apiKey) });
    if (onDisk !== undefined) policyState.hydrate(onDisk);
  } catch {
    // Every call above is already total; this is the belt to their braces.
  }
}

function safeHomeDir(): string {
  try {
    return homedir();
  } catch {
    return "";
  }
}

export function createExtension(overrides: Partial<Deps> = {}): ExtensionFactory {
  const env = overrides.env ?? process.env;
  const homeDir = overrides.homeDir ?? safeHomeDir();
  const deps: Deps = {
    env,
    homeDir,
    // The cache path is resolved from the same env/home pair the key came from, so a test with a
    // temp HOME cannot accidentally read or write the developer's real cache.
    makeChecker:
      overrides.makeChecker ?? ((apiKey, baseUrl) => defaultMakeChecker(apiKey, baseUrl, env, homeDir)),
    entrypoint: overrides.entrypoint,
  };

  let resolved: Resolved | undefined;
  let notified = false;

  /**
   * Lazy and cached. pi loads extensions in invocations that never start a session, and the docs
   * are explicit that the factory must not do work (§A1/§F9) — so the filesystem is first touched
   * by a handler, not at load time.
   */
  function init(): Resolved {
    if (resolved === undefined) {
      const apiKey = resolveApiKey(deps.env, deps.homeDir);
      // One resolution, used for the cache identity, the hydrate and the checker — three call sites
      // that must not be able to disagree, since the base URL is half the cache key (WR-09).
      const baseUrl = apiKey === undefined ? undefined : resolveGatewayUrl(deps.env, deps.homeDir);
      if (apiKey !== undefined && baseUrl !== undefined) {
        hydrateFromCache(apiKey, baseUrl, deps.env, deps.homeDir);
      }
      resolved = {
        apiKey,
        entrypoint: deps.entrypoint ?? resolveClientEntrypoint(deps.env, process.argv[1]),
        checker:
          apiKey === undefined || baseUrl === undefined
            ? undefined
            : deps.makeChecker(apiKey, baseUrl),
      };
    }
    return resolved;
  }

  return (pi: ExtensionAPI) => {
    pi.on("session_start", async (_event, ctx) => {
      try {
        const state = init();
        // One notice per extension instance. pi clears the module cache on `/reload`, so a reload
        // legitimately produces a fresh notice (§A7).
        if (state.apiKey === undefined && !notified) {
          notified = true;
          notifySafe(ctx, NO_KEY_NOTICE, "info");
        }
      } catch {
        // Startup is never worth failing.
      }
      return undefined;
    });

    pi.on("tool_call", async (event, ctx) => {
      try {
        const state = init();
        // No key ⇒ inert. Never a block, never a request (RES-06).
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideToolCall(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          // Bound to the LIVE ctx at the registration, so 09-02's breaker-open and key-rejected
          // notices — raised deep inside `checkTool` — actually reach the editor on this path.
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
        });
      } catch {
        // The fail-open net of last resort: allow, rather than let pi read an exception as a block.
        return undefined;
      }
    });

    pi.on("user_bash", async (event, ctx) => {
      try {
        const state = init();
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideUserBash(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
        });
      } catch {
        // Stricter than the others: pi rethrows out of `emitUserBash` and then declines to run the
        // command at all, with nothing rendered. `undefined` hands execution back instead.
        return undefined;
      }
    });
  };
}

/** What pi actually loads. */
export default createExtension();
