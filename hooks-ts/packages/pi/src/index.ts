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
// **The event surface is complete, and splits cleanly in two.** Three events decide, and three
// record:
//
//   | Event         | Role     | Returns                                                |
//   | ------------- | -------- | ------------------------------------------------------ |
//   | `tool_call`   | decide   | `{block, reason}` or `undefined`                       |
//   | `user_bash`   | decide   | a full `BashResult` or `undefined` — never a partial   |
//   | `input`       | decide   | `{action:"handled"}` or `undefined` — never a transform |
//   | `tool_result` | record   | **always `undefined`**                                 |
//   | `agent_end`   | record   | `undefined`, synchronously, POST not awaited            |
//   | `session_start`| record  | `undefined`; one gated heartbeat per process            |
//
// Nothing is registered speculatively: a registered handler is one pi will call, and every
// registration is another way to block or hang a session. `nothrow.test.ts` asserts the exact set and
// `build.test.ts` re-asserts it against the real bundle, so both adding and losing one is a
// deliberate act.
//
// **The two fail-CLOSED exceptions**, against the fail-open default above:
//   * an org whose last successful response asked for `policy_check_failure_action: block` — ours, and
//     the only case where an unreachable API stops a tool call;
//   * a thrown `user_bash` handler — pi's: it rethrows and then declines to run the typed command with
//     nothing rendered, which is why that file's fallback is `undefined` rather than a result.
//
// **The cache** (RES-03) is hydrated from disk at `init()` and written back from `onSync` at `0600`
// under a `gateway_url` + key-fingerprint identity, so one tenant's snapshot can never be read by
// another. It bounds `tools_synced_at` only: an org's fail-open opt-out is honoured regardless of age.
//
// **The audit trail** is hash-only. Tool output is recorded as a sha256 and a byte count and never
// leaves the process; the turn log's `model` is pinned to `"auto"` because the backend drops rows for
// anything else. Two consequences are accepted and documented rather than hidden: tool-output DLP and
// assistant-text DLP cannot fire for pi.
//
// Built and tested against pi 0.87.1 on Node >= 22.19.0.

import { homedir } from "node:os";

import type { ExtensionAPI, ExtensionFactory } from "@earendil-works/pi-coding-agent";

import { createBreaker } from "../../core/src/breaker.ts";
import { keyFingerprint, readCache, resolveCachePath, writeCache } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import type { ApiClient } from "../../core/src/client.ts";
import {
  CACHE_TTL_MS,
  NO_KEY_NOTICE,
  SESSION_PRESENCE_ROW_ENABLED,
} from "../../core/src/constants.ts";
import { buildHeartbeatPayload, createHeartbeatGate } from "../../core/src/heartbeat.ts";
import type { HeartbeatGate } from "../../core/src/heartbeat.ts";
import { buildTurnLogBody } from "../../core/src/turnLog.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { keyState } from "../../core/src/keyState.ts";
import { resolveClientEntrypoint } from "../../core/src/piVersion.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import { turnStore } from "../../core/src/turn.ts";
import { handleAgentEnd } from "./agentEnd.ts";
import { decideToolCall } from "./decide.ts";
import { decideInput } from "./prompt.ts";
import { recordToolResult } from "./toolResult.ts";
import { notifySafe } from "./ui.ts";
import { decideUserBash } from "./userBash.ts";

/**
 * The session id, read defensively: `ctx.sessionManager` is the live object and a fault reading it
 * must not reach the decision path. `""` means "not known", which `startTurn` declines to store —
 * better an unstamped record the turn log then skips than a `conversation_id` of `"undefined"`.
 */
function sessionIdOf(ctx: { sessionManager: { getSessionId(): string } }): string {
  try {
    const id = ctx.sessionManager.getSessionId();
    return typeof id === "string" ? id : "";
  } catch {
    return "";
  }
}

/** `ctx.cwd`, read behind a guard for the same reason. Absent means the column, not the request. */
function safeCwd(ctx: { cwd: string }): string {
  try {
    return typeof ctx.cwd === "string" ? ctx.cwd : "";
  } catch {
    return "";
  }
}

/**
 * `"pi/0.87.1"` → `"0.87.1"`, for `metadata.pi_version`.
 *
 * Derived from the resolved entrypoint rather than resolved a second time: two independent lookups
 * could disagree, and the entrypoint is the value that already survived `sanitizeVersion`.
 */
function versionOf(entrypoint: string): string {
  const slash = entrypoint.indexOf("/");
  return slash === -1 ? entrypoint : entrypoint.slice(slash + 1);
}

/**
 * RES-05's rate limit, at module scope so it outlives a session. `session_start` fires on every
 * session transition, not once per process (§F4), and this is the only thing standing between that and
 * a heartbeat per `/new`. Reset on `/reload`, like every other module-scope latch here.
 */
const processHeartbeatGate: HeartbeatGate = createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS });

/** The injectable seam. Production uses every default; tests replace what they need to observe. */
export interface Deps {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  makeChecker(apiKey: string, baseUrl: string): PolicyChecker;
  /** `undefined` means "resolve the pi version lazily, on first use". */
  entrypoint: string | undefined;
  /**
   * RES-05's rate limit. Defaults to the module-scope instance, which is the right production answer:
   * `session_start` fires on every session transition (§F4) and the limit only means something if it
   * outlives a session.
   *
   * Injectable for the same reason `DecideDeps.state` is — the singleton only moves one way. Once a
   * process has sent its heartbeat, no test in that process can get back to "never sent", so a suite
   * whose cases each expect a cold gate would be silently order-dependent.
   */
  heartbeatGate: HeartbeatGate;
}

interface Resolved {
  apiKey: string | undefined;
  entrypoint: string;
  /** Absent exactly when no key resolved — the inactive state. */
  checker: PolicyChecker | undefined;
  /**
   * The client the **non-decision** events use: the turn log and the heartbeat. Absent exactly when
   * `checker` is.
   *
   * A second instance rather than the checker's, deliberately. `ApiClient` is stateless — the state
   * that matters (the breaker, the key latch) lives in `PolicyChecker` and in the module-scope
   * `keyState` — and the two paths want different postures: a tool call is worth a 20 s wait and a
   * circuit breaker, while a turn log is fire-and-forget telemetry that must never open a circuit on
   * a gateway the decision path still needs. What they DO share is the revoked-key latch, which is
   * why every registration below consults `keyState` before sending (§F9).
   */
  client: ApiClient | undefined;
  /** Rate-limited failure reporting for the turn log. Absent exactly when `checker` is. */
  telemetry: Telemetry | undefined;
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
    heartbeatGate: overrides.heartbeatGate ?? processHeartbeatGate,
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
      const inactive = apiKey === undefined || baseUrl === undefined;
      const client = inactive ? undefined : createApiClient({ baseUrl, apiKey });
      resolved = {
        apiKey,
        entrypoint: deps.entrypoint ?? resolveClientEntrypoint(deps.env, process.argv[1]),
        checker: inactive ? undefined : deps.makeChecker(apiKey, baseUrl),
        client,
        telemetry:
          client === undefined
            ? undefined
            : createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
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
        // RES-05, strictly after the notice logic and strictly fire-and-forget. `session_start` is
        // awaited by pi, so nothing below may be `await`ed: a slow gateway must not delay the session
        // the developer is trying to start.
        if (state.apiKey === undefined || state.client === undefined) return undefined;
        if (keyState.isInactive()) return undefined;
        if (!deps.heartbeatGate.shouldSend(policyState.getFetchedAt())) return undefined;
        // Claimed BEFORE dispatch, like `telemetry.ts`'s rate-limit window: two `session_start`
        // events in the same tick must not both get through.
        deps.heartbeatGate.markSent();

        const payload = buildHeartbeatPayload({
          cwd: safeCwd(ctx),
          sessionId: sessionIdOf(ctx),
          model: ctx.model?.id,
          clientEntrypoint: state.entrypoint,
          hasUI: ctx.hasUI === true,
          piVersion: versionOf(state.entrypoint),
        });
        const client = state.client;
        void client
          .postPretool(payload)
          .then((result) => {
            // The response warms `policy_check_failure_action` only. `recordSuccess` is what
            // structurally refuses to stamp tools-freshness for a body with no `tools_to_check`
            // (§C2/C3), so there is deliberately no special-casing here.
            if (result.ok) policyState.recordSuccess(result.body);
          })
          .catch(() => {
            // A failed heartbeat is a cache miss, never a block and never a notice.
          });

        // The durable half: one `GatewayMetrics` row so "the extension is present" is visible in the
        // console and not only as a Sentry span tag. Behind one constant, per RESEARCH OQ1.
        if (SESSION_PRESENCE_ROW_ENABLED) {
          void client
            .postTurnLog(
              buildTurnLogBody(
                { tool_calls: [], results: [], session_id: sessionIdOf(ctx), started_at: Date.now() },
                { cwd: safeCwd(ctx), completedAtMs: Date.now() },
              ),
            )
            .catch(() => {
              // ditto
            });
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
          onDecision: (entry) => turnStore.recordToolCall(entry, sessionIdOf(ctx)),
        });
      } catch {
        // The fail-open net of last resort: allow, rather than let pi read an exception as a block.
        return undefined;
      }
    });

    // HOOK-06. Registered LAST among the tool events in reading order, and first in importance for
    // one reason: this handler returns `undefined` unconditionally, on every path, for every input.
    // Anything else here rewrites the tool result pi hands the model (`agent-session.js:265-294`).
    pi.on("tool_result", async (event, _ctx) => {
      try {
        // Recorded with or without a key: the record is in-memory only, and `agent_end` is what
        // decides whether anything is ever sent. A hash is cheaper than the branch to skip it.
        recordToolResult(event, turnStore);
      } catch {
        // Unreachable — `recordToolResult` is already total — and kept anyway: the cost of being
        // wrong about that is a rewritten tool result.
      }
      return undefined;
    });

    // RES-04. NOT declared `async` and containing no `await`: this event is part of pi's run
    // settlement (`AC/dist/types.d.ts:418-421`), so the handler hands back a resolved value at once
    // and the POST finishes on its own time under its own 10 s deadline.
    pi.on("agent_end", (event, ctx) => {
      try {
        const state = init();
        // No key ⇒ nothing is sent, and the record is left alone rather than discarded: RES-06's
        // "inert without a key" is about the network, and a `/reload` after adding one should still
        // find a session's worth of context. A rejected key is different — it is permanent for the
        // session, so the record is taken and dropped rather than growing without bound (§F9).
        if (state.apiKey === undefined || state.client === undefined) return undefined;
        if (keyState.isInactive()) {
          turnStore.take();
          return undefined;
        }
        return handleAgentEnd(event, ctx, {
          client: state.client,
          store: turnStore,
          ...(state.telemetry === undefined ? {} : { telemetry: state.telemetry }),
        });
      } catch {
        // Telemetry is never worth a diagnostic on the developer's screen.
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
          onDecision: (entry) => turnStore.recordToolCall(entry, sessionIdOf(ctx)),
        });
      } catch {
        // Stricter than the others: pi rethrows out of `emitUserBash` and then declines to run the
        // command at all, with nothing rendered. `undefined` hands execution back instead.
        return undefined;
      }
    });

    pi.on("input", async (event, ctx) => {
      try {
        const state = init();
        // No key ⇒ the prompt is never suppressed. Silence, not interference.
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideInput(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The turn log's only source for the prompt: `agent_end.messages` is pi's `newMessages`
          // and never contains it (§A4). Called for an ALLOWED prompt only — a suppressed turn
          // produced nothing to log.
          onPrompt: (text) => turnStore.recordPrompt(text, sessionIdOf(ctx)),
        });
      } catch {
        return undefined;
      }
    });
  };
}

/** What pi actually loads. */
export default createExtension();
