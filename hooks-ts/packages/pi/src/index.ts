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
// Turn logs come from two places. `agent_end` posts the turn the `input` / `tool_call` /
// `tool_result` handlers recorded; `user_bash` posts its `!cmd` as its own one-call row the moment the
// decision is made (`postStandaloneTurn`), because pi fires no `agent_end` for a typed command and a
// stored entry would otherwise ride the next turn's log under that turn's prompt. Neither awaits the
// POST. `tool_call` also sends the turn's prompt as the pretool `messages`, which is what the gateway
// writes a block/warn row from.
//
// **MCP is decided off that table, on `pi.events`.** pi-mcp-adapter (>= 2.21.0) emits
// `pi-mcp-adapter:tool-approval-request` for every MCP call it is about to run — proxy, direct,
// `mcpScript`, resource, iframe — with its own resolution of server, tool and arguments. One listener
// claims it (key present and not latched) and answers `allow_once` / `deny` / `abstain` from the same
// policy check every other call gets (`mcpBroker.ts`, `decideMcpApproval`). `tool_call` makes no MCP
// request and resolves no MCP names; it only remembers in-flight calls so the broker's decision can
// carry the call's id on the audit row. Older adapters, other MCP bridges and a pi without
// `pi.events` are unenforced for MCP.
//
// Nothing is registered speculatively: a registered handler is one pi will call, and every
// registration is another way to block or hang a session. `nothrow.test.ts` asserts the exact set —
// six `pi.on` events plus the one guarded `pi.events` listener — and `build.test.ts` re-asserts it
// against the real bundle, so both adding and losing one is a deliberate act.
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
// **The audit trail** carries tool output, capped and redacted. Each result is recorded as a sha256,
// a byte count and its TEXT parts capped at 8 KB (both ends kept) under a 128 KB per-turn budget;
// image parts are hash and bytes only. The turn log sends that text through `redactSecrets`, so
// tool-output DLP and MCP output audit can fire for pi (gated server-side per org by
// `DLP_SCAN_MCP_PAYLOAD_ORG_IDS` and the org's audit config), and the assistant's own text is already
// sent. Nothing is captured for a keyless or latched session: `recordingActive` is checked before
// `recordToolResult`. The turn log's `model` is pinned to `"auto"` because the backend drops rows for
// anything else.
//
// Built and tested against pi 0.87.1 on Node >= 22.19.0.

import { homedir } from "node:os";

import type { ExtensionAPI, ExtensionFactory } from "@earendil-works/pi-coding-agent";

import { createAccountIdentityLoader } from "../../core/src/accountIdentity.ts";
import type {
  AccountIdentity,
  AccountIdentityLoader,
  AccountIdentityLoaderOptions,
} from "../../core/src/accountIdentity.ts";
import { createBreaker } from "../../core/src/breaker.ts";
import {
  keyFingerprint,
  readCache,
  resolveCachePath,
  resolvePiAgentDir,
  writeCache,
} from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import type { ApiClient } from "../../core/src/client.ts";
import {
  CACHE_TTL_MS,
  MAX_INFLIGHT_MCP_CALLS,
  MCP_TOOL_APPROVAL_REQUEST_EVENT,
  NO_KEY_NOTICE,
  SESSION_PRESENCE_ROW_ENABLED,
} from "../../core/src/constants.ts";
import { NATIVE_FILE_TOOLS } from "../../core/src/payload.ts";
import { buildHeartbeatPayload, createHeartbeatGate } from "../../core/src/heartbeat.ts";
import type { HeartbeatGate } from "../../core/src/heartbeat.ts";
import { buildTurnLogBody } from "../../core/src/turnLog.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { keyState } from "../../core/src/keyState.ts";
import { resolveClientEntrypoint } from "../../core/src/piVersion.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import type { PolicySnapshot } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import { turnStore } from "../../core/src/turn.ts";
import { handleAgentEnd, postStandaloneTurn } from "./agentEnd.ts";
import { decideMcpApproval, decideToolCall } from "./decide.ts";
import type { DecideCtx, McpApprovalAnswer } from "./decide.ts";
import { createInflightCalls, createMcpApprovalListener, mintBrokerId } from "./mcpBroker.ts";
import type { McpBrokerCall } from "./mcpBroker.ts";
import { createMcpConfigReader } from "./mcpConfig.ts";
import { isShellCall } from "./narrow.ts";
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
 * `ctx.model.provider`, read behind a guard. Only the account-identity lookup uses it, to pick the
 * `auth.json` entry the session is actually signed in with.
 */
function modelProviderOf(ctx: { model?: { provider?: unknown } | undefined }): string | undefined {
  try {
    const provider = ctx.model?.provider;
    return typeof provider === "string" && provider.length > 0 ? provider : undefined;
  } catch {
    return undefined;
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
  /**
   * Seams for the account-identity lookup (profile URL, fetch, serial probe, deadline). The agent dir
   * is NOT among them: it is always resolved from `env` / `homeDir`, exactly like the policy cache.
   */
  identity: Omit<AccountIdentityLoaderOptions, "agentDir">;
  /** pi's argv, read only for the adapter's `--mcp-config` flag. Defaults to `process.argv`. */
  argv: readonly string[];
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
  /**
   * RES-03's cache writer, the SAME closure `defaultMakeChecker` hands to `onSync`. Held here so the
   * `session_start` heartbeat can persist what it learned: `policy_check_failure_action` is the one
   * field that turns a failure into a block, the heartbeat is the first thing in a session that can
   * learn it, and in memory alone it does not survive the `/reload` or restart that `hydrateFromCache`
   * exists to serve. Absent when no key resolved, or when no cache path could be resolved at all.
   */
  cacheSync: ((snapshot: PolicySnapshot) => void) | undefined;
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
 *     policy snapshot for the next session (RES-03) — built by `makeCacheSync` above, which the
 *     heartbeat path uses too. One closure, so the two cannot disagree about the identity the file is
 *     bound to; two copies of that binding would be two chances to write a file the reader rejects.
 *
 * Exported so `compose.test.ts` can assert the per-base-URL breaker directly. `env` / `homeDir`
 * default to values that make `resolveCachePath` refuse, i.e. no cache rather than a cache in the
 * wrong place.
 */
export function makeCacheSync(
  apiKey: string,
  baseUrl: string,
  env: NodeJS.ProcessEnv = {},
  homeDir = "",
): ((snapshot: PolicySnapshot) => void) | undefined {
  const cachePath = resolveCachePath(env, homeDir);
  if (cachePath === undefined) return undefined;
  const fingerprint = keyFingerprint(apiKey);
  return (snapshot: PolicySnapshot) => {
    // Total by contract: `writeCache` returns false rather than throwing, and both call sites wrap
    // this anyway — a cache that could not be written is a round trip next session, never a failed
    // tool call and never a failed session start.
    void writeCache(cachePath, {
      ...snapshot,
      gateway_url: baseUrl,
      key_fingerprint: fingerprint,
    });
  };
}

export function defaultMakeChecker(
  apiKey: string,
  baseUrl: string,
  env: NodeJS.ProcessEnv = {},
  homeDir = "",
): PolicyChecker {
  const client = createApiClient({ baseUrl, apiKey });
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey, isInactive: () => keyState.isInactive() }),
    breaker: createBreaker({ now: Date.now }),
    keyState,
    onSync: makeCacheSync(apiKey, baseUrl, env, homeDir),
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
    identity: overrides.identity ?? {},
    argv: overrides.argv ?? process.argv,
  };

  /**
   * Account identity (parity with the Claude Code hook's `account_identity`). Built here, but it
   * touches nothing until `session_start` calls `start()` — the factory stays free of work (§A1).
   * One loader per extension instance, i.e. one lookup per process; `/reload` re-derives it, like
   * every other module-scope latch.
   */
  const identityLoader: AccountIdentityLoader = createAccountIdentityLoader({
    ...deps.identity,
    agentDir: resolvePiAgentDir(env, homeDir),
  });

  /** The settled identity as a spreadable option: `{}` while pending or when there is none. */
  function identityOption(): { accountIdentity?: AccountIdentity } {
    try {
      const identity = identityLoader.current();
      return identity === undefined ? {} : { accountIdentity: identity };
    } catch {
      return {};
    }
  }

  /**
   * MCP enforcement state (see `mcpBroker.ts`). The config reader finds `mcp_server_config` by the
   * broker's exact server name; the in-flight list correlates a brokered call with its `tool_call`
   * for the audit row only. Neither touches anything until a handler or the broker asks.
   */
  const mcpConfigReader = createMcpConfigReader({ env, homeDir, argv: deps.argv });
  const inflight = createInflightCalls(MAX_INFLIGHT_MCP_CALLS);
  /**
   * The most recent ctx a handler saw. The broker request carries none, so the confirm dialog, the
   * notice, the cwd and the session id for a brokered call come from here. Possibly stale after a
   * reload — every read of it goes through a guard, and a stale UI simply means "no UI": deny.
   */
  let lastCtx: DecideCtx | undefined;
  const seeCtx = (ctx: unknown): void => {
    if (ctx !== null && typeof ctx === "object") lastCtx = ctx as DecideCtx;
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
        cacheSync: inactive ? undefined : makeCacheSync(apiKey, baseUrl, deps.env, deps.homeDir),
      };
    }
    return resolved;
  }

  /**
   * Whether anything should be written to the turn record right now.
   *
   * The record is in-memory and process-wide, and `agent_end` is the only thing that drains it — so
   * in any state where `agent_end` will not post, recording is pure accumulation with no reader. It
   * had one: a keyless session never starts a turn, which means even `take()`'s empty-turn guard
   * could not clear `results`, so every tool result of every turn was hashed and kept for the life of
   * the process. A latched session had the same shape one turn later.
   *
   * So: if nothing will ever post this record, nothing records into it.
   */
  function recordingActive(state: Resolved): state is Resolved & { apiKey: string; client: ApiClient } {
    return state.apiKey !== undefined && state.client !== undefined && !keyState.isInactive();
  }

  /** `ctx.model.id`, read behind a guard (a stale ctx's getters throw). */
  function modelIdOf(ctx: DecideCtx | undefined): string | undefined {
    try {
      const id = ctx?.model?.id;
      return typeof id === "string" ? id : undefined;
    } catch {
      return undefined;
    }
  }

  /** Synchronous: claim a broker request only with a key that is present and not latched. */
  function brokerActive(): boolean {
    try {
      const state = init();
      return recordingActive(state) && state.checker !== undefined;
    } catch {
      return false;
    }
  }

  /** Decide one brokered MCP call. Rejections and throws become `abstain` in the listener. */
  async function decideBrokered(call: McpBrokerCall): Promise<McpApprovalAnswer> {
    const state = init();
    if (!recordingActive(state) || state.checker === undefined) return "abstain";
    const ctx = lastCtx;
    const sessionId = ctx === undefined ? "" : sessionIdOf(ctx);
    const cwd = ctx === undefined ? "" : safeCwd(ctx);
    // Audit only: the matching in-flight `tool_call`'s id, or a minted one. Never a verdict input.
    const toolUseId = inflight.claim(call.prefixedToolName, call.originalToolName) ?? mintBrokerId();
    const serverConfig = mcpConfigReader.serverConfig(call.serverName, cwd);
    return decideMcpApproval(
      {
        call: {
          server: call.serverName,
          tool: call.originalToolName,
          args: call.args,
          ...(call.origin === "" ? {} : { origin: call.origin }),
          ...(serverConfig === undefined ? {} : { serverConfig }),
        },
        toolUseId,
        cwd,
        sessionId,
        model: modelIdOf(ctx),
        ui: ctx,
      },
      {
        checker: state.checker,
        apiKey: state.apiKey,
        entrypoint: state.entrypoint,
        ...identityOption(),
        currentPrompt: () => turnStore.currentPrompt(sessionId),
        onDecision: (entry) => {
          if (recordingActive(state)) turnStore.recordToolCall(entry, sessionId);
        },
      },
    );
  }

  return (pi: ExtensionAPI) => {
    // MCP enforcement: the adapter's approval broker, on the shared `pi.events` bus. The one
    // non-`pi.on` registration, and guarded: a pi without `events` (or a stub) simply has no MCP
    // enforcement, never a failed load. Registering a listener does no work — the factory stays
    // free of filesystem and network access (§A1).
    try {
      const events = (pi as unknown as { events?: { on?: unknown } }).events;
      if (events !== null && typeof events === "object" && typeof events.on === "function") {
        (events.on as (channel: string, handler: (data: unknown) => void) => unknown).call(
          events,
          MCP_TOOL_APPROVAL_REQUEST_EVENT,
          createMcpApprovalListener({ active: brokerActive, decide: decideBrokered }),
        );
      }
    } catch {
      // No bus, no MCP enforcement — the other six registrations are unaffected.
    }

    pi.on("session_start", async (_event, ctx) => {
      try {
        // FIRST, before `init()` and before every early return below: a turn record left pending by
        // the previous session cannot belong to this one, and `/new` is exactly when one can be
        // pending (a prompt whose run never ended). Dropped, never posted —
        // nothing says that turn finished, and this handler is awaited by pi, so it is the wrong
        // place for a POST. `reset` keys on the id, so a `/reload` re-firing with the same session
        // and a ctx whose id cannot be read both leave a mid-flight turn alone.
        turnStore.reset(sessionIdOf(ctx));
        // In-flight MCP correlation entries from another session can never match a call in this one.
        inflight.keepSession(sessionIdOf(ctx));
        seeCtx(ctx);

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
        // Fired, never awaited here: the promise settles within its own deadline and is cached, so
        // every later `session_start` gets the same one back. Started before the heartbeat gate so a
        // process whose gate is already closed (a `/reload`) still learns who it is signed in as.
        const identityPending = identityLoader.start(modelProviderOf(ctx));
        if (!deps.heartbeatGate.shouldSend(policyState.getFetchedAt())) return undefined;
        // Claimed BEFORE dispatch, like `telemetry.ts`'s rate-limit window: two `session_start`
        // events in the same tick must not both get through.
        deps.heartbeatGate.markSent();

        // Read from `ctx` now, while this handler still owns it; only the identity is waited for.
        const heartbeatInput = {
          cwd: safeCwd(ctx),
          sessionId: sessionIdOf(ctx),
          model: ctx.model?.id,
          clientEntrypoint: state.entrypoint,
          hasUI: ctx.hasUI === true,
          piVersion: versionOf(state.entrypoint),
        };
        const client = state.client;
        // The heartbeat waits for the identity (bounded by its deadline) so the session's first
        // contact carries the account; `session_start` itself returns immediately.
        void identityPending
          .then((identity) =>
            client.postPretool(
              buildHeartbeatPayload({
                ...heartbeatInput,
                ...(identity === undefined ? {} : { accountIdentity: identity }),
              }),
            ),
          )
          .then((result) => {
            // The response warms `policy_check_failure_action` only. `recordSuccess` is what
            // structurally refuses to stamp tools-freshness for a body with no `tools_to_check`
            // (§C2/C3), so there is deliberately no special-casing here.
            if (!result.ok) return;
            policyState.recordSuccess(result.body);
            // ...and then to disk, through the same identity-bound seam the checker's `onSync` uses.
            // In memory alone, an opt-out learned here died with the process — so a fail-closed org
            // that had only ever been seen by a heartbeat came back up failing OPEN. The snapshot is
            // whatever `recordSuccess` just left, which is why the two-timestamp rule holds for free:
            // no heartbeat shape carries `tools_to_check`, so `tools_synced_at` is either absent or
            // the value hydrated from this same file, never a fresh stamp.
            try {
              state.cacheSync?.(policyState.snapshot());
            } catch {
              // A cache that could not be written costs one round trip next session. It must never
              // cost the developer their session start.
            }
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
        seeCtx(ctx);
        // A non-native, non-shell call may be an MCP tool the adapter will broker: remember it, so
        // the broker handler can put this call's id on the audit row. No request, no resolution —
        // enforcement happens at the broker — and nothing remembered when nothing will be posted.
        if (recordingActive(state) && !isShellCall(event) && !NATIVE_FILE_TOOLS.has(event.toolName)) {
          inflight.remember(
            { toolCallId: event.toolCallId, toolName: event.toolName, input: event.input },
            sessionIdOf(ctx),
          );
        }
        return await decideToolCall(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          // Bound to the LIVE ctx at the registration, so 09-02's breaker-open and key-rejected
          // notices — raised deep inside `checkTool` — actually reach the editor on this path.
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The pretool `messages[0].content`, which the gateway writes its block/warn row from. A
          // cheap getter, not `snapshot()`: this runs on every evaluated tool call.
          currentPrompt: () => turnStore.currentPrompt(sessionIdOf(ctx)),
          // Re-checked here rather than above: `checkTool` may have latched the key on this very
          // call, and the turn that latched is one nothing will post.
          onDecision: (entry) => {
            if (recordingActive(state)) turnStore.recordToolCall(entry, sessionIdOf(ctx));
          },
        });
      } catch {
        // The fail-open net of last resort: allow, rather than let pi read an exception as a block.
        return undefined;
      }
    });

    // HOOK-06. Registered LAST among the tool events in reading order, and first in importance for
    // one reason: this handler returns `undefined` unconditionally, on every path, for every input.
    // Anything else here rewrites the tool result pi hands the model (`agent-session.js:265-294`).
    pi.on("tool_result", async (event, ctx) => {
      try {
        seeCtx(ctx);
        // The call is over: its in-flight correlation entry, if any, can no longer be claimed.
        inflight.forget(event?.toolCallId);
        // The branch IS cheaper than the hash, and it is also the only thing bounding this array: a
        // session that cannot post has no reader for what it records, and `recordToolResult` hashes
        // up to `MAX_HASH_BYTES` of output per call. Checked before the hash, not after it.
        if (!recordingActive(init())) return undefined;
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
        // Inert ⇒ nothing is sent, and the record is TAKEN rather than left: nothing records into it
        // in this state (see `recordingActive`), so there is no "session's worth of context" to
        // preserve for a later `/reload` — only whatever was pending when the session went inert, and
        // pinning that would keep it across every following turn. Covers both inert states: no key
        // (RES-06) and a key the gateway rejected (§F9).
        if (!recordingActive(state)) {
          turnStore.take();
          return undefined;
        }
        return handleAgentEnd(event, ctx, {
          client: state.client,
          store: turnStore,
          ...(state.apiKey === undefined ? {} : { apiKey: state.apiKey }),
          ...(state.telemetry === undefined ? {} : { telemetry: state.telemetry }),
          ...identityOption(),
        });
      } catch {
        // Telemetry is never worth a diagnostic on the developer's screen.
        return undefined;
      }
    });

    pi.on("user_bash", async (event, ctx) => {
      try {
        const state = init();
        seeCtx(ctx);
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideUserBash(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // Posted as its OWN one-call turn log, immediately, and never written into `turnStore`:
          // pi fires no `agent_end` for a `!cmd`, so a stored entry waited for the next agent turn
          // and was posted under that turn's prompt. Fire-and-forget — this handler is awaited, and
          // `postStandaloneTurn` returns before the POST settles. `recordingActive` is re-checked
          // here for the same reason as on `tool_call`: this very call may have latched the key.
          onDecision: (entry) => {
            if (recordingActive(state)) {
              postStandaloneTurn(entry, ctx, sessionIdOf(ctx), {
                client: state.client,
                apiKey: state.apiKey,
                ...(state.telemetry === undefined ? {} : { telemetry: state.telemetry }),
                ...identityOption(),
              });
            }
          },
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
        seeCtx(ctx);
        // No key ⇒ the prompt is never suppressed. Silence, not interference.
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideInput(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
          ...identityOption(),
          hooks: { notify: (message, level) => notifySafe(ctx, message, level) },
          // The turn log's only source for the prompt: `agent_end.messages` is pi's `newMessages`
          // and never contains it (§A4). Called for an ALLOWED prompt only — a suppressed turn
          // produced nothing to log.
          onPrompt: (text) => {
            if (recordingActive(state)) turnStore.recordPrompt(text, sessionIdOf(ctx));
          },
        });
      } catch {
        return undefined;
      }
    });
  };
}

/** What pi actually loads. */
export default createExtension();
