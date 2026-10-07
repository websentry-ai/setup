// The opencode v1 plugin factory (`server`) and the runtime behind it. Be honest about what this is:
//
//   * **It is fail-open.** If the Unbound API times out, refuses the connection, answers non-2xx or
//     unparseable JSON, the tool call is ALLOWED and the bypass is self-reported. The one exception
//     is an org whose last successful response asked for `policy_check_failure_action: block`.
//   * **On v1 an escaped raise IS a deny.** opencode turns an error out of `tool.execute.before` into
//     a failed tool part the model reads (`oc:opencode/src/plugin/index.ts:284-297`). So every hook
//     body here is total and the only deliberate raise lives in `block.ts`, called from the decision
//     files only (`test/throwSites.test.ts`).
//   * **`server()` does no I/O and awaits nothing.** The v1 loader awaits the factory with no timeout
//     and only LOGS a failure (`oc:opencode/src/plugin/index.ts:219-242`); Bun also caches a failed
//     import for the process lifetime. A factory that hangs, raises or touches the filesystem is a
//     silent bypass, invisible to the user (Pitfall 3). So key, gateway, cache and checker resolve
//     lazily on the first hook call, and a fault inside the factory resolves a DEGRADED hook set that
//     allows everything and reports `init_degraded` — server-visible, never a silent empty load.
//   * **One copy per process.** `plugin/` and `plugins/` can both hold a copy (Pitfall 15). The
//     sentinel `globalThis[Symbol.for("unbound.opencode")]` holds the MODULE token of the first copy
//     to load, defined non-writable / non-configurable / non-enumerable; a second copy of the SAME
//     build gets `{}` and reports `duplicate_load`. The same copy serving another directory is not a
//     duplicate: opencode calls `server()` once per project directory while the module is evaluated
//     once (13-SPIKES.md V1-9), so the sentinel keys on the module, never on a call count. Anything
//     else found in the slot (a project plugin can plant one) never disables this copy: it keeps
//     enforcing and reports `sentinel_tampered` (13-REVIEW WR-04). v2 re-evaluates the module per
//     directory (14-SPIKES.md V2-12) but never calls `server()`, so this sentinel is v1-only; a v2
//     guard must not key on a per-evaluation token.
//   * **State is scoped, never process-global.** One opencode process serves several projects.
//     Policy memory and the revoked-key latch come from core's `createScopedStates()` (per gateway
//     URL + key fingerprint, 12-REVIEW.md WR-03), the breaker from `createBreakerRegistry().forUrl`,
//     the turn record from `createSessionStates()` (by session id) and the heartbeat gate / no-key
//     latch from `createInstanceStates()` (by absolute directory). "Once" behaviour in those
//     registries needs an absolute directory and a non-empty session id (12-03 notes).
//   * **Without an API key it does nothing** but show one notice per directory (13-05), and looks
//     for a key again every `NO_KEY_RETRY_MS`, so a key added later works without a restart. A fault
//     while resolving is not "no key": it shows its own notice, reports `init_degraded` once and is
//     retried after `INIT_RETRY_MS` (13-REVIEW WR-03).
//
// Module scope holds only the module token; everything else is per factory.

import { homedir } from "node:os";

import { createBreakerRegistry } from "../../core/src/breakerRegistry.ts";
import { keyFingerprint, readCache, resolveCachePath, writeCache } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import type { ApiClient } from "../../core/src/client.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { createAccountIdentityLoader } from "../../core/src/accountIdentity.ts";
import type {
  AccountIdentity,
  AccountIdentityLoader,
  AccountIdentityLoaderOptions,
} from "../../core/src/accountIdentity.ts";
import { MAX_ASSISTANT_CHARS, MAX_TRACKED_INSTANCES, MAX_TRACKED_SESSIONS } from "../../core/src/constants.ts";
import { createKeyedState } from "../../core/src/keyedState.ts";
import { capCommand } from "../../core/src/payload.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import type { PolicySnapshot } from "../../core/src/policyState.ts";
import type { AgentAuthSummary } from "../../core/src/profile.ts";
import { createScopedStates } from "../../core/src/scopedState.ts";
import type { ScopedState, ScopedStates } from "../../core/src/scopedState.ts";
import { createInstanceStates, createSessionStates, directoryKey } from "../../core/src/sessionState.ts";
import type { InstanceStates, SessionStates } from "../../core/src/sessionState.ts";
import { createSignalReporter } from "../../core/src/signals.ts";
import type { SignalReporter } from "../../core/src/signals.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import type { TurnRecord, TurnStore } from "../../core/src/turn.ts";
import { readOpencodeAuthSummary } from "./auth.ts";
import { toolExecuteBefore } from "./before.ts";
import {
  ENTRYPOINT_PREFIX,
  SENTINEL_KEY,
  SIGNAL_DUPLICATE_LOAD,
  SIGNAL_INIT_DEGRADED,
  SIGNAL_SENTINEL_TAMPERED,
  UNKNOWN_ENTRYPOINT,
} from "./constants.ts";
import type { HooksLike, ServerFactory } from "./hostTypes.ts";
import { chatMessage } from "./prompt.ts";
import { OPENCODE_PROFILE, resolveOpencodeDataDir } from "./profile.ts";
import { eventHandler, toolExecuteAfter } from "./record.ts";
import { shellEnv } from "./userShell.ts";

// The build's own token: a content hash of the bundle's sources, injected by `scripts/build.mjs`
// (esbuild `define`). Unbuilt source (tests) gets `"source"`. It is not a secret: it only means that
// a foreign plugin has to read the installed bundle to forge a holder (13-REVIEW WR-04).
declare const __UNBOUND_OPENCODE_BUILD__: string | undefined;
export const BUILD_TOKEN: string =
  typeof __UNBOUND_OPENCODE_BUILD__ === "string" && __UNBOUND_OPENCODE_BUILD__ !== ""
    ? __UNBOUND_OPENCODE_BUILD__
    : "source";

/**
 * Does `value` look like a build token `scripts/build.mjs` defines (the first 32 hex characters of a
 * sha256 of the sources)? A frozen, non-configurable holder carrying one that is not ours is another
 * genuine build of this plugin (an in-place upgrade, or a managed copy beside a newer user copy), not
 * tampering (14-REVIEW IN-07).
 */
export function isBuildToken(value: unknown): boolean {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

/** A copy's sentinel holder: frozen, branded with the module key and the build token. */
export function createModuleToken(buildToken: string = BUILD_TOKEN): object {
  return Object.freeze({ module: SENTINEL_KEY, build: buildToken });
}

/** The token of THIS module copy. A second evaluated copy of the bundle has a different one. */
const MODULE_TOKEN: object = createModuleToken();

/** The most MCP server names kept per directory. A real config has a handful. */
const MAX_MCP_SERVER_NAMES = 1024;
/** At most one runtime MCP server-list refresh per directory in this window. */
const MCP_REFRESH_INTERVAL_MS = 10_000;
/** A runtime MCP server-list refresh that has not answered by then is ignored. */
const MCP_REFRESH_TIMEOUT_MS = 2_000;
/** The most allowed-call digests kept per session (HOOK-18); the oldest is dropped first. */
const MAX_DIGESTS_PER_SESSION = 256;
/** How far up a parent chain `rootOf` walks before it stops (a real chain is one or two deep). */
const MAX_PARENT_DEPTH = 8;
/** The longest model string kept per session. */
const MAX_MODEL_CHARS = 256;
/** The most call ids any one per-session id set keeps; the oldest is dropped first. */
const MAX_IDS_PER_SESSION = 512;
/** The most message roles remembered per session. */
const MAX_MESSAGES_PER_SESSION = 256;
/** The most assistant text parts kept per session between idles; the oldest is dropped first. */
const MAX_ASSISTANT_PARTS = 32;
/** The most bash commands stashed per session awaiting `shell.env`; the oldest is dropped first. */
const MAX_SHELL_STASH_PER_SESSION = 32;

/** The injectable seam. Production uses every default; tests replace what they need to observe. */
export interface Deps {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  /** Policy memory + revoked-key latch per (gateway, key). Never the process singletons. */
  scopes: ScopedStates;
  now: () => number;
  /** Replaces the real checker (tests). Called at most once per plugin copy. */
  makeChecker?(apiKey: string, baseUrl: string): PolicyChecker;
  timeouts?: { pretoolMs?: number; turnLogMs?: number; errorsMs?: number };
  /** `EvaluateDeps.deadlineMs`; defaults to core's 20 s + slack. */
  deadlineMs?: number;
  /** Signal reporter window per category; defaults to core's. */
  signalIntervalMs?: number;
  /** Account-identity loader options (serial probe seams, deadline). Tests pin the platform. */
  identity?: Partial<Omit<AccountIdentityLoaderOptions, "agentDir" | "readAuth">>;
  /** The `globalThis` slot of the double-load sentinel. Default `Symbol.for(SENTINEL_KEY)`. */
  sentinelKey: symbol;
  /** This copy's identity in that slot. Default: the module token (`createModuleToken()`). */
  moduleToken: object;
  /** The build token a genuine holder must carry. Default: `BUILD_TOKEN`. */
  buildToken: string;
  /**
   * Replaces the opencode credential-store reader (`auth.json` / `OPENCODE_AUTH_CONTENT`) the
   * identity loader uses. The v2 entry passes one that reads nothing, so identity stays
   * provider-level and no credential database is ever opened (14-SPIKES HV2-07).
   */
  readAuth?: (dataDir: string | undefined, provider: string | undefined) => AgentAuthSummary | undefined;
}

/**
 * What `init()` resolved. Every member below `status` is absent unless `status` is `"active"`.
 *
 *   * `active`     — a key resolved and every piece was built; cached for the copy's lifetime.
 *   * `no_key`     — no key found anywhere. Re-resolved after `NO_KEY_RETRY_MS`, so a key added to
 *                    `~/.unbound/config.json` later is picked up without restarting opencode.
 *   * `init_error` — something raised while resolving (13-REVIEW WR-03). Re-resolved after
 *                    `INIT_RETRY_MS`; reported once as `init_degraded` / `resolve_fault`.
 */
export interface Resolved {
  status: "active" | "no_key" | "init_error";
  apiKey: string | undefined;
  baseUrl: string | undefined;
  /** The (gateway, key) scope: hand `scope.policy` to `evaluateToolCall`, `scope.key` to latches. */
  scope: ScopedState | undefined;
  client: ApiClient | undefined;
  checker: PolicyChecker | undefined;
  telemetry: Telemetry | undefined;
  signals: SignalReporter | undefined;
  /** RES-03's cache writer, bound to this scope's identity. */
  cacheSync: ((snapshot: PolicySnapshot) => void) | undefined;
}

/** Per project directory: what the decision path needs from the host instance. */
export interface DirectoryRecord {
  /** The canonical absolute directory, or `""` when the host gave none usable. */
  readonly directory: string;
  /** The instance's SDK client (toasts). Untrusted; only `notify()` touches it. */
  client: unknown;
  /** `Object.keys(config.mcp)` from the `config` hook, read-only snapshot. */
  mcpServerNames: string[];
  /**
   * Server names the host reported at runtime (`client.mcp.status()`), which also covers servers
   * added through `POST /mcp` that never appear in the config. Refreshed lazily, never blocking.
   */
  liveMcpServerNames: string[];
  /** When the last runtime refresh started (`deps.now()`), or `undefined` before the first one. */
  mcpRefreshedAt: number | undefined;
  /** The init-error notice (WR-03) was shown for this directory. */
  initErrorNoticeShown: boolean;
  /** Bumped by every `server()` call for the directory; only the latest hook set may release. */
  generation: number;
}

/** The runtime one plugin copy shares across its directories. */
export interface Runtime {
  readonly deps: Readonly<Omit<Deps, "env" | "homeDir">>;
  /** Lazy, cached, total. */
  init(): Resolved;
  readonly sessions: SessionStates;
  readonly instances: InstanceStates;
  /** `opencode/<version>` once the host version is known, else `opencode/unknown`. */
  entrypoint(): string;
  /** Set from `session.created` `info.version` (13-06). */
  hostVersion: string | undefined;
  /** Whether a turn record would ever be posted: key present and not latched. */
  recordingActive(): boolean;
  /** A rate-limited signal; no-op without a key. */
  reportSignal(category: string, toolName: string, detail?: string): void;
  /** A signal sent at most once per plugin copy; no-op without a key. */
  reportOnce(category: string, toolName: string, detail?: string): void;
  /**
   * The turn record a session's decisions go to: its ROOT session's record (Pitfall 6), so a
   * subagent's tool calls roll up into the turn that spawned it. For a child the store is a thin view
   * that records under the root's id, because core's store rolls a record over when a different
   * session id arrives.
   */
  turnFor(sessionID: string): TurnStore;
  /** Remember the `provider/model` a session's prompt used (bounded). */
  setModel(sessionID: string, model: string): void;
  /** The model a session (or, for a child, its root) is using, once a prompt named it. */
  modelFor(sessionID: string): string | undefined;
  /** Start loading the account identity for a provider (first call wins; fire-and-forget). */
  startIdentity(provider: string | undefined): void;
  /** The settled account identity, or `undefined` while pending / when there is none. */
  identity(): AccountIdentity | undefined;
  /** Record a session's parent (only a non-empty `info.parentID` makes a child). */
  setParent(sessionID: string, parentID: unknown): void;
  /** True when the session is a known child (subagent) session. */
  isChild(sessionID: string): boolean;
  /** The root of a session's parent chain (depth ≤ 8, cycle-safe); the session itself if unknown. */
  rootOf(sessionID: string): string;
  /** Remember the args digest of an ALLOWED call, for the after-hook comparison (HOOK-18). */
  rememberDigest(sessionID: string, callID: string, digest: string | undefined): void;
  /** Take (and forget) a remembered digest. */
  takeDigest(sessionID: string, callID: string): string | undefined;
  /** Claim the one audited result of a call: true the first time, false after (and on a fault). */
  markResulted(sessionID: string, callID: string): boolean;
  /** Remember a message's role (`message.updated`). */
  setRole(sessionID: string, messageID: string, role: string): void;
  /** A remembered message role, or `undefined`. */
  roleOf(sessionID: string, messageID: string): string | undefined;
  /** Keep the latest text of one assistant text part (bounded). */
  setAssistantPart(sessionID: string, partID: string, text: string): void;
  /** The session's assistant text since the last take, parts joined with `\n`; clears it. */
  takeAssistantText(sessionID: string): string;
  /** Drop everything kept for a session (`session.deleted`). A pending turn is NOT posted. */
  releaseSession(sessionID: string): void;
  /** Note that `tool.execute.before` ran for a call (so `shell.env` never re-checks it). */
  markBeforeSeen(sessionID: string, callID: string): void;
  /** Whether `tool.execute.before` ran for a call. */
  beforeSeen(sessionID: string, callID: string): boolean;
  /** Stash a bash part's command by callID (bounded, short-lived; latest non-empty wins). */
  stashUserShell(sessionID: string, callID: string, command: string): void;
  /** Take (and forget) a stashed bash command. */
  takeUserShell(sessionID: string, callID: string): string | undefined;
  /** Forget a stashed bash command (the part reached a final status). */
  dropUserShell(sessionID: string, callID: string): void;
  /** Every MCP server name known for a directory: config order first, then runtime-only names. */
  mcpServerNamesFor(record: DirectoryRecord): string[];
  /**
   * Ask the host for its live MCP server list (rate-limited, bounded, fire-and-forget). The current
   * call never waits for it; a later call sees the result.
   */
  refreshMcpNames(record: DirectoryRecord): void;
}

/** Read-only test seam, attached to the factory as a NON-enumerable `inspect` property. */
export interface PluginInspector {
  /** How many times `init()` actually resolved: 1 once active; more only after no-key / fault retries. */
  resolveCount(): number;
  hasChecker(): boolean;
  instance(dir: string): { directory: string; mcpServerNames: string[] } | undefined;
  /** A copy of a session's turn record. */
  turn(sessionID: string): TurnRecord;
  runtime(): Runtime;
}

export type ServerPlugin = ServerFactory & { readonly inspect: PluginInspector };

/** How long a resolution that raised is kept before the next hook call tries again. */
export const INIT_RETRY_MS = 5_000;
/** How long "no key found" is kept before the next hook call looks again. */
export const NO_KEY_RETRY_MS = 30_000;

const NO_KEY: Resolved = Object.freeze({
  status: "no_key",
  apiKey: undefined,
  baseUrl: undefined,
  scope: undefined,
  client: undefined,
  checker: undefined,
  telemetry: undefined,
  signals: undefined,
  cacheSync: undefined,
});

const INIT_ERROR: Resolved = Object.freeze({
  status: "init_error",
  apiKey: undefined,
  baseUrl: undefined,
  scope: undefined,
  client: undefined,
  checker: undefined,
  telemetry: undefined,
  signals: undefined,
  cacheSync: undefined,
});

function safeHomeDir(): string {
  try {
    return homedir();
  } catch {
    return "";
  }
}

/** `Object.keys(cfg.mcp)` as strings, or `[]` for anything that is not a plain object. Total. */
function mcpServerNamesOf(cfg: unknown): string[] {
  try {
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) return [];
    const mcp: unknown = (cfg as { mcp?: unknown }).mcp;
    if (mcp === null || typeof mcp !== "object" || Array.isArray(mcp)) return [];
    const names: string[] = [];
    for (const key of Object.keys(mcp)) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (typeof key === "string" && key !== "") names.push(key);
    }
    return names;
  } catch {
    return [];
  }
}

/** A copy of a server-name list: non-empty strings only, bounded. Total. */
function mcpServerNamesFromList(list: readonly unknown[]): string[] {
  try {
    const names: string[] = [];
    for (const name of list) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (typeof name === "string" && name !== "" && !names.includes(name)) names.push(name);
    }
    return names;
  } catch {
    return [];
  }
}

/** The server names of a `client.mcp.status()` answer (`{ data: { <name>: status } }`). Total. */
function liveMcpNamesOf(answer: unknown): string[] | undefined {
  try {
    if (answer === null || typeof answer !== "object") return undefined;
    const data: unknown = (answer as { data?: unknown }).data;
    if (data === null || typeof data !== "object" || Array.isArray(data)) return undefined;
    const names: string[] = [];
    for (const key of Object.keys(data)) {
      if (names.length >= MAX_MCP_SERVER_NAMES) break;
      if (key !== "") names.push(key);
    }
    return names;
  } catch {
    return undefined;
  }
}

/** Run `fn` on a later macrotask, unref'd, with every fault swallowed. */
function later(fn: () => void): void {
  try {
    const timer = setTimeout(() => {
      try {
        fn();
      } catch {
        // A deferred report is never worth an uncaught exception.
      }
    }, 0);
    timer.unref?.();
  } catch {
    // No timer, no report.
  }
}

/** Per-session bookkeeping beyond the turn record. Every collection is bounded by its writer. */
export interface SessionExtras {
  /** `provider/model` from the session's latest prompt. */
  model?: string;
  /** The parent session id, for a child (subagent) session. */
  parent?: string;
  /** Call ids whose result was already audited (one result per call). */
  resulted: Set<string>;
  /** messageID → role, from `message.updated`. */
  roles: Map<string, string>;
  /** partID → latest assistant text of that part, in first-seen order. */
  assistant: Map<string, string>;
  /** Call ids that passed through `tool.execute.before` (model-issued). */
  before: Set<string>;
  /** callID → command of a bash part, until `shell.env` takes it or the part finishes. */
  shell: Map<string, string>;
}

function freshRecord(directory: string): DirectoryRecord {
  return {
    directory,
    client: undefined,
    mcpServerNames: [],
    liveMcpServerNames: [],
    mcpRefreshedAt: undefined,
    initErrorNoticeShown: false,
    generation: 0,
  };
}

function freshExtras(): SessionExtras {
  return {
    resulted: new Set<string>(),
    roles: new Map<string, string>(),
    assistant: new Map<string, string>(),
    before: new Set<string>(),
    shell: new Map<string, string>(),
  };
}

/** Set `key` in an insertion-ordered map, dropping the oldest past `max`. */
function boundedSet(map: Map<string, string>, key: string, value: string, max: number): void {
  if (!map.has(key)) {
    while (map.size >= max) {
      const oldest = map.keys().next().value;
      if (oldest === undefined) break;
      map.delete(oldest);
    }
  }
  map.set(key, value);
}

/**
 * One part's text as kept: whole up to twice the turn-log cap, otherwise its head and tail at the
 * cap each. The turn-log builder keeps both ends of the joined text at `MAX_ASSISTANT_CHARS`, so
 * nothing it could send is lost, and memory stays bounded however long the answer streams.
 */
function keepText(text: string): string {
  if (text.length <= MAX_ASSISTANT_CHARS * 2) return text;
  return text.slice(0, MAX_ASSISTANT_CHARS) + text.slice(text.length - MAX_ASSISTANT_CHARS);
}

/** Add `id` to an insertion-ordered set, dropping the oldest past `max`. */
function boundedAdd(set: Set<string>, id: string, max: number): void {
  set.add(id);
  while (set.size > max) {
    const oldest = set.values().next().value;
    if (oldest === undefined) break;
    set.delete(oldest);
  }
}

/**
 * A view of a root session's turn store for one of its child sessions: everything is recorded under
 * the ROOT id. Core's store treats a different session id as a new conversation and rolls the record
 * over, which would drop the root's prompt the moment a subagent made a call. `reset` is a no-op: a
 * child must never discard its root's turn.
 */
function rollUp(store: TurnStore, root: string): TurnStore {
  return {
    startTurn: (_sessionId, now) => store.startTurn(root, now),
    reset: () => undefined,
    recordPrompt: (text, _sessionId, now) => store.recordPrompt(text, root, now),
    recordToolCall: (entry, _sessionId, now) => store.recordToolCall(entry, root, now),
    recordResult: (entry) => store.recordResult(entry),
    currentPrompt: () => store.currentPrompt(root),
    take: () => store.take(),
    isEmpty: () => store.isEmpty(),
    snapshot: () => store.snapshot(),
  };
}

/**
 * One adapter runtime plus its directory records, built without I/O. `createServerPlugin` (v1) and
 * the v2 `setup` entry each build theirs through `createRuntime`, so key resolution, scoped state,
 * sessions, signals and identity have one implementation (14-CONTEXT design constraints).
 */
export interface RuntimeHandle {
  readonly runtime: Runtime;
  /**
   * The record of a directory (one per canonical absolute directory; `""` for an unusable one),
   * with `client` set. `mcpServerNames`, when given, replaces the record's config snapshot; when
   * omitted the previous snapshot is kept (v1 `server()` never resets it, 13-REVIEW BL-01).
   */
  recordFor(directory: unknown, client: unknown, mcpServerNames?: readonly string[]): DirectoryRecord;
  /** The stored record of a directory, or `undefined`. */
  peekRecord(directory: unknown): DirectoryRecord | undefined;
  /** Drop a directory's record. */
  releaseRecord(directory: unknown): void;
  /** How many times `init()` actually resolved. */
  resolveCount(): number;
  /** Whether the current resolution has a checker. */
  hasChecker(): boolean;
}

export function createRuntime(overrides: Partial<Deps> = {}): RuntimeHandle {
  // Construction reads no env value and no home directory: both are read on the first hook call.
  const source: Partial<Deps> = overrides ?? {};
  const deps: Readonly<Omit<Deps, "env" | "homeDir">> = Object.freeze({
    scopes: source.scopes ?? createScopedStates(),
    now: typeof source.now === "function" ? source.now : Date.now,
    ...(source.makeChecker === undefined ? {} : { makeChecker: source.makeChecker }),
    ...(source.timeouts === undefined ? {} : { timeouts: source.timeouts }),
    ...(source.deadlineMs === undefined ? {} : { deadlineMs: source.deadlineMs }),
    ...(source.signalIntervalMs === undefined ? {} : { signalIntervalMs: source.signalIntervalMs }),
    sentinelKey: typeof source.sentinelKey === "symbol" ? source.sentinelKey : Symbol.for(SENTINEL_KEY),
    moduleToken: source.moduleToken ?? MODULE_TOKEN,
    buildToken: typeof source.buildToken === "string" && source.buildToken !== "" ? source.buildToken : BUILD_TOKEN,
  });

  const breakers = createBreakerRegistry({ now: deps.now });
  const sessions = createSessionStates();
  const instances = createInstanceStates({ now: deps.now });
  const records = createKeyedState<DirectoryRecord>({
    max: MAX_TRACKED_INSTANCES,
    normalizeKey: directoryKey,
    create: (directory) => freshRecord(directory),
    fallback: () => freshRecord(""),
  });

  // Per-session bookkeeping: bounded sessions; every member is itself bounded.
  const extras = createKeyedState<SessionExtras>({
    max: MAX_TRACKED_SESSIONS,
    create: () => freshExtras(),
    fallback: () => freshExtras(),
  });

  // Per-session digests of allowed calls: bounded sessions, each a bounded insertion-ordered map.
  const digests = createKeyedState<Map<string, string>>({
    max: MAX_TRACKED_SESSIONS,
    create: () => new Map<string, string>(),
    fallback: () => new Map<string, string>(),
  });

  let resolved: Resolved | undefined;
  /** When a non-active `resolved` may be re-resolved (`deps.now()` time). */
  let retryAt = 0;
  let resolveCount = 0;
  let identityLoader: AccountIdentityLoader | undefined;

  /** The identity loader, created on first use with the DATA dir and an env-aware reader. */
  function loaderOf(): AccountIdentityLoader {
    if (identityLoader === undefined) {
      const env: NodeJS.ProcessEnv = source.env ?? process.env;
      const homeDir: string = "homeDir" in source && typeof source.homeDir === "string" ? source.homeDir : safeHomeDir();
      identityLoader = createAccountIdentityLoader({
        ...(source.identity ?? {}),
        agentDir: resolveOpencodeDataDir(env, homeDir),
        readAuth:
          typeof source.readAuth === "function"
            ? source.readAuth
            : (dataDir, provider) => readOpencodeAuthSummary(dataDir, provider, env),
      });
    }
    return identityLoader;
  }
  const reportedOnce = new Set<string>();

  /** What a resolution learnt before it raised, so the fault can still be reported. */
  interface Progress {
    apiKey?: string;
    baseUrl?: string;
  }

  function resolveNow(progress: Progress): Resolved {
    const env: NodeJS.ProcessEnv = source.env ?? process.env;
    const homeDir: string = "homeDir" in source && typeof source.homeDir === "string" ? source.homeDir : safeHomeDir();
    const apiKey = resolveApiKey(env, homeDir, OPENCODE_PROFILE);
    if (apiKey === undefined) return NO_KEY;
    progress.apiKey = apiKey;
    const baseUrl = resolveGatewayUrl(env, homeDir);
    progress.baseUrl = baseUrl;
    const scope = deps.scopes.forScope(baseUrl, apiKey);
    const fingerprint = keyFingerprint(apiKey);
    const cachePath = resolveCachePath(env, homeDir, OPENCODE_PROFILE);

    // RES-03: warm this scope's memory from disk. A missing, unreadable or foreign-identity file is
    // a cold start; `hydrate` never downgrades anything learned over the network.
    try {
      if (cachePath !== undefined) {
        const onDisk = readCache(cachePath, { gatewayUrl: baseUrl, fingerprint });
        if (onDisk !== undefined) scope.policy.hydrate(onDisk);
      }
    } catch {
      // Cold start.
    }

    const cacheSync =
      cachePath === undefined
        ? undefined
        : (snapshot: PolicySnapshot): void => {
            void writeCache(cachePath, { ...snapshot, gateway_url: baseUrl, key_fingerprint: fingerprint });
          };

    const client = createApiClient({
      baseUrl,
      apiKey,
      profile: OPENCODE_PROFILE,
      ...(deps.timeouts?.pretoolMs === undefined ? {} : { timeoutMs: deps.timeouts.pretoolMs }),
      ...(deps.timeouts?.errorsMs === undefined ? {} : { errorsTimeoutMs: deps.timeouts.errorsMs }),
      ...(deps.timeouts?.turnLogMs === undefined ? {} : { turnLogTimeoutMs: deps.timeouts.turnLogMs }),
    });
    const isInactive = (): boolean => scope.key.isInactive();
    const telemetry = createTelemetry({ client, profile: OPENCODE_PROFILE, apiKey, isInactive, now: deps.now });
    const signals = createSignalReporter({
      client,
      profile: OPENCODE_PROFILE,
      apiKey,
      isInactive,
      now: deps.now,
      ...(deps.signalIntervalMs === undefined ? {} : { intervalMs: deps.signalIntervalMs }),
    });
    const checker =
      deps.makeChecker !== undefined
        ? deps.makeChecker(apiKey, baseUrl)
        : createPolicyChecker({
            client,
            state: scope.policy,
            telemetry,
            breaker: breakers.forUrl(baseUrl),
            keyState: scope.key,
            onSync: cacheSync,
            now: deps.now,
          });
    return { status: "active", apiKey, baseUrl, scope, client, checker, telemetry, signals, cacheSync };
  }

  let initFaultReported = false;

  /**
   * Best-effort `init_degraded` / `resolve_fault`, once per plugin copy, through a client built only
   * from what resolved before the fault. If even that client cannot be built (the fault was in it),
   * there is nobody to tell, and the user still sees the init-error notice. Deferred and total.
   */
  function reportInitFault(progress: Progress): void {
    if (initFaultReported) return;
    initFaultReported = true;
    const { apiKey, baseUrl } = progress;
    if (apiKey === undefined || baseUrl === undefined) return;
    later(() => {
      const client = createApiClient({
        baseUrl,
        apiKey,
        profile: OPENCODE_PROFILE,
        ...(deps.timeouts?.errorsMs === undefined ? {} : { errorsTimeoutMs: deps.timeouts.errorsMs }),
      });
      createSignalReporter({ client, profile: OPENCODE_PROFILE, apiKey, now: deps.now }).report(SIGNAL_INIT_DEGRADED, {
        toolName: "init",
        detail: "resolve_fault",
      });
    });
  }

  function nowSafe(): number {
    try {
      const value = deps.now();
      return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
    } catch {
      return Date.now();
    }
  }

  const runtime: Runtime = {
    deps,
    sessions,
    instances,
    hostVersion: undefined,
    init(): Resolved {
      // `active` is kept for the copy's lifetime. `no_key` and `init_error` are kept only until
      // their retry time (13-REVIEW WR-03), so neither latches the plugin inactive for the life of
      // the process, and a broken home directory is still not re-read on every tool call.
      const now = nowSafe();
      if (resolved !== undefined && (resolved.status === "active" || now < retryAt)) return resolved;
      resolveCount += 1;
      const progress: Progress = {};
      try {
        resolved = resolveNow(progress);
        if (resolved.status !== "active") retryAt = now + NO_KEY_RETRY_MS;
      } catch {
        // A fault while resolving allows, never blocks: degraded, reported once, retried soon.
        resolved = INIT_ERROR;
        retryAt = now + INIT_RETRY_MS;
        try {
          reportInitFault(progress);
        } catch {
          // A report is never worth a fault.
        }
      }
      return resolved;
    },
    entrypoint(): string {
      const version = runtime.hostVersion;
      return typeof version === "string" && version !== "" ? ENTRYPOINT_PREFIX + version : UNKNOWN_ENTRYPOINT;
    },
    recordingActive(): boolean {
      try {
        const r = runtime.init();
        return r.apiKey !== undefined && r.client !== undefined && r.scope?.key.isInactive() === false;
      } catch {
        return false;
      }
    },
    reportSignal(category: string, toolName: string, detail?: string): void {
      try {
        runtime.init().signals?.report(category, detail === undefined ? { toolName } : { toolName, detail });
      } catch {
        // A signal is never worth a fault.
      }
    },
    reportOnce(category: string, toolName: string, detail?: string): void {
      try {
        if (reportedOnce.has(category)) return;
        const signals = runtime.init().signals;
        if (signals === undefined) return;
        reportedOnce.add(category);
        signals.report(category, detail === undefined ? { toolName } : { toolName, detail });
      } catch {
        // ditto
      }
    },
    turnFor(sessionID: string): TurnStore {
      const root = runtime.rootOf(sessionID);
      const store = sessions.forSession(root).turn;
      return root === sessionID ? store : rollUp(store, root);
    },
    setModel(sessionID: string, model: string): void {
      try {
        if (sessionID === "" || typeof model !== "string" || model === "" || model.length > MAX_MODEL_CHARS) return;
        extras.get(sessionID).model = model;
      } catch {
        // A model we could not keep is `auto` on the wire.
      }
    },
    modelFor(sessionID: string): string | undefined {
      try {
        const own = extras.peek(sessionID)?.model;
        if (own !== undefined) return own;
        const root = runtime.rootOf(sessionID);
        return root === sessionID ? undefined : extras.peek(root)?.model;
      } catch {
        return undefined;
      }
    },
    startIdentity(provider: string | undefined): void {
      try {
        // No key, no identity work: nothing would ever carry it.
        if (runtime.init().apiKey === undefined) return;
        void loaderOf()
          .start(typeof provider === "string" && provider !== "" ? provider : undefined)
          .catch(() => undefined);
      } catch {
        // Identity is decoration; never a fault.
      }
    },
    identity(): AccountIdentity | undefined {
      try {
        return identityLoader?.current();
      } catch {
        return undefined;
      }
    },
    setParent(sessionID: string, parentID: unknown): void {
      try {
        if (sessionID === "") return;
        // Truthiness, never key presence: a root session carries `parentID: undefined` (13-SPIKES.md).
        if (typeof parentID !== "string" || parentID === "" || parentID === sessionID) return;
        extras.get(sessionID).parent = parentID;
      } catch {
        // Unknown parent = root.
      }
    },
    isChild(sessionID: string): boolean {
      try {
        const parent = extras.peek(sessionID)?.parent;
        return typeof parent === "string" && parent !== "";
      } catch {
        return false;
      }
    },
    rootOf(sessionID: string): string {
      try {
        let current = sessionID;
        const seen = new Set<string>([current]);
        for (let depth = 0; depth < MAX_PARENT_DEPTH; depth += 1) {
          const parent = extras.peek(current)?.parent;
          if (typeof parent !== "string" || parent === "" || seen.has(parent)) break;
          seen.add(parent);
          current = parent;
        }
        return current;
      } catch {
        return sessionID;
      }
    },
    rememberDigest(sessionID: string, callID: string, digest: string | undefined): void {
      try {
        if (sessionID === "" || callID === "") return;
        const map = digests.get(sessionID);
        map.delete(callID);
        if (digest === undefined) return;
        map.set(callID, digest);
        while (map.size > MAX_DIGESTS_PER_SESSION) {
          const oldest = map.keys().next().value;
          if (oldest === undefined) break;
          map.delete(oldest);
        }
      } catch {
        // A digest we could not keep is a comparison we skip.
      }
    },
    takeDigest(sessionID: string, callID: string): string | undefined {
      try {
        const map = digests.peek(sessionID);
        const digest = map?.get(callID);
        map?.delete(callID);
        return digest;
      } catch {
        return undefined;
      }
    },
    setRole(sessionID: string, messageID: string, role: string): void {
      try {
        if (sessionID === "" || messageID === "" || typeof role !== "string" || role === "") return;
        boundedSet(extras.get(sessionID).roles, messageID, role, MAX_MESSAGES_PER_SESSION);
      } catch {
        // Unknown role = not assistant text.
      }
    },
    roleOf(sessionID: string, messageID: string): string | undefined {
      try {
        return extras.peek(sessionID)?.roles.get(messageID);
      } catch {
        return undefined;
      }
    },
    setAssistantPart(sessionID: string, partID: string, text: string): void {
      try {
        if (sessionID === "" || partID === "" || typeof text !== "string") return;
        boundedSet(extras.get(sessionID).assistant, partID, keepText(text), MAX_ASSISTANT_PARTS);
      } catch {
        // A lost column, never a fault.
      }
    },
    takeAssistantText(sessionID: string): string {
      try {
        const kept = extras.peek(sessionID);
        if (kept === undefined) return "";
        const text = [...kept.assistant.values()].filter((t) => t !== "").join("\n");
        kept.assistant.clear();
        kept.roles.clear();
        return text;
      } catch {
        return "";
      }
    },
    releaseSession(sessionID: string): void {
      try {
        if (sessionID === "") return;
        sessions.release(sessionID);
        extras.release(sessionID);
        digests.release(sessionID);
      } catch {
        // Nothing to release.
      }
    },
    markBeforeSeen(sessionID: string, callID: string): void {
      try {
        if (sessionID === "" || callID === "") return;
        boundedAdd(extras.get(sessionID).before, callID, MAX_IDS_PER_SESSION);
        // A model call never needs its stashed command again.
        extras.peek(sessionID)?.shell.delete(callID);
      } catch {
        // Unknown = not seen: at worst one extra check of a model bash call.
      }
    },
    beforeSeen(sessionID: string, callID: string): boolean {
      try {
        return extras.peek(sessionID)?.before.has(callID) === true;
      } catch {
        return false;
      }
    },
    stashUserShell(sessionID: string, callID: string, command: string): void {
      try {
        if (sessionID === "" || callID === "" || typeof command !== "string" || command === "") return;
        const kept = extras.get(sessionID);
        if (kept.before.has(callID)) return;
        boundedSet(kept.shell, callID, capCommand(command).command, MAX_SHELL_STASH_PER_SESSION);
      } catch {
        // A missing stash is reported as `no_part` at `shell.env` time.
      }
    },
    takeUserShell(sessionID: string, callID: string): string | undefined {
      try {
        const map = extras.peek(sessionID)?.shell;
        const command = map?.get(callID);
        map?.delete(callID);
        return command;
      } catch {
        return undefined;
      }
    },
    dropUserShell(sessionID: string, callID: string): void {
      try {
        extras.peek(sessionID)?.shell.delete(callID);
      } catch {
        // Bounded anyway.
      }
    },
    mcpServerNamesFor(record: DirectoryRecord): string[] {
      try {
        const names = [...record.mcpServerNames];
        const seen = new Set(names);
        for (const name of record.liveMcpServerNames) {
          if (names.length >= MAX_MCP_SERVER_NAMES) break;
          if (!seen.has(name)) {
            seen.add(name);
            names.push(name);
          }
        }
        return names;
      } catch {
        return [];
      }
    },
    refreshMcpNames(record: DirectoryRecord): void {
      try {
        const now = deps.now();
        const last = record.mcpRefreshedAt;
        if (last !== undefined && now - last < MCP_REFRESH_INTERVAL_MS) return;
        record.mcpRefreshedAt = now;
        // The SDK client is untrusted host input: every read is guarded, and its promise is raced
        // against an unref'd timer, so a hung host costs nothing but a missed refresh.
        const mcp: unknown = (record.client as { mcp?: unknown } | null | undefined)?.mcp;
        const status: unknown = (mcp as { status?: unknown } | null | undefined)?.status;
        if (typeof status !== "function") return;
        const pending = Promise.resolve((status as (this: unknown) => unknown).call(mcp));
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<undefined>((resolve) => {
          timer = setTimeout(() => resolve(undefined), MCP_REFRESH_TIMEOUT_MS);
          timer.unref?.();
        });
        void Promise.race([pending, timeout])
          .then((answer) => {
            const names = liveMcpNamesOf(answer);
            if (names !== undefined) record.liveMcpServerNames = names;
          })
          .catch(() => undefined)
          .finally(() => {
            if (timer !== undefined) clearTimeout(timer);
          });
      } catch {
        // A refresh is an optimisation; the call it was for is sent unattributed anyway.
      }
    },
    markResulted(sessionID: string, callID: string): boolean {
      try {
        if (sessionID === "" || callID === "") return false;
        const seen = extras.get(sessionID).resulted;
        if (seen.has(callID)) return false;
        boundedAdd(seen, callID, MAX_IDS_PER_SESSION);
        return true;
      } catch {
        return false;
      }
    },
  };

  return {
    runtime,
    recordFor(directory: unknown, client: unknown, mcpServerNames?: readonly string[]): DirectoryRecord {
      const record = records.get(directory);
      record.client = client;
      if (Array.isArray(mcpServerNames)) record.mcpServerNames = mcpServerNamesFromList(mcpServerNames);
      return record;
    },
    peekRecord: (directory: unknown) => records.peek(directory),
    releaseRecord: (directory: unknown) => records.release(directory),
    resolveCount: () => resolveCount,
    hasChecker: () => resolved?.checker !== undefined,
  };
}

export function createServerPlugin(overrides: Partial<Deps> = {}): ServerPlugin {
  const handle = createRuntime(overrides);
  const { runtime } = handle;
  const deps = runtime.deps;

  /** The allow-everything set served when the factory itself faulted. Reports, never decides. */
  function degradedHooks(): HooksLike {
    later(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, "server", "factory_fault"));
    return {
      "tool.execute.before": async () => {
        try {
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "tool.execute.before", "factory_fault");
        } catch {
          // Allow.
        }
        return undefined;
      },
      event: async () => {
        try {
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "event", "factory_fault");
        } catch {
          // Never reject from `event` (V1-4).
        }
      },
    };
  }

  function fullHooks(record: DirectoryRecord, generation: number): HooksLike {
    return {
      // The enforcement path. The handler raises only through `block.ts`, and only on a verdict.
      "tool.execute.before": toolExecuteBefore({ runtime, record }),
      // The success-path audit and the args tamper check. Never raises.
      "tool.execute.after": toolExecuteAfter({ runtime, record }),
      // The prompt check (V1-5 GO). Raises only through `block.ts`, and only on a verdict.
      "chat.message": chatMessage({ runtime, record }),
      // User `!cmd` (V1-7 GO). Raises only through `block.ts`, only on a verdict, and never for a
      // call that passed `tool.execute.before` (model bash is not checked twice).
      "shell.env": shellEnv({ runtime, record }),
      // The bus. Never rejects (V1-4): every branch is guarded and nothing is awaited.
      event: eventHandler({ runtime, record }),
      // Called with the live merged config once per instance. Read-only (Pitfall 16): the object is
      // shared with every other plugin, so only its MCP server NAMES are copied out.
      config: async (cfg: unknown) => {
        try {
          record.mcpServerNames = mcpServerNamesOf(cfg);
        } catch {
          // Keep the previous snapshot.
        }
        try {
          runtime.init();
        } catch {
          // Lazy init is total; this is the belt.
        }
      },
      // Instance teardown: drop this directory's state. A pending turn is never posted from here.
      // Only the LATEST hook set of the directory releases it (13-REVIEW WR-05): a late dispose of an
      // instance that a newer `server()` call superseded, or of a record already replaced after an
      // earlier release, must not drop the live instance's record, heartbeat gate or no-key latch.
      dispose: async () => {
        try {
          if (record.directory !== "" && record.generation === generation && handle.peekRecord(record.directory) === record) {
            runtime.instances.release(record.directory);
            handle.releaseRecord(record.directory);
          }
        } catch {
          // Nothing to release.
        }
      },
    };
  }

  /** Define the sentinel slot as this copy's: non-writable, non-configurable, non-enumerable. */
  function claimSentinel(): boolean {
    try {
      Object.defineProperty(globalThis, deps.sentinelKey, {
        value: deps.moduleToken,
        writable: false,
        configurable: false,
        enumerable: false,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Who holds the sentinel slot (13-REVIEW WR-04). Only `"duplicate"` makes this copy stand down,
   * and only a holder that looks exactly like another copy of THIS build can produce it: a data
   * property that is non-writable and non-configurable, holding a frozen object whose own `module`
   * is the sentinel key and whose own `build` is this build's token. Anything else in the slot (a
   * value a project plugin planted, an accessor, another build) is `"foreign"`: this copy keeps
   * enforcing and reports `sentinel_tampered`. Getters are never invoked.
   */
  function sentinelHolder(): "free" | "mine" | "duplicate" | "other_build" | { foreign: string } {
    try {
      const desc = Object.getOwnPropertyDescriptor(globalThis, deps.sentinelKey);
      if (desc === undefined) return "free";
      if (!("value" in desc)) return { foreign: "accessor" };
      const holder: unknown = desc.value;
      if (holder === deps.moduleToken) return "mine";
      if (holder === null || typeof holder !== "object") return { foreign: "foreign_value" };
      const own = (key: string): unknown => {
        const d = Object.getOwnPropertyDescriptor(holder, key);
        return d !== undefined && "value" in d ? d.value : undefined;
      };
      if (own("module") !== SENTINEL_KEY) return { foreign: "foreign_value" };
      const wellFormed = desc.writable === false && desc.configurable === false && Object.isFrozen(holder);
      if (own("build") !== deps.buildToken) {
        // Another genuine build (IN-07): both copies enforce; reported as information, not tampering.
        return wellFormed && isBuildToken(own("build")) ? "other_build" : { foreign: "other_build" };
      }
      if (!wellFormed) return { foreign: "forged_holder" };
      return "duplicate";
    } catch {
      // A holder whose traps raise (a planted Proxy) must not push this copy into the degraded set.
      return { foreign: "unreadable" };
    }
  }

  const factory = (input: unknown, _options?: unknown): Promise<HooksLike> => {
    try {
      const holder = sentinelHolder();
      if (holder === "duplicate") {
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, "server", "second_copy"));
        return Promise.resolve({});
      }
      if (holder === "free") {
        claimSentinel();
      } else if (holder === "other_build") {
        // Another build of this plugin holds the slot (an in-place upgrade, or a managed copy beside
        // a newer user copy). It cannot be taken back (non-configurable); this copy keeps enforcing,
        // so each call is checked by both until one of them goes.
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, "server", "other_build"));
      } else if (holder !== "mine") {
        // Not another copy of this build: never a reason to stand down. Take the slot back when it
        // can be taken (so later directories and copies see this copy), and keep enforcing either way.
        let configurable = false;
        try {
          configurable = Object.getOwnPropertyDescriptor(globalThis, deps.sentinelKey)?.configurable === true;
        } catch {
          // Leave the slot alone.
        }
        if (configurable) claimSentinel();
        const detail = holder.foreign;
        later(() => runtime.reportOnce(SIGNAL_SENTINEL_TAMPERED, "server", detail));
      }

      // Deliberately NOT read behind a guard: a host input whose getters raise is a broken host, and
      // the catch below turns it into the degraded, reporting set rather than a silently empty one.
      const host = input !== null && typeof input === "object" ? (input as Record<string, unknown>) : {};
      const directory: unknown = host.directory;
      const client: unknown = host.client;

      const record = handle.recordFor(directory, client);
      // The MCP names are NOT reset here (13-REVIEW BL-01 / WR-05): an existing record may still
      // serve a live hook set, and the next `config` call replaces the config names anyway.
      // The generation makes this the hook set that owns the record's release (WR-05).
      record.generation += 1;
      return Promise.resolve(fullHooks(record, record.generation));
    } catch {
      return Promise.resolve(degradedHooks());
    }
  };

  const inspector: PluginInspector = {
    resolveCount: () => handle.resolveCount(),
    hasChecker: () => handle.hasChecker(),
    instance(dir: string) {
      const record = handle.peekRecord(dir);
      return record === undefined ? undefined : { directory: record.directory, mcpServerNames: [...record.mcpServerNames] };
    },
    turn: (sessionID: string) => runtime.sessions.forSession(sessionID).turn.snapshot(),
    runtime: () => runtime,
  };
  Object.defineProperty(factory, "inspect", { value: inspector, enumerable: false });
  return factory as ServerPlugin;
}
