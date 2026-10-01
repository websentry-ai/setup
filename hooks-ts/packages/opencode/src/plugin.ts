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
//     to load; a second copy gets `{}` and reports `duplicate_load`. The same copy serving another
//     directory is not a duplicate: opencode calls `server()` once per project directory while the
//     module is evaluated once (13-SPIKES.md V1-9), so the sentinel keys on the module, never on a
//     call count.
//   * **State is scoped, never process-global.** One opencode process serves several projects.
//     Policy memory and the revoked-key latch come from core's `createScopedStates()` (per gateway
//     URL + key fingerprint, 12-REVIEW.md WR-03), the breaker from `createBreakerRegistry().forUrl`,
//     the turn record from `createSessionStates()` (by session id) and the heartbeat gate / no-key
//     latch from `createInstanceStates()` (by absolute directory). "Once" behaviour in those
//     registries needs an absolute directory and a non-empty session id (12-03 notes).
//   * **Without an API key it does nothing** but show one notice per directory (13-05).
//
// Module scope holds only the module token; everything else is per factory.

import { homedir } from "node:os";

import { createBreakerRegistry } from "../../core/src/breakerRegistry.ts";
import { keyFingerprint, readCache, resolveCachePath, writeCache } from "../../core/src/cache.ts";
import { createApiClient } from "../../core/src/client.ts";
import type { ApiClient } from "../../core/src/client.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { MAX_TRACKED_INSTANCES } from "../../core/src/constants.ts";
import { createKeyedState } from "../../core/src/keyedState.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import type { PolicySnapshot } from "../../core/src/policyState.ts";
import { createScopedStates } from "../../core/src/scopedState.ts";
import type { ScopedState, ScopedStates } from "../../core/src/scopedState.ts";
import { createInstanceStates, createSessionStates, directoryKey } from "../../core/src/sessionState.ts";
import type { InstanceStates, SessionStates } from "../../core/src/sessionState.ts";
import { createSignalReporter } from "../../core/src/signals.ts";
import type { SignalReporter } from "../../core/src/signals.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import type { Telemetry } from "../../core/src/telemetry.ts";
import type { TurnRecord } from "../../core/src/turn.ts";
import {
  ENTRYPOINT_PREFIX,
  SENTINEL_KEY,
  SIGNAL_DUPLICATE_LOAD,
  SIGNAL_INIT_DEGRADED,
  UNKNOWN_ENTRYPOINT,
} from "./constants.ts";
import type { HooksLike, ServerFactory } from "./hostTypes.ts";
import { OPENCODE_PROFILE } from "./profile.ts";

/** The token of THIS module copy. A second evaluated copy of the bundle has a different one. */
const MODULE_TOKEN: object = Object.freeze({ module: "unbound.opencode" });

/** The most MCP server names kept per directory. A real config has a handful. */
const MAX_MCP_SERVER_NAMES = 1024;

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
  /** The `globalThis` slot of the double-load sentinel. Default `Symbol.for(SENTINEL_KEY)`. */
  sentinelKey: symbol;
  /** This copy's identity in that slot. Default: the module token. */
  moduleToken: object;
}

/** What `init()` resolved. Every member is absent exactly when no key resolved (inactive). */
export interface Resolved {
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
}

/** Read-only test seam, attached to the factory as a NON-enumerable `inspect` property. */
export interface PluginInspector {
  /** How many times `init()` actually resolved (0 or 1). */
  resolveCount(): number;
  hasChecker(): boolean;
  instance(dir: string): { directory: string; mcpServerNames: string[] } | undefined;
  /** A copy of a session's turn record. */
  turn(sessionID: string): TurnRecord;
  runtime(): Runtime;
}

export type ServerPlugin = ServerFactory & { readonly inspect: PluginInspector };

const INERT: Resolved = Object.freeze({
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

export function createServerPlugin(overrides: Partial<Deps> = {}): ServerPlugin {
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
  });

  const breakers = createBreakerRegistry({ now: deps.now });
  const sessions = createSessionStates();
  const instances = createInstanceStates({ now: deps.now });
  const records = createKeyedState<DirectoryRecord>({
    max: MAX_TRACKED_INSTANCES,
    normalizeKey: directoryKey,
    create: (directory) => ({ directory, client: undefined, mcpServerNames: [] }),
    fallback: () => ({ directory: "", client: undefined, mcpServerNames: [] }),
  });

  let resolved: Resolved | undefined;
  let resolveCount = 0;
  const reportedOnce = new Set<string>();

  function resolveNow(): Resolved {
    const env: NodeJS.ProcessEnv = source.env ?? process.env;
    const homeDir: string = "homeDir" in source && typeof source.homeDir === "string" ? source.homeDir : safeHomeDir();
    const apiKey = resolveApiKey(env, homeDir, OPENCODE_PROFILE);
    if (apiKey === undefined) return INERT;
    const baseUrl = resolveGatewayUrl(env, homeDir);
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
    return { apiKey, baseUrl, scope, client, checker, telemetry, signals, cacheSync };
  }

  const runtime: Runtime = {
    deps,
    sessions,
    instances,
    hostVersion: undefined,
    init(): Resolved {
      if (resolved === undefined) {
        resolveCount += 1;
        try {
          resolved = resolveNow();
        } catch {
          // A fault while resolving is an inactive plugin, never a block. Cached, so a broken home
          // directory is not re-read on every tool call.
          resolved = INERT;
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
  };

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

  function fullHooks(record: DirectoryRecord): HooksLike {
    return {
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
      dispose: async () => {
        try {
          if (record.directory !== "") {
            instances.release(record.directory);
            records.release(record.directory);
          }
        } catch {
          // Nothing to release.
        }
      },
    };
  }

  const factory = (input: unknown, _options?: unknown): Promise<HooksLike> => {
    try {
      const slot = globalThis as unknown as Record<symbol, unknown>;
      const holder = slot[deps.sentinelKey];
      if (holder !== undefined && holder !== deps.moduleToken) {
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, "server", "second_copy"));
        return Promise.resolve({});
      }
      if (holder === undefined) slot[deps.sentinelKey] = deps.moduleToken;

      // Deliberately NOT read behind a guard: a host input whose getters raise is a broken host, and
      // the catch below turns it into the degraded, reporting set rather than a silently empty one.
      const host = input !== null && typeof input === "object" ? (input as Record<string, unknown>) : {};
      const directory: unknown = host.directory;
      const client: unknown = host.client;

      const record = records.get(directory);
      record.client = client;
      record.mcpServerNames = [];
      return Promise.resolve(fullHooks(record));
    } catch {
      return Promise.resolve(degradedHooks());
    }
  };

  const inspector: PluginInspector = {
    resolveCount: () => resolveCount,
    hasChecker: () => resolved?.checker !== undefined,
    instance(dir: string) {
      const record = records.peek(dir);
      return record === undefined ? undefined : { directory: record.directory, mcpServerNames: [...record.mcpServerNames] };
    },
    turn: (sessionID: string) => sessions.forSession(sessionID).turn.snapshot(),
    runtime: () => runtime,
  };
  Object.defineProperty(factory, "inspect", { value: inspector, enumerable: false });
  return factory as ServerPlugin;
}
