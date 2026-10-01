// Policy memory and the revoked-key latch, scoped by gateway and key (CORE-04, review WR-03).
//
// Two pieces of state carry ENFORCEMENT consequences, and in pi they are process singletons
// (`policyState`, `keyState`) because pi has exactly one key and one gateway per process:
//
//   * `PolicyState` holds the org's `tools_to_check` (with `toolsConfirmed` and its sync stamp) and
//     its `policy_check_failure_action`. Both are answers from ONE org, reached through ONE gateway.
//   * `KeyState` is the revoked-key latch: two consecutive 401/403s for ONE key.
//
// A long-lived host that serves several projects can see several keys and several gateways in one
// process. Sharing either singleton across them is an enforcement bug, not a cosmetic one:
//
//   * project A's org answers `tools_to_check: []`, and project B's file tools are cache-skipped for
//     300 s on A's answer — a bypass for B;
//   * two 401s from A's revoked key latch the shared state inactive, and B's tool calls are allowed
//     with zero HTTP;
//   * A's `policy_check_failure_action: block` makes B fail closed.
//
// So an adapter in that position keeps one `ScopedState` per (gateway, key) and hands BOTH halves of
// the same scope to everything that touches them: `createPolicyChecker({ state: s.policy, keyState:
// s.key })`, the reporter's `isInactive: () => s.key.isInactive()`, and
// `evaluateToolCall(call, { state: s.policy, ... })`. `EvaluateDeps.state` is required, so a
// forgotten argument is a type error rather than a silent fall back to the process singleton.
//
// The scope key is `normalizeGatewayUrl(baseUrl)` plus `keyFingerprint(apiKey)` — the same pair that
// identifies the on-disk policy cache (`cache.ts`). The API key itself is never stored, never used as
// a map key and never returned: only its truncated sha256 fingerprint is. One gateway spelled two ways
// (trailing slash, host case) is one scope; one key against two gateways is two scopes.
//
// An unusable scope — a URL the normaliser refuses, an empty or non-string key — gets a FRESH,
// unstored state on every call. That fails toward checking: a fresh `PolicyState` has no confirmed
// tool list (every file tool is asked about) and no remembered failure action, and a fresh `KeyState`
// is not latched. Two callers that both failed to produce a scope never share state through a common
// "unknown" entry.
//
// Bounded (LRU) and total, like every `createKeyedState` registry. An evicted scope starts cold on
// its next use: its next tool call pulls the tool list again, and its latch starts unlatched, which
// costs at most `KEY_REJECTION_THRESHOLD` more requests with a key the gateway refuses. No module-scope
// instance: each adapter owns its registry. pi does not use this file; it keeps its singletons.

import { keyFingerprint } from "./cache.ts";
import { normalizeGatewayUrl } from "./config.ts";
import { MAX_TRACKED_SCOPES } from "./constants.ts";
import { createKeyState } from "./keyState.ts";
import type { KeyState, KeyStateOptions } from "./keyState.ts";
import { createKeyedState } from "./keyedState.ts";
import { createPolicyState } from "./policyState.ts";
import type { PolicyState } from "./policyState.ts";

/** The enforcement state of one (gateway, key) pair. */
export interface ScopedState {
  /** The org's remembered policy metadata. Hand it to the checker AND to `evaluateToolCall`. */
  readonly policy: PolicyState;
  /** The revoked-key latch. Hand it to the checker AND to the reporter's `isInactive`. */
  readonly key: KeyState;
}

export interface ScopedStates {
  /** The state for a scope, created cold on first use. An unusable scope gets a fresh, unstored one. */
  forScope(baseUrl: unknown, apiKey: unknown): ScopedState;
  /** The stored state, or `undefined`. Creates nothing and does not count as use. */
  peek(baseUrl: unknown, apiKey: unknown): ScopedState | undefined;
  /** Forget a scope, e.g. when a project is closed or its key is rotated. */
  release(baseUrl: unknown, apiKey: unknown): void;
  clear(): void;
  size(): number;
  /** The stored scope keys (`<normalised url> <key fingerprint>`), least-recently-used first. */
  keys(): string[];
}

export interface ScopedStatesOptions {
  /** How many scopes are tracked. Defaults to `MAX_TRACKED_SCOPES`. */
  max?: number;
  /** Passed to every scope's `KeyState`; see `KeyStateOptions`. */
  keyState?: KeyStateOptions;
}

/**
 * The scope key for a gateway and an API key, or `undefined` when either is unusable. Contains the
 * key's fingerprint (a truncated sha256), never the key. The separator is a space, which a
 * normalised URL cannot contain.
 */
export function scopeKey(baseUrl: unknown, apiKey: unknown): string | undefined {
  try {
    const url = normalizeGatewayUrl(baseUrl);
    if (url === undefined) return undefined;
    if (typeof apiKey !== "string" || apiKey.trim() === "") return undefined;
    return `${url} ${keyFingerprint(apiKey)}`;
  } catch {
    return undefined;
  }
}

export function createScopedStates(opts: ScopedStatesOptions = {}): ScopedStates {
  const keyStateOptions = opts?.keyState;
  const fresh = (): ScopedState =>
    Object.freeze({ policy: createPolicyState(), key: createKeyState(keyStateOptions ?? {}) });

  const scopes = createKeyedState<ScopedState>({
    max: opts?.max ?? MAX_TRACKED_SCOPES,
    create: fresh,
    fallback: fresh,
  });

  return {
    forScope: (baseUrl, apiKey) => scopes.get(scopeKey(baseUrl, apiKey)),
    peek: (baseUrl, apiKey) => scopes.peek(scopeKey(baseUrl, apiKey)),
    release: (baseUrl, apiKey) => scopes.release(scopeKey(baseUrl, apiKey)),
    clear: () => scopes.clear(),
    size: () => scopes.size(),
    keys: () => scopes.keys(),
  };
}
