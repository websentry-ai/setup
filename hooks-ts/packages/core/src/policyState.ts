// The last-good policy metadata, held in memory — with two independent timestamps.
//
// Two fields ride ordinary allow/deny responses rather than a dedicated endpoint (§B4), so simply
// remembering them from the most recent success is enough:
//   * `policy_check_failure_action` — the org's opt-out from fail-open. It is the ONE thing that can
//     turn an API failure into a block, so it is read on every failure branch (`policy.ts`).
//   * `tools_to_check` — the native file tools that actually have a policy. RES-03 reads it to skip
//     the round trip for the tools that do not.
//
// **Still no file I/O here.** Phase 9 adds an on-disk cache, but it lives in `cache.ts`; this module
// only learns to `snapshot()` and `hydrate()` a plain object, so the composition root can persist it
// and `policy.ts` still never touches a filesystem. A local attacker who plants a cache file can
// therefore influence at most a cold instance — see `hydrate`.
//
// Two write rules, both load-bearing:
//
//   1. **Never overwrite a known value with an unknown one.** A response without the field, or with
//      an out-of-enum value, leaves the previous value standing. Clobbering a remembered `block`
//      with `undefined` would silently convert an org that opted out of fail-open back into
//      fail-open — a security regression that no test upstream of here would notice.
//   2. **Never advance `tools_synced_at` for a response that did not carry `tools_to_check`.** This
//      is the upstream bug, not a hypothetical: `handleGuardrails` (the user_prompt path) omits the
//      field on purpose (`preToolUseHandler.ts:1399-1405`), and the Python hook stamps its single
//      `last_synced` fresh anyway (`unbound.py:258-299`), so a first-ever session ends up *fresh
//      with `[]`* and skips every native file tool for 300 s (`unbound.py:3821-3826`). Splitting
//      `fetched_at` from `tools_synced_at` is the entire fix.
//
// And `[]` is a **value**: "this org has no file policies" is an answer; "the field was absent" is
// not. Collapsing the two is what makes rule 2 violable in the first place.

import type { PreToolResponseBody } from "./types.ts";

export type FailureAction = "allow" | "block";

/**
 * The on-disk cache shape minus its identity keys (`gateway_url` / `key_fingerprint`, which belong
 * to `cache.ts`). snake_case deliberately: the file is meant to be diffable against the Python
 * hook's cache by eye.
 */
export interface PolicySnapshot {
  /** Any response that carried policy metadata at all. */
  fetched_at?: number;
  /** ONLY a response that literally contained `tools_to_check`. */
  tools_synced_at?: number;
  /** `[]` means "no file policies"; absent means "never learned". */
  tools_to_check?: string[];
  policy_check_failure_action?: FailureAction;
}

export interface PolicyState {
  /**
   * @param nowMs injectable so a TTL test runs in milliseconds. Phase 8 call sites pass one
   *              argument; this only ever gained an optional parameter.
   */
  recordSuccess(body: PreToolResponseBody, nowMs?: number): void;
  getFailureAction(): FailureAction | undefined;
  getToolsToCheck(): string[] | undefined;
  getToolsSyncedAt(): number | undefined;
  getFetchedAt(): number | undefined;
  snapshot(): PolicySnapshot;
  hydrate(snapshot: PolicySnapshot): void;
}

function parseFailureAction(raw: unknown): FailureAction | undefined {
  return raw === "allow" || raw === "block" ? raw : undefined;
}

/**
 * `undefined` means **the field was absent or unusable**, never "the list was empty".
 *
 * A mixed array keeps its strings rather than rejecting the whole response: dropping a junk entry
 * narrows the skip set (more round trips, same verdicts), while rejecting the response would widen
 * it to whatever stale value was already remembered.
 */
export function parseToolsToCheck(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  return raw.filter((entry): entry is string => typeof entry === "string");
}

/** A timestamp off a file another process wrote. Finite, non-negative, or it did not happen. */
function parseTimestamp(raw: unknown): number | undefined {
  return typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? raw : undefined;
}

export function createPolicyState(): PolicyState {
  let failureAction: FailureAction | undefined;
  let toolsToCheck: string[] | undefined;
  let toolsSyncedAt: number | undefined;
  let fetchedAt: number | undefined;

  return {
    recordSuccess(body: PreToolResponseBody, nowMs: number = Date.now()): void {
      let learned = false;

      // Order matters only for readability; the two fields are independent.
      const nextTools = parseToolsToCheck(body?.tools_to_check);
      if (nextTools !== undefined) {
        toolsToCheck = nextTools;
        toolsSyncedAt = nowMs;
        learned = true;
      }

      const nextAction = parseFailureAction(body?.policy_check_failure_action);
      if (nextAction !== undefined) {
        failureAction = nextAction;
        learned = true;
      }

      // A response that taught nothing is not a fetch. Note that an out-of-enum failure action
      // counts as nothing learned, deliberately: a garbage value must not refresh freshness either.
      if (learned) fetchedAt = nowMs;
    },
    getFailureAction: () => failureAction,
    // Copy out: a caller that mutates the returned array must not widen the skip set.
    getToolsToCheck: () => (toolsToCheck === undefined ? undefined : [...toolsToCheck]),
    getToolsSyncedAt: () => toolsSyncedAt,
    getFetchedAt: () => fetchedAt,

    /** Only what was actually learned. An absent key is the honest encoding of "never learned". */
    snapshot(): PolicySnapshot {
      const out: PolicySnapshot = {};
      if (fetchedAt !== undefined) out.fetched_at = fetchedAt;
      if (toolsSyncedAt !== undefined) out.tools_synced_at = toolsSyncedAt;
      if (toolsToCheck !== undefined) out.tools_to_check = [...toolsToCheck];
      if (failureAction !== undefined) out.policy_check_failure_action = failureAction;
      return out;
    },

    /**
     * Load a disk snapshot, **without downgrading anything learned over the network**. In-memory is
     * authoritative for the session (09-CONTEXT), which is also what caps T-09-01/T-09-02: a planted
     * cache can only ever influence a value this instance has not yet been told by the server.
     *
     * Every field is re-validated. This object came off a file, so its types are claims.
     */
    hydrate(snapshot: PolicySnapshot): void {
      if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) return;

      if (toolsSyncedAt === undefined) {
        const tools = parseToolsToCheck(snapshot.tools_to_check);
        const syncedAt = parseTimestamp(snapshot.tools_synced_at);
        // Both or neither: an unstamped list cannot be aged, and an unlisted stamp means nothing.
        if (tools !== undefined && syncedAt !== undefined) {
          toolsToCheck = tools;
          toolsSyncedAt = syncedAt;
        }
      }

      if (fetchedAt === undefined) {
        const action = parseFailureAction(snapshot.policy_check_failure_action);
        if (action !== undefined) failureAction = action;
        // Independent of the action, because `getFailureAction` ignores the TTL (unbound.py:225):
        // a valid action with an unparseable timestamp is still usable.
        const fetched = parseTimestamp(snapshot.fetched_at);
        if (fetched !== undefined) fetchedAt = fetched;
      }
    },
  };
}

/**
 * The process-wide instance the adapter uses, so the memory survives across tool calls within one
 * pi session. It resets on `/reload`, because pi clears the extension module cache (§A7) — and a
 * reset means "cold start", which fails open, exactly as a fresh session would. A cold start is
 * also the one moment `hydrate` can contribute anything.
 */
export const policyState: PolicyState = createPolicyState();
