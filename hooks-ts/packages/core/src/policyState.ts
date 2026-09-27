// The last-good policy metadata, held in memory.
//
// Two fields ride ordinary allow/deny responses rather than a dedicated endpoint (§B4), so simply
// remembering them from the most recent success is enough:
//   * `policy_check_failure_action` — the org's opt-out from fail-open. It is the ONE thing that can
//     turn an API failure into a block, so it is read on every failure branch (`policy.ts`).
//   * `tools_to_check` — stored for Phase 9's RES-03 filtering; Phase 8 never reads it.
//
// In-memory only. The on-disk 300 s cache is Phase 9, so this module performs no file I/O at all —
// which also means there is no cache file for a local attacker to poison into a permanent block.
//
// The write rule that matters: **never overwrite a known value with an unknown one.** A response
// without the field, or with an out-of-enum value, leaves the previous value standing. Clobbering a
// remembered `block` with `undefined` would silently convert an org that opted out of fail-open back
// into fail-open — a security regression that no test upstream of here would notice.

import type { PreToolResponseBody } from "./types.ts";

export type FailureAction = "allow" | "block";

export interface PolicyState {
  recordSuccess(body: PreToolResponseBody): void;
  getFailureAction(): FailureAction | undefined;
  getToolsToCheck(): string[] | undefined;
}

function parseFailureAction(raw: unknown): FailureAction | undefined {
  return raw === "allow" || raw === "block" ? raw : undefined;
}

function parseToolsToCheck(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const tools = raw.filter((entry): entry is string => typeof entry === "string");
  return tools.length > 0 ? tools : undefined;
}

export function createPolicyState(): PolicyState {
  let failureAction: FailureAction | undefined;
  let toolsToCheck: string[] | undefined;

  return {
    recordSuccess(body: PreToolResponseBody): void {
      const nextAction = parseFailureAction(body.policy_check_failure_action);
      if (nextAction !== undefined) failureAction = nextAction;
      const nextTools = parseToolsToCheck(body.tools_to_check);
      if (nextTools !== undefined) toolsToCheck = nextTools;
    },
    getFailureAction: () => failureAction,
    getToolsToCheck: () => toolsToCheck,
  };
}

/**
 * The process-wide instance the adapter uses, so the memory survives across tool calls within one
 * pi session. It resets on `/reload`, because pi clears the extension module cache (§A7) — and a
 * reset means "cold start", which fails open, exactly as a fresh session would.
 */
export const policyState: PolicyState = createPolicyState();
