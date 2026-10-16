// What a verdict means on opencode v1, and the text it blocks with.
//
// v1 has no approval primitive a plugin can drive: `permission.ask` is never triggered for plugin
// decisions (`oc:opencode/src/permission/index.ts:67-107`), so there is nobody to ask. An `ask` /
// `approval_required` verdict (core `confirm`) therefore BLOCKS, with its own wording, so the model
// and the user can tell "needs approval" from "denied" (HOOK-10, Pitfall 7, pi WR-05). It is never a
// silent allow.
//
// Spike V1-1: the model receives the block message verbatim, so these strings are the whole UX.
//
// Every function here is total.

import { sanitizeReason } from "../../core/src/verdict.ts";
import { verdictMessage } from "../../core/src/evaluate.ts";
import type { ToolEvaluation } from "../../core/src/evaluate.ts";

export const APPROVAL_PREFIX = "Unbound policy requires approval for this action";
const APPROVAL_TAIL =
  "opencode cannot show an approval prompt, so it was not run. Do not retry it; ask your Unbound admin to approve it.";

/** The approval-required block text. The reason is sanitised; no `: …` part without one. */
export function approvalMessage(reason?: unknown): string {
  try {
    const clean = sanitizeReason(reason)?.trim();
    if (clean === undefined || clean === "") return `${APPROVAL_PREFIX}. ${APPROVAL_TAIL}`;
    const end = /[.!?]$/.test(clean) ? "" : ".";
    return `${APPROVAL_PREFIX}: ${clean}${end} ${APPROVAL_TAIL}`;
  } catch {
    return `${APPROVAL_PREFIX}. ${APPROVAL_TAIL}`;
  }
}

/**
 * The message to block with, or `undefined` to let the call run.
 *
 *   * allow / skip  → `undefined`
 *   * deny          → core `verdictMessage` (`DENY_PREFIX + reason`)
 *   * confirm       → `approvalMessage(reason)`
 *   * unavailable   → core `verdictMessage` (the engine-unavailable text, fail-closed orgs only)
 *
 * Anything unrecognised is `undefined`: a malformed verdict must never become a block.
 */
export function blockingMessage(verdict: ToolEvaluation): string | undefined {
  try {
    if (verdict === null || typeof verdict !== "object") return undefined;
    switch (verdict.kind) {
      case "deny":
      case "unavailable":
        return verdictMessage(verdict);
      case "confirm":
        return approvalMessage(verdict.reason);
      default:
        return undefined;
    }
  } catch {
    return undefined;
  }
}

const RANK: Readonly<Record<string, number>> = Object.freeze({
  deny: 4,
  unavailable: 3,
  confirm: 2,
  allow: 1,
  skip: 0,
});

const NOTHING: ToolEvaluation = Object.freeze({ kind: "skip", why: "nothing-evaluable" }) as ToolEvaluation;

/** The strictest of several verdicts (deny > unavailable > confirm > allow > skip); first of equals. */
export function strictest(list: readonly ToolEvaluation[]): ToolEvaluation {
  try {
    if (!Array.isArray(list)) return NOTHING;
    let best: ToolEvaluation | undefined;
    let bestRank = -1;
    for (const verdict of list) {
      const kind: unknown = verdict?.kind;
      const rank = typeof kind === "string" && Object.hasOwn(RANK, kind) ? RANK[kind] : undefined;
      if (rank === undefined) continue;
      if (rank > bestRank) {
        best = verdict;
        bestRank = rank;
      }
    }
    return best ?? NOTHING;
  } catch {
    return NOTHING;
  }
}
