// Parsing the API response, which is untrusted input (ASVS V5).
//
// Two properties of the response reach the user and the model: `decision` drives enforcement and
// `reason` is rendered in the TUI *and* fed back to the model as the tool error. The upstream
// `custom_message` prompt-injection finding on ai-gateway#707 is still open (STATE.md), so the
// reason text arriving here may be attacker-authored — it is length-capped and control-character
// stripped before it leaves core.
//
// The failure direction matters: an unrecognised `decision` must degrade to **allow**, never to a
// block. A block is the outcome an attacker would want from a malformed or injected response, and
// fail-open is this phase's locked contract (RES-01).

import { MAX_REASON_CHARS } from "./constants.ts";
import type { Decision } from "./types.ts";

/**
 * What core hands the adapter. `confirm` covers both `ask` and `approval_required`: Phase 8 renders
 * an identical local confirmation for each (Slack approval polling is Future, per 08-CONTEXT).
 * `unavailable` is the one non-allow failure outcome — see `policy.ts`.
 */
export type PolicyOutcome =
  | { kind: "allow" }
  | { kind: "deny"; reason?: string }
  | { kind: "confirm"; reason?: string }
  | { kind: "unavailable" };

/** Every ASCII control character except `\n`, which is meaningful inside a multi-line reason. */
const CONTROL_CHARS = /[\x00-\x09\x0b-\x1f\x7f]/g;

/**
 * Strict equality against the four literals of the server enum (`preToolUseHandler.ts:278-283`) —
 * no case-folding, no aliasing, no trimming. `'DENY'`, `'block'` and any non-string yield
 * `undefined`, which callers must treat as allow.
 */
export function parseDecision(raw: unknown): Decision | undefined {
  if (raw === "allow" || raw === "deny" || raw === "ask" || raw === "approval_required") {
    return raw;
  }
  return undefined;
}

/**
 * Make a `reason` safe to render and to hand back to the model.
 *
 * Deliberately does NOT trim, reflow or ellipsise: the gateway may already have appended its
 * `"\n\nEnforced by Unbound · Trace ID <id>"` attribution footer at emit time, and that footer has
 * to survive byte-for-byte. Only two transformations happen — control characters are dropped and
 * the string is cut at `MAX_REASON_CHARS`.
 */
export function sanitizeReason(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const stripped = raw.replace(CONTROL_CHARS, "");
  if (stripped.length === 0) return undefined;
  return stripped.length > MAX_REASON_CHARS ? stripped.slice(0, MAX_REASON_CHARS) : stripped;
}

/**
 * Fold a successful response body into an outcome. Every field other than `decision` and `reason`
 * is ignored — including `additionalContext`, which Phase 8 deliberately does not echo to the
 * model (08-CONTEXT), and `policy_check_failure_action`, which `policyState` remembers separately.
 */
export function mapResponseToOutcome(body: unknown): PolicyOutcome {
  if (body === null || typeof body !== "object") return { kind: "allow" };
  const record = body as Record<string, unknown>;
  const decision = parseDecision(record["decision"]);
  if (decision === "deny") return { kind: "deny", reason: sanitizeReason(record["reason"]) };
  if (decision === "ask" || decision === "approval_required") {
    return { kind: "confirm", reason: sanitizeReason(record["reason"]) };
  }
  // `allow`, and every unrecognised value, are the same thing here.
  return { kind: "allow" };
}
