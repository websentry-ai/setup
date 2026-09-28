// RES-04 — the `/v1/hooks/pi` body, assembled from the turn record. Pure: same input, same output,
// nothing written anywhere.
//
// Four field decisions here are contracts rather than choices, and each one is a place a later reader
// will be tempted to "fix":
//
//   1. **`model` is `TURNLOG_MODEL`.** See that constant. A real model id means the backend drops the
//      row. This is the single highest-consequence line in the file.
//   2. **`tool_use[].tool_input` is the allowlisted input, not `{}`.** It used to be literally `{}`,
//      on the reasoning that reaching back to the live `event.input` would re-open the egress 09-02's
//      `sanitizeToolInput` allowlist closed. That was true of `event.input` and false of what the
//      pretool request already sends, and the cost was a row that named a tool without saying what it
//      did — `bash` with no command, `read` with no path. So the decision seam now hands
//      `payload.ts`'s `auditToolInput` projection to the record, and this file emits it verbatim:
//      `command` (both-ends capped), `path`, `pattern` and the other allowlisted keys; **never**
//      `content`, `edits` or any file body. One allowlist, shared with the enforcement request, so a
//      key that cannot ride a pretool check cannot ride an audit row either. `turnLog.test.ts`
//      asserts both halves — `content`/`edits` absent, `command`/`path`/`pattern` present — rather
//      than trusting this paragraph.
//   3. **`tool_response` carries `{content_sha256, content_bytes}`** — HOOK-06's whole point. This is
//      also a documented parity gap: `audit_service.py:113-139` feeds the serialised `tool_use` array
//      (including `tool_response`) to DLP, so **tool-output DLP cannot fire for pi**. That is a direct
//      consequence of the locked requirement, not a bug.
//   4. **The assistant `content` is the model's own text**, capped at `MAX_ASSISTANT_CHARS`. It used
//      to be hard-coded `""`, on the reasoning that the turn record holds no assistant text and
//      inventing one would be new egress. The record still holds none: the text is read off
//      `agent_end`'s `messages` by `assistantTextFrom`, handed to this builder through `opts`, and
//      never stored in the turn store, never written to disk and never logged locally — it exists for
//      the length of one POST. What the old empty string cost was a row that showed the user's prompt
//      and a silent assistant, i.e. half a conversation, and assistant-text DLP that could not fire
//      for want of anything to match on. Capped at both ends with the same marker a command gets, and
//      `assistant_truncated` rides the body when that happened.
//
// `applicationId`, `organizationId` and `key_source` are server-set (`:80-83`) and are never sent. No
// `unbound_app_label` either: the route already labels this `pi`, which is what makes
// `metadata.source = 'hooks'` true (`add_gateway_metrics_task.py:676-677`).

import { redactSecrets } from "./config.ts";
import { MAX_ASSISTANT_CHARS, TURNLOG_MODEL, TURNLOG_TOOL_USE_TYPE } from "./constants.ts";
import { capCommand } from "./payload.ts";
import type { TurnRecord } from "./turn.ts";

/** The hash pair, or the honest statement that the output was too big to hash. */
export type ToolResponse =
  | Record<string, never>
  | { content_sha256: string; content_bytes: number }
  | { hash_skipped: true; content_bytes: number };

export interface TurnLogToolUse {
  type: string;
  tool_name: string;
  tool_use_id: string;
  /**
   * The allowlisted, capped input the pretool request carried — see decision 2 in the header. `{}`
   * when the call was recorded without one.
   */
  tool_input: Record<string, unknown>;
  tool_response: ToolResponse;
}

export interface TurnLogMessage {
  role: "user" | "assistant";
  content: string;
  tool_use?: TurnLogToolUse[];
}

/** Token counts are not available to a hook, so a zero stub stands in (`:248-253` accepts one). */
export interface TurnLogUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface TurnLogBody {
  conversation_id: string;
  model: string;
  messages: TurnLogMessage[];
  cwd: string;
  requestInitialized?: string;
  requestCompleted: string;
  usage: TurnLogUsage;
  /**
   * How many tool results the `MAX_TURN_RESULTS` cap dropped from this turn. Diagnostic only — no
   * reader on the server consumes it — and present only when it is a positive count, so an ordinary
   * row carries no extra key at all. A truncated row that said nothing would look complete.
   */
  results_truncated?: number;
  /** The same, for the `MAX_TURN_TOOL_CALLS` cap on `tool_calls` (WR-04). Same present-only rule. */
  tool_calls_truncated?: number;
  /**
   * `true` when the assistant text is a head-plus-tail of what the model actually said. Present-only,
   * like the two counters above: a reader must be able to tell a whole answer from a spliced one
   * without diffing it against the marker.
   */
  assistant_truncated?: true;
}

export interface TurnLogOptions {
  cwd: string;
  completedAtMs: number;
  /**
   * What the model said this turn, already extracted from `agent_end`'s messages.
   *
   * An option rather than a field on the record, because it never belongs to the record: the record
   * accumulates across four handler invocations, while this arrives whole at `agent_end` and is used
   * once. Keeping it out of the store is also what keeps "never logged locally" true by construction —
   * there is no in-memory copy to leak into a snapshot.
   */
  assistantText?: string;
  /** The session's API key, so `redactSecrets` can scrub it from anything the model or a command echoes. */
  apiKey?: string;
}

/**
 * The empty-turn guard, mirroring `PY:4975`'s `if len(messages) < 2: return None`.
 *
 * A result with no call is deliberately not enough: it belongs to a turn this process already posted
 * (or never saw), and posting it would produce a row describing nothing. `agent_end` fires for retries
 * and aborted runs too (§F3), so this guard runs on every one of them.
 */
export function shouldPostTurn(record: TurnRecord | undefined): boolean {
  try {
    if (record === null || typeof record !== "object") return false;
    if (typeof record.prompt === "string") return true;
    return Array.isArray(record.tool_calls) && record.tool_calls.length > 0;
  } catch {
    return false;
  }
}

/**
 * The recorded `tool_input`, or `{}`.
 *
 * Read, never re-sanitised: the allowlist ran at the decision seam, where the live `event.input` still
 * existed, and a second pass here would only strip the `_dropped` / `_truncated` markers the server is
 * meant to see. Anything that is not a plain object is `{}` — a malformed record degrades a key, not
 * the row.
 */
function toolInputFor(value: unknown, apiKey?: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
  const input = { ...(value as Record<string, unknown>) };
  // The command persists in the audit row, so bearer tokens and the session key are scrubbed the same
  // way the telemetry path scrubs them. The pretool check itself saw the command unredacted.
  if (typeof input.command === "string") input.command = redactSecrets(input.command, apiKey);
  return input;
}

/**
 * The assistant text as it goes on the wire: capped at `MAX_ASSISTANT_CHARS`, both ends kept.
 *
 * `capCommand` is reused rather than reimplemented — it is the project's both-ends cap, marker and
 * all, and a second splicer would be a second thing to get wrong. Anything that is not a non-empty
 * string is the empty string, so a hostile or half-built message array costs the column, not the row.
 */
function capAssistantText(text: unknown, apiKey?: string): { content: string; truncated: boolean } {
  try {
    if (typeof text !== "string" || text === "") return { content: "", truncated: false };
    // The model often quotes what a tool returned, so the same secret redaction the telemetry path
    // applies runs here before the cap; server-side DLP scans what remains, as for every other hook.
    const capped = capCommand(redactSecrets(text, apiKey), MAX_ASSISTANT_CHARS);
    return { content: capped.command, truncated: capped.truncated };
  } catch {
    return { content: "", truncated: false };
  }
}

/** `{}` for a call with no result, the hash pair otherwise. Never the raw output. */
function toolResponseFor(record: TurnRecord, toolUseId: string): ToolResponse {
  const results = Array.isArray(record.results) ? record.results : [];
  // Matched by id, not by position: a batch can finish out of order, and mis-pairing a digest with
  // another tool's call would make the audit trail actively misleading.
  const match = results.find((entry) => entry?.tool_use_id === toolUseId);
  if (match === undefined) return {};
  if (match.hash_skipped === true) {
    return { hash_skipped: true, content_bytes: match.content_bytes };
  }
  if (typeof match.content_sha256 === "string") {
    return { content_sha256: match.content_sha256, content_bytes: match.content_bytes };
  }
  return {};
}

/**
 * Assemble the §B3 body. Total: a malformed record produces a minimal body rather than a throw,
 * because the only caller is a handler on pi's run-settlement path.
 */
export function buildTurnLogBody(record: TurnRecord, opts: TurnLogOptions): TurnLogBody {
  let conversationId = "";
  let prompt = "";
  let toolUse: TurnLogToolUse[] = [];
  let startedAt: number | undefined;
  let truncated: number | undefined;
  let callsTruncated: number | undefined;

  try {
    const safe: TurnRecord = record === null || typeof record !== "object" ? { tool_calls: [], results: [] } : record;
    conversationId = typeof safe.session_id === "string" ? safe.session_id : "";
    prompt = typeof safe.prompt === "string" ? safe.prompt : "";
    startedAt =
      typeof safe.started_at === "number" && Number.isFinite(safe.started_at) ? safe.started_at : undefined;
    // A count, or nothing. Zero and anything non-numeric are the same statement — "nothing was
    // dropped" — and neither is worth a key the server would have to interpret.
    truncated =
      typeof safe.results_truncated === "number" &&
      Number.isFinite(safe.results_truncated) &&
      safe.results_truncated > 0
        ? Math.floor(safe.results_truncated)
        : undefined;
    callsTruncated =
      typeof safe.tool_calls_truncated === "number" &&
      Number.isFinite(safe.tool_calls_truncated) &&
      safe.tool_calls_truncated > 0
        ? Math.floor(safe.tool_calls_truncated)
        : undefined;
    const calls = Array.isArray(safe.tool_calls) ? safe.tool_calls : [];
    toolUse = calls.map((call) => ({
      type: TURNLOG_TOOL_USE_TYPE,
      tool_name: typeof call?.tool_name === "string" ? call.tool_name : "",
      tool_use_id: typeof call?.tool_use_id === "string" ? call.tool_use_id : "",
      // `call`-derived, and still never `event.input`-derived: what the record holds was already
      // allowlisted and capped by `auditToolInput` — header decision 2.
      tool_input: toolInputFor(call?.tool_input, opts?.apiKey),
      tool_response: toolResponseFor(safe, typeof call?.tool_use_id === "string" ? call.tool_use_id : ""),
    }));
  } catch {
    // Fall through with the defaults above: a degraded row beats a thrown handler.
  }

  const assistant = capAssistantText(opts?.assistantText, opts?.apiKey);

  const body: TurnLogBody = {
    conversation_id: conversationId,
    model: TURNLOG_MODEL,
    messages: [
      { role: "user", content: prompt },
      { role: "assistant", content: assistant.content, tool_use: toolUse },
    ],
    cwd: opts.cwd,
    requestCompleted: new Date(opts.completedAtMs).toISOString(),
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
  // Omitted rather than guessed when the record was never stamped: `useBodyTimestamps: true` means
  // the server honours what arrives, so a fabricated start time would become a fabricated latency.
  if (startedAt !== undefined) body.requestInitialized = new Date(startedAt).toISOString();
  if (truncated !== undefined) body.results_truncated = truncated;
  if (callsTruncated !== undefined) body.tool_calls_truncated = callsTruncated;
  if (assistant.truncated) body.assistant_truncated = true;
  return body;
}
