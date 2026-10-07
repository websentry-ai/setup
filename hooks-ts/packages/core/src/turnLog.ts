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
//   3. **`tool_response` carries the tool's text output, capped and redacted**, alongside
//      `{content_sha256, content_bytes}`. HOOK-06 used to make it hash-only, and that was reversed by
//      user decision: `audit_service.py:113-139` feeds the serialised `tool_use` array (including
//      `tool_response`) to DLP, so hash-only meant **tool-output DLP could not fire for pi**, and an MCP
//      call's output could never be audited. The text is the record's `captureText` capture (8 KB per
//      result, both ends; 128 KB per turn), scrubbed with `redactSecrets` at capture time — over
//      windows wider than each cut, so a secret straddling a cut cannot survive in part — and again
//      here, at post time. Image parts are never captured — hash and bytes only.
//      `is_error`, `content_truncated`, `content_original_chars` and `content_omitted` ride only when
//      they say something.
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
import type { AccountIdentity } from "./accountIdentity.ts";
import { capCommand, withAccountIdentity } from "./payload.ts";
import type { TurnRecord } from "./turn.ts";

/**
 * `{}` for a call with no result; otherwise the hash pair (or the honest statement that the output was
 * too big to hash) plus, when captured, the redacted text and its present-only flags.
 */
export type ToolResponse =
  | Record<string, never>
  | ({ content_bytes: number } & (
      | { content_sha256: string; hash_skipped?: never }
      | { hash_skipped: true; content_sha256?: never }
      | { content_sha256?: never; hash_skipped?: never }
    ) & {
      content?: string;
      is_error?: true;
      content_truncated?: true;
      content_original_chars?: number;
      content_omitted?: true;
    });

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
  /** Forwarded by the gateway into `metadata.account` / `metadata.device`. Absent when unknown. */
  account_identity?: AccountIdentity;
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
  /** The process's settled account identity; attached as `account_identity` when present. */
  accountIdentity?: AccountIdentity;
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

/** How deep `redactLeaves` walks a recorded input before dropping what is below. */
const MAX_REDACT_DEPTH = 8;

/**
 * A copy of `value` with `redactSecrets` applied to every string leaf, arrays included. Plain objects
 * and arrays are walked to `MAX_REDACT_DEPTH`; anything deeper, and anything that is not a string,
 * number, boolean, `null`, plain object or array, is dropped (`undefined`).
 *
 * Leaf by leaf, never serialise-then-redact: `redactSecrets`' `Bearer \S+` would swallow the JSON
 * quote and comma after a token and corrupt the structure it was meant to scrub.
 */
function redactLeaves(value: unknown, apiKey: string | undefined, depth: number): unknown {
  if (typeof value === "string") return redactSecrets(value, apiKey);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (depth >= MAX_REDACT_DEPTH || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    return value.map((item) => {
      const out = redactLeaves(item, apiKey, depth + 1);
      return out === undefined ? null : out;
    });
  }
  const proto = Object.getPrototypeOf(value) as unknown;
  if (proto !== Object.prototype && proto !== null) return undefined;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const redacted = redactLeaves(item, apiKey, depth + 1);
    // `defineProperty`, never `out[key] =`: a `__proto__` key in model-written args would otherwise
    // hit the prototype setter and vanish from the audit row while the tool still received it (WR-06).
    if (redacted !== undefined) {
      Object.defineProperty(out, key, { value: redacted, enumerable: true, writable: true, configurable: true });
    }
  }
  return out;
}

/**
 * The recorded `tool_input`, or `{}`.
 *
 * Read, never re-sanitised: the allowlist ran at the decision seam, where the live `event.input` still
 * existed, and a second pass here would only strip the `_dropped` / `_truncated` markers the server is
 * meant to see. Anything that is not a plain object is `{}` — a malformed record degrades a key, not
 * the row.
 *
 * Every string leaf is scrubbed (bearer tokens and the session key, the same scrub the telemetry path
 * applies), not just `command`: a resolved MCP call records its capped ARGUMENTS here, which are free
 * text the model wrote and can carry a token anywhere in the structure. The audit row persists; the
 * pretool check itself saw the input unredacted.
 */
function toolInputFor(value: unknown, apiKey?: string): Record<string, unknown> {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
    const redacted = redactLeaves(value, apiKey, 0);
    return redacted !== null && typeof redacted === "object" && !Array.isArray(redacted)
      ? (redacted as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
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

/**
 * `{}` for a call with no result; otherwise the digest (or `hash_skipped`), the byte count and — when
 * the record captured any — the output text, redacted here, at post time.
 *
 * This is the SECOND redaction. The first runs at capture time (`captureText` with a `redact`
 * function), over windows wider than each cut, so a token straddling the head/tail boundary is
 * replaced before the cut can split it. This pass covers anything recorded without that (a test, a
 * future caller). `redactSecrets` only knows `Bearer …` and the session key; server-side DLP scans
 * what arrives.
 */
function toolResponseFor(record: TurnRecord, toolUseId: string, apiKey?: string): ToolResponse {
  const results = Array.isArray(record.results) ? record.results : [];
  // Matched by id, not by position: a batch can finish out of order, and mis-pairing a digest with
  // another tool's call would make the audit trail actively misleading.
  const match = results.find((entry) => entry?.tool_use_id === toolUseId);
  if (match === undefined) return {};
  const bytes = typeof match.content_bytes === "number" ? match.content_bytes : 0;
  let response: ToolResponse;
  if (match.hash_skipped === true) {
    response = { hash_skipped: true, content_bytes: bytes };
  } else if (typeof match.content_sha256 === "string") {
    response = { content_sha256: match.content_sha256, content_bytes: bytes };
  } else if (typeof match.content !== "string") {
    return {};
  } else {
    response = { content_bytes: bytes };
  }
  if (typeof match.content === "string") response.content = redactSecrets(match.content, apiKey);
  if (match.is_error === true) response.is_error = true;
  if (match.content_truncated === true) response.content_truncated = true;
  if (typeof match.content_original_chars === "number") {
    response.content_original_chars = match.content_original_chars;
  }
  if (match.content_omitted === true) response.content_omitted = true;
  return response;
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
      tool_response: toolResponseFor(
        safe,
        typeof call?.tool_use_id === "string" ? call.tool_use_id : "",
        opts?.apiKey,
      ),
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
  return withAccountIdentity(body, opts?.accountIdentity);
}
