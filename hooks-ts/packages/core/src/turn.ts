// The in-memory turn record (HOOK-06 / RES-04) — what happened during one turn, and nothing more.
//
// Three deliberate limits define this module.
//
//   * **Tool output is held capped, and images never.** A result is recorded as a tool name, an
//     `isError` flag, a sha256 of a canonical projection, a byte count — and, since HOOK-06's
//     hash-only rule was reversed by user decision so tool-output DLP and MCP output audit can fire,
//     the TEXT parts' content capped at `MAX_TOOL_OUTPUT_CHARS` with both ends kept (`captureText`),
//     under a per-turn budget of `MAX_TURN_OUTPUT_CHARS`. Image parts are hashed and counted and
//     their base64 is never stored; `turn.test.ts` proves it by grepping `snapshot()` for a marker
//     hidden in one. Nothing is written anywhere: the text lives until `agent_end` posts it (redacted
//     there, in `turnLog.ts`). Tool *input* is a different question and answered differently: a call
//     stores the allowlisted projection the pretool request already sent (`tool_input`), because that
//     is what makes the row say which command ran. Nothing here does the allowlisting — see that field.
//   * **No `model`.** 09-CONTEXT's record shape lists one, and it is deliberately omitted here: the
//     wire value is pinned to `TURNLOG_MODEL` (`"auto"`) because the backend drops the row for any id
//     that is not an enabled `AIModel` (`add_gateway_metrics_task.py:565-577`). Keeping a real model
//     id in the record would only invite a future reader to send it and silently lose every row. The
//     real id is available on `agent_end`'s messages if analytics ever wants it server-side.
//   * **No I/O of any kind** — no filesystem, no network, no stderr; `node:crypto` is the only
//     import. `tool_result` is an awaited pass over every tool result, so this module is pure
//     computation on data already in memory. A grep of this file for either capability finds
//     nothing, which is how the property is checked rather than asserted.
//
// `startTurn` is called lazily by `recordPrompt` and `recordToolCall`, never by a handler directly.
// `conversation_id` is load-bearing on the wire — it becomes `thread_id` and `derive_hook_request_id`
// returns `None` without it (§B2) — and a turn can genuinely begin with a tool call rather than a
// prompt, because `agent_end` fires for extension-initiated runs too (§F3). Whichever event arrives
// first therefore stamps the session id and the start time, and no later event *in that session*
// resets them.
//
// Across sessions the opposite is required. pi's session id changes on `/new`, `/resume` and `/fork`,
// and a record pending when that happens can never be posted under the new one — `thread_id` would
// stitch two conversations together. `user_bash` is what first made this reachable: it used to record
// a tool call here, and pi fires no `agent_end` for a bare `!cmd`, so that record sat pending until
// the developer typed `/new` (or rode the NEXT turn's log under that turn's prompt). A `!cmd` is now
// posted as its own one-call turn log and never enters this store (`agentEnd.ts postStandaloneTurn`),
// but a prompt left by an aborted run can still be pending across `/new`, so both guards stay, belt
// and braces: `reset(sessionId)` for `session_start` to drop it, and `startTurn` rolling the record
// over when the id it is handed differs from the stored one. Neither ever posts the old record —
// `agent_end` never fired for it.
//
// Every method is total. A fault here would surface inside a `tool_call` or `tool_result` handler,
// and pi reads a thrown `tool_call` handler as a BLOCK — an audit record must never be able to change
// a verdict.

import { createHash } from "node:crypto";

import {
  MAX_HASH_BYTES,
  MAX_TURN_OUTPUT_CHARS,
  MAX_TURN_RESULTS,
  MAX_TURN_TOOL_CALLS,
  OUTPUT_TRUNCATION_MARKER,
} from "./constants.ts";

/** pi's `TextContent` (`AI/dist/types.d.ts:242-246`). `textSignature` is provider metadata. */
export interface TextPart {
  type: "text";
  text: string;
  textSignature?: string;
}

/** pi's `ImageContent` (`:256-260`). `data` is base64, so its length is an ENCODED byte count. */
export interface ImagePart {
  type: "image";
  data: string;
  mimeType: string;
}

export type ContentPart = TextPart | ImagePart;

/** The hash of one tool result, or an honest statement that it was too big to hash. */
export interface ContentHash {
  /** Absent exactly when `hash_skipped` is true. */
  content_sha256: string | undefined;
  /** Byte length of the canonical projection — for an image part, of its base64 form. */
  content_bytes: number;
  /** Only ever `true`; absent means the digest is real. */
  hash_skipped?: boolean;
}

export interface TurnToolCall {
  tool_name: string;
  tool_use_id: string;
  /** The `PolicyOutcome.kind` that actually applied, or `"skipped"` for a cache-skipped file tool. */
  decision: string;
  ts: number;
  /**
   * The **already-sanitised** tool input, as `payload.ts`'s `auditToolInput` produced it: the
   * allowlisted keys plus the capped `command`, and never a file body.
   *
   * Sanitised by the caller, not here, and that is the contract — this module holds no allowlist and
   * must not grow one. The decision seam is the only place that still has the live `event.input`, so
   * it is the only place that can project it; by the time a value reaches this field it is already
   * the same thing the pretool request sent. Absent means the call was recorded without one (a
   * cache-skipped file tool has no command and may have no allowlisted key either), which the turn
   * log sends as `{}`.
   *
   * For an MCP call (recorded by the approval-broker handler) it is the audit copy of the MCP
   * arguments (`auditMcpArgs`: owned, capped, `__proto__`-safe) — the one case where values can be
   * nested objects. `turnLog.ts` redacts every string leaf.
   */
  tool_input?: Record<string, unknown>;
  /**
   * The session this call actually happened in (WR-04). Never sent — it exists so a record can be
   * *attributed* rather than merely dropped: the whole-record rollover keys on `record.session_id`,
   * which is only ever set from whichever event arrived first, so a `ctx` whose session id could not
   * be read (`sessionIdOf`'s `""`) left entries from two sessions mixed with nothing to separate
   * them by. Absent means the id was not knowable when the call was recorded.
   */
  session_id?: string;
}

export interface TurnResult {
  tool_name: string;
  tool_use_id: string;
  is_error: boolean;
  content_sha256?: string;
  content_bytes: number;
  hash_skipped?: boolean;
  /** The text parts of the output, capped by `captureText`. Absent: no text, or over the budget. */
  content?: string;
  /** Only ever `true`: `content` is a head + marker + tail of the output, not all of it. */
  content_truncated?: true;
  /** The full text length (UTF-16 units) when `content_truncated` is set. */
  content_original_chars?: number;
  /** Only ever `true`: there was text, but the turn's `MAX_TURN_OUTPUT_CHARS` budget was spent. */
  content_omitted?: true;
}

/** What `captureText` hands back: the text to keep, and whether it is all of it. */
export interface CapturedText {
  text: string;
  truncated?: true;
  original_chars?: number;
}

export interface TurnRecord {
  /** The prompt as checked, captured by the `input` handler — `agent_end` never carries it (§A4). */
  prompt?: string;
  tool_calls: TurnToolCall[];
  results: TurnResult[];
  session_id?: string;
  started_at?: number;
  /** How many results the `MAX_TURN_RESULTS` cap dropped. Absent means none — never a zero. */
  results_truncated?: number;
  /** How many tool calls the `MAX_TURN_TOOL_CALLS` cap dropped. Absent means none — never a zero. */
  tool_calls_truncated?: number;
}

export interface TurnStore {
  /** Not called by handlers — `recordPrompt`/`recordToolCall` call it when the store is empty. */
  startTurn(sessionId: string, now: number): void;
  /**
   * Drop a pending record that belongs to a different session. Called by `session_start`, which pi
   * fires again on `/new`, `/resume`, `/fork` and `/reload`.
   *
   * Keyed on the id rather than unconditional, because two of those reasons re-fire with the SAME
   * session: dropping then would discard a turn that is still mid-flight. `""` — what `sessionIdOf`
   * answers for a ctx it cannot read — means "not known", never "changed", and drops nothing.
   */
  reset(sessionId: string): void;
  recordPrompt(text: string, sessionId: string, now?: number): void;
  recordToolCall(entry: Omit<TurnToolCall, "ts">, sessionId: string, now?: number): void;
  recordResult(entry: TurnResult): void;
  /**
   * The record, plus an empty store — so a retried `agent_end` cannot re-post it (§F3). The store is
   * emptied even when the answer is `undefined`: a record that is not postable is still consumed,
   * because nothing else will ever clear it.
   */
  take(): TurnRecord | undefined;
  /** True when neither a prompt nor a tool call has been seen. Mirrors `PY:4975`. */
  isEmpty(): boolean;
  /** A deep-enough copy for assertions; mutating it cannot reach the live record. */
  snapshot(): TurnRecord;
  /**
   * The pending prompt, when it belongs to `sessionId` — or `undefined`.
   *
   * The pretool request's `messages[0].content` is what the gateway writes its block/warn row from,
   * so `tool_call` reads this on every evaluated call. That is why it is a getter and not
   * `snapshot()`: it is the per-tool-call path and must stay O(1) — no copy, no allocation, one
   * reference handed back. `""` (an unreadable session id) means "not known" and still answers, as
   * does a record not yet stamped with any session; a record stamped with a DIFFERENT session does
   * not, because its prompt describes another conversation. Total.
   */
  currentPrompt(sessionId: string): string | undefined;
}

/**
 * One part's canonical projection, **split at the boundary between the small fixed tag and the
 * potentially enormous payload** (WR-03).
 *
 * The projection is still exactly `"text:" + text` / `"image:" + mimeType + ":" + data`, byte for
 * byte, so no digest changes. What changes is that it is never *concatenated*: `prefix` is a handful
 * of bytes built here, and `body` is the string that was already on the part, returned by reference.
 * Sizing and hashing then both work off the pair, so a 100 MB `read` result costs no copy of itself
 * at any point. `textSignature` is excluded, so a provider annotation cannot move the hash.
 */
interface PartProjection {
  prefix: string;
  body: string;
}

const EMPTY_PROJECTION: PartProjection = { prefix: "", body: "" };

function projectPart(part: unknown): PartProjection {
  if (part === null || typeof part !== "object") return EMPTY_PROJECTION;
  const record = part as { type?: unknown; text?: unknown; data?: unknown; mimeType?: unknown };
  if (record.type === "image") {
    const mimeType = typeof record.mimeType === "string" ? record.mimeType : "";
    const data = typeof record.data === "string" ? record.data : "";
    return { prefix: `image:${mimeType}:`, body: data };
  }
  const text = typeof record.text === "string" ? record.text : "";
  return { prefix: "text:", body: text };
}

/**
 * The projection's byte length, without building it. `Buffer.byteLength` scans; it does not allocate,
 * which is the entire property that lets the cap below be checked before any memory is committed.
 */
function projectionByteLength(projection: PartProjection): number {
  return Buffer.byteLength(projection.prefix, "utf8") + Buffer.byteLength(projection.body, "utf8");
}

/**
 * sha256 of the canonical projection of a tool result's content.
 *
 * **Not a JSON serialisation of `content`** (§F7): key order is not content, and `textSignature` is provider
 * metadata that changes between runs of the same command — either would make the digest useless for
 * telling "the same output" from "a different output". The projection is built by hand instead, one
 * line per part, separated by `\n`, and fed to the digest in pieces so no concatenated string is ever
 * built — see `projectPart`.
 *
 * Above `MAX_HASH_BYTES` nothing is hashed at all, and — since WR-03 — nothing is *allocated* either.
 * The old version counted the size first and did skip the digest, but `list.map(projectPart)` ran
 * before the count, so `"text:" + text` was materialised for every part: measured at a 114 MB heap
 * peak against 9 MB for a single 100 MB text part, i.e. a full extra copy of the tool output, on the
 * awaited pass between a tool finishing and the model seeing its output. Now the parts are sized
 * through `projectionByteLength` (a scan, not a copy) and the digest is fed prefix-then-body per
 * part, so no concatenated string is ever built — at any size.
 *
 * The count is still the EXACT total rather than "however far we got before exceeding the cap":
 * sizing is allocation-free, so there is nothing to save by bailing early, and `content_bytes` stays
 * an honest number on the skipped path where it is the only thing reported.
 */
export function hashContent(parts: readonly unknown[]): ContentHash {
  try {
    const list = Array.isArray(parts) ? parts : [];
    // Sized before anything is built, including the `\n` separators, so the cap decides whether any
    // work happens at all rather than capping work already done.
    let bytes = 0;
    for (let i = 0; i < list.length; i += 1) {
      if (i > 0) bytes += 1;
      bytes += projectionByteLength(projectPart(list[i]));
    }
    if (bytes > MAX_HASH_BYTES) {
      return { content_sha256: undefined, content_bytes: bytes, hash_skipped: true };
    }

    const hash = createHash("sha256");
    for (let i = 0; i < list.length; i += 1) {
      if (i > 0) hash.update("\n", "utf8");
      // Two updates, never a concatenation: the byte stream fed to the digest is identical to the
      // joined projection, so every existing hash stays what it was.
      const projection = projectPart(list[i]);
      hash.update(projection.prefix, "utf8");
      hash.update(projection.body, "utf8");
    }
    return { content_sha256: hash.digest("hex"), content_bytes: bytes };
  } catch {
    // A digest we could not compute is a digest we do not report. The count is not worth guessing
    // either, so this is the one shape that says "nothing is known".
    return { content_sha256: undefined, content_bytes: 0, hash_skipped: true };
  }
}

/** A structural copy of a recorded input; a shallow one if the structure cannot be cloned. */
function copyInput(input: Record<string, unknown>): Record<string, unknown> {
  try {
    return structuredClone(input);
  } catch {
    return { ...input };
  }
}

/** The text of a part, or `undefined` for anything that is not a `type:"text"` part with a string. */
function textOf(part: unknown): string | undefined {
  if (part === null || typeof part !== "object") return undefined;
  const record = part as { type?: unknown; text?: unknown };
  return record.type === "text" && typeof record.text === "string" ? record.text : undefined;
}

/**
 * A flat copy of `value`. V8 can represent `big.slice(…)` as a view that keeps `big` alive, and
 * `big` here can be a 100 MB `read`; a UTF-8 round trip forces a fresh, standalone string. Only ever
 * applied to text already bounded by the cap.
 */
function flatten(value: string): string {
  return Buffer.from(value, "utf8").toString("utf8");
}

/**
 * The TEXT of a tool result, capped at `maxChars` with both ends kept — or `undefined` when there is
 * no text part at all (an all-image result, an empty array, a hostile input).
 *
 * Same discipline as `hashContent`: the parts are SIZED first without concatenating them, and an
 * over-cap output only ever has its first `maxChars/2` and last `maxChars/2` characters collected,
 * across part boundaries (parts are joined with `\n`, as `hashContent` separates them). Image parts are
 * skipped entirely — base64 is never captured. The result is flattened so it cannot pin a huge parent
 * string in memory for the rest of the turn. Total.
 */
export function captureText(parts: readonly unknown[], maxChars: number): CapturedText | undefined {
  try {
    if (!Array.isArray(parts)) return undefined;
    const texts: string[] = [];
    for (const part of parts) {
      const text = textOf(part);
      if (text !== undefined) texts.push(text);
    }
    if (texts.length === 0) return undefined;

    let total = 0;
    for (let i = 0; i < texts.length; i += 1) total += (i > 0 ? 1 : 0) + texts[i]!.length;
    const cap = Number.isFinite(maxChars) && maxChars > 0 ? Math.floor(maxChars) : 0;
    if (total <= cap) return { text: flatten(texts.join("\n")) };

    const headBudget = Math.ceil(cap / 2);
    const tailBudget = cap - headBudget;
    // The joined stream is `texts[0] + "\n" + texts[1] + …`, walked as segments so nothing is joined.
    const segments: string[] = [];
    for (let i = 0; i < texts.length; i += 1) {
      if (i > 0) segments.push("\n");
      segments.push(texts[i]!);
    }
    let head = "";
    for (const segment of segments) {
      const room = headBudget - head.length;
      if (room <= 0) break;
      head += segment.length <= room ? segment : segment.slice(0, room);
    }
    let tail = "";
    for (let i = segments.length - 1; i >= 0; i -= 1) {
      const room = tailBudget - tail.length;
      if (room <= 0) break;
      const segment = segments[i]!;
      tail = (segment.length <= room ? segment : segment.slice(segment.length - room)) + tail;
    }
    return {
      text: flatten(head) + OUTPUT_TRUNCATION_MARKER + flatten(tail),
      truncated: true,
      original_chars: total,
    };
  } catch {
    return undefined;
  }
}

export function createTurnStore(): TurnStore {
  let record: TurnRecord = { tool_calls: [], results: [] };
  /** Output characters stored in THIS record — the `MAX_TURN_OUTPUT_CHARS` budget. */
  let outputChars = 0;
  /** A new, empty record — and a fresh budget with it. Every replacement goes through here. */
  const fresh = (): TurnRecord => {
    outputChars = 0;
    return { tool_calls: [], results: [] };
  };

  const started = (): boolean => record.prompt !== undefined || record.tool_calls.length > 0;

  /** `undefined` for anything that is not a usable session id — see `sessionIdOf`'s `""`. */
  const idOf = (sessionId: unknown): string | undefined =>
    typeof sessionId === "string" && sessionId !== "" ? sessionId : undefined;

  function startTurn(sessionId: string, now: number): void {
    const incoming = idOf(sessionId);
    // A session id that differs from the stored one is a different conversation, not a later event in
    // this one. The pending record can never be posted under it — `conversation_id` becomes
    // `thread_id` (§B2) — so it rolls over here rather than accumulating across `/new`. This is the
    // backstop for any path that reaches a record before `session_start` resets it; `user_bash` is
    // the one that made it necessary, because pi fires no `agent_end` for a bare `!cmd`.
    if (incoming !== undefined && record.session_id !== undefined && record.session_id !== incoming) {
      record = fresh();
    }
    // Per-entry attribution, for the case the whole-record check above cannot see (WR-04). A `ctx`
    // whose session id is unreadable stamps `record.session_id` with nothing, so a later real id
    // never "differs" from it and a pending `!cmd` call from the previous session would ride this
    // turn's `tool_use[]` — a row claiming N calls for a turn that made one. Entries carry their own
    // id, so the foreign ones can be dropped without discarding this session's work.
    if (incoming !== undefined) {
      const ours = record.tool_calls.filter(
        (entry) => entry.session_id === undefined || entry.session_id === incoming,
      );
      if (ours.length !== record.tool_calls.length) record.tool_calls = ours;
    }
    if (record.session_id === undefined && incoming !== undefined) {
      record.session_id = incoming;
    }
    if (record.started_at === undefined && typeof now === "number" && Number.isFinite(now)) {
      record.started_at = now;
    }
  }

  return {
    startTurn,

    reset(sessionId: string): void {
      try {
        const incoming = idOf(sessionId);
        if (incoming === undefined) return;
        if (record.session_id === incoming) return;
        record = fresh();
      } catch {
        // Total by contract — see the header.
      }
    },

    recordPrompt(text: string, sessionId: string, now: number = Date.now()): void {
      try {
        startTurn(sessionId, now);
        record.prompt = typeof text === "string" ? text : "";
      } catch {
        // Total by contract — see the header.
      }
    },

    /**
     * Capped at `MAX_TURN_TOOL_CALLS`, dropping the oldest, exactly as `recordResult` caps `results`
     * (WR-04). `user_bash` is why: it records a call, pi fires no `agent_end` for a bare `!cmd`, so
     * nothing drains the record and a developer working through a series of them accumulated an entry
     * per invocation for the whole session.
     */
    recordToolCall(entry: Omit<TurnToolCall, "ts">, sessionId: string, now: number = Date.now()): void {
      try {
        if (entry === null || typeof entry !== "object") return;
        startTurn(sessionId, now);
        while (record.tool_calls.length >= MAX_TURN_TOOL_CALLS) {
          record.tool_calls.shift();
          record.tool_calls_truncated = (record.tool_calls_truncated ?? 0) + 1;
        }
        const stored: TurnToolCall = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          decision: typeof entry.decision === "string" ? entry.decision : "",
          ts: now,
        };
        // Copied, not referenced: the caller's object is derived from pi's live `event.input`, and a
        // record that aliased it would describe whatever that object became later rather than what
        // was actually checked. A non-object is not stored at all — an audit field is either the
        // sanitised projection or absent, never junk.
        const input = entry.tool_input;
        if (input !== null && typeof input === "object" && !Array.isArray(input)) {
          stored.tool_input = { ...input };
        }
        // Stamped at record time, from the id this call was actually made under — not read back off
        // the record, which may carry an older session's id or none at all.
        const incoming = idOf(sessionId);
        if (incoming !== undefined) stored.session_id = incoming;
        record.tool_calls.push(stored);
      } catch {
        // ditto
      }
    },

    /**
     * A result does **not** start a turn. A tool result whose call was never recorded belongs to a
     * turn already posted (or to one this process never saw), and starting a turn from it would post
     * a record with no prompt and no call — exactly the noise `PY:4975` refuses to send.
     *
     * Capped at `MAX_TURN_RESULTS`, dropping the oldest: the newest results are the ones a developer
     * is looking at, and an early call that loses its digest gets an honest empty `tool_response`
     * rather than another call's. The caller is expected not to record at all when nothing will post
     * the record (`index.ts` does exactly that for a keyless or latched session) — this is the
     * backstop for the turn that legitimately produces more results than anyone wants to read.
     */
    recordResult(entry: TurnResult): void {
      try {
        if (entry === null || typeof entry !== "object") return;
        while (record.results.length >= MAX_TURN_RESULTS) {
          const evicted = record.results.shift();
          record.results_truncated = (record.results_truncated ?? 0) + 1;
          // Refund: an evicted result's text is never posted, so it must not keep spending (WR-03).
          if (typeof evicted?.content === "string") outputChars = Math.max(0, outputChars - evicted.content.length);
        }
        const stored: TurnResult = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          is_error: entry.is_error === true,
          content_bytes: typeof entry.content_bytes === "number" ? entry.content_bytes : 0,
        };
        if (typeof entry.content_sha256 === "string") stored.content_sha256 = entry.content_sha256;
        if (entry.hash_skipped === true) stored.hash_skipped = true;
        // The output text, under the per-turn budget. Over it, the text is dropped and the row says
        // so; the hash and the byte count above still describe the output.
        //
        // Only for a result whose CALL is recorded (WR-03). The turn log pairs results to calls by id
        // and never posts an unmatched one, so text from an unrecorded call (a custom tool that took
        // the nothing-evaluable skip, an MCP proxy `search`) would be held and charged for nothing —
        // and a model could spend the whole budget that way to blind output DLP on a later call. Calls
        // are recorded at the decision seam (or by the MCP broker) before their result arrives.
        const id = stored.tool_use_id;
        const recorded = id !== "" && record.tool_calls.some((call) => call.tool_use_id === id);
        if (!recorded) {
          // Hash and bytes only; nothing to post it against, so nothing is charged.
        } else if (typeof entry.content === "string") {
          if (outputChars + entry.content.length > MAX_TURN_OUTPUT_CHARS) {
            stored.content_omitted = true;
          } else {
            stored.content = entry.content;
            outputChars += entry.content.length;
            if (entry.content_truncated === true) stored.content_truncated = true;
            if (typeof entry.content_original_chars === "number" && Number.isFinite(entry.content_original_chars)) {
              stored.content_original_chars = entry.content_original_chars;
            }
          }
        } else if (entry.content_omitted === true) {
          stored.content_omitted = true;
        }
        record.results.push(stored);
      } catch {
        // ditto
      }
    },

    /**
     * Consumes the record unconditionally, and answers `undefined` when there was nothing postable.
     *
     * The reset is NOT conditional on the record being postable, and that is the point. A turn can
     * collect results without ever starting — a custom tool (or an MCP call nobody could resolve)
     * takes the nothing-evaluable skip and records no decision, an extension-sourced prompt records
     * no prompt — and an early return here left those results in place, where `agent_end` could
     * never drain them. They then belonged to no turn at all: `shouldPostTurn` refuses to send them, and a later started turn would only
     * fail to match them by `tool_use_id`. Consumed and dropped is the honest outcome.
     */
    take(): TurnRecord | undefined {
      try {
        const taken = record;
        const postable = started();
        record = fresh();
        return postable ? taken : undefined;
      } catch {
        return undefined;
      }
    },

    isEmpty(): boolean {
      try {
        return !started();
      } catch {
        return true;
      }
    },

    snapshot(): TurnRecord {
      const copy: TurnRecord = {
        // `tool_input` is copied a second time so `snapshot()` never hands callers a live reference
        // into the record. A native call's values are scalars (`sanitizeToolInput` forwards nothing
        // else), but an MCP call's capped arguments can nest, so the copy is structural.
        tool_calls: record.tool_calls.map((entry) =>
          entry.tool_input === undefined
            ? { ...entry }
            : { ...entry, tool_input: copyInput(entry.tool_input) },
        ),
        results: record.results.map((entry) => ({ ...entry })),
      };
      if (record.prompt !== undefined) copy.prompt = record.prompt;
      if (record.session_id !== undefined) copy.session_id = record.session_id;
      if (record.started_at !== undefined) copy.started_at = record.started_at;
      if (record.results_truncated !== undefined) copy.results_truncated = record.results_truncated;
      if (record.tool_calls_truncated !== undefined) {
        copy.tool_calls_truncated = record.tool_calls_truncated;
      }
      return copy;
    },

    currentPrompt(sessionId: string): string | undefined {
      try {
        const prompt = record.prompt;
        if (typeof prompt !== "string") return undefined;
        if (sessionId === "" || record.session_id === undefined || record.session_id === sessionId) {
          return prompt;
        }
        return undefined;
      } catch {
        // Total by contract — a fault here would surface inside a `tool_call` handler.
        return undefined;
      }
    },
  };
}

/**
 * The process-wide instance, mirroring `policyState`: the record has to survive from the `input`
 * event through every `tool_call` and `tool_result` to `agent_end`, which is four separate handler
 * invocations. It resets on `/reload` because pi clears the extension module cache (§A7) — losing at
 * most one unposted turn log, which is the cheapest thing in this file to lose.
 */
export const turnStore: TurnStore = createTurnStore();
