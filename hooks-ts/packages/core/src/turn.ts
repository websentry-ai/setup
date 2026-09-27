// The in-memory turn record (HOOK-06 / RES-04) — what happened during one turn, and nothing more.
//
// Three deliberate absences define this module.
//
//   * **No raw tool output.** A result is recorded as a tool name, an `isError` flag, a sha256 of a
//     canonical projection and a byte count. The content itself is read once, projected, hashed and
//     dropped; it is never stored, never serialised and never written anywhere. That is the whole
//     requirement, and `turn.test.ts` proves it by grepping `snapshot()` for a marker string.
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
// first therefore stamps the session id and the start time, and no later event resets them.
//
// Every method is total. A fault here would surface inside a `tool_call` or `tool_result` handler,
// and pi reads a thrown `tool_call` handler as a BLOCK — an audit record must never be able to change
// a verdict.

import { createHash } from "node:crypto";

import { MAX_HASH_BYTES } from "./constants.ts";

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
}

export interface TurnResult {
  tool_name: string;
  tool_use_id: string;
  is_error: boolean;
  content_sha256?: string;
  content_bytes: number;
  hash_skipped?: boolean;
}

export interface TurnRecord {
  /** The prompt as checked, captured by the `input` handler — `agent_end` never carries it (§A4). */
  prompt?: string;
  tool_calls: TurnToolCall[];
  results: TurnResult[];
  session_id?: string;
  started_at?: number;
}

export interface TurnStore {
  /** Not called by handlers — `recordPrompt`/`recordToolCall` call it when the store is empty. */
  startTurn(sessionId: string, now: number): void;
  recordPrompt(text: string, sessionId: string, now?: number): void;
  recordToolCall(entry: Omit<TurnToolCall, "ts">, sessionId: string, now?: number): void;
  recordResult(entry: TurnResult): void;
  /** The record, plus an empty store — so a retried `agent_end` cannot re-post it (§F3). */
  take(): TurnRecord | undefined;
  /** True when neither a prompt nor a tool call has been seen. Mirrors `PY:4975`. */
  isEmpty(): boolean;
  /** A deep-enough copy for assertions; mutating it cannot reach the live record. */
  snapshot(): TurnRecord;
}

/** `"text:" + text` — `textSignature` is excluded, so a provider annotation cannot move the hash. */
function projectPart(part: unknown): string {
  if (part === null || typeof part !== "object") return "";
  const record = part as { type?: unknown; text?: unknown; data?: unknown; mimeType?: unknown };
  if (record.type === "image") {
    const mimeType = typeof record.mimeType === "string" ? record.mimeType : "";
    const data = typeof record.data === "string" ? record.data : "";
    return `image:${mimeType}:${data}`;
  }
  const text = typeof record.text === "string" ? record.text : "";
  return `text:${text}`;
}

/**
 * sha256 of the canonical projection of a tool result's content.
 *
 * **Not a JSON serialisation of `content`** (§F7): key order is not content, and `textSignature` is provider
 * metadata that changes between runs of the same command — either would make the digest useless for
 * telling "the same output" from "a different output". The projection is built by hand instead, one
 * line per part, joined with `\n`, and the digest is fed part-by-part so a large content array never
 * needs one concatenated string.
 *
 * Above `MAX_HASH_BYTES` nothing is hashed at all: the size is counted first, and the bail-out
 * returns before `createHash` is ever called.
 */
export function hashContent(parts: readonly unknown[]): ContentHash {
  try {
    const list = Array.isArray(parts) ? parts : [];
    const projected = list.map(projectPart);
    // Sized before hashing, including the `\n` separators, so the cap decides whether any work
    // happens at all rather than capping work already done.
    let bytes = 0;
    for (let i = 0; i < projected.length; i += 1) {
      bytes += Buffer.byteLength(projected[i] ?? "", "utf8");
      if (i > 0) bytes += 1;
    }
    if (bytes > MAX_HASH_BYTES) {
      return { content_sha256: undefined, content_bytes: bytes, hash_skipped: true };
    }

    const hash = createHash("sha256");
    for (let i = 0; i < projected.length; i += 1) {
      if (i > 0) hash.update("\n", "utf8");
      hash.update(projected[i] ?? "", "utf8");
    }
    return { content_sha256: hash.digest("hex"), content_bytes: bytes };
  } catch {
    // A digest we could not compute is a digest we do not report. The count is not worth guessing
    // either, so this is the one shape that says "nothing is known".
    return { content_sha256: undefined, content_bytes: 0, hash_skipped: true };
  }
}

export function createTurnStore(): TurnStore {
  let record: TurnRecord = { tool_calls: [], results: [] };

  const started = (): boolean => record.prompt !== undefined || record.tool_calls.length > 0;

  function startTurn(sessionId: string, now: number): void {
    if (record.session_id === undefined && typeof sessionId === "string" && sessionId !== "") {
      record.session_id = sessionId;
    }
    if (record.started_at === undefined && typeof now === "number" && Number.isFinite(now)) {
      record.started_at = now;
    }
  }

  return {
    startTurn,

    recordPrompt(text: string, sessionId: string, now: number = Date.now()): void {
      try {
        startTurn(sessionId, now);
        record.prompt = typeof text === "string" ? text : "";
      } catch {
        // Total by contract — see the header.
      }
    },

    recordToolCall(entry: Omit<TurnToolCall, "ts">, sessionId: string, now: number = Date.now()): void {
      try {
        if (entry === null || typeof entry !== "object") return;
        startTurn(sessionId, now);
        record.tool_calls.push({
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          decision: typeof entry.decision === "string" ? entry.decision : "",
          ts: now,
        });
      } catch {
        // ditto
      }
    },

    /**
     * A result does **not** start a turn. A tool result whose call was never recorded belongs to a
     * turn already posted (or to one this process never saw), and starting a turn from it would post
     * a record with no prompt and no call — exactly the noise `PY:4975` refuses to send.
     */
    recordResult(entry: TurnResult): void {
      try {
        if (entry === null || typeof entry !== "object") return;
        const stored: TurnResult = {
          tool_name: typeof entry.tool_name === "string" ? entry.tool_name : "",
          tool_use_id: typeof entry.tool_use_id === "string" ? entry.tool_use_id : "",
          is_error: entry.is_error === true,
          content_bytes: typeof entry.content_bytes === "number" ? entry.content_bytes : 0,
        };
        if (typeof entry.content_sha256 === "string") stored.content_sha256 = entry.content_sha256;
        if (entry.hash_skipped === true) stored.hash_skipped = true;
        record.results.push(stored);
      } catch {
        // ditto
      }
    },

    take(): TurnRecord | undefined {
      try {
        if (!started()) return undefined;
        const taken = record;
        record = { tool_calls: [], results: [] };
        return taken;
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
        tool_calls: record.tool_calls.map((entry) => ({ ...entry })),
        results: record.results.map((entry) => ({ ...entry })),
      };
      if (record.prompt !== undefined) copy.prompt = record.prompt;
      if (record.session_id !== undefined) copy.session_id = record.session_id;
      if (record.started_at !== undefined) copy.started_at = record.started_at;
      return copy;
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
