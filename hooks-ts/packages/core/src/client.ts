// The HTTP client. Its single hard guarantee: **it never throws**.
//
// An exception escaping a pi `tool_call` handler is a BLOCK (RESEARCH §F1 — `emitToolCall` has no
// try/catch and agent-core turns the exception into a denial whose message leaks to the model), so
// every path here resolves to a discriminated result instead. There is no `throw` statement in this
// file, and the whole body of each request — `JSON.stringify` included — sits inside try/catch.
//
// Two deliberate constraints on the request itself:
//   * `AbortSignal.timeout(...)` is the ONLY real deadline. pi replaces `globalThis.fetch` with
//     npm-undici and installs a process-global dispatcher whose idle timeout is user-configurable
//     and can be switched off entirely (§F3), so we neither rely on that dispatcher nor mutate it,
//     and we set no `dispatcher`, `agent` or `keepalive` of our own. `AbortSignal.timeout` also
//     aborts the socket itself, which merely racing the request against a timer would not (§D7).
//   * `redirect: "error"` (ASVS V13). undici defaults to `follow`, so a 30x from a hijacked or
//     misconfigured host would replay the `Authorization: Bearer <key>` header at another origin.
//
// Error classes are a telemetry label only. `AbortSignal.timeout` rejects with `TimeoutError`, a
// manual abort with `AbortError`, and undici nests transport failures under `err.cause.code`
// (§F4) — none of that is stable across Node/undici releases, so no product behaviour branches on
// it: a timeout, a refused connection, a 500 and unparseable JSON all take one single fail-open path.

import {
  ERRORS_PATH,
  ERRORS_TIMEOUT_MS,
  PRETOOL_PATH,
  PRETOOL_TIMEOUT_MS,
} from "./constants.ts";
import type { PreToolResponseBody, PretoolRequestBody } from "./types.ts";

/** The server caps a single `/v1/hooks/errors` request at 10 entries (§B6). */
const MAX_ERRORS_PER_REQUEST = 10;
/** A telemetry label is a label, not a payload. */
const MAX_ERROR_CLASS_CHARS = 40;

export type PretoolResult =
  | { ok: true; body: PreToolResponseBody; elapsedMs: number }
  | { ok: false; errorClass: string; elapsedMs: number };

/** One entry of the `/v1/hooks/errors` array (§B6). */
export interface HookErrorEntry {
  message: string;
  timestamp: string;
  category?: string;
  payload_size_bytes?: number;
}

/**
 * The `/v1/hooks/errors` body. Note there is no `unbound_app_label` on this endpoint — the app
 * label rides `hook_source` (§B6, correcting the earlier draft).
 */
export interface HookErrorsBody {
  errors: HookErrorEntry[];
  hook_source: string;
}

export interface ApiClient {
  postPretool(payload: PretoolRequestBody): Promise<PretoolResult>;
  postHookErrors(body: HookErrorsBody): Promise<boolean>;
}

export interface ApiClientOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
  errorsTimeoutMs?: number;
  /** Injected only by tests; production resolves `globalThis.fetch` at call time (§F3). */
  fetchImpl?: typeof fetch;
}

/**
 * A short, safe token naming the failure, for `/v1/hooks/errors` and stderr.
 *
 * Defensive by design (§F4): reads `name`, then `cause.code`, then falls back to `"Error"`, and
 * strips everything outside `[A-Za-z0-9_]` so a hostile or verbose error message cannot smuggle
 * text (a URL with the key in it, say) into a telemetry field. Property access itself is guarded,
 * because a thrown getter here would defeat the purpose of the whole module.
 */
export function classifyError(err: unknown): string {
  let candidate = "";
  try {
    const record = err as { name?: unknown; cause?: { code?: unknown } } | null | undefined;
    const name = typeof record?.name === "string" ? record.name : "";
    const code = typeof record?.cause?.code === "string" ? record.cause.code : "";
    // undici wraps EVERY transport failure in a generic `TypeError: fetch failed` and puts the
    // useful label on `cause.code` (§F4). Preferring the code in that one case is what keeps
    // ECONNREFUSED / ENOTFOUND / UND_ERR_* distinguishable in Sentry instead of collapsing them
    // all — and a real programming TypeError (no `cause.code`) still reports as `TypeError`.
    candidate = name === "TypeError" && code !== "" ? code : name !== "" ? name : code;
  } catch {
    candidate = "";
  }
  const token = candidate.replace(/[^A-Za-z0-9_]/g, "");
  return token.length > 0 ? token.slice(0, MAX_ERROR_CLASS_CHARS) : "Error";
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const timeoutMs = opts.timeoutMs ?? PRETOOL_TIMEOUT_MS;
  const errorsTimeoutMs = opts.errorsTimeoutMs ?? ERRORS_TIMEOUT_MS;

  /** Resolved per call: pi swaps `globalThis.fetch` for undici's before extensions load (§F3). */
  const resolveFetch = (): typeof fetch => opts.fetchImpl ?? globalThis.fetch;

  const headers = (): Record<string, string> => ({
    "content-type": "application/json",
    authorization: `Bearer ${opts.apiKey}`,
  });

  async function postPretool(payload: PretoolRequestBody): Promise<PretoolResult> {
    const startedAt = Date.now();
    const elapsed = (): number => Date.now() - startedAt;
    try {
      const res = await resolveFetch()(`${opts.baseUrl}${PRETOOL_PATH}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "error",
      });
      if (!res.ok) {
        return { ok: false, errorClass: `HttpStatus${res.status}`, elapsedMs: elapsed() };
      }
      let parsed: unknown;
      try {
        parsed = await res.json();
      } catch {
        return { ok: false, errorClass: "MalformedJson", elapsedMs: elapsed() };
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        // A 200 whose body is not an object is as unusable as unparseable bytes.
        return { ok: false, errorClass: "MalformedJson", elapsedMs: elapsed() };
      }
      return { ok: true, body: parsed as PreToolResponseBody, elapsedMs: elapsed() };
    } catch (err) {
      return { ok: false, errorClass: classifyError(err), elapsedMs: elapsed() };
    }
  }

  /**
   * Self-report a fail-open bypass. Returns `true` only on a 2xx and swallows everything else: a
   * broken errors endpoint must be completely invisible to the decision path (T-08-13).
   */
  async function postHookErrors(body: HookErrorsBody): Promise<boolean> {
    try {
      const capped: HookErrorsBody = {
        ...body,
        errors: body.errors.slice(0, MAX_ERRORS_PER_REQUEST),
      };
      const res = await resolveFetch()(`${opts.baseUrl}${ERRORS_PATH}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(capped),
        signal: AbortSignal.timeout(errorsTimeoutMs),
        redirect: "error",
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  return { postPretool, postHookErrors };
}
