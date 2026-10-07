// Reporting non-enforcement signals on `/v1/hooks/errors`.
//
// These are OBSERVATIONS, never enforcement outcomes: a second copy of an adapter loaded into the
// same process, a tool call whose attribution could not be determined, arguments that changed after
// they were checked, an API family that is installed but not active on this host. They are worth an
// alert, and none of them says a check was bypassed or blocked. The bypass/blocked categories stay
// exclusive to `telemetry.ts`, so these signals can never reach the fail-open alert.
//
// The adapter chooses the category names; core defines none of them. A category must match
// `^[a-z][a-z0-9_]{0,63}$`, or the report is dropped.
//
// Same posture as `createTelemetry`, in order:
//
//   1. **Rate-limited per category**, one report per window (default `ERROR_REPORT_INTERVAL_MS`) on
//      an injectable clock, with the window claimed BEFORE dispatch. Unlike telemetry's single shared
//      window, a duplicate-load signal must not silence a tamper signal in the same minute. The map
//      of windows is bounded (`MAX_SIGNAL_CATEGORIES`): a category past the bound is dropped, so a
//      caller cannot grow memory by inventing names.
//   2. **Fire-and-forget.** `report` returns `void` synchronously; nothing awaits the POST.
//   3. **Re-entrant-safe** per category: a report is not sent while the previous one of the same
//      category is still in flight.
//   4. **Redacted and minimal.** Only a category, a tool label and a short detail token go out. The
//      detail and label are reduced to `[A-Za-z0-9_.:/-]` and capped, and the whole message goes
//      through `redactSecrets` with the api key.
//
// Total: `report` never raises, whatever the client, the clock or the context does. No pi module
// imports this file.

import { redactSecrets } from "./config.ts";
import { ERROR_REPORT_INTERVAL_MS } from "./constants.ts";
import type { ApiClient, HookErrorsBody } from "./client.ts";
import type { AgentProfile } from "./profile.ts";

/** The most distinct categories one reporter tracks; past it, a new category is dropped. */
export const MAX_SIGNAL_CATEGORIES = 32;
/** The longest detail token (and tool label) a signal message carries. */
export const MAX_SIGNAL_DETAIL_CHARS = 100;

const CATEGORY_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const UNSAFE_DETAIL_CHARS = /[^A-Za-z0-9_.:/-]/g;

export interface SignalContext {
  /** A label for where the signal came from: a tool name, a hook name. Not necessarily a tool. */
  toolName: string;
  /** A short machine token describing the observation; never free text, never a payload. */
  detail?: string;
}

export interface SignalReporter {
  report(category: string, ctx: SignalContext): void;
}

export interface SignalReporterOptions {
  client: Pick<ApiClient, "postHookErrors">;
  /** `hook_source` and the `<hookSource> hook <category>` message prefix. */
  profile: Pick<AgentProfile, "hookSource">;
  /** Absent or empty key ⇒ never report: the endpoint authenticates with it. */
  apiKey?: string | undefined;
  /** The revoked-key latch: once set, this endpoint would reject the key too, so stay silent. */
  isInactive?: () => boolean;
  now?: () => number;
  intervalMs?: number;
}

// Reduce a value to the safe token alphabet, after removing the api key from it, so a key whose
// characters fall outside the alphabet cannot survive as fragments.
function token(value: unknown, apiKey: string, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const reduced = redactSecrets(value, apiKey).replace(UNSAFE_DETAIL_CHARS, "").slice(0, MAX_SIGNAL_DETAIL_CHARS);
  return reduced === "" ? fallback : reduced;
}

function readField(ctx: unknown, field: keyof SignalContext): unknown {
  try {
    if (ctx === null || typeof ctx !== "object") return undefined;
    return (ctx as Record<string, unknown>)[field];
  } catch {
    return undefined;
  }
}

export function createSignalReporter(opts: SignalReporterOptions): SignalReporter {
  const now = opts.now ?? Date.now;
  const rawInterval = opts.intervalMs;
  const intervalMs =
    typeof rawInterval === "number" && Number.isFinite(rawInterval) && rawInterval >= 0
      ? rawInterval
      : ERROR_REPORT_INTERVAL_MS;
  const lastReportAtMs = new Map<string, number>();
  const inFlight = new Set<string>();

  function report(category: string, ctx: SignalContext): void {
    try {
      const apiKey = opts.apiKey;
      if (typeof apiKey !== "string" || apiKey === "") return;
      if (typeof category !== "string" || !CATEGORY_PATTERN.test(category)) return;
      if (opts.isInactive?.() === true) return;
      if (inFlight.has(category)) return;

      const last = lastReportAtMs.get(category);
      if (last === undefined && lastReportAtMs.size >= MAX_SIGNAL_CATEGORIES) return;
      const at = now();
      if (typeof at !== "number" || !Number.isFinite(at)) return;
      if (last !== undefined && at - last < intervalMs) return;
      // Claim the window before dispatching, not after.
      lastReportAtMs.set(category, at);

      const toolName = token(readField(ctx, "toolName"), apiKey, "unknown");
      const detail = token(readField(ctx, "detail"), apiKey, "unspecified");
      const message = redactSecrets(
        `${opts.profile.hookSource} hook ${category}: ${detail} for tool=${toolName}`,
        apiKey,
      );
      const body: HookErrorsBody = {
        errors: [{ message, timestamp: new Date(at).toISOString(), category }],
        hook_source: opts.profile.hookSource,
      };

      inFlight.add(category);
      let posted: Promise<boolean>;
      try {
        posted = Promise.resolve(opts.client.postHookErrors(body));
      } catch {
        inFlight.delete(category);
        return;
      }
      void posted
        .catch(() => false)
        .finally(() => {
          inFlight.delete(category);
        });
    } catch {
      // A signal is never worth a fault on the caller's path.
      inFlight.delete(category);
    }
  }

  return { report };
}
