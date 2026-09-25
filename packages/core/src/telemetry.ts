// Self-reporting a fail-open bypass (RES-02).
//
// Fail-open is a locked architectural contract, which means "enforcement silently didn't happen" is
// a reachable state by design (T-08-08). This reporter is the audit trail that makes it visible, so
// it is a security control — but it must never become a second failure mode. Hence, in order:
//
//   1. **Rate-limited** to one report per 60 s on an injectable clock, with `lastReportAtMs` set
//      BEFORE dispatch so two concurrent calls in the same window cannot both send.
//   2. **Fire-and-forget.** `reportBypass` returns `void` synchronously — there is deliberately no
//      promise for a caller to await, so a hung errors endpoint cannot stall a tool call (T-08-13).
//   3. **Re-entrant-safe**, a port of `unbound.py`'s `_reporting_error` guard: a failure raised while
//      reporting cannot recurse into another report.
//   4. **Redacted and minimal.** Only an error class, a tool name and an elapsed time go out — never
//      the command, the payload or `cwd` (ASVS V8; the command routinely contains secrets), and
//      everything is passed through `redactSecrets` before it leaves the process.
//
// Message ordering is load-bearing: the server fingerprints on `message.slice(0, 100)` (§B6), so the
// error class and tool name come first and the elapsed-ms suffix goes strictly last. Reversing them
// would make every latency produce a distinct fingerprint, fragmenting the alert into noise.

import { redactSecrets } from "./config.ts";
import { ERROR_CATEGORY_BYPASS, ERROR_REPORT_INTERVAL_MS, HOOK_SOURCE } from "./constants.ts";
import type { ApiClient, HookErrorsBody } from "./client.ts";

/** Everything the report is allowed to know. Note the absence of a command or payload field. */
export interface BypassContext {
  errorClass: string;
  toolName: string;
  elapsedMs: number;
}

export interface Telemetry {
  reportBypass(ctx: BypassContext): void;
}

export interface TelemetryOptions {
  client: Pick<ApiClient, "postHookErrors">;
  /** Absent key ⇒ never report: the endpoint answers 401 without an Authorization header (§B6). */
  apiKey?: string | undefined;
  now?: () => number;
  intervalMs?: number;
}

export function createTelemetry(opts: TelemetryOptions): Telemetry {
  const now = opts.now ?? Date.now;
  const intervalMs = opts.intervalMs ?? ERROR_REPORT_INTERVAL_MS;
  let lastReportAtMs: number | undefined;
  let reporting = false;

  function reportBypass(ctx: BypassContext): void {
    try {
      const apiKey = opts.apiKey;
      if (apiKey === undefined || apiKey === "") return;
      if (reporting) return;

      const at = now();
      if (lastReportAtMs !== undefined && at - lastReportAtMs < intervalMs) return;
      // Claim the window before dispatching, not after.
      lastReportAtMs = at;
      reporting = true;

      const message = redactSecrets(
        `pi hook ${ERROR_CATEGORY_BYPASS}: ${ctx.errorClass} for tool=${ctx.toolName} after ${ctx.elapsedMs}ms`,
        apiKey,
      );
      const body: HookErrorsBody = {
        errors: [
          { message, timestamp: new Date(at).toISOString(), category: ERROR_CATEGORY_BYPASS },
        ],
        hook_source: HOOK_SOURCE,
      };

      void opts.client
        .postHookErrors(body)
        .catch(() => false)
        .finally(() => {
          reporting = false;
        });
    } catch {
      // A telemetry fault must never surface to the decision path.
      reporting = false;
    }
  }

  return { reportBypass };
}
