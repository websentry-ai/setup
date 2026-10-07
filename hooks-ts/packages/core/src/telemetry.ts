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
import {
  ERROR_CATEGORY_BLOCKED,
  ERROR_CATEGORY_BYPASS,
  ERROR_CATEGORY_TURNLOG,
  ERROR_REPORT_INTERVAL_MS,
} from "./constants.ts";
import type { ApiClient, HookErrorsBody } from "./client.ts";
import type { AgentProfile } from "./profile.ts";

/** Everything any report is allowed to know. Note the absence of a command or payload field. */
export interface ReportContext {
  errorClass: string;
  /** A free-form label, not necessarily a tool: the turn-log path sends `agent_end` (§B6). */
  toolName: string;
  elapsedMs: number;
}

export interface BypassContext extends ReportContext {
  /**
   * WR-03: did this failure end in a **block** (a fail-closed org) rather than a bypass? The caller
   * must therefore decide the failure action BEFORE reporting. Required, not optional, so a future
   * call site cannot silently mislabel a block by forgetting it.
   */
  blocked: boolean;
}

export interface Telemetry {
  /** An enforcement failure: bypassed (fail-open) or blocked (fail-closed). Never anything else. */
  reportBypass(ctx: BypassContext): void;
  /**
   * A lost audit row — the turn-log POST (`AgentProfile.turnLogPath`) failed. A separate method rather than a third state of
   * `blocked`, because it is not an enforcement outcome at all: the check already happened and was
   * honoured. Filed under `ERROR_CATEGORY_TURNLOG`, which exists so this cannot reach the fail-open
   * alert. Shares the window, the re-entrancy guard and the redaction with `reportBypass`.
   */
  reportTurnLogFailure(ctx: ReportContext): void;
}

export interface TelemetryOptions {
  client: Pick<ApiClient, "postHookErrors">;
  /**
   * Which agent is reporting. `hookSource` is both the `hook_source` field and the message prefix
   * (`<hookSource> hook <category>: …`), so the Sentry tag and the fingerprint name the same agent.
   */
  profile: Pick<AgentProfile, "hookSource">;
  /** Absent key ⇒ never report: the endpoint answers 401 without an Authorization header (§B6). */
  apiKey?: string | undefined;
  now?: () => number;
  intervalMs?: number;
  /**
   * WR-01: the session's revoked-key latch (`keyState.ts`). Once it is set, reporting is pointless —
   * this endpoint authenticates with the same rejected key (§F9) — so the reporter goes silent too.
   *
   * Belt and braces: `checkTool` already returns before any HTTP once the latch trips, but the
   * reporter must not depend on its only caller getting that right.
   */
  isInactive?: () => boolean;
}

export function createTelemetry(opts: TelemetryOptions): Telemetry {
  const now = opts.now ?? Date.now;
  const intervalMs = opts.intervalMs ?? ERROR_REPORT_INTERVAL_MS;
  let lastReportAtMs: number | undefined;
  let reporting = false;

  /**
   * The one dispatcher. `category` is chosen by the caller and used in BOTH the `category` field and
   * the message prefix, so the Sentry tag and the fingerprint can never disagree — and so a new report
   * kind cannot be added without stating its label.
   *
   * The rate-limit window is shared across every category on purpose: the one-per-60 s budget belongs
   * to `/v1/hooks/errors`, not to a label, so a lost audit row must not buy a report that a bypass in
   * the same window could not have.
   */
  function report(category: string, ctx: ReportContext): void {
    try {
      const apiKey = opts.apiKey;
      if (apiKey === undefined || apiKey === "") return;
      // A rejected key cannot authenticate this endpoint either, so an inactive session says nothing.
      if (opts.isInactive?.() === true) return;
      if (reporting) return;

      const at = now();
      if (lastReportAtMs !== undefined && at - lastReportAtMs < intervalMs) return;
      // Claim the window before dispatching, not after.
      lastReportAtMs = at;
      reporting = true;

      // The `after <n>ms` suffix stays strictly last: the server fingerprints on
      // `message.slice(0, 100)` (§B6), so a leading latency would fragment one alert into one per
      // millisecond value.
      const message = redactSecrets(
        `${opts.profile.hookSource} hook ${category}: ${ctx.errorClass} for tool=${ctx.toolName} after ${ctx.elapsedMs}ms`,
        apiKey,
      );
      const body: HookErrorsBody = {
        errors: [{ message, timestamp: new Date(at).toISOString(), category }],
        hook_source: opts.profile.hookSource,
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

  return {
    reportBypass(ctx: BypassContext): void {
      report(ctx.blocked === true ? ERROR_CATEGORY_BLOCKED : ERROR_CATEGORY_BYPASS, ctx);
    },
    reportTurnLogFailure(ctx: ReportContext): void {
      report(ERROR_CATEGORY_TURNLOG, ctx);
    },
  };
}
