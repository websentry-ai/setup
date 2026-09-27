// The only two places this package touches `ctx.ui`.
//
// `confirmWithTimeout` exists to make one pitfall structurally impossible: in `--mode rpc` `hasUI`
// is true, but a dialog opened without `opts.timeout`/`opts.signal` never settles, and because pi
// gates the entire tool batch on our handler (§F2) the agent is dead (§F5). Funnelling every dialog
// through one function means a two-argument confirm call cannot exist anywhere in the codebase —
// and a grep proves it.
//
// `notifySafe` exists because notifications are cosmetic and must never be able to break a tool
// call: it swallows its own failures, and when there is no UI it mirrors to **stderr**, never
// stdout, which is pi's JSON/print channel (§F9). Everything it emits is redacted first.

import { CONFIRM_TIMEOUT_MS } from "../../core/src/constants.ts";
import { redactSecrets } from "../../core/src/config.ts";

export type NotifyLevel = "info" | "warning" | "error";

/** The structural slice of `ExtensionContext` the UI helpers need. */
export interface UiCtx {
  hasUI: boolean;
  signal: AbortSignal | undefined;
  ui: {
    confirm(
      title: string,
      message: string,
      opts?: { signal?: AbortSignal; timeout?: number },
    ): Promise<boolean>;
    notify(message: string, type?: NotifyLevel): void;
  };
}

export function notifySafe(ctx: UiCtx, message: string, level: NotifyLevel): void {
  try {
    const safe = redactSecrets(message);
    if (ctx.hasUI) {
      ctx.ui.notify(safe, level);
      return;
    }
    // Headless: `noOpUIContext.notify` is a no-op (§A6), so the notice would simply vanish.
    process.stderr.write(`${safe}\n`);
  } catch {
    // A notice is never worth failing a tool call over.
  }
}

/**
 * The single `confirm` call site. Resolves `false` for every non-acceptance — No, Escape, dismissal,
 * timeout, abort (§A5) — and also for a UI implementation that raises, so an exploding dialog
 * declines rather than becoming a thrown handler (which pi would turn into a block, §F1).
 */
export async function confirmWithTimeout(
  ctx: UiCtx,
  title: string,
  message: string,
  timeoutMs: number = CONFIRM_TIMEOUT_MS,
): Promise<boolean> {
  try {
    return await ctx.ui.confirm(title, message, { timeout: timeoutMs, signal: ctx.signal });
  } catch {
    return false;
  }
}
