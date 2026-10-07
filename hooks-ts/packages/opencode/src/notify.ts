// A toast through `client.tui.showToast`, bounded and fire-and-forget.
//
// Spike V1-11 (13-SPIKES.md): GO. The method exists on 1.18.x and resolves `true` in 2-3 ms, also
// with no TUI attached; visibility in the TUI is a human check. A toast is cosmetic: it must never
// raise, never reject, and never hold a handler up for longer than `TOAST_TIMEOUT_MS`.
//
// The returned promise always RESOLVES, once the toast settled or the bound passed, whichever comes
// first. Callers normally ignore it (`void notify(...)`); a caller that wants the toast on screen
// before it blocks may await it, and waits at most `TOAST_TIMEOUT_MS`.

import { TOAST_TIMEOUT_MS } from "./constants.ts";

export type NotifyLevel = "info" | "warning" | "error";

const TOAST_TITLE = "Unbound";

function showToastOf(client: unknown): ((opts: unknown) => unknown) | undefined {
  try {
    if (client === null || typeof client !== "object") return undefined;
    const tui = (client as { tui?: unknown }).tui;
    if (tui === null || typeof tui !== "object") return undefined;
    const show = (tui as { showToast?: unknown }).showToast;
    return typeof show === "function" ? (opts: unknown) => show.call(tui, opts) : undefined;
  } catch {
    return undefined;
  }
}

export function notify(client: unknown, message: string, level: NotifyLevel): Promise<void> {
  try {
    const show = showToastOf(client);
    if (show === undefined || typeof message !== "string" || message === "") return Promise.resolve();
    const toast = Promise.resolve(show({ body: { message, variant: level, title: TOAST_TITLE } }));
    return new Promise<void>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const done = (): void => {
        if (timer !== undefined) clearTimeout(timer);
        resolve();
      };
      try {
        timer = setTimeout(done, TOAST_TIMEOUT_MS);
        timer.unref?.();
      } catch {
        // No timer: the toast's own settlement still resolves this.
      }
      toast.then(done, done);
    });
  } catch {
    return Promise.resolve();
  }
}
