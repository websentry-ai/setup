// HOOK-05 — the pre-model prompt check. Two return values only: `{action:"handled"}`, which
// suppresses the turn entirely, or `undefined`, which means "no opinion, carry on".
//
// **`{action:"transform"}` is never returned.** It exists in pi's union and it is the wrong tool
// here: transforming rewrites what the user typed, and `agent-session.js:1229` fires this event
// *before* pi's own skill/template expansion, so a rewrite would also be fighting that. If the
// gateway ever returns `additionalContext` for pi, the honest surface is a notice, not an edit to the
// developer's words.
//
// **`{action:"continue"}` is never returned either.** `undefined` is what lets later `input` handlers
// run; `handled` short-circuits them (`runner.js:1096-1131`), and `continue` would be us claiming an
// opinion we do not have.
//
// What the developer sees, and why it matters more here than anywhere else: a suppressed prompt never
// reaches the model, so there is no error tool result and no assistant reply to carry the reason. The
// notification is the entire feedback channel. A deny without one is a prompt that silently vanished.
//
// What never leaves the machine:
//
//   * `event.images` — base64 image data, potentially megabytes, read by nothing server-side (§F5).
//     It is simply never passed to the payload builder, which has no field for it.
//   * the prompt text, to any local sink. Nothing here writes to stdout, stderr or a file. (The
//     headless branch of `notifySafe` does write to stderr, but only the API's own reason.)
//
// Two deliberate skips, both before any network call:
//
//   * `source === "extension"` — text another extension sent via `pi.sendMessage()`. It is machine
//     output, not a user prompt; checking it would double-charge and could block an extension's own
//     workflow. `"interactive"` and `"rpc"` are both real users (§A2).
//   * blank text — which is also how an image-only paste arrives (`text: ""`), matching
//     `unbound.py:4705`'s `'messages': […] if prompt else []`.
//
// Note what is NOT skipped: text beginning with `/`. Built-in and extension slash commands never
// reach this handler at all, but a prompt-template invocation does — unexpanded. That text is exactly
// what the user typed, so it is checked as typed; the *expanded* body is never seen by us, which is a
// documented parity gap, not a bug to fix here.

import {
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  GENERIC_DENY_REASON,
} from "../../core/src/constants.ts";
import type { AccountIdentity } from "../../core/src/accountIdentity.ts";
import { buildPromptPayload } from "../../core/src/payload.ts";
import type { CheckHooks, PolicyChecker } from "../../core/src/policy.ts";
import { noteSafe } from "./decide.ts";
import { notifySafe } from "./ui.ts";
import type { UiCtx } from "./ui.ts";

/** The structural slice of `InputEvent` this adapter reads — `images` deliberately not among it. */
export interface InputLike {
  text: string;
  source: "interactive" | "rpc" | "extension";
}

/** The structural slice of `ExtensionContext` a prompt check needs. */
export interface InputCtx extends UiCtx {
  cwd: string;
  sessionManager: { getSessionId(): string };
  model: { id: string; provider?: string } | undefined;
}

export interface InputDeps {
  checker: PolicyChecker;
  apiKey: string;
  entrypoint: string;
  hooks?: CheckHooks;
  /**
   * Hand an ALLOWED prompt to the turn store (RES-04). Optional and unwired today: `agent_end`'s
   * `messages` is only what the run produced and never contains the user prompt, so the turn log has
   * to capture it here — but the store itself lands in a later wave, and this event is the only place
   * the prompt exists. The call site is here now so wiring it is one line, not a re-read of this file.
   *
   * Called through `noteSafe`, never directly (WR-06). It closes over the module-scope turn store and
   * `ctx.sessionManager.getSessionId()`; a throw from any of that inside the outer try/catch below
   * would be swallowed into `return undefined` — i.e. a prompt that should have been suppressed
   * silently proceeding.
   */
  onPrompt?: (text: string) => void;
  /** The process's settled account identity, when known. Never awaited on this path. */
  accountIdentity?: AccountIdentity;
}

/** What pi reads back: suppress the turn, or say nothing. */
export type InputDecision = { action: "handled" } | undefined;

export async function decideInput(
  event: InputLike,
  ctx: InputCtx,
  deps: InputDeps,
): Promise<InputDecision> {
  try {
    if (event.source === "extension") return undefined;
    const text = typeof event.text === "string" ? event.text : "";
    if (text.trim() === "") return undefined;

    const payload = buildPromptPayload({
      prompt: text,
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      model: ctx.model?.id,
      clientEntrypoint: deps.entrypoint,
      hasUI: ctx.hasUI,
      ...(deps.accountIdentity === undefined ? {} : { accountIdentity: deps.accountIdentity }),
    });

    const hooks: CheckHooks =
      deps.hooks ?? { notify: (message, level) => notifySafe(ctx, message, level) };
    // The tool-name argument is only ever used as a telemetry label, so the event name is the
    // informative thing to pass: a bypass on this path is a prompt check, not a tool call.
    const outcome = await deps.checker.checkTool(payload, "user_prompt", hooks);

    switch (outcome.kind) {
      case "deny": {
        const reason = outcome.reason;
        notifySafe(ctx, reason === undefined ? GENERIC_DENY_REASON : DENY_PREFIX + reason, "error");
        return { action: "handled" };
      }

      case "unavailable":
        // Only reachable for an org whose last-good failure action was `block`; every other failure
        // resolves to `allow` in core and takes the branch below.
        notifySafe(ctx, outcome.reason ?? ENGINE_UNAVAILABLE_REASON, "error");
        return { action: "handled" };

      case "confirm":
        // Defensive, and deliberately NON-blocking. pi is in neither cost gate (§C1), so the only
        // deny a prompt check can produce today is a BLOCK-action guardrail — an `ask` cannot happen.
        // If one ever does, interrupting a developer mid-sentence with a modal is the wrong answer,
        // so the reason is surfaced and the prompt proceeds.
        notifySafe(ctx, outcome.reason ?? GENERIC_DENY_REASON, "warning");
        noteSafe(() => deps.onPrompt?.(text));
        return undefined;

      case "allow":
        noteSafe(() => deps.onPrompt?.(text));
        return undefined;

      default:
        // An unmapped verdict is no opinion. Suppressing a turn on a value we do not understand
        // would be the worst possible default.
        return undefined;
    }
  } catch {
    // pi contains `input` handler errors itself (`runner.js:1096-1131` catches rather than rethrows),
    // but a malformed return would be worse than no return, so this stays.
    return undefined;
  }
}
