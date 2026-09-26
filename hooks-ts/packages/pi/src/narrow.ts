// A local type guard for pi's **shell** tools.
//
// pi exports a ready-made narrowing helper for tool-call events, but it is a **runtime value**
// export: importing it would make esbuild follow `@earendil-works/pi-coding-agent` into the whole
// coding agent, TUI, providers and undici, turning a few-KB extension into a multi-MB bundle whose
// own bare specifiers cannot resolve under pi's jiti loader (§F6 / §A9). So the pi package is
// referenced here by `import type` only — those imports vanish at compile time — and the three-line
// equivalent lives below.
//
// A bare `event.toolName === "bash"` check does NOT narrow on its own, because
// `CustomToolCallEvent.toolName` is `string` and overlaps every literal in the union (§A10); the
// `input.command` probe is what makes the predicate sound.
//
// **There are two shell tools, not one.** `powershell` is as much a built-in as `bash`
// (`dist/core/tools/index.js:19-28` lists it in `allToolNames`; `dist/core/extensions/types.d.ts:752`
// declares `PowerShellToolCallEvent`), and its input is literally the same type —
// `PowerShellToolInput = BashToolInput` (`dist/core/tools/powershell.d.ts:10`), i.e. `{command, timeout?}`.
// It is only absent from the *default* active set (`dist/core/sdk.js:140`), so `--tools`, the
// `defaultTools` setting or `setActiveTools` enables it — the ordinary configuration on Windows.
// Narrowing on `bash` alone therefore sent `command: ""` for every powershell call, which the
// gateway's entry gate answers `allow` without consulting a policy: the command ran unchecked while
// the extension reported itself active. Both shells must go through the same path (CR-01).

import type { ToolCallEvent } from "@earendil-works/pi-coding-agent";

/** The structural slice of a tool-call event this package reads. */
export interface ToolCallLike {
  toolName: string;
  toolCallId: string;
  input: unknown;
}

/**
 * Drift alarm: pi's real event union must stay assignable to `ToolCallLike`. If a future pi release
 * renames `toolCallId` or `toolName`, `npm run typecheck` resolves this to `never` and fails.
 */
export type ToolCallEventIsCompatible = ToolCallEvent extends ToolCallLike ? true : never;

/** The input shared by pi's shell tools (`tools/bash.js:26-29`; powershell reuses this exact type). */
export interface BashInput {
  command: string;
  timeout?: number;
}

/**
 * pi's shell tools. Both take `{command, timeout?}` and both execute what they are given, so both
 * are checked. Keyed by name rather than by an `input.command` probe alone, because a custom/MCP
 * tool may also carry a `command` field without being a shell (its verdict is the gateway's call,
 * not ours).
 */
const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell"]);

/**
 * True for a `bash` or `powershell` call carrying a string `command`.
 *
 * The `input !== null` guard is load-bearing, not defensive noise: `ToolCallLike.input` is
 * `unknown`, so a third-party `registerTool` (or a future pi shape change) can deliver `null` here,
 * and dereferencing it would throw a `TypeError` inside `decideToolCall` — swallowed by the outer
 * catch, allowing the call by accident rather than by design.
 */
export function isShellCall<T extends ToolCallLike>(e: T): e is T & { input: BashInput } {
  if (!SHELL_TOOLS.has(e.toolName)) return false;
  const input = e.input;
  return (
    typeof input === "object" &&
    input !== null &&
    typeof (input as { command?: unknown }).command === "string"
  );
}
