// Structural slices of the opencode v1 plugin API (`@opencode-ai/plugin` 1.18.x), hand-written.
//
// Why not import `@opencode-ai/plugin`: it installs cleanly (13-SPIKES.md TYPES) but pulls `effect`,
// `zod` and `@ai-sdk/provider` into the lockfile, and the bundle must stay dependency-free. These
// types claim only what this adapter reads, every field is treated as untrusted at runtime anyway,
// and the nightly job (13-08) checks conformance against the real package. If opencode changes one
// of these shapes, that job is the drift alarm, not this file.
//
// Every citation is `oc:` = the local read-only copy of the opencode 1.x source.
//
// Type-only: no runtime statement may appear in this file.

/** `client.tui.showToast` and `client.session.get` (`oc:sdk/js/src/gen/sdk.gen.ts` ~1118). */
export interface OpencodeClientLike {
  tui?: {
    showToast?(opts: {
      body: { message: string; variant: "info" | "success" | "warning" | "error"; title?: string };
    }): Promise<unknown>;
  };
  session?: {
    get?(opts: { path: { id: string } }): Promise<unknown>;
  };
}

/**
 * `PluginInput` (`oc:plugin/src/index.ts:56-66`). `$` (a Bun shell) and `experimental_workspace`
 * are deliberately absent: the adapter never uses them, and `$` is undefined off Bun.
 */
export interface PluginInputLike {
  client?: OpencodeClientLike;
  directory?: string;
  worktree?: string;
  serverUrl?: unknown;
  project?: unknown;
}

/** `tool.execute.before` input (`oc:plugin/src/index.ts:278-281`). */
export interface ToolBeforeInput {
  tool: string;
  sessionID: string;
  callID: string;
}

/** `tool.execute.before` output; `args` is the live object the tool will run with. */
export interface ToolBeforeOutput {
  args: unknown;
}

/** `tool.execute.after` input (`oc:plugin/src/index.ts:286-288`). */
export interface ToolAfterInput {
  tool: string;
  sessionID: string;
  callID: string;
  args: unknown;
}

/** `tool.execute.after` output. */
export interface ToolAfterOutput {
  title: string;
  output: unknown;
  metadata: unknown;
}

/** `chat.message` input (`oc:plugin/src/index.ts:236-244`). */
export interface ChatMessageInput {
  sessionID: string;
  agent?: string;
  model?: { providerID: string; modelID: string };
  messageID?: string;
  variant?: string;
}

/** `chat.message` output. */
export interface ChatMessageOutput {
  message: unknown;
  parts: unknown[];
}

/** `event` input (`oc:plugin/src/index.ts:223`). */
export interface EventInput {
  event: { type: string; properties?: unknown };
}

/** `shell.env` input (`oc:plugin/src/index.ts:282-285`). */
export interface ShellEnvInput {
  cwd: string;
  sessionID?: string;
  callID?: string;
}

/** `shell.env` output. */
export interface ShellEnvOutput {
  env: Record<string, string>;
}

/** The subset of `Hooks` (`oc:plugin/src/index.ts:221-335`) this adapter may register. */
export interface HooksLike {
  config?: (input: unknown) => Promise<void>;
  dispose?: () => Promise<void>;
  event?: (input: EventInput) => Promise<void>;
  "tool.execute.before"?: (input: ToolBeforeInput, output: ToolBeforeOutput) => Promise<void>;
  "tool.execute.after"?: (input: ToolAfterInput, output: ToolAfterOutput) => Promise<void>;
  "chat.message"?: (input: ChatMessageInput, output: ChatMessageOutput) => Promise<void>;
  "shell.env"?: (input: ShellEnvInput, output: ShellEnvOutput) => Promise<void>;
}

/** `Plugin` (`oc:plugin/src/index.ts:74`): awaited by the v1 loader with no timeout. */
export type ServerFactory = (input: unknown, options?: unknown) => Promise<HooksLike>;
