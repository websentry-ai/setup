// Recording double for pi's `ExtensionContext`, declared structurally with ZERO imports from the pi
// coding-agent package. Mirrors the 0.87.1 shapes the adapter actually touches
// (cwd, mode, hasUI, signal, sessionManager.getSessionId, model.id, ui.confirm/notify). Keeping it
// import-free means a test file can never accidentally pull a pi runtime value into the graph.
//
// The vendor package name appears nowhere in this file, not even in prose: `fakeCtx.test.ts`
// asserts that, so the absence of an import is checkable by a grep rather than by reading.

export type FakeCtxMode = "tui" | "rpc" | "json" | "print";
export type FakeNotifyType = "info" | "warning" | "error";

/** pi's `ExtensionUIDialogOptions`. */
export interface FakeDialogOptions {
  signal?: AbortSignal;
  timeout?: number;
}

export interface FakeConfirmCall {
  title: string;
  message: string;
  opts: FakeDialogOptions | undefined;
}

export interface FakeNotifyCall {
  message: string;
  type: FakeNotifyType | undefined;
}

export interface FakeCtxOptions {
  cwd: string;
  mode: FakeCtxMode;
  /** true in TUI and RPC modes; false under `pi -p` / `--mode json`. */
  hasUI: boolean;
  signal: AbortSignal | undefined;
  sessionId: string;
  /** `undefined` models the real `ctx.model: Model | undefined`. */
  modelId: string | undefined;
  /** What `ui.confirm` resolves to. pi resolves `false` on dismiss, timeout and abort. */
  confirmResult: boolean;
}

export interface FakeCtx {
  cwd: string;
  mode: FakeCtxMode;
  hasUI: boolean;
  signal: AbortSignal | undefined;
  sessionManager: { getSessionId(): string };
  model: { id: string } | undefined;
  ui: {
    confirm(title: string, message: string, opts?: FakeDialogOptions): Promise<boolean>;
    notify(message: string, type?: FakeNotifyType): void;
    select(title: string, options: string[], opts?: FakeDialogOptions): Promise<string | undefined>;
    input(title: string, placeholder?: string, opts?: FakeDialogOptions): Promise<string | undefined>;
    setStatus(key: string, text: string | undefined): void;
  };
  confirmCalls: FakeConfirmCall[];
  notifyCalls: FakeNotifyCall[];
}

export function createFakeCtx(overrides: Partial<FakeCtxOptions> = {}): FakeCtx {
  const opts: FakeCtxOptions = {
    cwd: "/tmp/fake-cwd",
    mode: "tui",
    hasUI: true,
    signal: new AbortController().signal,
    sessionId: "session-abc",
    modelId: "claude-sonnet-4-5",
    confirmResult: true,
    ...overrides,
  };

  const confirmCalls: FakeConfirmCall[] = [];
  const notifyCalls: FakeNotifyCall[] = [];

  return {
    cwd: opts.cwd,
    mode: opts.mode,
    hasUI: opts.hasUI,
    signal: opts.signal,
    sessionManager: {
      getSessionId: () => opts.sessionId,
    },
    model: opts.modelId === undefined ? undefined : { id: opts.modelId },
    ui: {
      async confirm(title, message, dialogOpts) {
        confirmCalls.push({ title, message, opts: dialogOpts });
        return opts.confirmResult;
      },
      notify(message, type) {
        notifyCalls.push({ message, type });
      },
      async select() {
        return undefined;
      },
      async input() {
        return undefined;
      },
      setStatus() {
        // no-op
      },
    },
    confirmCalls,
    notifyCalls,
  };
}

export interface FakeToolCallEvent {
  type: "tool_call";
  toolName: string;
  toolCallId: string;
  input: Record<string, unknown>;
}

let toolCallCounter = 0;

/** Minimal `ToolCallEvent` double; `input` stays mutable so a test can assert it was not touched. */
export function createFakeToolCallEvent(
  toolName: string,
  input: Record<string, unknown>,
  toolCallId?: string,
): FakeToolCallEvent {
  toolCallCounter += 1;
  return {
    type: "tool_call",
    toolName,
    toolCallId: toolCallId ?? `toolu_fake_${toolCallCounter}`,
    input,
  };
}

// ---------------------------------------------------------------------------------------------
// Phase 9 event doubles. Every shape is transcribed from pi 0.87.1
// `dist/core/extensions/types.d.ts`; the cited line ranges are the source of truth, not this file.
// Each factory emits ONLY the keys pi emits - an extra key here is a field a handler could read in
// a test and then find missing at runtime.
// ---------------------------------------------------------------------------------------------

/** pi's `TextContent` (pi-ai `types.d.ts:242-246`). `textSignature` is provider metadata. */
export interface FakeTextContent {
  type: "text";
  text: string;
  textSignature?: string;
}

/** pi's `ImageContent` (pi-ai `types.d.ts:256-260`). `data` is base64, so byte counts are encoded. */
export interface FakeImageContent {
  type: "image";
  data: string;
  mimeType: string;
}

export type FakeContent = FakeTextContent | FakeImageContent;

/** `UserBashEvent` (`types.d.ts:710-719`) - fires on a user-typed `!cmd` / `!!cmd`. */
export interface FakeUserBashEvent {
  type: "user_bash";
  command: string;
  /** true when `!!` was used: the output is kept out of the LLM context (still shown to the user). */
  excludeFromContext: boolean;
  cwd: string;
}

export interface FakeUserBashOptions {
  excludeFromContext: boolean;
  cwd: string;
}

/**
 * `user_bash` double. Exactly four fields and **no id** - pi does not give the event one, which is
 * why the adapter has to generate `ubash_<ulid>` for `tool_use_id`.
 */
export function createFakeUserBashEvent(
  command: string,
  overrides: Partial<FakeUserBashOptions> = {},
): FakeUserBashEvent {
  return {
    type: "user_bash",
    command,
    excludeFromContext: overrides.excludeFromContext ?? false,
    cwd: overrides.cwd ?? "/tmp/fake-cwd",
  };
}

/** `InputSource` (`types.d.ts:721`) - where the text came from, NOT what kind of text it is. */
export type FakeInputSource = "interactive" | "rpc" | "extension";

/** `InputEvent` (`types.d.ts:721-732`). */
export interface FakeInputEvent {
  type: "input";
  text: string;
  images?: FakeImageContent[];
  source: FakeInputSource;
  /** `undefined` when the agent is idle; `"steer"` / `"followUp"` mid-run. */
  streamingBehavior?: "steer" | "followUp";
}

export interface FakeInputOptions {
  source: FakeInputSource;
  images: FakeImageContent[];
  streamingBehavior: "steer" | "followUp";
}

/**
 * `input` double. `source` defaults to `"interactive"` (pi's own default in
 * `agent-session.js:1231`); `images` and `streamingBehavior` are only set when asked, because
 * "absent" and "present but empty" are different inputs to the prompt-check skip logic.
 */
export function createFakeInputEvent(
  text: string,
  overrides: Partial<FakeInputOptions> = {},
): FakeInputEvent {
  const event: FakeInputEvent = {
    type: "input",
    text,
    source: overrides.source ?? "interactive",
  };
  if (overrides.images !== undefined) event.images = overrides.images;
  if (overrides.streamingBehavior !== undefined) event.streamingBehavior = overrides.streamingBehavior;
  return event;
}

/** pi's `Usage` (pi-ai `types.d.ts:270+`), only the fields a turn log would read. */
export interface FakeUsage {
  input?: number;
  output?: number;
  cacheRead?: number;
  cacheWrite?: number;
}

/**
 * `ToolResultEvent` (`types.d.ts:791-836`). `toolName` lives on each **variant**, not on
 * `ToolResultEventBase`, so a structural type has to declare it here - the same trick
 * `ToolCallLike` uses.
 */
export interface FakeToolResultEvent {
  type: "tool_result";
  toolCallId: string;
  toolName: string;
  input: Record<string, unknown>;
  content: FakeContent[];
  isError: boolean;
  usage?: FakeUsage;
}

export interface FakeToolResultOptions {
  toolCallId: string;
  input: Record<string, unknown>;
  content: FakeContent[];
  isError: boolean;
  usage: FakeUsage;
}

let toolResultCounter = 0;

/**
 * `tool_result` double. The handler under test must return `undefined` for one of these - any
 * defined key in the return rewrites the real tool result pi hands the model.
 */
export function createFakeToolResultEvent(
  toolName: string,
  overrides: Partial<FakeToolResultOptions> = {},
): FakeToolResultEvent {
  toolResultCounter += 1;
  const event: FakeToolResultEvent = {
    type: "tool_result",
    toolCallId: overrides.toolCallId ?? `call_fake_${toolResultCounter}`,
    toolName,
    input: overrides.input ?? {},
    content: overrides.content ?? [{ type: "text", text: "ok" }],
    isError: overrides.isError ?? false,
  };
  if (overrides.usage !== undefined) event.usage = overrides.usage;
  return event;
}

/** `AgentEndEvent` (`types.d.ts:570-573`). */
export interface FakeAgentEndEvent {
  type: "agent_end";
  messages: Record<string, unknown>[];
}

/**
 * `agent_end` double. `messages` is pi's `newMessages` - only what THIS run produced, so it never
 * contains the user prompt. That is why the turn record has to capture the prompt separately.
 */
export function createFakeAgentEndEvent(messages: Record<string, unknown>[]): FakeAgentEndEvent {
  return { type: "agent_end", messages };
}

/** `SessionStartEvent` reason (`types.d.ts:416-423`). */
export type FakeSessionStartReason = "startup" | "reload" | "new" | "resume" | "fork";

export interface FakeSessionStartEvent {
  type: "session_start";
  reason: FakeSessionStartReason;
  previousSessionFile?: string;
}

/**
 * `session_start` double. It fires on every session transition (`/new`, `/resume`, `/fork`,
 * `/reload`), not once per process - which is why the heartbeat has to be rate-limited.
 */
export function createFakeSessionStartEvent(
  reason: FakeSessionStartReason,
  overrides: { previousSessionFile?: string } = {},
): FakeSessionStartEvent {
  const event: FakeSessionStartEvent = { type: "session_start", reason };
  if (overrides.previousSessionFile !== undefined) {
    event.previousSessionFile = overrides.previousSessionFile;
  }
  return event;
}

export interface FakeClock {
  /** Pure: repeated calls without an `advance` return the same value. */
  now(): number;
  advance(ms: number): void;
}

/**
 * An injectable clock for the 300 s cache TTL and the 60 s circuit breaker.
 *
 * No `setTimeout`, no timers, no real time: a test that wants to be 300 s in the future says so
 * and the suite still finishes in milliseconds. A real-timer test for a 60 s breaker would either
 * take a minute or be flaky.
 */
export function createFakeClock(startMs = 1_000_000): FakeClock {
  let current = startMs;
  return {
    now: () => current,
    advance(ms: number) {
      current += ms;
    },
  };
}
