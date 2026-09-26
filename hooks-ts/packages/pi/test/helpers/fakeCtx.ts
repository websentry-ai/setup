// Recording double for pi's `ExtensionContext`, declared structurally with ZERO imports from
// `@earendil-works/pi-coding-agent`. Mirrors the 0.87.1 shapes the adapter actually touches
// (cwd, mode, hasUI, signal, sessionManager.getSessionId, model.id, ui.confirm/notify). Keeping it
// import-free means a test file can never accidentally pull a pi runtime value into the graph.

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
