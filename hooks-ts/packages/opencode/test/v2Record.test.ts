// The v2 recording side (14-04, HV2-06 GO / HV2-07 PROVIDER-LEVEL) against a fake v2 ctx that
// records the registered handlers and feeds `ctx.event.subscribe()` from a test-controlled stream,
// with the event shapes 14-SPIKES.md recorded on @opencode/cli 2.0.22:
//
//   * heartbeat on `session.created` (`data.version`, falling back to `ctx.app.version`);
//   * turn end on `session.execution.succeeded` / `interrupted` (`session.idle` never fires on v2);
//   * assistant text from `session.text.ended`; tool results from `tool.execute.after` and
//     `session.tool.failed` (hash-only, one result per call);
//   * identity provider-level only, from `session.model.request` (no credential store is read).
//
// The decision side (`registerV2Enforcement`) is registered too, exactly as setup does, so the prompt
// and the tool calls reach the turn record through the same path they do in production.

import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";

import type { TurnLogBody } from "../../core/src/turnLog.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { CapturedRequest, MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { SIGNAL_ARGS_CHANGED } from "../src/constants.ts";
import type { V2ContextLike } from "../src/hostTypesV2.ts";
import { createRuntime } from "../src/plugin.ts";
import type { DirectoryRecord, Deps, RuntimeHandle } from "../src/plugin.ts";
import { registerV2Enforcement, v2HostClient } from "../src/v2Enforce.ts";
import { registerV2Recording, V2_RECORDING_GAPS, v2ProviderIdentity } from "../src/v2Record.ts";
import { makeDeps, pretoolRequests, signalsOf, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const DIRECTORY = "/repo";
const TURNLOG_PATH = "/v1/hooks/opencode";

type Handler = (event: unknown) => Promise<void> | void;

/** A push-fed async event stream that ends when `subscribe`'s signal aborts. */
function eventStream() {
  const queue: unknown[] = [];
  let wake: (() => void) | undefined;
  let subscribed = 0;
  let ended = false;
  const push = (event: unknown): void => {
    queue.push(event);
    wake?.();
  };
  const subscribe = (options?: { signal?: AbortSignal }): AsyncIterable<unknown> => {
    subscribed += 1;
    options?.signal?.addEventListener("abort", () => {
      ended = true;
      wake?.();
    });
    return {
      async *[Symbol.asyncIterator]() {
        while (!ended) {
          while (queue.length > 0) yield queue.shift();
          if (ended) break;
          await new Promise<void>((resolve) => {
            wake = resolve;
          });
          wake = undefined;
        }
      },
    };
  };
  return { push, subscribe, subscriptions: () => subscribed, ended: () => ended };
}

interface FakeV2 {
  ctx: V2ContextLike;
  handlers: Map<string, Handler>;
  handle: RuntimeHandle;
  record: DirectoryRecord;
  emit(type: string, data: unknown): Promise<void>;
  stop: (() => void) | undefined;
  stream: ReturnType<typeof eventStream>;
  homeDir: string;
  cleanup(): void;
}

interface FakeOptions {
  mode?: MockMode;
  deps?: Partial<Deps> & { withKey?: boolean };
  app?: unknown;
  parents?: Record<string, string>;
  prepareHome?: (homeDir: string) => void;
}

async function fakeV2(opts: FakeOptions = {}): Promise<FakeV2> {
  mock.requests.length = 0;
  mock.setMode(opts.mode ?? "allow");
  mock.setTurnLogMode("ok");
  mock.setErrorsMode("ok");
  const t = makeDeps(mock, { signalIntervalMs: 0, ...(opts.deps ?? {}) });
  opts.prepareHome?.(t.homeDir);
  const handle = createRuntime({ ...t.deps, readAuth: (_dir, provider) => v2ProviderIdentity(provider) });
  const handlers = new Map<string, Handler>();
  const domain = (name: string) => ({
    hook: async (hook: string, cb: Handler) => {
      handlers.set(`${name}.${hook}`, cb);
      return { dispose: async () => undefined };
    },
  });
  const parents = opts.parents ?? {};
  const stream = eventStream();
  const ctx = {
    app: "app" in opts ? opts.app : { name: "cli", version: "2.0.22", channel: "latest" },
    location: { directory: DIRECTORY },
    tool: domain("tool"),
    permission: domain("permission"),
    session: {
      ...domain("session"),
      get: (input: { sessionID: string }) =>
        Promise.resolve({
          id: input.sessionID,
          ...(parents[input.sessionID] === undefined ? {} : { parentID: parents[input.sessionID] }),
          model: { id: "openai/gpt-4.1-nano", providerID: "openrouter", variant: "default" },
        }),
    },
    event: { subscribe: stream.subscribe },
    mcp: { list: async () => ({ data: [] }) },
  } as unknown as V2ContextLike;
  const record = handle.recordFor(DIRECTORY, v2HostClient(ctx, DIRECTORY), []);
  const recordFor = (dir: string): DirectoryRecord => handle.recordFor(dir, v2HostClient(ctx, dir));
  registerV2Enforcement(ctx, handle.runtime, recordFor);
  const stop = registerV2Recording(ctx, handle.runtime, recordFor);
  return {
    ctx,
    handlers,
    handle,
    record,
    stop,
    stream,
    homeDir: t.homeDir,
    emit: async (type, data) => {
      stream.push({ id: `evt_${type}`, type, created: Date.now(), location: { directory: DIRECTORY }, data });
      await tick(5);
    },
    cleanup() {
      stop?.();
      t.cleanup();
    },
  };
}

function heartbeats(): PretoolRequestBody[] {
  return pretoolRequests(mock)
    .map((r) => r.body as PretoolRequestBody)
    .filter((b) => b.event_name === "session_start");
}

function turnLogs(): CapturedRequest[] {
  return mock.requests.filter((r) => r.path === TURNLOG_PATH);
}

function hook(f: FakeV2, name: string): Handler {
  const fn = f.handlers.get(name);
  assert.ok(fn !== undefined, `${name} registered`);
  return fn;
}

/** A root prompt, then one model shell call (before → evaluate → after) with `result`. */
async function promptAndShell(f: FakeV2, sessionID: string, id: string, result: unknown = "SECRET-TOOL-OUTPUT"): Promise<void> {
  await hook(f, "session.prompt")({ sessionID, messageID: "msg_u", prompt: { text: "hi there" }, delivery: "steer" });
  const input = { command: "ls" };
  await hook(f, "tool.execute.before")({ tool: "shell", sessionID, agent: "build", messageID: "msg_a", id, input });
  const evaluate = { sessionID, action: "shell", resources: ["ls"], source: { type: "tool", messageID: "msg_a", id }, effect: "allow" };
  await hook(f, "permission.evaluate")(evaluate);
  await hook(f, "tool.execute.after")({ tool: "shell", sessionID, agent: "build", messageID: "msg_a", id, input, status: "completed", result });
}

test("a root session.created sends one heartbeat with the v2 host version", async () => {
  const f = await fakeV2();
  try {
    await f.emit("session.created", {
      sessionID: "s1",
      projectID: "p",
      location: { directory: DIRECTORY },
      model: { id: "openai/gpt-4.1-nano", providerID: "openrouter" },
      version: "2.0.22",
    });
    assert.ok(await waitFor(() => heartbeats().length === 1));
    const hb = heartbeats()[0] as PretoolRequestBody;
    assert.equal((hb.pre_tool_use_data.metadata as Record<string, unknown>).opencode_version, "2.0.22");
    assert.equal(hb.client_entrypoint, "opencode/2.0.22");
    assert.equal(hb.conversation_id, "s1");
    // A child never heartbeats.
    await f.emit("session.created", { sessionID: "c1", parentID: "s1", version: "2.0.22" });
    await tick(80);
    assert.equal(heartbeats().length, 1);
  } finally {
    f.cleanup();
  }
});

test("without data.version the heartbeat falls back to ctx.app.version; a bad app version is unknown", async () => {
  const f = await fakeV2({ app: { name: "cli", version: "2.0.23", channel: "latest" } });
  try {
    assert.equal(f.handle.runtime.entrypoint(), "opencode/2.0.23", "known from setup, before any event");
    await f.emit("session.created", { sessionID: "s1" });
    assert.ok(await waitFor(() => heartbeats().length === 1));
    assert.equal((heartbeats()[0]?.pre_tool_use_data.metadata as Record<string, unknown>).opencode_version, "2.0.23");
  } finally {
    f.cleanup();
  }
  const g = await fakeV2({ app: { version: "2.0; rm -rf" } });
  try {
    assert.equal(g.handle.runtime.entrypoint(), "opencode/unknown");
  } finally {
    g.cleanup();
  }
});

test("a root turn end posts one turn log with prompt, tool call and assistant text; output is hash-only", async () => {
  const f = await fakeV2();
  try {
    await f.emit("session.created", { sessionID: "s1", version: "2.0.22" });
    await promptAndShell(f, "s1", "call_1");
    await f.emit("session.step.started", { sessionID: "s1", assistantMessageID: "m2", model: { id: "openai/gpt-4.1-nano", providerID: "openrouter" } });
    await f.emit("session.text.ended", { sessionID: "s1", assistantMessageID: "m2", ordinal: 0, text: "Hello" });
    await f.emit("session.text.ended", { sessionID: "s1", assistantMessageID: "m2", ordinal: 1, text: "world" });
    await f.emit("session.execution.succeeded", { sessionID: "s1" });
    assert.ok(await waitFor(() => turnLogs().length === 1));
    const b = turnLogs()[0]?.body as TurnLogBody;
    const raw = JSON.stringify(b);
    assert.equal(b.conversation_id, "s1");
    assert.equal(b.cwd, DIRECTORY);
    assert.ok(b.messages.some((m) => m.role === "user" && m.content === "hi there"), raw);
    assert.ok(b.messages.some((m) => m.role === "assistant" && m.content === "Hello\nworld"), raw);
    assert.ok(raw.includes('"tool_use_id":"call_1"'), raw);
    for (const req of mock.requests) {
      assert.equal(JSON.stringify(req.body).includes("SECRET-TOOL-OUTPUT"), false, `clear output in ${req.path}`);
    }
    // Nothing new: a second turn end posts nothing.
    await f.emit("session.execution.succeeded", { sessionID: "s1" });
    await tick(80);
    assert.equal(turnLogs().length, 1);
  } finally {
    f.cleanup();
  }
});

test("an interrupted turn also posts; a child turn end posts nothing", async () => {
  const f = await fakeV2({ parents: { c1: "s1" } });
  try {
    await f.emit("session.created", { sessionID: "s1", version: "2.0.22" });
    await f.emit("session.created", { sessionID: "c1", parentID: "s1", version: "2.0.22" });
    await promptAndShell(f, "c1", "call_c");
    await f.emit("session.execution.succeeded", { sessionID: "c1" });
    await tick(80);
    assert.equal(turnLogs().length, 0, "a child posts nothing");
    await promptAndShell(f, "s1", "call_r");
    await f.emit("session.execution.interrupted", { sessionID: "s1", reason: "user" });
    assert.ok(await waitFor(() => turnLogs().length === 1));
    const raw = JSON.stringify(turnLogs()[0]?.body);
    assert.ok(raw.includes('"tool_use_id":"call_c"'), "the child's call rolls up into the root turn");
    assert.ok(raw.includes('"tool_use_id":"call_r"'));
  } finally {
    f.cleanup();
  }
});

test("a failed turn (session.execution.failed, e.g. a provider error) also posts, so nothing lingers into the next turn", async () => {
  const f = await fakeV2();
  try {
    await f.emit("session.created", { sessionID: "s1", version: "2.0.22" });
    await promptAndShell(f, "s1", "call_f");
    await f.emit("session.execution.failed", { sessionID: "s1", error: { type: "provider.auth", message: "401" } });
    assert.ok(await waitFor(() => turnLogs().length === 1));
    assert.ok(JSON.stringify(turnLogs()[0]?.body).includes('"tool_use_id":"call_f"'));
    // The next turn starts clean: its log does not repeat the failed turn's call.
    await promptAndShell(f, "s1", "call_g");
    await f.emit("session.execution.succeeded", { sessionID: "s1" });
    assert.ok(await waitFor(() => turnLogs().length === 2));
    const second = JSON.stringify(turnLogs()[1]?.body);
    assert.ok(second.includes('"tool_use_id":"call_g"'));
    assert.equal(second.includes('"tool_use_id":"call_f"'), false);
  } finally {
    f.cleanup();
  }
});

test("a denied call is recorded once although execute.after(error) and session.tool.failed both arrive", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    await f.emit("session.created", { sessionID: "s1", version: "2.0.22" });
    const id = "call_d";
    const input = { command: "cat .env" };
    await f.emit("session.tool.input.started", { sessionID: "s1", assistantMessageID: "m", id, name: "shell" });
    await hook(f, "tool.execute.before")({ tool: "shell", sessionID: "s1", agent: "build", messageID: "m", id, input });
    const evaluate = { sessionID: "s1", action: "shell", resources: ["cat .env"], source: { type: "tool", messageID: "m", id }, effect: "allow" } as Record<string, unknown>;
    await hook(f, "permission.evaluate")(evaluate);
    assert.equal(evaluate.effect, "deny");
    const error = { _tag: "Tool.Error", error: { _tag: "Permission.BlockedError", reason: String(evaluate.message) } };
    await hook(f, "tool.execute.after")({ tool: "shell", sessionID: "s1", agent: "build", messageID: "m", id, input, status: "error", error });
    await f.emit("session.tool.failed", { sessionID: "s1", id, error: { type: "permission.rejected", message: String(evaluate.message) } });
    const results = f.handle.runtime.sessions.forSession("s1").turn.snapshot().results;
    assert.equal(results.filter((r) => r.tool_use_id === id).length, 1);
    assert.equal(results[0]?.is_error, true);
    assert.equal(results[0]?.tool_name, "bash", "recorded under the decided (v1) tool name");
  } finally {
    f.cleanup();
  }
});

test("a raised (MCP) call has no execute.after: session.tool.failed records its error once", async () => {
  const f = await fakeV2();
  try {
    await f.emit("session.tool.input.started", { sessionID: "s1", assistantMessageID: "m", id: "call_m", name: "gh_list" });
    await f.emit("session.tool.failed", { sessionID: "s1", id: "call_m", error: { type: "unknown", message: "Blocked" } });
    await f.emit("session.tool.failed", { sessionID: "s1", id: "call_m", error: { type: "unknown", message: "Blocked" } });
    const results = f.handle.runtime.sessions.forSession("s1").turn.snapshot().results;
    assert.equal(results.length, 1);
    assert.equal(results[0]?.tool_name, "gh_list");
    assert.equal(results[0]?.is_error, true);
  } finally {
    f.cleanup();
  }
});

test("Code Mode: inner MCP calls sharing the outer id each get a result, and no false args-changed signal", async () => {
  const f = await fakeV2();
  try {
    await f.emit("session.created", { sessionID: "s1", version: "2.0.22" });
    await hook(f, "session.prompt")({ sessionID: "s1", messageID: "u", prompt: { text: "go" }, delivery: "steer" });
    const before = hook(f, "tool.execute.before");
    const afterHook = hook(f, "tool.execute.after");
    const base = { sessionID: "s1", agent: "build", messageID: "m", id: "call_x" };
    await before({ ...base, tool: "execute", input: { code: "..." } });
    for (const n of ["1", "2"]) {
      const input = { n };
      await before({ ...base, tool: "spike_echo", input });
      await afterHook({ ...base, tool: "spike_echo", input, status: "completed", result: { content: [{ type: "text", text: `r${n}` }] } });
    }
    await afterHook({ ...base, tool: "execute", input: { code: "..." }, status: "completed", result: "done" });
    const results = f.handle.runtime.sessions.forSession("s1").turn.snapshot().results;
    assert.equal(results.filter((r) => r.tool_name === "spike_echo").length, 2, JSON.stringify(results));
    await tick(50);
    assert.equal(signalsOf(mock, SIGNAL_ARGS_CHANGED).length, 0);
  } finally {
    f.cleanup();
  }
});

test("identity is provider-level from session.model.request; the credential store is never read", async () => {
  const f = await fakeV2({
    prepareHome: (home) => {
      // An Anthropic OAuth sign-in in the v1 credential file: the v2 entry must not read it.
      const dir = join(home, ".local", "share", "opencode");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "auth.json"), JSON.stringify({ anthropic: { type: "oauth", access: "tok", refresh: "r", expires: Date.now() + 3_600_000 } }));
    },
  });
  try {
    const modelRequest = hook(f, "session.model.request");
    await modelRequest({ sessionID: "s1", agent: "build", model: { id: "claude-x", providerID: "anthropic", variant: "default" }, kind: "primary", headers: {} });
    assert.ok(await waitFor(() => f.handle.runtime.identity() !== undefined));
    assert.deepEqual(f.handle.runtime.identity(), { auth_mode: "anthropic" });
    assert.equal(f.handle.runtime.modelFor("s1"), "anthropic/claude-x");
  } finally {
    f.cleanup();
  }
});

test("v2ProviderIdentity reads nothing and answers only for a plain provider id", () => {
  assert.deepEqual(v2ProviderIdentity("openrouter"), {
    provider: "openrouter",
    hasCredential: false,
    anthropicOAuth: false,
    authMode: "openrouter",
  });
  for (const bad of [undefined, "", "  ", "a b", "x".repeat(65), 5, null]) {
    assert.equal(v2ProviderIdentity(bad as string | undefined), undefined, String(bad));
  }
  assert.deepEqual(V2_RECORDING_GAPS, [], "HV2-06 GO: nothing missing");
});

test("mcp.status.changed lets the next unattributed call re-read the server list", async () => {
  const f = await fakeV2();
  try {
    f.record.mcpRefreshedAt = 123;
    await f.emit("mcp.status.changed", { server: "gh" });
    assert.equal(f.record.mcpRefreshedAt, undefined);
  } finally {
    f.cleanup();
  }
});

test("hostile events and hook inputs never reject; stop ends the subscription", async () => {
  const f = await fakeV2();
  const boom = new Proxy({}, { get: () => { throw new Error("boom"); } });
  try {
    // (A bare Proxy cannot be yielded from an async generator: `yield` awaits its `then`.)
    const raising = { get type(): string { throw new Error("boom"); } };
    for (const event of [null, 5, "x", raising, { type: 5 }, { type: "session.created", data: boom }, { type: "session.text.ended", data: null }]) {
      f.stream.push(event);
    }
    await tick(20);
    for (const name of ["tool.execute.after", "session.model.request"]) {
      for (const input of [null, undefined, boom, { tool: boom }]) {
        await hook(f, name)(input);
      }
    }
    // The loop survived: a real event still works.
    await f.emit("session.created", { sessionID: "s9", version: "2.0.22" });
    assert.ok(await waitFor(() => heartbeats().length === 1));
    assert.equal(f.stream.subscriptions(), 1);
    f.stop?.();
    await tick(10);
    assert.equal(f.stream.ended(), true);
  } finally {
    f.cleanup();
  }
});

test("a ctx whose event.subscribe raises, or with no domains, registers what it can and never raises", () => {
  const t = makeDeps(mock);
  try {
    const handle = createRuntime(t.deps);
    const recordFor = (dir: string): DirectoryRecord => handle.recordFor(dir, undefined);
    const raising = { location: { directory: DIRECTORY }, event: { subscribe: () => { throw new Error("no"); } } } as unknown as V2ContextLike;
    assert.doesNotThrow(() => registerV2Recording(raising, handle.runtime, recordFor));
    assert.doesNotThrow(() => registerV2Recording({} as V2ContextLike, handle.runtime, recordFor));
  } finally {
    t.cleanup();
  }
});
