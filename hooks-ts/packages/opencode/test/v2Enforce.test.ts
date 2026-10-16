// The v2 decision side (14-03) against a hand-built fake v2 ctx that records the registered handlers
// and invokes them with the event shapes 14-SPIKES.md recorded on @opencode/cli 2.0.22:
//
//   * tool calls run `tool.execute.before` → `permission.evaluate` (same call id in `source.id`);
//   * a raise from `execute.before` ends the call (evaluate never fires), as on the real host;
//   * `evaluate` input is mutable (`effect`, `message`).
//
// Every branch is tested for BOTH sides of each verdict (the shipped `V2_CAPABILITIES` picks one,
// a later host may need the other): HV2-02 enforce/audit, HV2-03 native/deny/audit, HV2-04
// enforce/audit/none.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENY_PREFIX, USER_BASH_ID_PREFIX } from "../../core/src/constants.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { V2_CAPABILITIES } from "../src/constants.ts";
import type { V2Capabilities } from "../src/constants.ts";
import type { V2ContextLike } from "../src/hostTypesV2.ts";
import { mcpCandidates } from "../src/narrow.ts";
import { createRuntime } from "../src/plugin.ts";
import type { Deps, Runtime } from "../src/plugin.ts";
import { APPROVAL_PREFIX, approvalMessage } from "../src/verdicts.ts";
import {
  claimEvent,
  claimHookInput,
  createV2Scope,
  nativeApprovalMessage,
  noteInterrupted,
  noteRootSession,
  noteSessionDirectory,
  PENDING_SHELL_TTL_MS,
  promptBlockNotice,
  registerV2Enforcement,
  SUBAGENT_PROMPT_PREFIX,
  v1ToolName,
  v2HostClient,
} from "../src/v2Enforce.ts";
import type { V2Scope } from "../src/v2Enforce.ts";
import { makeDeps, pretoolRequests, signalsOf, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

const SECRETS_DENY = `${DENY_PREFIX}Reading secrets is blocked.`;
const DIRECTORY = "/repo";

type Handler = (event: unknown) => Promise<void> | void;

interface FakeV2 {
  ctx: V2ContextLike;
  handlers: Map<string, Handler>;
  runtime: Runtime;
  scope: V2Scope;
  cleanup(): void;
}

interface FakeOptions {
  mode?: MockMode;
  capabilities?: Partial<V2Capabilities>;
  deps?: Partial<Deps> & { withKey?: boolean };
  mcpServers?: string[];
  parents?: Record<string, string>;
  /** `ctx.session.get` never answers. */
  sessionGetHangs?: boolean;
  /** The ctx has none of these domains. */
  omit?: Array<"tool" | "permission" | "session" | "shell">;
  /** A dedicated mock (default: the shared one, whose mode is reset). */
  api?: MockApi;
}

async function fakeV2(opts: FakeOptions = {}): Promise<FakeV2> {
  const api = opts.api ?? mock;
  if (opts.api === undefined) {
    mock.requests.length = 0;
    mock.setMode(opts.mode ?? "allow");
    mock.setErrorsMode("ok");
  }
  const t = makeDeps(api, { signalIntervalMs: 0, ...(opts.deps ?? {}) });
  const handle = createRuntime(t.deps);
  const handlers = new Map<string, Handler>();
  const domain = (name: string) => ({
    hook: async (hook: string, cb: Handler) => {
      handlers.set(`${name}.${hook}`, cb);
      return { dispose: async () => undefined };
    },
  });
  const parents = opts.parents ?? {};
  const servers = opts.mcpServers ?? [];
  const full: Record<string, unknown> = {
    app: { name: "cli", version: "2.0.22", channel: "latest" },
    location: { directory: DIRECTORY },
    tool: domain("tool"),
    permission: domain("permission"),
    shell: domain("shell"),
    session: {
      ...domain("session"),
      get: (input: { sessionID: string }) =>
        opts.sessionGetHangs === true
          ? new Promise(() => {})
          : Promise.resolve({
              id: input.sessionID,
              ...(parents[input.sessionID] === undefined ? {} : { parentID: parents[input.sessionID] }),
              model: { id: "openai/gpt-4.1-nano", providerID: "openrouter", variant: "default" },
            }),
    },
    mcp: {
      list: async () => ({ data: servers.map((name) => ({ name, status: { status: "connected" } })) }),
    },
  };
  for (const key of opts.omit ?? []) delete full[key];
  const ctx = full as unknown as V2ContextLike;
  const caps: V2Capabilities = { ...V2_CAPABILITIES, ...(opts.capabilities ?? {}) };
  const scope = createV2Scope();
  registerV2Enforcement(ctx, handle.runtime, (dir) => handle.recordFor(dir, v2HostClient(ctx, dir)), caps, scope);
  return { ctx, handlers, runtime: handle.runtime, scope, cleanup: t.cleanup };
}

const ACTION: Record<string, string> = { shell: "shell", write: "edit", edit: "edit", read: "read", subagent: "subagent" };

interface CallResult {
  /** The message a raise from `execute.before` carried (the call never reached evaluate). */
  raised: string | undefined;
  /** Whether evaluate ran (the host only asserts after `execute.before` resolved). */
  evaluated: boolean;
  effect: string;
  message: string | undefined;
}

/** Drive one model tool call through the fake host: execute.before, then evaluate. */
async function toolCall(
  f: FakeV2,
  tool: string,
  input: unknown,
  ids: { sessionID?: string; id?: string; effect?: "allow" | "deny" | "ask" } = {},
): Promise<CallResult> {
  const sessionID = ids.sessionID ?? "ses_root";
  const id = ids.id ?? "call_1";
  const beforeHook = f.handlers.get("tool.execute.before");
  assert.ok(beforeHook !== undefined, "execute.before registered");
  try {
    await beforeHook({ tool, sessionID, agent: "build", messageID: "msg_1", id, input });
  } catch (err) {
    return { raised: (err as Error).message, evaluated: false, effect: "allow", message: undefined };
  }
  const evaluate = f.handlers.get("permission.evaluate");
  assert.ok(evaluate !== undefined, "evaluate registered");
  const event: { effect: string; message?: string } & Record<string, unknown> = {
    sessionID,
    agent: "build",
    action: ACTION[tool] ?? tool,
    resources: ["*"],
    source: { type: "tool", messageID: "msg_1", id },
    effect: ids.effect ?? "allow",
  };
  await evaluate(event);
  return { raised: undefined, evaluated: true, effect: event.effect, message: event.message };
}

/** One more evaluate for an already-decided call (a second assertion of the same call). */
async function evaluateAgain(f: FakeV2, sessionID: string, id: string, action = "shell"): Promise<{ effect: string; message?: string }> {
  const event: { effect: string; message?: string } & Record<string, unknown> = {
    sessionID,
    action,
    resources: ["*"],
    source: { type: "tool", messageID: "msg_1", id },
    effect: "allow",
  };
  await f.handlers.get("permission.evaluate")?.(event);
  return { effect: event.effect, ...(event.message === undefined ? {} : { message: event.message }) };
}

function toolBodies(): PretoolRequestBody[] {
  return pretoolRequests(mock)
    .map((r) => r.body as PretoolRequestBody)
    .filter((b) => b.event_name === "tool_use");
}

function metadataOf(b: PretoolRequestBody | undefined): Record<string, unknown> {
  return (b?.pre_tool_use_data.metadata ?? {}) as Record<string, unknown>;
}

// --- naming ---------------------------------------------------------------------------------------

test("v2 tool ids map onto the v1 decision names: shell → bash, subagent → task", () => {
  assert.equal(v1ToolName("shell"), "bash");
  assert.equal(v1ToolName("subagent"), "task");
  assert.equal(v1ToolName("write"), "write");
  assert.equal(v1ToolName("github_create_issue"), "github_create_issue");
});

test("registers execute.before and evaluate on a v2 ctx; nothing and no raise without the domains", async () => {
  const f = await fakeV2();
  try {
    assert.ok(f.handlers.has("tool.execute.before"));
    assert.ok(f.handlers.has("permission.evaluate"));
  } finally {
    f.cleanup();
  }
  const t = makeDeps(mock);
  try {
    const { runtime } = createRuntime(t.deps);
    registerV2Enforcement({} as V2ContextLike, runtime, () => createRuntime(t.deps).recordFor("/repo", undefined));
    registerV2Enforcement(null as unknown as V2ContextLike, runtime, () => createRuntime(t.deps).recordFor("/repo", undefined));
    const raising = {
      get tool(): never {
        throw new Error("hostile ctx");
      },
    } as unknown as V2ContextLike;
    registerV2Enforcement(raising, runtime, () => createRuntime(t.deps).recordFor("/repo", undefined));
  } finally {
    t.cleanup();
  }
});

// --- HV2-02 tool calls --------------------------------------------------------------------------

test("GO: a denied shell call is refused at evaluate with the verbatim verdict text, never raised", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const r = await toolCall(f, "shell", { command: "cat secrets.txt", workdir: "/w" });
    assert.equal(r.raised, undefined, "no raise for a built-in tool");
    assert.equal(r.effect, "deny");
    assert.equal(r.message, SECRETS_DENY);
    const bodies = toolBodies();
    assert.equal(bodies.length, 1);
    assert.equal(bodies[0]?.pre_tool_use_data.tool_name, "bash");
    assert.equal(bodies[0]?.pre_tool_use_data.command, "cat secrets.txt");
    assert.equal(bodies[0]?.pre_tool_use_data.tool_use_id, "call_1");
    assert.equal(metadataOf(bodies[0]).cwd, "/w");
  } finally {
    f.cleanup();
  }
});

test("a relative shell workdir is checked in the directory the call runs in, not the project root", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const input = { command: "cat secret.txt", workdir: "sub" };
    const r = await toolCall(f, "shell", input);
    assert.equal(r.effect, "deny");
    assert.equal(metadataOf(toolBodies()[0]).cwd, `${DIRECTORY}/sub`, "resolved under the project directory");
    // The host's arguments are not rewritten (the after-digest compares them).
    assert.deepEqual(input, { command: "cat secret.txt", workdir: "sub" });
    // A known session directory is the base, as for the spawn mark; `..` is normalised.
    noteSessionDirectory(f.scope, "ses_other", "/elsewhere/app");
    await toolCall(f, "shell", { command: "cat secret.txt", workdir: "../lib" }, { sessionID: "ses_other", id: "call_2" });
    assert.equal(metadataOf(toolBodies()[1]).cwd, "/elsewhere/lib");
    // Absolute and missing workdirs are unchanged.
    await toolCall(f, "shell", { command: "ls", workdir: "/abs" }, { id: "call_3" });
    await toolCall(f, "shell", { command: "ls" }, { id: "call_4" });
    assert.equal(metadataOf(toolBodies()[2]).cwd, "/abs");
    assert.equal(metadataOf(toolBodies()[3]).cwd, DIRECTORY);
  } finally {
    f.cleanup();
  }
});

test("GO: write/read/edit carry `path`; a deny applies through evaluate (write asserts action edit)", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    for (const [i, tool] of ["write", "read", "edit"].entries()) {
      const r = await toolCall(f, tool, { path: "src/a.ts", content: "x" }, { id: `call_${i}` });
      assert.equal(r.effect, "deny", tool);
      assert.equal(r.message, SECRETS_DENY, tool);
    }
    const names = toolBodies().map((b) => b.pre_tool_use_data.tool_name);
    assert.deepEqual(names, ["write", "read", "edit"]);
    assert.ok(toolBodies().every((b) => JSON.stringify(b).includes("src/a.ts")), "path reaches the wire");
  } finally {
    f.cleanup();
  }
});

test("GO: an allowed call leaves effect and message untouched and never raises", async () => {
  const f = await fakeV2({ mode: "allow" });
  try {
    const r = await toolCall(f, "shell", { command: "ls" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "allow");
    assert.equal(r.message, undefined);
  } finally {
    f.cleanup();
  }
});

test("evaluate never re-checks: one request per call, and an unknown call id is left untouched", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    await toolCall(f, "shell", { command: "cat secrets.txt" }, { id: "call_a" });
    const again = await evaluateAgain(f, "ses_root", "call_a");
    assert.equal(again.effect, "deny", "a second assertion of the same denied call is denied too");
    const unknown = await evaluateAgain(f, "ses_root", "call_never_seen");
    assert.equal(unknown.effect, "allow");
    assert.equal(toolBodies().length, 1, "decided once in execute.before");
  } finally {
    f.cleanup();
  }
});

test("never loosens: a host deny stays a deny whatever the verdict", async () => {
  for (const mode of ["allow", "ask"] as const) {
    const f = await fakeV2({ mode });
    try {
      const r = await toolCall(f, "shell", { command: "ls" }, { effect: "deny" });
      assert.equal(r.effect, "deny", mode);
      assert.equal(r.message, undefined, mode);
    } finally {
      f.cleanup();
    }
  }
});

test("NO-GO (tools: audit): a deny is decided and recorded, never applied; v2_not_enforcing once", async () => {
  const f = await fakeV2({ mode: "deny", capabilities: { tools: "audit" } });
  try {
    const a = await toolCall(f, "shell", { command: "cat secrets.txt" }, { id: "c1" });
    const b = await toolCall(f, "shell", { command: "cat secrets.txt" }, { id: "c2" });
    for (const r of [a, b]) {
      assert.equal(r.raised, undefined);
      assert.equal(r.effect, "allow");
      assert.equal(r.message, undefined);
    }
    assert.equal(toolBodies().length, 2, "both calls checked");
    const recorded = f.runtime.sessions.forSession("ses_root").turn.snapshot().tool_calls;
    assert.deepEqual(
      recorded.map((c) => c.decision),
      ["deny", "deny"],
    );
    assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
    await tick(100);
    assert.equal(signalsOf(mock, "v2_not_enforcing").length, 1, "once per runtime");
  } finally {
    f.cleanup();
  }
});

test("NO-GO (tools: audit) also never raises for an MCP deny", async () => {
  const f = await fakeV2({ mode: "deny", capabilities: { tools: "audit" }, mcpServers: ["github"] });
  try {
    const r = await toolCall(f, "github_create_issue", { title: "x" });
    assert.equal(r.raised, undefined);
    assert.equal(toolBodies().length, 1);
  } finally {
    f.cleanup();
  }
});

test("subagent is audited, never sent and never denied (v1 task parity)", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const r = await toolCall(f, "subagent", { agent: "general", prompt: "do it", description: "d" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "allow");
    assert.equal(toolBodies().length, 0);
    const recorded = f.runtime.sessions.forSession("ses_root").turn.snapshot().tool_calls;
    assert.equal(recorded[0]?.tool_name, "task");
    assert.equal(recorded[0]?.decision, "audited");
  } finally {
    f.cleanup();
  }
});

test("the Code Mode wrapper `execute` is not checked itself (its inner MCP calls are)", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const r = await toolCall(f, "execute", { code: "return 1" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "allow");
    assert.equal(toolBodies().length, 0);
  } finally {
    f.cleanup();
  }
});

test("fail-open: API down or no key leaves every call untouched and never raises", async () => {
  const down = await fakeV2({ mode: "500", mcpServers: ["github"] });
  try {
    const r = await toolCall(down, "shell", { command: "cat secrets.txt" });
    assert.equal(r.effect, "allow");
    const m = await toolCall(down, "github_create_issue", { title: "x" }, { id: "c2" });
    assert.equal(m.raised, undefined);
  } finally {
    down.cleanup();
  }
  const noKey = await fakeV2({ mode: "deny", deps: { withKey: false }, mcpServers: ["github"] });
  try {
    const r = await toolCall(noKey, "shell", { command: "cat secrets.txt" });
    assert.equal(r.effect, "allow");
    const m = await toolCall(noKey, "github_create_issue", { title: "x" }, { id: "c2" });
    assert.equal(m.raised, undefined);
    assert.equal(pretoolRequests(mock).length, 0);
  } finally {
    noKey.cleanup();
  }
});

test("handlers never raise on hostile events", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const before = f.handlers.get("tool.execute.before");
    const evaluate = f.handlers.get("permission.evaluate");
    for (const event of [null, undefined, 1, "x", {}, { tool: 5 }, { source: null }, { source: { id: 3 } }]) {
      await before?.(event);
      await evaluate?.(event);
    }
    const throwing = {
      get tool(): never {
        throw new Error("boom");
      },
    };
    await before?.(throwing);
    await evaluate?.({
      sessionID: "s",
      get source(): never {
        throw new Error("boom");
      },
    });
  } finally {
    f.cleanup();
  }
});

// --- HV2-03 ask -----------------------------------------------------------------------------------

test("ask NATIVE: a confirm verdict asks through opencode's own approval, once per call", async () => {
  const f = await fakeV2({ mode: "ask" });
  try {
    const r = await toolCall(f, "shell", { command: "rm -rf build" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "ask");
    assert.equal(r.message, nativeApprovalMessage("Unusual command."));
    assert.ok(r.message?.startsWith(APPROVAL_PREFIX));
    assert.ok(!r.message?.includes("cannot show an approval prompt"), "no v1 'cannot ask' tail");
    const again = await evaluateAgain(f, "ses_root", "call_1");
    assert.equal(again.effect, "allow", "one approval card per call");
  } finally {
    f.cleanup();
  }
});

test("ask DENY-AS-V1: a confirm verdict denies with the v1 approval sentence", async () => {
  const f = await fakeV2({ mode: "approval", capabilities: { ask: "deny" } });
  try {
    const r = await toolCall(f, "shell", { command: "rm -rf build" });
    assert.equal(r.effect, "deny");
    assert.equal(r.message, approvalMessage("Needs admin approval."));
  } finally {
    f.cleanup();
  }
});

test("ask AUDIT: a confirm verdict is left untouched and reported not-enforcing", async () => {
  const f = await fakeV2({ mode: "ask", capabilities: { ask: "audit" } });
  try {
    const r = await toolCall(f, "shell", { command: "rm -rf build" });
    assert.equal(r.effect, "allow");
    assert.equal(r.message, undefined);
    assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
  } finally {
    f.cleanup();
  }
});

// --- HV2-04 MCP ---------------------------------------------------------------------------------

test("MCP GO: `<server>_<tool>` is attributed from the host's server list and a deny raises with the reason", async () => {
  const f = await fakeV2({ mode: "deny", mcpServers: ["spikemcp"] });
  try {
    const r = await toolCall(f, "spikemcp_echo_marker", { n: "1" });
    assert.equal(r.raised, SECRETS_DENY, "raised with the verbatim verdict text");
    assert.equal(r.evaluated, false);
    const b = toolBodies()[0];
    assert.equal(metadataOf(b).mcp_server, "spikemcp");
    assert.equal(metadataOf(b).mcp_tool, "echo_marker");
    assert.equal(signalsOf(mock, "mcp_attribution_miss").length, 0);
  } finally {
    f.cleanup();
  }
});

test("MCP GO: an allowed MCP call resolves and is never raised", async () => {
  const f = await fakeV2({ mode: "allow", mcpServers: ["spikemcp"] });
  try {
    const r = await toolCall(f, "spikemcp_echo_marker", { n: "1" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "allow");
  } finally {
    f.cleanup();
  }
});

test("MCP GO: an ask on an MCP id blocks with the v1 approval sentence (MCP ask unproven)", async () => {
  const f = await fakeV2({ mode: "ask", mcpServers: ["spikemcp"] });
  try {
    const r = await toolCall(f, "spikemcp_echo_marker", { n: "1" });
    assert.equal(r.raised, approvalMessage("Unusual command."));
  } finally {
    f.cleanup();
  }
});

test("MCP: an unresolvable non-built-in id is still sent and reports mcp_attribution_miss", async () => {
  const f = await fakeV2({ mode: "allow", mcpServers: [] });
  try {
    const r = await toolCall(f, "mystery_tool", { a: 1 });
    assert.equal(r.raised, undefined);
    assert.equal(toolBodies().length, 1);
    assert.equal("mcp_server" in metadataOf(toolBodies()[0]), false);
    assert.ok(await waitFor(() => signalsOf(mock, "mcp_attribution_miss").length === 1));
  } finally {
    f.cleanup();
  }
});

test("MCP AUDIT: a deny is decided and recorded, never raised; v2_not_enforcing reported", async () => {
  const f = await fakeV2({ mode: "deny", mcpServers: ["spikemcp"], capabilities: { mcp: "audit" } });
  try {
    const r = await toolCall(f, "spikemcp_echo_marker", { n: "1" });
    assert.equal(r.raised, undefined);
    assert.equal(r.effect, "allow");
    assert.equal(metadataOf(toolBodies()[0]).mcp_server, "spikemcp");
    assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
  } finally {
    f.cleanup();
  }
});

test("MCP NONE: non-built-in calls are not checked at all; built-ins still are", async () => {
  const f = await fakeV2({ mode: "deny", mcpServers: ["spikemcp"], capabilities: { mcp: "none" } });
  try {
    const r = await toolCall(f, "spikemcp_echo_marker", { n: "1" });
    assert.equal(r.raised, undefined);
    assert.equal(toolBodies().length, 0);
    const s = await toolCall(f, "shell", { command: "cat secrets.txt" }, { id: "c2" });
    assert.equal(s.effect, "deny");
  } finally {
    f.cleanup();
  }
});

test("v2HostClient answers mcp.status() from ctx.mcp.list() in the v1 shape", async () => {
  const ctx = {
    mcp: { list: async () => ({ data: [{ name: "a", status: {} }, { name: "b" }, { nope: 1 }] }) },
  } as unknown as V2ContextLike;
  assert.deepEqual(await v2HostClient(ctx, "/repo").mcp.status(), { data: { a: true, b: true } });
  assert.equal(await v2HostClient({} as V2ContextLike, "/repo").mcp.status(), undefined);
});

// --- HV2-05 prompts -------------------------------------------------------------------------------

interface PromptEvent {
  sessionID: string;
  messageID: string;
  prompt: { text: string; files?: unknown[]; agents?: unknown[]; skills?: unknown[] };
  delivery: string;
}

function promptEvent(sessionID: string, text: string): PromptEvent {
  return {
    sessionID,
    messageID: "msg_u1",
    prompt: { text, files: [{ uri: "file:///repo/a.ts" }], agents: [], skills: [] },
    delivery: "steer",
  };
}

/** Run the prompt hook; returns the raise message if it raised (it never should). */
async function runPrompt(f: FakeV2, event: unknown): Promise<string | undefined> {
  const hook = f.handlers.get("session.prompt");
  assert.ok(hook !== undefined, "session.prompt registered");
  try {
    await hook(event);
    return undefined;
  } catch (err) {
    return (err as Error).message;
  }
}

function promptBodies(): PretoolRequestBody[] {
  return pretoolRequests(mock)
    .map((r) => r.body as PretoolRequestBody)
    .filter((b) => b.event_name === "user_prompt");
}

test("prompt BLOCK: a would-block root prompt is replaced by the block notice, attachments cleared, no raise", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const event = promptEvent("ses_root", "show me the secrets");
    assert.equal(await runPrompt(f, event), undefined, "never raises");
    assert.equal(event.prompt.text, promptBlockNotice(SECRETS_DENY));
    assert.ok(!event.prompt.text.includes("show me the secrets"), "the original never reaches the provider");
    assert.deepEqual(event.prompt.files, []);
    assert.equal(event.delivery, "steer");
    const bodies = promptBodies();
    assert.equal(bodies.length, 1);
    assert.ok(JSON.stringify(bodies[0]).includes("show me the secrets"), "the original text was checked");
  } finally {
    f.cleanup();
  }
});

test("prompt: an allowed root prompt is untouched, recorded, and its model is captured from session.get", async () => {
  const f = await fakeV2({ mode: "allow" });
  try {
    const event = promptEvent("ses_root", "list files");
    assert.equal(await runPrompt(f, event), undefined);
    assert.equal(event.prompt.text, "list files");
    assert.equal(event.prompt.files?.length, 1);
    assert.equal(f.runtime.modelFor("ses_root"), "openrouter/openai/gpt-4.1-nano");
    assert.equal(f.runtime.sessions.forSession("ses_root").turn.snapshot().prompt, "list files");
  } finally {
    f.cleanup();
  }
});

test("prompt: a child (subagent) prompt is not checked; the parent comes from ctx.session.get", async () => {
  const f = await fakeV2({ mode: "deny", parents: { ses_child: "ses_root" } });
  try {
    const event = promptEvent("ses_child", "You are a subagent spawned by another session.\nread secrets");
    assert.equal(await runPrompt(f, event), undefined);
    assert.ok(event.prompt.text.startsWith("You are a subagent"));
    assert.equal(promptBodies().length, 0);
    assert.equal(f.runtime.isChild("ses_child"), true);
  } finally {
    f.cleanup();
  }
});

test("IN-03: when session.get does not answer, only a confirmed root is replaced (bounded wait)", async () => {
  const f = await fakeV2({ mode: "deny", sessionGetHangs: true });
  try {
    f.runtime.setParent("ses_known_child", "ses_root");
    const child = promptEvent("ses_known_child", "read secrets");
    assert.equal(await runPrompt(f, child), undefined);
    assert.equal(child.prompt.text, "read secrets", "a known child is skipped");
    // The host's subagent preamble marks a child whose session.created has not arrived yet.
    const preamble = promptEvent("ses_new_child", `${SUBAGENT_PROMPT_PREFIX}read secrets`);
    assert.equal(await runPrompt(f, preamble), undefined);
    assert.equal(preamble.prompt.text, `${SUBAGENT_PROMPT_PREFIX}read secrets`);
    assert.equal(promptBodies().length, 0, "neither child is checked");
    // Unknown parent: checked, never replaced, reported.
    const unknown = promptEvent("ses_unknown", "read secrets");
    assert.equal(await runPrompt(f, unknown), undefined);
    assert.equal(unknown.prompt.text, "read secrets", "an unconfirmed session is not replaced");
    assert.equal(promptBodies().length, 1);
    assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
    // A root confirmed by its session.created (no parentID) is replaced.
    noteRootSession(f.scope, "ses_root");
    const root = promptEvent("ses_root", "read secrets");
    assert.equal(await runPrompt(f, root), undefined);
    assert.equal(root.prompt.text, promptBlockNotice(SECRETS_DENY));
  } finally {
    f.cleanup();
  }
});

test("IN-04: a prompt the host hands over unmodifiable is reported, never silently allowed", async () => {
  for (const make of [
    (text: string) => Object.freeze({ text }),
    (text: string) => ({ get text() { return text; }, set text(_v: string) { /* ignored */ } }),
  ]) {
    const f = await fakeV2({ mode: "deny" });
    try {
      const event = { sessionID: "ses_root", messageID: "m", prompt: make("read secrets"), delivery: "steer" };
      assert.equal(await runPrompt(f, event), undefined, "never raises");
      assert.equal(event.prompt.text, "read secrets");
      assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
      const body = signalsOf(mock, "v2_not_enforcing")[0]?.body as { errors?: Array<{ message?: string }> };
      assert.ok((body.errors?.[0]?.message ?? "").includes("prompt_mutate_failed"));
    } finally {
      f.cleanup();
    }
  }
});

test("prompt WARN-ONLY: checked and recorded, never blocked; v2_prompt_warn_only once per session", async () => {
  const f = await fakeV2({ mode: "deny", capabilities: { prompt: "warn" } });
  try {
    const a = promptEvent("ses_a", "read secrets");
    await runPrompt(f, a);
    await runPrompt(f, promptEvent("ses_a", "read secrets again"));
    await runPrompt(f, promptEvent("ses_b", "read secrets"));
    assert.equal(a.prompt.text, "read secrets");
    assert.equal(promptBodies().length, 3);
    assert.ok(await waitFor(() => signalsOf(mock, "v2_prompt_warn_only").length === 2));
    await tick(100);
    assert.equal(signalsOf(mock, "v2_prompt_warn_only").length, 2, "one per session");
  } finally {
    f.cleanup();
  }
});

test("prompt: fail-open (API down, no key) leaves the prompt untouched; hostile events never raise", async () => {
  const down = await fakeV2({ mode: "500" });
  try {
    const event = promptEvent("ses_root", "read secrets");
    assert.equal(await runPrompt(down, event), undefined);
    assert.equal(event.prompt.text, "read secrets");
    for (const hostile of [null, undefined, 1, {}, { sessionID: "s", prompt: null }, { sessionID: "s", prompt: { text: 5 } }]) {
      assert.equal(await runPrompt(down, hostile), undefined);
    }
  } finally {
    down.cleanup();
  }
  const noKey = await fakeV2({ mode: "deny", deps: { withKey: false } });
  try {
    const event = promptEvent("ses_root", "read secrets");
    assert.equal(await runPrompt(noKey, event), undefined);
    assert.equal(event.prompt.text, "read secrets");
    assert.equal(pretoolRequests(mock).length, 0);
  } finally {
    noKey.cleanup();
  }
});

// --- user `!cmd` shell (shell.create.before, deferred-items 14-03 #1) -----------------------------

/**
 * A `shell.create.before` input as 14-SPIKES V2-10 recorded it: no session id, no call id. The user
 * routes (`!cmd`, `POST /api/shell`) spawn with `timeout: 0`; the model's `shell` tool with its own
 * timeout (120000 by default), as re-observed on 2.0.24.
 */
function shellCreate(command: string, cwd = DIRECTORY, timeout = 0): Record<string, unknown> {
  return { command, cwd, timeout, shell: "/bin/zsh", env: { PATH: "/usr/bin" } };
}

async function spawnHook(f: FakeV2, input: unknown): Promise<string | undefined> {
  const handler = f.handlers.get("shell.create.before");
  assert.ok(handler !== undefined, "shell.create.before registered");
  try {
    await handler(input);
    return undefined;
  } catch (err) {
    return (err as Error).message;
  }
}

/** A user `!cmd` spawn (`timeout: 0`). */
async function userShell(f: FakeV2, command: string, cwd?: string): Promise<string | undefined> {
  return spawnHook(f, shellCreate(command, cwd, 0));
}

/** The spawn hook of a model `shell` tool call (positive timeout). */
async function modelSpawn(f: FakeV2, command: string, cwd?: string): Promise<string | undefined> {
  return spawnHook(f, shellCreate(command, cwd, 120_000));
}

test("user shell: an unseen command is checked as bash through the v1 path and raised on deny", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    assert.equal(await userShell(f, "cat .env"), SECRETS_DENY);
    const bodies = toolBodies();
    assert.equal(bodies.length, 1);
    assert.equal(bodies[0]?.pre_tool_use_data.tool_name, "bash");
    assert.equal(bodies[0]?.pre_tool_use_data.command, "cat .env");
    assert.ok(bodies[0]?.pre_tool_use_data.tool_use_id?.startsWith(USER_BASH_ID_PREFIX));
    assert.equal(metadataOf(bodies[0]).cwd, DIRECTORY);
    // A relative cwd falls back to the directory.
    assert.equal(await userShell(f, "cat .env", "sub"), SECRETS_DENY);
    assert.equal(metadataOf(toolBodies()[1]).cwd, DIRECTORY);
  } finally {
    f.cleanup();
  }
});

test("user shell: an approval verdict also raises (no native approval exists for a user shell)", async () => {
  const f = await fakeV2({ mode: "ask" });
  try {
    const message = await userShell(f, "cat .env");
    assert.ok(message?.startsWith(APPROVAL_PREFIX), message);
  } finally {
    f.cleanup();
  }
});

test("user shell: an allowed command runs; the model's shell call is never checked twice", async () => {
  const f = await fakeV2({ mode: "allow" });
  try {
    assert.equal(await userShell(f, "ls"), undefined);
    assert.equal(toolBodies().length, 1);
    // Model shell: execute.before, then shell.create.before with the same command → not re-checked.
    const r = await toolCall(f, "shell", { command: "echo hi" }, { id: "call_m" });
    assert.equal(r.raised, undefined);
    assert.equal(toolBodies().length, 2);
    assert.equal(await modelSpawn(f, "echo hi"), undefined);
    assert.equal(toolBodies().length, 2, "the model call's spawn is not checked again");
    // The pending mark is consumed once: another spawn of the same command is checked.
    assert.equal(await modelSpawn(f, "echo hi"), undefined);
    assert.equal(toolBodies().length, 3);
  } finally {
    f.cleanup();
  }
});

test("user shell: a model shell that will be denied at evaluate is not raised from its spawn hook", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const before = f.handlers.get("tool.execute.before");
    await before?.({ tool: "shell", sessionID: "ses_root", agent: "build", messageID: "m", id: "call_d", input: { command: "cat .env" } });
    // Host order (V2-10): execute.before → shell.create.before → evaluate.
    assert.equal(await modelSpawn(f, "cat .env"), undefined);
    assert.equal(toolBodies().length, 1);
    const evaluated = await evaluateAgain(f, "ses_root", "call_d");
    assert.equal(evaluated.effect, "deny");
  } finally {
    f.cleanup();
  }
});

// --- CR-01: the dedupe mark is set only once the model call's decision is in --------------------

/** Start a model `shell` call's `execute.before` without awaiting it. */
function startModelShell(f: FakeV2, command: string, id: string, extra: Record<string, unknown> = {}): Promise<unknown> {
  const before = f.handlers.get("tool.execute.before");
  assert.ok(before !== undefined);
  return Promise.resolve(
    before({ tool: "shell", sessionID: "ses_root", agent: "build", messageID: "m", id, input: { command, ...extra } }),
  ).catch((err: unknown) => err);
}

test("CR-01: a user !cmd with the same text sent while the model's check is in flight IS checked", async () => {
  const f = await fakeV2({ mode: "hang", deps: { deadlineMs: 400 } });
  try {
    const model = startModelShell(f, "cat .env", "call_inflight");
    await tick(50);
    mock.setMode("deny");
    // The user's spawn arrives while the model's check is still pending: nothing is marked yet.
    assert.equal(await userShell(f, "cat .env"), SECRETS_DENY, "checked and raised");
    // Even a tool-like spawn (positive timeout) is checked while nothing is marked.
    assert.equal(await modelSpawn(f, "cat .env"), SECRETS_DENY);
    await model;
    assert.equal(toolBodies().filter((b) => b.pre_tool_use_data.command === "cat .env").length, 3);
  } finally {
    f.cleanup();
  }
});

test("CR-01: a user command after a denied model call IS checked (the denied call's mark is the tool's own)", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    await startModelShell(f, "cat .env", "call_denied");
    // No model spawn follows (it failed before Shell.create, or another plugin raised).
    assert.equal(await userShell(f, "cat .env"), SECRETS_DENY, "the user's own command is checked");
    assert.equal(toolBodies().length, 2);
    // The model's own spawn (positive timeout) still consumes the denied call's mark: not checked
    // again, and evaluate refuses the call with permission.rejected.
    assert.equal(await modelSpawn(f, "cat .env"), undefined);
    assert.equal(toolBodies().length, 2);
    assert.equal((await evaluateAgain(f, "ses_root", "call_denied")).effect, "deny");
  } finally {
    f.cleanup();
  }
});

test("CR-01: a call whose session was interrupted while being decided never marks", async () => {
  const f = await fakeV2({ mode: "hang", deps: { deadlineMs: 300 } });
  try {
    const model = startModelShell(f, "echo hi", "call_interrupted");
    await tick(50);
    noteInterrupted(f.scope, "ses_root", f.runtime.deps.now());
    await model; // the check times out and allows; the host already aborted the call
    assert.equal(f.scope.modelShells.length, 0, "no mark for an interrupted call");
    mock.setMode("deny");
    assert.equal(await modelSpawn(f, "echo hi"), SECRETS_DENY, "a later spawn of the command is checked");
  } finally {
    f.cleanup();
  }
});

test("CR-01: an interrupt drops the session's pending marks", async () => {
  const f = await fakeV2({ mode: "allow" });
  try {
    await startModelShell(f, "echo hi", "call_a");
    assert.equal(f.scope.modelShells.length, 1);
    noteInterrupted(f.scope, "ses_root", f.runtime.deps.now());
    assert.equal(f.scope.modelShells.length, 0);
    assert.equal(await modelSpawn(f, "echo hi"), undefined);
    assert.equal(toolBodies().length, 2, "checked: the mark was dropped");
  } finally {
    f.cleanup();
  }
});

test("CR-01: a mark lives only a few seconds and is bound to the working directory", async () => {
  let clock = 1_000_000;
  const f = await fakeV2({ mode: "allow", deps: { now: () => clock } });
  try {
    assert.ok(PENDING_SHELL_TTL_MS <= 10_000, "a few seconds");
    // Another directory: not the model's spawn.
    await startModelShell(f, "make", "call_w", { workdir: "/w" });
    assert.equal(await modelSpawn(f, "make", DIRECTORY), undefined);
    assert.equal(toolBodies().length, 2, "a spawn in another directory is checked");
    assert.equal(await modelSpawn(f, "make", "/w"), undefined);
    assert.equal(toolBodies().length, 2, "the spawn in the call's own workdir is the model's");
    // A relative workdir resolves under the project directory.
    await startModelShell(f, "make", "call_rel", { workdir: "sub" });
    assert.equal(await modelSpawn(f, "make", `${DIRECTORY}/sub`), undefined);
    assert.equal(toolBodies().length, 3);
    // Expiry.
    await startModelShell(f, "make", "call_late");
    clock += PENDING_SHELL_TTL_MS + 1;
    assert.equal(await modelSpawn(f, "make"), undefined);
    assert.equal(toolBodies().length, 5, "a stale mark exempts nothing");
  } finally {
    f.cleanup();
  }
});

test("CR-01: a user !cmd (timeout 0) never consumes a model mark", async () => {
  const f = await fakeV2({ mode: "allow" });
  try {
    await startModelShell(f, "echo hi", "call_u");
    assert.equal(await userShell(f, "echo hi"), undefined);
    assert.equal(toolBodies().length, 2, "the user's command is checked even with a live mark");
    assert.equal(await modelSpawn(f, "echo hi"), undefined);
    assert.equal(toolBodies().length, 2, "the mark is still there for the model's own spawn");
  } finally {
    f.cleanup();
  }
});

test("WR-04: a fail-closed `unavailable` never blocks a spawn without a session id (reported); a policy deny still does", async () => {
  const own = await startOpencodeMock("failBlock");
  const f = await fakeV2({
    api: own,
    deps: { deadlineMs: 300, timeouts: { pretoolMs: 200, errorsMs: 1000, turnLogMs: 1000 } },
  });
  try {
    // Prime the org's failure action (fail-closed) with one allowed model call.
    const primed = await toolCall(f, "read", { path: "a.txt" }, { id: "call_prime" });
    assert.equal(primed.effect, "allow");
    // The gateway now hangs: the user-route spawn is `unavailable` and must not be blocked.
    assert.equal(await userShell(f, "make build"), undefined, "no fail-closed raise from the spawn hook");
    assert.ok(await waitFor(() => signalsOf(own, "user_shell_unchecked").length === 1, 3000));
    // The model's own call still fails closed through its permission step.
    const model = await toolCall(f, "shell", { command: "make build" }, { id: "call_m" });
    assert.equal(model.effect, "deny");
  } finally {
    f.cleanup();
    await own.close();
  }
});

test("WR-04: every unmarked spawn is still checked; a deny or approval verdict on it blocks", async () => {
  for (const [mode, prefix] of [["deny", DENY_PREFIX], ["ask", APPROVAL_PREFIX]] as const) {
    const f = await fakeV2({ mode });
    try {
      const terminal = { command: "cat .env", cwd: DIRECTORY, timeout: 0, shell: "/bin/zsh", env: {} };
      assert.ok((await spawnHook(f, terminal))?.startsWith(prefix), mode);
    } finally {
      f.cleanup();
    }
  }
});

test("user shell: no key, API down and hostile inputs never raise", async () => {
  const f = await fakeV2({ mode: "allow", deps: { withKey: false } });
  try {
    assert.equal(await userShell(f, "cat .env"), undefined);
    assert.equal(toolBodies().length, 0);
    const handler = f.handlers.get("shell.create.before");
    const boom = new Proxy({}, { get: () => { throw new Error("boom"); } });
    for (const input of [null, undefined, 5, boom, { command: 5 }, { command: "" }]) {
      await handler?.(input);
    }
  } finally {
    f.cleanup();
  }
  const g = await fakeV2({ mode: "500" });
  try {
    assert.equal(await userShell(g, "cat .env"), undefined, "fail-open org: an unreachable API allows");
  } finally {
    g.cleanup();
  }
});

test("user shell AUDIT: checked and reported, never raised; NONE: not registered", async () => {
  const f = await fakeV2({ mode: "deny", capabilities: { userShell: "audit" } });
  try {
    assert.equal(await userShell(f, "cat .env"), undefined);
    assert.equal(toolBodies().length, 1);
    assert.ok(await waitFor(() => signalsOf(mock, "v2_not_enforcing").length === 1));
  } finally {
    f.cleanup();
  }
  const g = await fakeV2({ capabilities: { userShell: "none" } });
  try {
    assert.equal(g.handlers.has("shell.create.before"), false);
  } finally {
    g.cleanup();
  }
  const h = await fakeV2({ omit: ["shell"] });
  try {
    assert.equal(h.handlers.has("shell.create.before"), false);
    assert.ok(h.handlers.has("tool.execute.before"), "the other domains still register");
  } finally {
    h.cleanup();
  }
});

// --- WR-03: directory awareness (events are delivered to every registration on 2.0.24) ----------

test("WR-03 claimEvent: another registered directory's event is skipped; unknown ownership is claimed once", () => {
  const directories = new Set<string>(["/proj", "/proj2"]);
  const scope = createV2Scope(directories);
  const ev = (id: string, extra: Record<string, unknown>) => ({ id, type: "session.text.ended", ...extra });
  // Owned by its location.
  assert.equal(claimEvent(scope, "/proj", ev("e1", { location: { directory: "/proj2" }, data: {} })), false);
  assert.equal(claimEvent(scope, "/proj2", ev("e1", { location: { directory: "/proj2" }, data: {} })), true);
  assert.equal(claimEvent(scope, "/proj2", ev("e1", { location: { directory: "/proj2" }, data: {} })), false, "once");
  // A location that has no registration: exactly one registration takes it.
  assert.equal(claimEvent(scope, "/proj", ev("e2", { location: { directory: "/elsewhere" }, data: {} })), true);
  assert.equal(claimEvent(scope, "/proj2", ev("e2", { location: { directory: "/elsewhere" }, data: {} })), false);
  // No location: the session's directory decides, else the first claim.
  noteSessionDirectory(scope, "ses_b", "/proj2");
  assert.equal(claimEvent(scope, "/proj", ev("e3", { data: { sessionID: "ses_b" } })), false);
  assert.equal(claimEvent(scope, "/proj2", ev("e3", { data: { sessionID: "ses_b" } })), true);
  assert.equal(claimEvent(scope, "/proj2", ev("e4", { data: { sessionID: "ses_unknown" } })), true);
  assert.equal(claimEvent(scope, "/proj", ev("e4", { data: { sessionID: "ses_unknown" } })), false);
  // No id: handled (cannot be de-duplicated); hostile input: handled.
  assert.equal(claimEvent(scope, "/proj", { type: "x", data: {} }), true);
  assert.equal(claimEvent(scope, "/proj", null), true);
});

test("WR-03 claimHookInput: one hook input object is decided once process-wide, per hook name", () => {
  const scope = createV2Scope();
  const input = { tool: "shell" };
  assert.equal(claimHookInput(scope, "tool.execute.before", input), true);
  assert.equal(claimHookInput(scope, "tool.execute.before", input), false);
  assert.equal(claimHookInput(scope, "tool.execute.after", input), true, "another hook is its own call");
  assert.equal(claimHookInput(scope, "tool.execute.before", { tool: "shell" }), true, "a copy is a new call");
  assert.equal(claimHookInput(scope, "tool.execute.before", null), true);
});

test("WR-03: the session map is bounded", () => {
  const scope = createV2Scope();
  for (let i = 0; i < 1100; i += 1) noteSessionDirectory(scope, `s${i}`, "/proj");
  assert.ok(scope.sessionDirs.size <= 1024);
  noteSessionDirectory(scope, "s", "relative/dir");
  assert.equal(scope.sessionDirs.has("s"), false, "only absolute directories");
});

// --- WR-06: MCP names on 2.x ---------------------------------------------------------------------

test("WR-06: a server name the host sanitises (`my-server.v2` → `my-server_v2_<tool>`) is attributed", async () => {
  assert.deepEqual(mcpCandidates("my-server_v2_echo_marker", ["my-server.v2"]), [{ server: "my-server.v2", tool: "echo_marker" }]);
  const f = await fakeV2({ mode: "deny", mcpServers: ["my-server.v2"] });
  try {
    const r = await toolCall(f, "my-server_v2_echo_marker", { n: "1" });
    assert.equal(r.raised, SECRETS_DENY);
    assert.equal(metadataOf(toolBodies()[0]).mcp_server, "my-server.v2");
    assert.equal(metadataOf(toolBodies()[0]).mcp_tool, "echo_marker");
    assert.equal(signalsOf(mock, "mcp_attribution_miss").length, 0);
  } finally {
    f.cleanup();
  }
});

test("WR-06: ctx.mcp.list is called with {location:{directory}}, and without arguments when that yields no list", async () => {
  const calls: unknown[] = [];
  const scopedOk = {
    mcp: {
      list: async (input?: unknown) => {
        calls.push(input);
        return { data: [{ name: "a" }] };
      },
    },
  } as unknown as V2ContextLike;
  assert.deepEqual(await v2HostClient(scopedOk, "/repo").mcp.status(), { data: { a: true } });
  assert.deepEqual(calls, [{ location: { directory: "/repo" } }]);

  for (const scopedAnswer of ["reject", "no-data"] as const) {
    const seen: unknown[] = [];
    const fallback = {
      mcp: {
        list: async (input?: unknown) => {
          seen.push(input);
          if (input !== undefined) {
            if (scopedAnswer === "reject") throw new Error("Expected object");
            return {};
          }
          return { data: [{ name: "b" }] };
        },
      },
    } as unknown as V2ContextLike;
    assert.deepEqual(await v2HostClient(fallback, "/repo").mcp.status(), { data: { b: true } }, scopedAnswer);
    assert.deepEqual(seen, [{ location: { directory: "/repo" } }, undefined], scopedAnswer);
  }
});

// --- WR-07: a built-in decision that evaluate cannot find is raised instead -----------------------

test("WR-07: a built-in call with an empty session id or call id is blocked by a raise from execute.before", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    for (const ids of [{ sessionID: "" }, { id: "" }]) {
      const r = await toolCall(f, "shell", { command: "cat secrets.txt" }, ids);
      assert.equal(r.raised, SECRETS_DENY, JSON.stringify(ids));
    }
    const allowed = await fakeV2({ mode: "allow" });
    try {
      assert.equal((await toolCall(allowed, "read", { path: "a" }, { sessionID: "" })).raised, undefined, "never on allow");
    } finally {
      allowed.cleanup();
    }
  } finally {
    f.cleanup();
  }
  const ask = await fakeV2({ mode: "ask" });
  try {
    const r = await toolCall(ask, "shell", { command: "rm -rf build" }, { id: "" });
    assert.equal(r.raised, approvalMessage("Unusual command."), "an approval cannot be native without a call id");
  } finally {
    ask.cleanup();
  }
  const audit = await fakeV2({ mode: "deny", capabilities: { tools: "audit" } });
  try {
    assert.equal((await toolCall(audit, "shell", { command: "cat secrets.txt" }, { id: "" })).raised, undefined, "audit-only never raises");
  } finally {
    audit.cleanup();
  }
});

test("WR-07: an evaluate with no source applies the session's kept block for that action, then built-ins raise", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    const before = f.handlers.get("tool.execute.before");
    await before?.({ tool: "write", sessionID: "ses_root", agent: "build", messageID: "m", id: "call_w", input: { path: "a.ts", content: "x" } });
    const sourceless: { effect: string; message?: string } & Record<string, unknown> = {
      sessionID: "ses_root",
      action: "edit",
      resources: ["a.ts"],
      effect: "allow",
    };
    await f.handlers.get("permission.evaluate")?.(sourceless);
    assert.equal(sourceless.effect, "deny");
    assert.equal(sourceless.message, SECRETS_DENY);
    assert.ok(await waitFor(() => signalsOf(mock, "init_degraded").length === 1));
    // From now on the correlation is not trusted: the next built-in block is raised.
    const next = await toolCall(f, "shell", { command: "cat secrets.txt" }, { id: "call_next" });
    assert.equal(next.raised, SECRETS_DENY);
    // An allowed call still never raises.
    mock.setMode("allow");
    assert.equal((await toolCall(f, "read", { path: "b" }, { id: "call_ok" })).raised, undefined);
  } finally {
    f.cleanup();
  }
});

test("WR-07: a sourceless evaluate for another action or session leaves the effect alone", async () => {
  const f = await fakeV2({ mode: "deny" });
  try {
    await f.handlers.get("tool.execute.before")?.({ tool: "shell", sessionID: "ses_root", agent: "b", messageID: "m", id: "c1", input: { command: "cat x" } });
    for (const event of [
      { sessionID: "ses_root", action: "read", resources: ["*"], effect: "allow" },
      { sessionID: "ses_other", action: "shell", resources: ["*"], effect: "allow" },
      { sessionID: "", action: "shell", resources: ["*"], effect: "allow" },
    ]) {
      await f.handlers.get("permission.evaluate")?.(event);
      assert.equal(event.effect, "allow", JSON.stringify(event));
    }
  } finally {
    f.cleanup();
  }
});
