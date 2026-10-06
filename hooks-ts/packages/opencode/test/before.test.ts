// `tool.execute.before` (HOOK-08, HOOK-10..13, RES-11): every model-issued tool call is evaluated
// through core's total `evaluateToolCall` and blocked through `block()` on deny, approval-required
// and fail-closed-unavailable. Driven through the real plugin entry against the core mock API.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENY_PREFIX, ENGINE_UNAVAILABLE_REASON, NO_KEY_NOTICE } from "../../core/src/constants.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { PATCH_TOO_LARGE_REASON } from "../src/before.ts";
import { createServerPlugin } from "../src/plugin.ts";
import type { Deps } from "../src/plugin.ts";
import { APPROVAL_PREFIX, approvalMessage, blockingMessage, strictest } from "../src/verdicts.ts";
import { createScopedStates } from "../../core/src/scopedState.ts";
import {
  makeDeps,
  makeFakeInput,
  pretoolRequests,
  signalsOf,
  startOpencodeMock,
  TEST_KEY,
  tick,
  waitFor,
} from "./helpers/fakeHost.ts";
import type { FakeInput } from "./helpers/fakeHost.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

type BeforeHook = (input: unknown, output: unknown) => Promise<void>;
type Hooks = Record<string, ((...args: unknown[]) => Promise<unknown>) | undefined>;

interface Harness {
  hooks: Hooks;
  before: BeforeHook;
  fake: FakeInput;
  server: ReturnType<typeof createServerPlugin>;
  cleanup(): void;
}

async function harness(
  mode: MockMode,
  opts: { directory?: string; deps?: Partial<Deps> & { withKey?: boolean } } = {},
): Promise<Harness> {
  mock.requests.length = 0;
  mock.setMode(mode);
  const t = makeDeps(mock, opts.deps ?? {});
  const server = createServerPlugin(t.deps);
  const fake = makeFakeInput({ directory: opts.directory ?? "/repo" });
  const hooks = (await server(fake.input)) as Hooks;
  const hook = hooks["tool.execute.before"];
  assert.equal(typeof hook, "function", "tool.execute.before is registered");
  return { hooks, before: hook as BeforeHook, fake, server, cleanup: t.cleanup };
}

function call(tool: string, sessionID = "ses_root", callID = "call_1"): { tool: string; sessionID: string; callID: string } {
  return { tool, sessionID, callID };
}

/** Resolves to the rejection message, or `undefined` if the hook resolved. */
async function outcome(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (err) {
    assert.ok(err instanceof Error, "only Error instances are raised");
    return err.message;
  }
}

function body(index = 0): PretoolRequestBody {
  const req = pretoolRequests(mock)[index];
  assert.ok(req !== undefined, `pretool request #${index} exists`);
  return req.body as PretoolRequestBody;
}

function metadataOf(b: PretoolRequestBody): Record<string, unknown> {
  return b.pre_tool_use_data.metadata as Record<string, unknown>;
}

const SECRETS_DENY = `${DENY_PREFIX}Reading secrets is blocked.`;

// --- shell --------------------------------------------------------------------------------------

test("bash under deny rejects with the deny text and sends the opencode wire shape", async () => {
  const h = await harness("deny");
  try {
    const message = await outcome(h.before(call("bash", "ses_abc"), { args: { command: "cat .env" } }));
    assert.equal(message, SECRETS_DENY);
    assert.equal(pretoolRequests(mock).length, 1);
    const b = body();
    assert.equal(b.event_name, "tool_use");
    assert.equal(b.unbound_app_label, "opencode");
    assert.equal(b.pre_tool_use_data.tool_name, "bash");
    assert.equal(b.pre_tool_use_data.command, "cat .env");
    assert.equal(b.client_entrypoint, "opencode/unknown");
    assert.equal(metadataOf(b).cwd, "/repo");
    assert.equal(b.conversation_id, "ses_abc");
    assert.equal(b.pre_tool_use_data.tool_use_id, "call_1");
  } finally {
    h.cleanup();
  }
});

test("bash workdir sets metadata.cwd; a child session is enforced like a root one", async () => {
  const h = await harness("deny");
  try {
    assert.equal(await outcome(h.before(call("bash"), { args: { command: "cat .env", workdir: "/w" } })), SECRETS_DENY);
    assert.equal(metadataOf(body(0)).cwd, "/w");
    assert.equal(await outcome(h.before(call("bash", "ses_child"), { args: { command: "cat .env" } })), SECRETS_DENY);
    assert.equal(body(1).conversation_id, "ses_child");
  } finally {
    h.cleanup();
  }
});

test("allow resolves undefined and leaves output.args untouched", async () => {
  const h = await harness("allow");
  try {
    const args = { command: "ls -la", workdir: "/repo" };
    const snapshot = structuredClone(args);
    const output = { args };
    assert.equal(await outcome(h.before(call("bash"), output)), undefined);
    assert.equal(output.args, args, "same object");
    assert.deepEqual(output.args, snapshot, "not mutated");
    assert.equal(pretoolRequests(mock).length, 1);
  } finally {
    h.cleanup();
  }
});

test("hostile inputs never raise", async () => {
  const h = await harness("deny");
  try {
    const boom = new Proxy({}, { get: () => { throw new Error("boom"); } });
    for (const [input, output] of [
      [null, null],
      [undefined, undefined],
      [boom, { args: {} }],
      [call("bash"), boom],
      [call("bash"), { args: null }],
      [{ tool: 5, sessionID: {}, callID: [] }, { args: "x" }],
    ] as const) {
      assert.equal(await outcome(h.before(input, output)), undefined);
    }
  } finally {
    h.cleanup();
  }
});

// --- file tools ---------------------------------------------------------------------------------

test("read sends filePath as metadata.file_path; a differing path is visible in tool_input", async () => {
  const h = await harness("allow");
  try {
    await h.before(call("read"), { args: { filePath: "/repo/.env" } });
    assert.equal(metadataOf(body(0)).file_path, "/repo/.env");
    await h.before(call("read", "ses_root", "call_2"), { args: { filePath: "/a", path: "/b" } });
    const m = metadataOf(body(1));
    assert.equal(m.file_path, "/a");
    assert.equal((m.tool_input as Record<string, unknown>).path, "/b");
  } finally {
    h.cleanup();
  }
});

test("grep defaults file_path to cwd and forwards pattern and include; lsp sends filePath", async () => {
  const h = await harness("allow");
  try {
    await h.before(call("grep"), { args: { pattern: "AKIA", include: "*.env" } });
    const m = metadataOf(body(0));
    assert.equal(m.file_path, "/repo");
    assert.equal((m.tool_input as Record<string, unknown>).pattern, "AKIA");
    assert.equal((m.tool_input as Record<string, unknown>).include, "*.env");
    await h.before(call("lsp", "ses_root", "call_2"), { args: { filePath: "/repo/x.ts", operation: "hover" } });
    assert.equal(metadataOf(body(1)).file_path, "/repo/x.ts");
  } finally {
    h.cleanup();
  }
});

// --- apply_patch --------------------------------------------------------------------------------

function patchChecker(seen: PretoolRequestBody[]): PolicyChecker {
  return {
    async checkTool(payload: PretoolRequestBody) {
      seen.push(payload);
      const filePath = (payload.pre_tool_use_data.metadata as Record<string, unknown>).file_path;
      return typeof filePath === "string" && filePath.endsWith(".env")
        ? { kind: "deny", reason: "No env edits." }
        : { kind: "allow" };
    },
  };
}

const PATCH_TWO = [
  "*** Begin Patch",
  "*** Update File: src/a.ts",
  "@@",
  "-a",
  "+b",
  "*** Add File: .env",
  "+SECRET=1",
  "*** End Patch",
].join("\n");

test("apply_patch: one check per header path, strictest wins", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => patchChecker(seen) } });
  try {
    const message = await outcome(h.before(call("apply_patch"), { args: { patchText: PATCH_TWO } }));
    assert.equal(message, `${DENY_PREFIX}No env edits.`);
    assert.equal(seen.length, 2);
    assert.deepEqual(seen.map((p) => p.pre_tool_use_data.tool_name), ["apply_patch", "apply_patch"]);
    assert.deepEqual(
      seen.map((p) => (p.pre_tool_use_data.metadata as Record<string, unknown>).file_path).sort(),
      [".env", "src/a.ts"],
    );
  } finally {
    h.cleanup();
  }
});

test("apply_patch: only an allowed file resolves; no headers makes no check", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => patchChecker(seen) } });
  try {
    const onlyA = "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-a\n+b\n*** End Patch";
    assert.equal(await outcome(h.before(call("apply_patch"), { args: { patchText: onlyA } })), undefined);
    assert.equal(seen.length, 1);
    assert.equal(await outcome(h.before(call("apply_patch", "ses_root", "call_2"), { args: { patchText: "no headers" } })), undefined);
    assert.equal(await outcome(h.before(call("apply_patch", "ses_root", "call_3"), { args: {} })), undefined);
    assert.equal(seen.length, 1);
  } finally {
    h.cleanup();
  }
});

test("apply_patch naming 1025 files (last one protected) is blocked without any request", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => patchChecker(seen) } });
  try {
    const lines = ["*** Begin Patch"];
    for (let i = 0; i < 1024; i += 1) lines.push(`*** Add File: junk/${i}.txt`, "+x");
    lines.push("*** Update File: .env", "@@", "-A=1", "+A=2", "*** End Patch");
    const message = await outcome(h.before(call("apply_patch", "ses_p", "call_p"), { args: { patchText: lines.join("\n") } }));
    assert.equal(message, `${DENY_PREFIX}${PATCH_TOO_LARGE_REASON}`);
    assert.match(message ?? "", /patch too large to verify/);
    assert.equal(seen.length, 0, "no per-file check is made");
    assert.ok(await waitFor(() => signalsOf(mock, "patch_targets_capped").length === 1));
    assert.ok(h.fake.toasts.some((t) => t.variant === "error"));
    const turn = h.server.inspect.turn("ses_p");
    assert.equal(turn.tool_calls[0]?.decision, "deny");
  } finally {
    h.cleanup();
  }
});

test("apply_patch naming exactly 1024 files is checked file by file", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => patchChecker(seen) } });
  try {
    const lines = ["*** Begin Patch"];
    for (let i = 0; i < 1024; i += 1) lines.push(`*** Add File: junk/${i}.txt`, "+x");
    lines.push("*** End Patch");
    assert.equal(await outcome(h.before(call("apply_patch"), { args: { patchText: lines.join("\n") } })), undefined);
    assert.equal(seen.length, 1024);
  } finally {
    h.cleanup();
  }
});

/** A patch naming `n` junk files, optionally with `.env` first. */
function junkPatch(n: number, envFirst = false): string {
  const lines = ["*** Begin Patch"];
  if (envFirst) lines.push("*** Update File: .env", "@@", "-A=1", "+A=2");
  for (let i = 0; i < n; i += 1) lines.push(`*** Add File: junk/${i}.txt`, "+x");
  lines.push("*** End Patch");
  return lines.join("\n");
}

/** Denies `.env` at once and never answers for any other file. */
function hangingChecker(seen: PretoolRequestBody[]): PolicyChecker {
  return {
    checkTool(payload: PretoolRequestBody) {
      seen.push(payload);
      const filePath = (payload.pre_tool_use_data.metadata as Record<string, unknown>).file_path;
      if (typeof filePath === "string" && filePath.endsWith(".env")) {
        return Promise.resolve({ kind: "deny", reason: "No env edits." });
      }
      return new Promise(() => {});
    },
  };
}

test("apply_patch: one shared deadline bounds the whole fan-out and fails open (WR-02)", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => hangingChecker(seen), deadlineMs: 200 } });
  try {
    const started = Date.now();
    const message = await outcome(h.before(call("apply_patch", "ses_d", "call_d"), { args: { patchText: junkPatch(40) } }));
    const elapsed = Date.now() - started;
    assert.equal(message, undefined, "a cold (fail-open) org allows on expiry");
    // Per-check deadlines alone would take ⌈40 / 8⌉ × 200 ms = 1 s.
    assert.ok(elapsed < 600, `bounded by one deadline, took ${elapsed} ms`);
    assert.ok(seen.length < 40, `no new check after expiry (${seen.length} started)`);
    assert.ok(
      await waitFor(() => signalsOf(mock, "bypassed_due_to_failure").some((r) => JSON.stringify(r.body).includes("apply_patch"))),
      "the expiry is reported as a fail-open bypass for apply_patch",
    );
    const turn = h.server.inspect.turn("ses_d");
    assert.ok(turn.tool_calls.some((c) => c.tool_name === "apply_patch" && c.decision === "allow"), "expiry recorded");
  } finally {
    h.cleanup();
  }
});

test("apply_patch: a deny that arrived before the shared deadline still blocks (WR-02)", async () => {
  const seen: PretoolRequestBody[] = [];
  const h = await harness("allow", { deps: { makeChecker: () => hangingChecker(seen), deadlineMs: 200 } });
  try {
    const message = await outcome(h.before(call("apply_patch"), { args: { patchText: junkPatch(20, true) } }));
    assert.equal(message, `${DENY_PREFIX}No env edits.`);
  } finally {
    h.cleanup();
  }
});

test("apply_patch: a fail-closed org blocks on the shared deadline and reports a blocked failure (WR-02)", async () => {
  const seen: PretoolRequestBody[] = [];
  const scopes = createScopedStates();
  scopes.forScope(mock.url, TEST_KEY).policy.recordSuccess({ policy_check_failure_action: "block" } as never);
  const h = await harness("allow", { deps: { makeChecker: () => hangingChecker(seen), deadlineMs: 200, scopes } });
  try {
    const message = await outcome(h.before(call("apply_patch"), { args: { patchText: junkPatch(20) } }));
    assert.equal(message, ENGINE_UNAVAILABLE_REASON);
    assert.ok(await waitFor(() => signalsOf(mock, "blocked_due_to_failure").length >= 1));
  } finally {
    h.cleanup();
  }
});

// --- verdict helpers ----------------------------------------------------------------------------

test("strictest: deny > unavailable > confirm > allow > skip", () => {
  const skip = { kind: "skip", why: "nothing-evaluable" } as const;
  const allow = { kind: "allow" } as const;
  const confirm = { kind: "confirm", reason: "c" } as const;
  const unavailable = { kind: "unavailable" } as const;
  const deny = { kind: "deny", reason: "d" } as const;
  assert.equal(strictest([skip, allow, confirm, unavailable, deny]).kind, "deny");
  assert.equal(strictest([confirm, unavailable, allow]).kind, "unavailable");
  assert.equal(strictest([allow, confirm, skip]).kind, "confirm");
  assert.equal(strictest([skip, allow]).kind, "allow");
  assert.equal(strictest([skip]).kind, "skip");
  assert.equal(strictest([]).kind, "skip");
  assert.equal(strictest([deny, { kind: "deny", reason: "second" }]), deny, "first of equals wins");
});

test("blockingMessage maps each verdict", () => {
  assert.equal(blockingMessage({ kind: "allow" }), undefined);
  assert.equal(blockingMessage({ kind: "skip", why: "cached" }), undefined);
  assert.equal(blockingMessage({ kind: "deny", reason: "r" }), `${DENY_PREFIX}r`);
  assert.equal(blockingMessage({ kind: "confirm", reason: "c" }), approvalMessage("c"));
  assert.equal(blockingMessage({ kind: "unavailable" }), "Unbound policy engine unavailable — please retry");
  assert.equal(blockingMessage(null as never), undefined);
});

test("approvalMessage is approval-specific and sanitised", () => {
  const m = approvalMessage("x");
  assert.ok(m.startsWith(APPROVAL_PREFIX));
  assert.ok(m.includes("x"));
  assert.ok(!m.startsWith(DENY_PREFIX));
  assert.ok(!approvalMessage("evil‮text").includes("‮"));
  assert.ok(approvalMessage("evil‮text").includes("eviltext"));
  const bare = approvalMessage();
  assert.ok(bare.startsWith(APPROVAL_PREFIX));
  assert.ok(!bare.startsWith(`${APPROVAL_PREFIX}:`), "no ': …' part without a reason");
  assert.equal(approvalMessage(42 as never), bare);
});

// --- MCP attribution (HOOK-13) ------------------------------------------------------------------

test("MCP: longest configured prefix → explicit mcp_server / mcp_tool, and the deny applies", async () => {
  const h = await harness("deny");
  try {
    await h.hooks.config?.({ mcp: { my: {}, my_server: {} } });
    const message = await outcome(h.before(call("my_server_list_files"), { args: {} }));
    assert.equal(message, SECRETS_DENY);
    const m = metadataOf(body(0));
    assert.equal(m.mcp_server, "my_server");
    assert.equal(m.mcp_tool, "list_files");
    assert.equal(body(0).pre_tool_use_data.tool_name, "my_server_list_files");
  } finally {
    h.cleanup();
  }
});

test("MCP resource tools carry their server argument", async () => {
  const h = await harness("allow");
  try {
    await h.hooks.config?.({ mcp: { my: {} } });
    await h.before(call("read_mcp_resource"), { args: { server: "my", uri: "u" } });
    const m = metadataOf(body(0));
    assert.equal(m.mcp_server, "my");
    assert.equal(m.mcp_tool, "read_mcp_resource");
  } finally {
    h.cleanup();
  }
});

test("an unresolved non-built-in tool is sent bare (raw id, no MCP keys), reported, never a guess", async () => {
  const h = await harness("deny");
  try {
    await h.hooks.config?.({ mcp: { my: {}, my_server: {} } });
    // The mock mirrors the server's entry gate: an unattributed call reaches the server, which logs
    // the miss and answers no_policy (allow). What matters here is that the request is made.
    assert.equal(await outcome(h.before(call("other_tool"), { args: {} })), undefined);
    assert.ok(await waitFor(() => signalsOf(mock, "mcp_attribution_miss").length === 1));
    assert.equal(pretoolRequests(mock).length, 1);
    const b = body(0);
    assert.equal(b.pre_tool_use_data.tool_name, "other_tool");
    assert.equal(b.pre_tool_use_data.command, "");
    assert.equal("mcp_server" in metadataOf(b), false);
    assert.equal("mcp_tool" in metadataOf(b), false);
  } finally {
    h.cleanup();
  }
});

test("with no MCP servers configured a custom tool is still sent and the miss still reported", async () => {
  for (const cfg of [{}, undefined] as const) {
    const h = await harness("allow");
    try {
      if (cfg !== undefined) await h.hooks.config?.(cfg);
      assert.equal(await outcome(h.before(call("mytool"), { args: {} })), undefined);
      assert.ok(await waitFor(() => signalsOf(mock, "mcp_attribution_miss").length === 1), "reported");
      assert.equal(pretoolRequests(mock).length, 1);
      assert.equal(body(0).pre_tool_use_data.tool_name, "mytool");
    } finally {
      h.cleanup();
    }
  }
});

test("a configured server name over the attribution cap is sent without MCP keys and reported", async () => {
  const h = await harness("allow");
  try {
    const long = "s".repeat(257);
    await h.hooks.config?.({ mcp: { [long]: {} } });
    assert.equal(await outcome(h.before(call(`${long}_echo`), { args: {} })), undefined);
    assert.equal(pretoolRequests(mock).length, 1);
    assert.equal("mcp_server" in metadataOf(body(0)), false);
    assert.ok(await waitFor(() => signalsOf(mock, "mcp_attribution_miss").length === 1));
  } finally {
    h.cleanup();
  }
});

test("a server added at runtime is learnt from client.mcp.status() for later calls", async () => {
  mock.requests.length = 0;
  mock.setMode("allow");
  const t = makeDeps(mock);
  try {
    const server = createServerPlugin(t.deps);
    const fake = makeFakeInput({ directory: "/repo" });
    let statusCalls = 0;
    const input = {
      ...fake.input,
      client: {
        ...fake.input.client,
        mcp: {
          status(): Promise<unknown> {
            statusCalls += 1;
            return Promise.resolve({ data: { late: { status: "connected" } } });
          },
        },
      },
    };
    const hooks = (await server(input)) as Hooks;
    await hooks.config?.({ mcp: { cfgd: {} } });
    const before = hooks["tool.execute.before"] as BeforeHook;
    await before(call("late_echo"), { args: {} });
    assert.equal("mcp_server" in metadataOf(body(0)), false, "first call: not yet known");
    await tick(20);
    await before(call("late_echo", "ses_root", "call_2"), { args: {} });
    assert.equal(metadataOf(body(1)).mcp_server, "late");
    assert.equal(metadataOf(body(1)).mcp_tool, "echo");
    await before(call("other_x", "ses_root", "call_3"), { args: {} });
    assert.equal(statusCalls, 1, "refresh is rate-limited");
  } finally {
    t.cleanup();
  }
});

test("a raising or hanging client.mcp.status() never affects the call", async () => {
  for (const status of [
    () => {
      throw new Error("boom");
    },
    () => new Promise<unknown>(() => {}),
    () => Promise.reject(new Error("no")),
    5,
  ]) {
    mock.requests.length = 0;
    mock.setMode("deny");
    const t = makeDeps(mock);
    try {
      const fake = makeFakeInput({ directory: "/repo" });
      const hooks = (await createServerPlugin(t.deps)({ ...fake.input, client: { ...fake.input.client, mcp: { status } } })) as Hooks;
      await hooks.config?.({ mcp: { x: {} } });
      const message = await outcome((hooks["tool.execute.before"] as BeforeHook)(call("z_y"), { args: {} }));
      assert.equal(message, undefined);
      assert.equal(pretoolRequests(mock).length, 1);
    } finally {
      t.cleanup();
    }
  }
});

test("server() for an existing directory keeps its MCP names until the next config", async () => {
  const h = await harness("allow");
  try {
    await h.hooks.config?.({ mcp: { my: {} } });
    await h.server(makeFakeInput({ directory: "/repo" }).input);
    await h.before(call("my_tool"), { args: {} });
    assert.equal(metadataOf(body(0)).mcp_server, "my");
  } finally {
    h.cleanup();
  }
});

test("built-in tools that carry nothing evaluable are not sent", async () => {
  const h = await harness("deny");
  try {
    for (const tool of ["webfetch", "websearch", "skill", "todowrite", "question", "execute", "invalid"]) {
      assert.equal(await outcome(h.before(call(tool), { args: { url: "https://x" } })), undefined, tool);
    }
    await tick(50);
    assert.equal(pretoolRequests(mock).length, 0);
    assert.equal(signalsOf(mock, "mcp_attribution_miss").length, 0);
  } finally {
    h.cleanup();
  }
});

// --- task (HOOK-11) -----------------------------------------------------------------------------

test("task is audited, never sent for a decision, never denied", async () => {
  const h = await harness("deny");
  try {
    const args = { description: "d", prompt: "cat .env", subagent_type: "general" };
    assert.equal(await outcome(h.before(call("task", "ses_t", "call_task"), { args })), undefined);
    assert.equal(pretoolRequests(mock).length, 0);
    const turn = h.server.inspect.turn("ses_t");
    assert.equal(turn.tool_calls.length, 1);
    assert.equal(turn.tool_calls[0]?.tool_name, "task");
    assert.equal(turn.tool_calls[0]?.tool_use_id, "call_task");
    assert.equal(turn.tool_calls[0]?.decision, "audited");
  } finally {
    h.cleanup();
  }
});

// --- approval, fail-closed, fail-open (HOOK-10, RES-11) -----------------------------------------

test("ask and approval_required block with the approval text, not the deny text", async () => {
  const h = await harness("ask");
  try {
    assert.equal(await outcome(h.before(call("bash"), { args: { command: "rm -rf /tmp/x" } })), approvalMessage("Unusual command."));
    mock.setMode("approval");
    assert.equal(
      await outcome(h.before(call("bash", "ses_root", "call_2"), { args: { command: "rm -rf /tmp/x" } })),
      approvalMessage("Needs admin approval."),
    );
    assert.ok(h.fake.toasts.some((t) => t.variant === "warning"), "approval is toasted as a warning");
  } finally {
    h.cleanup();
  }
});

test("a fail-closed org blocks with the engine-unavailable text and reports a blocked failure", async () => {
  const h = await harness("failBlock", {
    deps: { timeouts: { pretoolMs: 200, errorsMs: 2000, turnLogMs: 2000 }, deadlineMs: 400 },
  });
  try {
    assert.equal(await outcome(h.before(call("bash"), { args: { command: "ls" } })), undefined, "first call learns block");
    const message = await outcome(h.before(call("bash", "ses_root", "call_2"), { args: { command: "ls" } }));
    assert.equal(message, ENGINE_UNAVAILABLE_REASON);
    assert.ok(await waitFor(() => signalsOf(mock, "blocked_due_to_failure").length >= 1));
  } finally {
    h.cleanup();
  }
});

test("a 500 or a malformed answer fails open and reports a bypass", async () => {
  for (const mode of ["500", "malformed"] as const) {
    const h = await harness(mode);
    try {
      assert.equal(await outcome(h.before(call("bash"), { args: { command: "cat .env" } })), undefined);
      assert.ok(await waitFor(() => signalsOf(mock, "bypassed_due_to_failure").length >= 1), mode);
    } finally {
      h.cleanup();
    }
  }
});

// --- no key -------------------------------------------------------------------------------------

test("without a key: no requests, one no-key notice per directory", async () => {
  const h = await harness("deny", { deps: { withKey: false } });
  try {
    assert.equal(await outcome(h.before(call("bash"), { args: { command: "cat .env" } })), undefined);
    assert.equal(await outcome(h.before(call("bash", "ses_root", "call_2"), { args: { command: "cat .env" } })), undefined);
    await tick();
    assert.equal(mock.requests.length, 0);
    assert.equal(h.fake.toasts.filter((t) => t.message === NO_KEY_NOTICE).length, 1);

    const other = makeFakeInput({ directory: "/other" });
    const otherHooks = (await h.server(other.input)) as Hooks;
    await (otherHooks["tool.execute.before"] as BeforeHook)(call("bash"), { args: { command: "ls" } });
    await (otherHooks["tool.execute.before"] as BeforeHook)(call("bash"), { args: { command: "ls" } });
    await tick();
    assert.equal(other.toasts.filter((t) => t.message === NO_KEY_NOTICE).length, 1);
    assert.equal(h.fake.toasts.filter((t) => t.message === NO_KEY_NOTICE).length, 1);
    assert.equal(mock.requests.length, 0);
  } finally {
    h.cleanup();
  }
});
