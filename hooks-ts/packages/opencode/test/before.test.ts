// `tool.execute.before` (HOOK-08, HOOK-10..13, RES-11): every model-issued tool call is evaluated
// through core's total `evaluateToolCall` and blocked through `block()` on deny, approval-required
// and fail-closed-unavailable. Driven through the real plugin entry against the core mock API.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENY_PREFIX } from "../../core/src/constants.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import type { PretoolRequestBody } from "../../core/src/types.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { createServerPlugin } from "../src/plugin.ts";
import type { Deps } from "../src/plugin.ts";
import { APPROVAL_PREFIX, approvalMessage, blockingMessage, strictest } from "../src/verdicts.ts";
import { makeDeps, makeFakeInput, pretoolRequests, startOpencodeMock } from "./helpers/fakeHost.ts";
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
