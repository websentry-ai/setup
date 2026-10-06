// narrow.ts (13-03): the pure readers where silent non-enforcement hides (PITFALLS Pitfall 8) —
// the shell command and its cwd, every apply_patch target, MCP attribution without splitting on `_`,
// and a key-order-independent args digest. Every export is total.

import assert from "node:assert/strict";
import test from "node:test";

import { MAX_PATCH_TARGETS } from "../src/constants.ts";
import {
  BUILTIN_TOOLS,
  MCP_RESOURCE_TOOLS,
  PATCH_HEADER_PREFIXES,
  SHELL_TOOLS,
  TASK_TOOL,
  applyPatchTargets,
  argsDigest,
  mcpResourceTarget,
  mcpCandidates,
  resolveMcpTool,
  sanitizeMcpName,
  shellCommandOf,
  shellCwdOf,
} from "../src/narrow.ts";

const wrong = <T>(value: unknown): T => value as T;

function hostile<T extends object>(): T {
  const boom = (): never => {
    throw new Error("hostile getter");
  };
  return new Proxy({}, { get: boom, has: boom, ownKeys: boom, getOwnPropertyDescriptor: boom }) as T;
}

// --- shell --------------------------------------------------------------------------------------

test("shellCommandOf: bash's command, else empty", () => {
  assert.ok(SHELL_TOOLS.has("bash"));
  assert.equal(shellCommandOf("bash", { command: "ls" }), "ls");
  assert.equal(shellCommandOf("bash", { command: 5 }), "");
  assert.equal(shellCommandOf("bash", wrong(null)), "");
  assert.equal(shellCommandOf("read", { command: "ls" }), "");
  assert.equal(shellCommandOf("bash", hostile()), "");
  assert.equal(shellCommandOf(wrong(undefined), { command: "ls" }), "");
});

test("shellCwdOf: an absolute workdir, else the instance directory", () => {
  assert.equal(shellCwdOf({ workdir: "/w" }, "/d"), "/w");
  assert.equal(shellCwdOf({ workdir: "rel" }, "/d"), "/d");
  assert.equal(shellCwdOf({ workdir: 5 }, "/d"), "/d");
  assert.equal(shellCwdOf({ workdir: "" }, "/d"), "/d");
  assert.equal(shellCwdOf(wrong(null), "/d"), "/d");
  assert.equal(shellCwdOf(hostile(), "/d"), "/d");
  assert.equal(shellCwdOf({}, wrong(5)), "");
});

// --- apply_patch --------------------------------------------------------------------------------

test("PATCH_HEADER_PREFIXES are the server's four, in its order", () => {
  assert.deepEqual([...PATCH_HEADER_PREFIXES], [
    "*** Add File:",
    "*** Update File:",
    "*** Delete File:",
    "*** Move to:",
  ]);
});

test("applyPatchTargets: every distinct Add/Update/Delete/Move-to path", () => {
  const patch =
    "*** Begin Patch\n*** Add File: a.ts\n+x\n*** Update File: /r/b.ts\n*** Move to: /r/c.ts\n*** Delete File: d.ts\n*** End Patch";
  assert.deepEqual(applyPatchTargets(patch), { targets: ["a.ts", "/r/b.ts", "/r/c.ts", "d.ts"], capped: false });
});

test("applyPatchTargets: CRLF, leading whitespace and duplicates", () => {
  const patch = "*** Begin Patch\r\n   *** Update File: a.ts  \r\n\t*** Update File: a.ts\r\n*** Delete File: b.ts\r\n*** End Patch\r\n";
  assert.deepEqual(applyPatchTargets(patch), { targets: ["a.ts", "b.ts"], capped: false });
});

test("applyPatchTargets: no headers, blank paths or a non-string are empty", () => {
  assert.deepEqual(applyPatchTargets("*** Begin Patch\n*** End Patch"), { targets: [], capped: false });
  assert.deepEqual(applyPatchTargets("*** Add File:   \n"), { targets: [], capped: false });
  for (const value of [undefined, null, 5, {}, hostile()]) {
    assert.deepEqual(applyPatchTargets(wrong(value)), { targets: [], capped: false });
  }
});

test("applyPatchTargets: past MAX_PATCH_TARGETS distinct paths it caps and says so", () => {
  const lines: string[] = ["*** Begin Patch"];
  for (let i = 0; i < MAX_PATCH_TARGETS + 5; i += 1) lines.push(`*** Add File: f${i}.ts`, "+x");
  lines.push("*** End Patch");
  const result = applyPatchTargets(lines.join("\n"));
  assert.equal(result.capped, true);
  assert.equal(result.targets.length, MAX_PATCH_TARGETS);
  assert.equal(result.targets[0], "f0.ts");
  assert.equal(result.targets[MAX_PATCH_TARGETS - 1], `f${MAX_PATCH_TARGETS - 1}.ts`);

  const exact: string[] = [];
  for (let i = 0; i < MAX_PATCH_TARGETS; i += 1) exact.push(`*** Add File: f${i}.ts`);
  assert.equal(applyPatchTargets(exact.join("\n")).capped, false);
});

// --- MCP ----------------------------------------------------------------------------------------

test("sanitizeMcpName mirrors opencode's key sanitiser", () => {
  assert.equal(sanitizeMcpName("my.server"), "my_server");
  assert.equal(sanitizeMcpName("a-b_c"), "a-b_c");
  assert.equal(sanitizeMcpName("a b/c@d"), "a_b_c_d");
  assert.equal(sanitizeMcpName(wrong(5)), "");
});

test("resolveMcpTool: longest sanitised prefix wins and the configured name is returned", () => {
  assert.deepEqual(resolveMcpTool("my_server_list_files", ["my", "my_server"]), {
    server: "my_server",
    tool: "list_files",
  });
  assert.deepEqual(resolveMcpTool("my_server_list_files", ["my"]), { server: "my", tool: "server_list_files" });
  assert.equal(resolveMcpTool("gh_create", ["gh.com"]), undefined);
  assert.deepEqual(resolveMcpTool("gh_com_create", ["gh.com"]), { server: "gh.com", tool: "create" });
  assert.equal(resolveMcpTool("my_", ["my"]), undefined);
  assert.equal(resolveMcpTool("bash", ["my"]), undefined);
});

test("resolveMcpTool: empty or unusable server lists and ids", () => {
  assert.equal(resolveMcpTool("my_x", []), undefined);
  assert.equal(resolveMcpTool("my_x", wrong(null)), undefined);
  assert.equal(resolveMcpTool("my_x", wrong("my")), undefined);
  assert.equal(resolveMcpTool("my_x", wrong([5, null, ""])), undefined);
  assert.equal(resolveMcpTool(wrong(5), ["my"]), undefined);
  assert.equal(resolveMcpTool("my_x", hostile()), undefined);
});

test("resolveMcpTool: two names that sanitise identically resolve to the smaller original name", () => {
  // opencode's own key collides the same way: both servers register `a_b_<tool>`.
  assert.deepEqual(resolveMcpTool("a_b_t", ["a_b", "a.b", "a@b"]), { server: "a.b", tool: "t" });
  assert.deepEqual(resolveMcpTool("a_b_t", ["a@b", "a.b"]), { server: "a.b", tool: "t" });
});

test("mcpCandidates: every server that could produce the id, longest prefix first (WR-01)", () => {
  assert.deepEqual(mcpCandidates("github_create_issue", ["github", "github_create", "gh"]), [
    { server: "github_create", tool: "issue" },
    { server: "github", tool: "create_issue" },
  ]);
  assert.deepEqual(mcpCandidates("a_b_t", ["a@b", "a_b", "a.b", "a_b"]), [
    { server: "a.b", tool: "t" },
    { server: "a@b", tool: "t" },
    { server: "a_b", tool: "t" },
  ]);
  assert.deepEqual(mcpCandidates("my_", ["my"]), []);
  assert.deepEqual(mcpCandidates("x_y", wrong(null)), []);
  assert.deepEqual(mcpCandidates("x_y", hostile()), []);
  assert.deepEqual(mcpCandidates(wrong(5), ["x"]), []);
});

test("mcpResourceTarget: the server arg of the three MCP resource tools", () => {
  assert.deepEqual([...MCP_RESOURCE_TOOLS].sort(), [
    "list_mcp_resource_templates",
    "list_mcp_resources",
    "read_mcp_resource",
  ]);
  assert.deepEqual(mcpResourceTarget("read_mcp_resource", { server: "gh", uri: "x" }), {
    server: "gh",
    tool: "read_mcp_resource",
  });
  assert.deepEqual(mcpResourceTarget("list_mcp_resources", { server: "gh" }), {
    server: "gh",
    tool: "list_mcp_resources",
  });
  assert.equal(mcpResourceTarget("list_mcp_resources", {}), undefined);
  assert.equal(mcpResourceTarget("read_mcp_resource", { server: 5 }), undefined);
  assert.equal(mcpResourceTarget("read_mcp_resource", { server: " " }), undefined);
  assert.equal(mcpResourceTarget("read", { server: "gh" }), undefined);
  assert.equal(mcpResourceTarget("read_mcp_resource", hostile()), undefined);
});

test("BUILTIN_TOOLS and TASK_TOOL", () => {
  for (const id of [
    "bash", "read", "write", "edit", "apply_patch", "glob", "grep", "webfetch", "websearch", "task",
    "todowrite", "skill", "question", "invalid", "lsp", "plan_exit", "execute", "list_mcp_resources",
    "list_mcp_resource_templates", "read_mcp_resource",
  ]) {
    assert.ok(BUILTIN_TOOLS.has(id), id);
  }
  assert.equal(BUILTIN_TOOLS.has("gh_create"), false);
  assert.equal(TASK_TOOL, "task");
});

// --- argsDigest ---------------------------------------------------------------------------------

test("argsDigest: key-order independent sha256", () => {
  const a = argsDigest({ b: 1, a: [1, { c: 2 }] });
  const b = argsDigest({ a: [1, { c: 2 }], b: 1 });
  assert.equal(a, b);
  assert.match(a ?? "", /^[0-9a-f]{64}$/);
  assert.notEqual(argsDigest({ a: [1, 2] }), argsDigest({ a: [2, 1] }));
  assert.notEqual(argsDigest({ a: "1" }), argsDigest({ a: 1 }));
});

test("argsDigest: an in-place mutation changes the digest", () => {
  const args: Record<string, unknown> = { command: "ls", nested: { x: 1 } };
  const before = argsDigest(args);
  (args.nested as Record<string, unknown>).x = 2;
  assert.notEqual(argsDigest(args), before);
  args.command = "rm -rf /";
  assert.notEqual(argsDigest(args), before);
});

test("argsDigest: cyclic, too deep, too large or hostile input is undefined", () => {
  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic.self = cyclic;
  assert.equal(argsDigest(cyclic), undefined);

  let deep: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < 40; i += 1) deep = { next: deep };
  assert.equal(argsDigest(deep), undefined);
  let shallow: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < 10; i += 1) shallow = { next: shallow };
  assert.match(argsDigest(shallow) ?? "", /^[0-9a-f]{64}$/);

  assert.equal(argsDigest({ big: "x".repeat(1024 * 1024 + 1) }), undefined);
  const many: unknown[] = [];
  for (let i = 0; i < 300_000; i += 1) many.push("abcd");
  assert.equal(argsDigest({ many }), undefined);

  const getter = Object.defineProperty({}, "boom", {
    enumerable: true,
    get() {
      throw new Error("hostile");
    },
  });
  assert.equal(argsDigest(getter), undefined);
  assert.equal(argsDigest(hostile()), undefined);
});

test("argsDigest: a shared (non-cyclic) reference is fine", () => {
  const shared = { x: 1 };
  assert.match(argsDigest({ a: shared, b: shared }) ?? "", /^[0-9a-f]{64}$/);
  assert.equal(argsDigest({ a: shared, b: shared }), argsDigest({ a: { x: 1 }, b: { x: 1 } }));
});
