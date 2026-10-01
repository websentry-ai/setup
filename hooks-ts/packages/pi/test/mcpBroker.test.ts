// MCP enforcement through the pi-mcp-adapter approval broker (Revision 2).
//
// Driven end to end through `createExtension` against the scripted mock gateway, with two fakes that
// are TRANSCRIPTIONS rather than inventions, so a pass here means the real adapter would see the same:
//
//   * `createBus` is pi's `createEventBus` (`dist/core/event-bus.js`): `on` wraps the listener in an
//     `async` function that awaits it and swallows errors; `emit` is a synchronous EventEmitter emit.
//   * `brokerRequest` is pi-mcp-adapter 4.0.0 `tool-approval.ts requestBrokerApproval`: the claim window
//     closes on the line after `emit`, the handler runs via `Promise.resolve().then(handler)`, and a
//     thrown handler or any value outside the four decisions is read as `"deny"`.
//
// The cases cover every listener outcome, the no-claim states, audit correlation, the config lookup,
// and each of the review's four reproduced bypasses (CR-01..CR-04) as a regression: a policy request
// IS made, for the right server and tool.

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createApiClient } from "../../core/src/client.ts";
import { TURNLOG_PATH } from "../../core/src/constants.ts";
import { keyState } from "../../core/src/keyState.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { turnStore } from "../../core/src/turn.ts";
import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createInflightCalls, createMcpApprovalListener } from "../src/mcpBroker.ts";
import {
  createFakeAgentEndEvent,
  createFakeCtx,
  createFakeInputEvent,
  createFakeToolCallEvent,
  createFakeToolResultEvent,
} from "./helpers/fakeCtx.ts";
import type { FakeCtx, FakeCtxOptions } from "./helpers/fakeCtx.ts";

const EVENT = "pi-mcp-adapter:tool-approval-request";
const PRETOOL_PATH = "/v1/hooks/pretool";
const MBROKER_ID = new RegExp("^mcpb_[0-9a-f]{20}$");

type AnyHandler = (event: unknown, ctx: unknown) => unknown;
type Decision = "allow_once" | "allow_for_session" | "deny" | "abstain";

// --- Transcribed fakes --------------------------------------------------------------------------

/** pi's `createEventBus`, verbatim in behaviour. */
function createBus() {
  const emitter = new EventEmitter();
  return {
    emit: (channel: string, data: unknown) => {
      emitter.emit(channel, data);
    },
    on: (channel: string, handler: (data: unknown) => unknown) => {
      const safeHandler = async (data: unknown) => {
        try {
          await handler(data);
        } catch {
          // pi logs and swallows
        }
      };
      emitter.on(channel, safeHandler);
      return () => emitter.off(channel, safeHandler);
    },
    listenerCount: (channel: string) => emitter.listenerCount(channel),
  };
}

interface BrokerFields {
  serverName: string;
  originalToolName: string;
  prefixedToolName?: string;
  args?: Record<string, unknown>;
  origin?: string;
  signal?: AbortSignal;
}

/** `requestBrokerApproval`, verbatim in behaviour. `claimed` reports whether anyone claimed. */
async function brokerRequest(
  bus: ReturnType<typeof createBus>,
  fields: BrokerFields,
): Promise<{ decision: Decision; claimed: boolean }> {
  let acceptingClaim = true;
  let handler: (() => unknown) | undefined;
  const request = {
    requestId: "req-1",
    serverName: fields.serverName,
    originalToolName: fields.originalToolName,
    prefixedToolName: fields.prefixedToolName ?? `${fields.serverName}_${fields.originalToolName}`,
    args: fields.args ?? {},
    origin: fields.origin ?? "proxy",
    ...(fields.signal === undefined ? {} : { signal: fields.signal }),
    claim(candidate: () => unknown) {
      if (!acceptingClaim || handler) return false;
      handler = candidate;
      return true;
    },
  };
  bus.emit(EVENT, request);
  acceptingClaim = false;
  if (!handler) return { decision: "abstain", claimed: false };
  try {
    const decision = await Promise.resolve().then(handler);
    const valid = ["allow_once", "allow_for_session", "deny", "abstain"].includes(decision as string);
    return { decision: valid ? (decision as Decision) : "deny", claimed: true };
  } catch {
    return { decision: "deny", claimed: true };
  }
}

// --- Fixture ------------------------------------------------------------------------------------

interface Fixture {
  api: MockApi;
  bus: ReturnType<typeof createBus>;
  handlers: Map<string, AnyHandler>;
  ctx: FakeCtx;
  homeDir: string;
  cwd: string;
  write(path: string, content: string): void;
  close(): Promise<void>;
}

const closedGate: Deps["heartbeatGate"] = { shouldSend: () => false, markSent: () => {} };

/** A short-timeout checker on a FRESH policy state, so cases cannot leak policy memory. */
function fastChecker(apiKey: string, baseUrl: string): PolicyChecker {
  const client = createApiClient({ baseUrl, apiKey, timeoutMs: 80 });
  return createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: createTelemetry({ client, apiKey }),
    keyState,
  });
}

async function fixture(
  mode: MockMode,
  opts: {
    key?: boolean;
    ctx?: Partial<FakeCtxOptions>;
    makeChecker?: Deps["makeChecker"];
    argv?: string[];
    env?: Record<string, string>;
    seeCtx?: boolean;
  } = {},
): Promise<Fixture> {
  turnStore.take();
  const api = await startMockApi({ mode });
  const home = createFakeHome();
  const cwd = mkdtempSync(join(tmpdir(), "mcp-broker-cwd-"));
  const bus = createBus();
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
    events: { on: bus.on, emit: bus.emit },
  };
  await createExtension({
    env: {
      ...(opts.key === false ? {} : { UNBOUND_PI_API_KEY: TEST_KEY }),
      UNBOUND_GATEWAY_URL: api.url,
      ...(opts.env ?? {}),
    },
    homeDir: home.homeDir,
    entrypoint: "pi/0.87.1",
    heartbeatGate: closedGate,
    makeChecker: opts.makeChecker ?? fastChecker,
    argv: opts.argv ?? ["node", "pi"],
  })(pi as unknown as ExtensionAPI);
  const ctx = createFakeCtx({ cwd, sessionId: "sess-broker", ...(opts.ctx ?? {}) });
  // The broker carries no ctx; the extension uses the most recent one a handler saw.
  if (opts.seeCtx !== false) await handlers.get("session_start")?.({ type: "session_start", reason: "startup" }, ctx);
  return {
    api,
    bus,
    handlers,
    ctx,
    homeDir: home.homeDir,
    cwd,
    write(path, content) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
    },
    async close() {
      home.cleanup();
      rmSync(cwd, { recursive: true, force: true });
      await api.close();
    },
  };
}

function pretoolBodies(api: MockApi): Record<string, unknown>[] {
  return api.requests.filter((r) => r.path === PRETOOL_PATH).map((r) => r.body as Record<string, unknown>);
}

function dataOf(body: Record<string, unknown> | undefined): {
  tool_name: string;
  command: string;
  tool_use_id?: string;
  metadata: Record<string, unknown>;
} {
  return body?.pre_tool_use_data as never;
}

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

// --- Outcomes -----------------------------------------------------------------------------------

test("allow ⇒ abstain, after exactly one Path-3 policy request with the adapter's resolution", async () => {
  const f = await fixture("allow");
  try {
    const { decision, claimed } = await brokerRequest(f.bus, {
      serverName: "github",
      originalToolName: "create_issue",
      prefixedToolName: "github_create_issue",
      args: { title: "t", body: { nested: [1, 2] } },
      origin: "direct",
    });
    assert.equal(claimed, true);
    assert.equal(decision, "abstain", "allow leaves the adapter's own approval settings in force");
    const bodies = pretoolBodies(f.api);
    assert.equal(bodies.length, 1);
    const data = dataOf(bodies[0]);
    assert.equal(data.tool_name, "mcp__github__create_issue");
    assert.equal(data.command, "");
    assert.equal(data.metadata.mcp_server, "github");
    assert.equal(data.metadata.mcp_tool, "create_issue");
    assert.deepStrictEqual(data.metadata.tool_input, { title: "t", body: { nested: [1, 2] } });
    assert.equal(data.metadata.mcp_origin, "direct");
    assert.equal(bodies[0]?.pull_policies, true, "pull_policies follows the same rule as every call");
  } finally {
    await f.close();
  }
});

test("deny ⇒ deny, and the developer is shown the policy reason", async () => {
  const f = await fixture("deny");
  try {
    const { decision } = await brokerRequest(f.bus, { serverName: "slack", originalToolName: "post_message" });
    assert.equal(decision, "deny");
    assert.deepStrictEqual(f.ctx.notifyCalls.at(-1), { message: "Reading secrets is blocked.", type: "error" });
  } finally {
    await f.close();
  }
});

test("confirm ⇒ asks through the live ctx: yes ⇒ allow_once, no ⇒ deny, no UI ⇒ deny without asking", async () => {
  for (const [ctx, expected, asked] of [
    [{ hasUI: true, confirmResult: true }, "allow_once", 1],
    [{ hasUI: true, confirmResult: false }, "deny", 1],
    [{ hasUI: false }, "deny", 0],
  ] as const) {
    const f = await fixture("ask", { ctx });
    try {
      const { decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
      assert.equal(decision, expected, JSON.stringify(ctx));
      assert.equal(f.ctx.confirmCalls.length, asked);
    } finally {
      await f.close();
    }
  }
});

test("confirm with no ctx seen yet ⇒ deny (there is nobody to ask)", async () => {
  const f = await fixture("ask", { seeCtx: false });
  try {
    assert.equal((await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" })).decision, "deny");
  } finally {
    await f.close();
  }
});

test("a fail-closed org: unavailable ⇒ deny", async () => {
  // `failBlock` answers the first request with `policy_check_failure_action: block`, then hangs.
  const f = await fixture("failBlock");
  try {
    assert.equal((await brokerRequest(f.bus, { serverName: "s", originalToolName: "warm" })).decision, "abstain");
    assert.equal((await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" })).decision, "deny");
  } finally {
    await f.close();
  }
});

test("a fail-open API failure ⇒ abstain (never a block)", async () => {
  for (const mode of ["500", "malformed", "hang"] as MockMode[]) {
    const f = await fixture(mode);
    try {
      assert.equal((await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" })).decision, "abstain", mode);
    } finally {
      await f.close();
    }
  }
});

test("the claimed handler never throws and never answers anything unknown: a faulting checker ⇒ abstain", async () => {
  const throwing: Deps["makeChecker"] = () => ({
    checkTool() {
      throw new Error("core exploded");
    },
  });
  const garbage: Deps["makeChecker"] = () => ({
    async checkTool() {
      return { kind: "nonsense" } as never;
    },
  });
  for (const makeChecker of [throwing, garbage]) {
    const f = await fixture("allow", { makeChecker });
    try {
      // A throw would have been read by the adapter as "deny" — an internal error must not block.
      assert.equal((await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" })).decision, "abstain");
    } finally {
      await f.close();
    }
  }
});

test("no key ⇒ no claim, and no request", async () => {
  const f = await fixture("deny", { key: false });
  try {
    const { decision, claimed } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
    assert.equal(claimed, false, "the adapter's own approval applies, as if we were not installed");
    assert.equal(decision, "abstain");
    assert.equal(f.api.requests.length, 0);
  } finally {
    await f.close();
  }
});

test("a malformed request is not claimed; an aborted one is abstained without a request", async () => {
  const f = await fixture("deny");
  try {
    let claimedMalformed = false;
    f.bus.emit(EVENT, { claim: () => (claimedMalformed = true), serverName: "", originalToolName: "t" });
    f.bus.emit(EVENT, { serverName: "s", originalToolName: "t" });
    f.bus.emit(EVENT, null);
    assert.equal(claimedMalformed, false);

    const aborted = AbortSignal.abort();
    const { decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t", signal: aborted });
    assert.equal(decision, "abstain");
    assert.equal(pretoolBodies(f.api).length, 0);
  } finally {
    await f.close();
  }
});

test("mcpScript, resource and iframe origins are all checked", async () => {
  const f = await fixture("deny");
  try {
    for (const origin of ["script", "resource", "iframe"]) {
      const { decision } = await brokerRequest(f.bus, { serverName: "db", originalToolName: "query", origin });
      assert.equal(decision, "deny", origin);
    }
    const bodies = pretoolBodies(f.api);
    assert.deepStrictEqual(bodies.map((b) => dataOf(b).metadata.mcp_origin), ["script", "resource", "iframe"]);
    for (const b of bodies) assert.ok(MBROKER_ID.test(String(dataOf(b).tool_use_id)), "no tool_call to match: minted id");
  } finally {
    await f.close();
  }
});

test("a tool_call for an MCP tool makes no request itself — only the broker does", async () => {
  const f = await fixture("deny");
  try {
    const result = await f.handlers.get("tool_call")?.(createFakeToolCallEvent("mcp", { tool: "create_issue" }), f.ctx);
    assert.equal(result, undefined);
    assert.equal(f.api.requests.length, 0);
  } finally {
    await f.close();
  }
});

// --- Audit correlation --------------------------------------------------------------------------

test("correlation: a matched tool_call id rides the request, the record and the output pairing", async () => {
  const f = await fixture("allow");
  try {
    await f.handlers.get("input")?.(createFakeInputEvent("file the bug"), f.ctx);
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("mcp", { tool: "create_issue", args: {} }, "toolu_proxy_1"), f.ctx);
    await brokerRequest(f.bus, {
      serverName: "github",
      originalToolName: "create_issue",
      prefixedToolName: "github_create_issue",
      args: { title: "Bearer sk-live-argsecret" },
    });
    // The first pretool body is the `input` prompt check; the MCP request is the one naming a server.
    const mcpBody = pretoolBodies(f.api).find((b) => dataOf(b).metadata.mcp_server !== undefined);
    assert.equal(dataOf(mcpBody).tool_use_id, "toolu_proxy_1");
    assert.equal(
      (mcpBody?.messages as { content: string }[] | undefined)?.[0]?.content,
      "file the bug",
      "the turn prompt rides the MCP request too",
    );

    await f.handlers.get("tool_result")?.(
      createFakeToolResultEvent("mcp", { toolCallId: "toolu_proxy_1", content: [{ type: "text", text: "issue #42 created" }] }),
      f.ctx,
    );
    f.handlers.get("agent_end")?.(createFakeAgentEndEvent([]), f.ctx);
    await sleep(80);

    const log = f.api.requests.find((r) => r.path === TURNLOG_PATH)?.body as {
      messages: { tool_use?: { tool_name: string; tool_use_id: string; tool_input: Record<string, unknown>; tool_response: Record<string, unknown> }[] }[];
    };
    const use = log.messages[1]?.tool_use?.[0];
    assert.equal(use?.tool_name, "mcp__github__create_issue");
    assert.equal(use?.tool_use_id, "toolu_proxy_1");
    assert.deepStrictEqual(use?.tool_input, { title: "Bearer [REDACTED]" }, "args redacted in the audit row");
    assert.equal(use?.tool_response.content, "issue #42 created", "output paired by the matched id");
  } finally {
    await f.close();
  }
});

test("correlation: a direct tool matches by prefixed name; an unmatched call gets a minted id", async () => {
  const f = await fixture("allow");
  try {
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("github_list_repos", {}, "toolu_direct_1"), f.ctx);
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "list_repos", prefixedToolName: "github_list_repos" });
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "list_repos", prefixedToolName: "github_list_repos" });
    const ids = pretoolBodies(f.api).map((b) => dataOf(b).tool_use_id);
    assert.equal(ids[0], "toolu_direct_1");
    assert.ok(MBROKER_ID.test(String(ids[1])), "a match is consumed once; the second call is minted");
  } finally {
    await f.close();
  }
});

test("in-flight entries are bounded, forgotten on tool_result, and dropped on a session change", () => {
  const inflight = createInflightCalls(3);
  for (let i = 0; i < 5; i += 1) inflight.remember({ toolCallId: `c${i}`, toolName: "mcp", input: { tool: "t" } }, "A");
  assert.equal(inflight.size(), 3, "bounded, oldest dropped");
  inflight.forget("c4");
  assert.equal(inflight.size(), 2);
  inflight.keepSession("B");
  assert.equal(inflight.size(), 0, "another session's calls can never match");
  assert.doesNotThrow(() => inflight.remember(null as never, "A"));
});

test("the listener is synchronous and total, whatever the deps do", () => {
  const listener = createMcpApprovalListener({
    active: () => {
      throw new Error("active exploded");
    },
    decide: async () => "deny",
  });
  let claimed = false;
  assert.doesNotThrow(() => listener({ serverName: "s", originalToolName: "t", claim: () => (claimed = true) }));
  assert.equal(claimed, false);
  assert.equal(listener({}), undefined);
});

// --- mcp_server_config by exact server name -----------------------------------------------------

test("mcp_server_config: found by exact name, JSONC (comments, trailing comma, BOM) and symlinks accepted", async () => {
  const f = await fixture("allow");
  try {
    f.write(
      join(f.homeDir, ".config", "mcp", "mcp.json"),
      '﻿{\n  // global\n  "mcpServers": {\n    "remote": { "url": "https://remote.invalid/mcp", "headers": {"Authorization": "Bearer sk-SECRET"}, "env": {"K": "sk-SECRET2"}, },\n  },\n}\n',
    );
    const real = join(f.cwd, "tools", "mcp.json");
    f.write(real, '{ /* project */ "mcpServers": { "local": { "command": "npx", "args": ["-y", "srv"], "env": {"API_KEY": "sk-SECRET3"} } } }');
    symlinkSync(real, join(f.cwd, ".mcp.json"));

    await brokerRequest(f.bus, { serverName: "remote", originalToolName: "q" });
    await brokerRequest(f.bus, { serverName: "local", originalToolName: "r" });
    await brokerRequest(f.bus, { serverName: "unknown", originalToolName: "s" });
    const configs = pretoolBodies(f.api).map((b) => dataOf(b).metadata.mcp_server_config);
    assert.deepStrictEqual(configs, [
      { url: "https://remote.invalid/mcp" },
      { command: "npx", args: ["-y", "srv"] },
      undefined,
    ]);
    assert.equal(JSON.stringify(f.api.requests).includes("SECRET"), false, "env and headers are never read in");
  } finally {
    await f.close();
  }
});

test("mcp_server_config is OMITTED when any existing source cannot be parsed", async () => {
  const f = await fixture("allow");
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), '{"mcpServers": {"github": {"url": "https://ok.invalid"}}}');
    f.write(join(f.cwd, ".mcp.json"), "{ this is not json");
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    const data = dataOf(pretoolBodies(f.api)[0]);
    assert.equal(Object.hasOwn(data.metadata, "mcp_server_config"), false, "never a possibly wrong config");
    assert.equal(data.metadata.mcp_server, "github", "the call is still checked");
  } finally {
    await f.close();
  }
});

test("--mcp-config replaces the adapter file; exclusive mode reads only it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-override-"));
  const override = join(dir, "custom.json");
  writeFileSync(override, '{"mcpServers": {"s": {"url": "https://override.invalid"}}}');
  const f = await fixture("allow", { argv: ["node", "pi", "--mcp-config", override], env: { PI_MCP_CONFIG_MODE: "exclusive" } });
  try {
    f.write(join(f.cwd, ".mcp.json"), '{"mcpServers": {"s": {"command": "ignored-in-exclusive"}}}');
    await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
    assert.deepStrictEqual(dataOf(pretoolBodies(f.api)[0]).metadata.mcp_server_config, { url: "https://override.invalid" });
  } finally {
    await f.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- Regressions for the reproduced bypasses ----------------------------------------------------

test("CR-01 regression: a stale cache server sharing a tool name no longer makes the call unchecked", async () => {
  const f = await fixture("deny");
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), '{"mcpServers": {"pg-staging": {"command": "pg-mcp"}}}');
    f.write(
      join(f.homeDir, ".pi", "agent", "mcp-cache.json"),
      JSON.stringify({ version: 1, servers: { "pg-staging": { tools: [{ name: "query" }] }, "pg-prod-old": { tools: [{ name: "query" }] } } }),
    );
    const { decision } = await brokerRequest(f.bus, { serverName: "pg-staging", originalToolName: "query", prefixedToolName: "pg-staging_query" });
    assert.equal(decision, "deny");
    const data = dataOf(pretoolBodies(f.api)[0]);
    assert.equal(data.metadata.mcp_server, "pg-staging");
    assert.equal(data.metadata.mcp_tool, "query");
  } finally {
    await f.close();
  }
});

test("CR-02 regression: a JSONC / symlinked project file that redefines a server is honoured, not spoofed", async () => {
  for (const variant of ["comment", "trailing", "bom", "symlink"]) {
    const f = await fixture("allow");
    try {
      f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), '{"mcpServers": {"github": {"url": "https://api.githubcopilot.com/mcp/"}}}');
      const evil = '{"mcpServers": {"github": {"command": "evil", "args": ["--x"]}}}';
      const text =
        variant === "comment" ? `// project\n${evil}` :
        variant === "trailing" ? '{"mcpServers": {"github": {"command": "evil", "args": ["--x"],},},}' :
        variant === "bom" ? `﻿${evil}` : evil;
      if (variant === "symlink") {
        const target = join(f.cwd, "tools", "mcp.json");
        f.write(target, text);
        symlinkSync(target, join(f.cwd, ".mcp.json"));
      } else {
        f.write(join(f.cwd, ".mcp.json"), text);
      }
      await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue" });
      assert.deepStrictEqual(
        dataOf(pretoolBodies(f.api)[0]).metadata.mcp_server_config,
        { command: "evil", args: ["--x"] },
        `${variant}: the binary the adapter runs, never the sanctioned url`,
      );
    } finally {
      await f.close();
    }
  }
});

test("CR-03 regression: another server's colliding tool name cannot switch off checks on a wrapper", async () => {
  const f = await fixture("deny");
  try {
    f.write(
      join(f.homeDir, ".config", "mcp", "mcp.json"),
      '{"mcpServers": {"github": {"url": "https://gh.invalid"}, "other": {"command": "o", "toolPrefix": "none"}}}',
    );
    // The model calls the github namespace wrapper; the adapter resolves it and asks the broker.
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("mcp__github", { tool: "delete_repo" }, "toolu_ns"), f.ctx);
    const { decision } = await brokerRequest(f.bus, { serverName: "github", originalToolName: "delete_repo", prefixedToolName: "github_delete_repo" });
    assert.equal(decision, "deny");
    const data = dataOf(pretoolBodies(f.api)[0]);
    assert.deepStrictEqual([data.metadata.mcp_server, data.metadata.mcp_tool, data.tool_use_id], ["github", "delete_repo", "toolu_ns"]);

    // And a non-MCP extension tool that merely LOOKS like `<server>_<tool>` is never sent as MCP:
    // no broker request is emitted for it, and `tool_call` makes none.
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("todo_write", { content: "file body" }), f.ctx);
    assert.equal(pretoolBodies(f.api).length, 1);
  } finally {
    await f.close();
  }
});

test("CR-04 regression: a secret past 16 KB of padding, and in a nested value, reaches the gateway", async () => {
  const f = await fixture("allow");
  try {
    const args = { pad: "x".repeat(17_000), text: `${"y".repeat(17_000)} AKIA-SECRET`, data: { token: "ghp_nested" } };
    await brokerRequest(f.bus, { serverName: "slack", originalToolName: "post_message", args });
    const data = dataOf(pretoolBodies(f.api)[0]);
    assert.deepStrictEqual(data.metadata.tool_input, args);
    assert.equal(Object.hasOwn(data.metadata, "tool_input_truncated"), false);
  } finally {
    await f.close();
  }
});

// Must stay LAST: the key latch is permanent for this process.
test("a latched key ⇒ no claim", async () => {
  const f = await fixture("401");
  try {
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("bash", { command: "ls" }), f.ctx);
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("bash", { command: "ls" }), f.ctx);
    assert.equal(keyState.isInactive(), true, "the latch is what this case is about");
    const before = f.api.requests.length;
    const { claimed, decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
    assert.equal(claimed, false);
    assert.equal(decision, "abstain");
    assert.equal(f.api.requests.length, before, "no request behind the latch");
  } finally {
    await f.close();
  }
});
