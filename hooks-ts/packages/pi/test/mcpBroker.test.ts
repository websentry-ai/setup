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
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createApiClient } from "../../core/src/client.ts";
import { keyState } from "../../core/src/keyState.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { PI_PROFILE } from "../src/profile.ts";
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

const TURNLOG_PATH = PI_PROFILE.turnLogPath;

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
  write(path: string, content: unknown): void;
  close(): Promise<void>;
}

const closedGate: Deps["heartbeatGate"] = { shouldSend: () => false, markSent: () => {} };

/** A short-timeout checker on a FRESH policy state, so cases cannot leak policy memory. */
function fastChecker(apiKey: string, baseUrl: string): PolicyChecker {
  const client = createApiClient({ baseUrl, apiKey, timeoutMs: 80, profile: PI_PROFILE });
  return createPolicyChecker({
    client,
    state: createPolicyState(),
    telemetry: createTelemetry({ client, apiKey, profile: PI_PROFILE }),
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
    /** Write config files BEFORE `session_start`, which is when the config snapshot is taken. */
    setup?: (homeDir: string, cwd: string, write: (path: string, content: unknown) => void) => void;
    /** A listener registered on the bus BEFORE the extension's — another permission extension. */
    preListener?: (data: unknown) => void;
  } = {},
): Promise<Fixture> {
  turnStore.take();
  const api = await startMockApi({ mode });
  const home = createFakeHome();
  const cwd = mkdtempSync(join(tmpdir(), "mcp-broker-cwd-"));
  const writeFile = (path: string, content: unknown): void => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
  };
  opts.setup?.(home.homeDir, cwd, writeFile);
  const bus = createBus();
  if (opts.preListener !== undefined) bus.on(EVENT, opts.preListener);
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
    write: writeFile,
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
    await f.handlers.get("tool_call")?.(
      createFakeToolCallEvent("mcp", { tool: "create_issue", args: '{"title":"Bearer sk-live-argsecret"}' }, "toolu_proxy_1"),
      f.ctx,
    );
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
  const inflight = createInflightCalls(3, 60_000);
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

const GOOD = { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] };
const EVIL = { command: "/tmp/evil-mcp" };

test("mcp_server_config: plain strict JSON is sent by exact name; env and headers never are", async () => {
  const f = await fixture("allow", {
    setup: (home, cwd, write) => {
      write(join(home, ".config", "mcp", "mcp.json"), {
        mcpServers: { remote: { url: "https://remote.invalid/mcp", headers: { Authorization: "Bearer sk-SECRET" } } },
      });
      const real = join(cwd, "tools", "mcp.json");
      write(real, { mcpServers: { local: { command: "npx", args: ["-y", "srv"], env: { API_KEY: "sk-SECRET3" } } } });
      symlinkSync(real, join(cwd, ".mcp.json"));
    },
  });
  try {
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

test("mcp_server_config: a two-source override is sent merged", async () => {
  const f = await fixture("allow", {
    setup: (home, cwd, write) => {
      write(join(home, ".config", "mcp", "mcp.json"), { mcpServers: { github: { url: "https://api.githubcopilot.com/mcp/" } } });
      write(join(cwd, ".mcp.json"), { mcpServers: { github: EVIL } });
    },
  });
  try {
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue" });
    assert.deepStrictEqual(dataOf(pretoolBodies(f.api)[0]).metadata.mcp_server_config, EVIL, "the binary the adapter runs");
  } finally {
    await f.close();
  }
});

test("mcp_server_config is OMITTED when any source cannot be parsed strictly — the call is still checked", async () => {
  const f = await fixture("allow", {
    setup: (home, cwd, write) => {
      write(join(home, ".config", "mcp", "mcp.json"), { mcpServers: { github: { url: "https://ok.invalid" } } });
      write(join(cwd, ".mcp.json"), "{ this is not json");
    },
  });
  try {
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    const data = dataOf(pretoolBodies(f.api)[0]);
    assert.equal(Object.hasOwn(data.metadata, "mcp_server_config"), false, "never a possibly wrong config");
    assert.equal(data.metadata.mcp_server, "github");
  } finally {
    await f.close();
  }
});

test("--mcp-config on argv omits the config; exclusive mode without it reads only the adapter file", async () => {
  const flagged = await fixture("allow", {
    argv: ["node", "pi", "--mcp-config", "/tmp/custom.json"],
    setup: (_home, cwd, write) => write(join(cwd, ".mcp.json"), { mcpServers: { s: { url: "https://s.invalid" } } }),
  });
  try {
    await brokerRequest(flagged.bus, { serverName: "s", originalToolName: "t" });
    assert.equal(Object.hasOwn(dataOf(pretoolBodies(flagged.api)[0]).metadata, "mcp_server_config"), false);
  } finally {
    await flagged.close();
  }
  const exclusive = await fixture("allow", {
    env: { PI_MCP_CONFIG_MODE: "exclusive" },
    setup: (home, cwd, write) => {
      write(join(home, ".pi", "agent", "mcp-adapter.json"), { mcpServers: { s: { url: "https://adapter.invalid" } } });
      write(join(cwd, ".mcp.json"), { mcpServers: { s: { command: "ignored-in-exclusive" } } });
    },
  });
  try {
    await brokerRequest(exclusive.bus, { serverName: "s", originalToolName: "t" });
    assert.deepStrictEqual(dataOf(pretoolBodies(exclusive.api)[0]).metadata.mcp_server_config, { url: "https://adapter.invalid" });
  } finally {
    await exclusive.close();
  }
});

// --- REVIEW-2 regressions -----------------------------------------------------------------------

test("REVIEW-2 CR-01: all five reproduced config differentials omit the config, and the call is still checked", async () => {
  // Each case: the adapter runs the EVIL project server (or a socket), while the old lenient reader
  // described GOOD. Strict-or-omit sends no config at all — never the sanctioned fingerprint.
  const cases: [string, unknown, unknown][] = [
    ["mcpServers non-object + mcp-servers", { mcpServers: { github: EVIL } }, { mcpServers: 0, "mcp-servers": { github: GOOD } }],
    ["invalid settings (adapter skips the file)", { mcpServers: { github: EVIL } }, { settings: 1, mcpServers: { github: GOOD } }],
    ["socket override", { mcpServers: { github: GOOD } }, { mcpServers: { github: { socket: "/tmp/evil.sock" } } }],
    ["lone CR ends // only for a lenient stripper", { mcpServers: { github: EVIL } }, '{"mcpServers":{//\r"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}\n}}'],
    ["unterminated block comment", { mcpServers: { github: EVIL } }, '{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}} /* '],
  ];
  for (const [name, project, projectPi] of cases) {
    const f = await fixture("deny", {
      setup: (_home, cwd, write) => {
        write(join(cwd, ".mcp.json"), project);
        write(join(cwd, ".pi", "mcp-adapter.json"), projectPi);
      },
    });
    try {
      const { decision } = await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue" });
      assert.equal(decision, "deny", name);
      const data = dataOf(pretoolBodies(f.api)[0]);
      assert.equal(Object.hasOwn(data.metadata, "mcp_server_config"), false, `${name}: config ABSENT`);
      assert.deepStrictEqual([data.metadata.mcp_server, data.metadata.mcp_tool], ["github", "create_issue"], name);
    } finally {
      await f.close();
    }
  }
});

test("REVIEW-2 CR-02: a config file edited after session start omits the config from then on", async () => {
  const f = await fixture("allow", {
    setup: (_home, cwd, write) => write(join(cwd, ".mcp.json"), { mcpServers: { github: EVIL } }),
  });
  try {
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    f.write(join(f.cwd, ".mcp.json"), { mcpServers: { github: GOOD } });
    const later = new Date(Date.now() + 5_000);
    utimesSync(join(f.cwd, ".mcp.json"), later, later);
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    const configs = pretoolBodies(f.api).map((b) => dataOf(b).metadata.mcp_server_config);
    assert.deepStrictEqual(configs[0], EVIL, "what the adapter loaded at session start");
    assert.equal(configs[1], undefined, "never the rewritten (sanctioned-looking) file");
  } finally {
    await f.close();
  }
});

test("REVIEW-2 CR-03: ~1 MiB ASCII and >1 MiB CJK args keep the body under 900 KiB, marked truncated", async () => {
  const f = await fixture("deny");
  try {
    for (const args of [{ body: "a".repeat(1_048_000) }, { body: "中".repeat(400_000) }, { body: '"'.repeat(2_000_000) }]) {
      const { decision } = await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue", args });
      assert.equal(decision, "deny", "evaluated — not a 413 turned fail-open allow");
    }
    for (const request of f.api.requests.filter((r) => r.path === PRETOOL_PATH)) {
      const bytes = Buffer.byteLength(JSON.stringify(request.body));
      assert.ok(bytes < 900 * 1024, `body ${bytes} bytes`);
      assert.equal(dataOf(request.body as Record<string, unknown>).metadata.tool_input_truncated, true);
    }
  } finally {
    await f.close();
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

test("CR-02 (first review) regression: JSONC never yields the sanctioned url; a plain symlinked override is honoured", async () => {
  for (const variant of ["comment", "trailing", "symlink"]) {
    const f = await fixture("allow", {
      setup: (home, cwd, write) => {
        write(join(home, ".config", "mcp", "mcp.json"), { mcpServers: { github: { url: "https://api.githubcopilot.com/mcp/" } } });
        const evil = '{"mcpServers": {"github": {"command": "evil", "args": ["--x"]}}}';
        if (variant === "symlink") {
          const target = join(cwd, "tools", "mcp.json");
          write(target, evil);
          symlinkSync(target, join(cwd, ".mcp.json"));
        } else {
          write(join(cwd, ".mcp.json"), variant === "comment" ? `// project\n${evil}` : '{"mcpServers": {"github": {"command": "evil",},}}');
        }
      },
    });
    try {
      await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue" });
      const config = dataOf(pretoolBodies(f.api)[0]).metadata.mcp_server_config;
      if (variant === "symlink") assert.deepStrictEqual(config, { command: "evil", args: ["--x"] });
      else assert.equal(config, undefined, `${variant}: omitted, never the sanctioned url`);
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

// --- Revision 3 broker behaviour --------------------------------------------------------------

test("another broker claimed first ⇒ no request, and one rate-limited bypass report", async () => {
  const f = await fixture("deny", {
    preListener: (data) => {
      (data as { claim: (h: () => string) => boolean }).claim(() => "allow_once");
    },
  });
  try {
    for (let i = 0; i < 3; i += 1) {
      const { decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
      assert.equal(decision, "allow_once", "the other extension's answer stands");
    }
    await sleep(60);
    assert.equal(pretoolBodies(f.api).length, 0, "no policy request for a call someone else decides");
    const reports = f.api.requests.filter((r) => r.path === "/v1/hooks/errors");
    assert.equal(reports.length, 1, "reported once");
    assert.match(JSON.stringify(reports[0]?.body), /McpBrokerPreempted/);
  } finally {
    await f.close();
  }
});

test("aborted while the policy request was in flight ⇒ abstain, and no dialog", async () => {
  const controller = new AbortController();
  const f = await fixture("allow", {
    ctx: { hasUI: true, confirmResult: true },
    makeChecker: () => ({
      async checkTool() {
        controller.abort();
        return { kind: "confirm", reason: "Unusual." };
      },
    }),
  });
  try {
    const { decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t", signal: controller.signal });
    assert.equal(decision, "abstain");
    assert.equal(f.ctx.confirmCalls.length, 0, "no dialog for a call that will never run");
  } finally {
    await f.close();
  }
});

test("a throw inside the confirm branch ⇒ deny, never abstain", async () => {
  const f = await fixture("ask", { seeCtx: false });
  try {
    const stale = createFakeCtx({ cwd: f.cwd, sessionId: "sess-broker" });
    Object.defineProperty(stale, "hasUI", {
      get() {
        throw new Error("This extension ctx is stale");
      },
    });
    await f.handlers.get("session_start")?.({ type: "session_start", reason: "startup" }, stale);
    const { decision } = await brokerRequest(f.bus, { serverName: "s", originalToolName: "t" });
    assert.equal(decision, "deny", "a verdict that needed confirmation must not become an allow");
  } finally {
    await f.close();
  }
});

test("overlapping same-name calls with different args correlate to the right tool_call ids", async () => {
  const f = await fixture("allow");
  try {
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("github_create_issue", { title: "a" }, "toolu_A"), f.ctx);
    await f.handlers.get("tool_call")?.(createFakeToolCallEvent("github_create_issue", { title: "b" }, "toolu_B"), f.ctx);
    // B reaches the broker first (A is still connecting).
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue", prefixedToolName: "github_create_issue", args: { title: "b" } });
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "create_issue", prefixedToolName: "github_create_issue", args: { title: "a" } });
    const ids = pretoolBodies(f.api).map((b) => [dataOf(b).tool_use_id, (dataOf(b).metadata.tool_input as { title: string }).title]);
    assert.deepStrictEqual(ids, [["toolu_B", "b"], ["toolu_A", "a"]]);
  } finally {
    await f.close();
  }
});

test("in-flight entries expire by age", () => {
  let now = 1_000;
  const inflight = createInflightCalls(10, 60_000, () => now);
  inflight.remember({ toolCallId: "old", toolName: "github_x", input: {} }, "S");
  now += 61_000;
  assert.equal(inflight.claim("github_x", "x", {}), undefined, "a stale entry is never claimed");
  inflight.remember({ toolCallId: "fresh", toolName: "github_x", input: {} }, "S");
  assert.equal(inflight.claim("github_x", "x", {}), "fresh");
  assert.equal(inflight.claim("github_x", "x", { other: 1 }), undefined, "args must match too");
});

test("an unmatched brokered call posts its own one-call turn log and never enters the turn store", async () => {
  const f = await fixture("allow");
  try {
    await f.handlers.get("input")?.(createFakeInputEvent("an unrelated prompt"), f.ctx);
    await brokerRequest(f.bus, { serverName: "db", originalToolName: "query", origin: "script", args: { sql: "select 1" } });
    await sleep(80);
    const logs = f.api.requests.filter((r) => r.path === TURNLOG_PATH).map((r) => r.body as {
      messages: { content: string; tool_use?: { tool_name: string; tool_use_id: string }[] }[];
    });
    assert.equal(logs.length, 1, "posted immediately, without agent_end");
    assert.equal(logs[0]?.messages[0]?.content, "", "no prompt — it is not part of a turn");
    assert.equal(logs[0]?.messages[1]?.tool_use?.[0]?.tool_name, "mcp__db__query");
    assert.ok(MBROKER_ID.test(String(logs[0]?.messages[1]?.tool_use?.[0]?.tool_use_id)));
    assert.deepStrictEqual(turnStore.snapshot().tool_calls, [], "the shared store is untouched");
  } finally {
    await f.close();
  }
});

test("PR #371: a broker request before session_start does not latch the config off", async () => {
  const f = await fixture("allow", {
    seeCtx: false,
    setup: (_home, cwd, write) => write(join(cwd, ".mcp.json"), { mcpServers: { github: GOOD } }),
  });
  try {
    // No ctx seen yet ⇒ no cwd ⇒ this call goes without a config…
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    // …and once a session starts, calls are described again.
    await f.handlers.get("session_start")?.({ type: "session_start", reason: "startup" }, f.ctx);
    await brokerRequest(f.bus, { serverName: "github", originalToolName: "q" });
    const configs = pretoolBodies(f.api).map((b) => dataOf(b).metadata.mcp_server_config);
    assert.equal(configs[0], undefined);
    assert.deepStrictEqual(configs[1], GOOD);
  } finally {
    await f.close();
  }
});

test("PR #371: a direct tool under toolPrefix \"mcp\" (mcp__<server>_<tool>) correlates, and its output lands on its row", async () => {
  const f = await fixture("allow");
  try {
    await f.handlers.get("input")?.(createFakeInputEvent("open an issue"), f.ctx);
    // Top-level arguments, no `tool`/`args` wrapper fields — a direct tool that merely LOOKS like a wrapper.
    await f.handlers.get("tool_call")?.(
      createFakeToolCallEvent("mcp__github_create_issue", { title: "t", labels: ["bug"] }, "toolu_direct_mcp"),
      f.ctx,
    );
    await brokerRequest(f.bus, {
      serverName: "github",
      originalToolName: "create_issue",
      prefixedToolName: "mcp__github_create_issue",
      args: { labels: ["bug"], title: "t" },
      origin: "direct",
    });
    const mcpBody = pretoolBodies(f.api).find((b) => dataOf(b).metadata.mcp_server !== undefined);
    assert.equal(dataOf(mcpBody).tool_use_id, "toolu_direct_mcp", "the real id, not a minted one");

    await f.handlers.get("tool_result")?.(
      createFakeToolResultEvent("mcp__github_create_issue", { toolCallId: "toolu_direct_mcp", content: [{ type: "text", text: "issue #7" }] }),
      f.ctx,
    );
    f.handlers.get("agent_end")?.(createFakeAgentEndEvent([]), f.ctx);
    await sleep(80);
    const logs = f.api.requests.filter((r) => r.path === TURNLOG_PATH);
    assert.equal(logs.length, 1, "no standalone row: it is part of the turn");
    const use = (logs[0]?.body as { messages: { tool_use?: { tool_use_id: string; tool_response: { content?: string } }[] }[] })
      .messages[1]?.tool_use?.[0];
    assert.equal(use?.tool_use_id, "toolu_direct_mcp");
    assert.equal(use?.tool_response.content, "issue #7");
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
