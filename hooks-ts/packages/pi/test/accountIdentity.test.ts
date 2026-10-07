// Account-identity parity, through the real composition root: the console's Account Usage page shows
// the signed-in provider account for pi the way it does for Claude Code.
//
// Two servers per case: the Unbound `mockApi` (which must NEVER see the OAuth token) and a local
// stand-in for Anthropic's profile endpoint (the only place the token may go). `auth.json` lives in a
// temp HOME at the default `~/.pi/agent`, so the agent-dir resolution under test is the production one.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import type { ExecFileLike } from "../../core/src/accountIdentity.ts";
import { CACHE_TTL_MS, EVENT_NAME_SESSION_START, PRETOOL_PATH } from "../../core/src/constants.ts";
import { createHeartbeatGate } from "../../core/src/heartbeat.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import {
  createFakeAgentEndEvent,
  createFakeAssistantMessage,
  createFakeCtx,
  createFakeInputEvent,
  createFakeSessionStartEvent,
  createFakeToolCallEvent,
} from "./helpers/fakeCtx.ts";
import type { FakeCtx } from "./helpers/fakeCtx.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TURNLOG_PATH = PI_PROFILE.turnLogPath;

const TOKEN = "sk-ant-oat01-PI-IDENTITY-TEST-TOKEN";
const REFRESH = "sk-ant-ort01-PI-IDENTITY-REFRESH";
const SERIAL = "C02PITEST01";
const FULL = {
  auth_mode: "subscription",
  user_email: "dev@example.com",
  email_domain: "example.com",
  org_id: "org-uuid-1",
  plan: "claude_max",
  device_serial: SERIAL,
};

type AnyHandler = (event: unknown, ctx: unknown) => unknown;
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

interface ProfileServer {
  url: string;
  hits: number;
  close(): Promise<void>;
}

async function startProfile(mode: "ok" | "500" | "hang"): Promise<ProfileServer> {
  const state = { hits: 0 };
  const server: Server = createServer((_req: IncomingMessage, res: ServerResponse) => {
    state.hits += 1;
    if (mode === "hang") return;
    if (mode === "500") {
      res.writeHead(500);
      res.end("nope");
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        account: { uuid: "acct-1", email: "dev@example.com", has_claude_max: true },
        organization: { uuid: "org-uuid-1", organization_type: "claude_max" },
      }),
    );
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/api/oauth/profile`,
    get hits() {
      return state.hits;
    },
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections();
        server.close(() => done());
      }),
  };
}

const serialProbe: ExecFileLike = async () => `Hardware:\n      Serial Number (system): ${SERIAL}\n`;
const failingProbe: ExecFileLike = async () => {
  throw new Error("ENOENT system_profiler");
};

const oauth = (expires = Date.now() + 3_600_000) => ({
  type: "oauth",
  access: TOKEN,
  refresh: REFRESH,
  expires,
});

interface Fixture {
  handlers: Map<string, AnyHandler>;
  api: MockApi;
  profile: ProfileServer;
  cleanup(): Promise<void>;
}

async function fixture(opts: {
  auth: unknown;
  profileMode?: "ok" | "500" | "hang";
  execFile?: ExecFileLike;
  timeoutMs?: number;
}): Promise<Fixture> {
  const api = await startMockApi({ mode: "allow" });
  const profile = await startProfile(opts.profileMode ?? "ok");
  const homeDir = mkdtempSync(join(tmpdir(), "pi-identity-"));
  if (opts.auth !== undefined) {
    const agentDir = join(homeDir, ".pi", "agent");
    mkdirSync(agentDir, { recursive: true });
    writeFileSync(
      join(agentDir, "auth.json"),
      typeof opts.auth === "string" ? opts.auth : JSON.stringify(opts.auth),
      { mode: 0o600 },
    );
  }
  const handlers = new Map<string, AnyHandler>();
  const pi = {
    on(event: string, handler: AnyHandler) {
      handlers.set(event, handler);
      return () => {};
    },
  };
  const overrides: Partial<Deps> = {
    env: { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url },
    homeDir,
    entrypoint: "pi/0.87.1",
    heartbeatGate: createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS }),
    identity: {
      profileUrl: profile.url,
      platform: "darwin",
      execFile: opts.execFile ?? serialProbe,
      timeoutMs: opts.timeoutMs ?? 2_000,
    },
  };
  await createExtension(overrides)(pi as unknown as ExtensionAPI);
  return {
    handlers,
    api,
    profile,
    cleanup: async () => {
      await api.close();
      await profile.close();
      rmSync(homeDir, { recursive: true, force: true });
    },
  };
}

function handlerOf(f: Fixture, name: string): AnyHandler {
  const handler = f.handlers.get(name);
  assert.ok(handler !== undefined, `${name} must be registered`);
  return handler;
}

const bodies = (api: MockApi, path: string) =>
  api.requests.filter((r) => r.path === path).map((r) => r.body as Record<string, unknown>);

async function waitForHeartbeat(api: MockApi, withinMs = 3_000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + withinMs;
  while (Date.now() < deadline) {
    const hb = bodies(api, PRETOOL_PATH).find((b) => b.event_name === EVENT_NAME_SESSION_START);
    if (hb !== undefined) return hb;
    await sleep(10);
  }
  assert.fail("no heartbeat arrived");
}

/** session_start → prompt → tool call → agent_end; returns every body Unbound saw, by kind. */
async function runTurn(f: Fixture, ctx: FakeCtx) {
  assert.equal(await handlerOf(f, "session_start")(createFakeSessionStartEvent("startup"), ctx), undefined);
  const heartbeat = await waitForHeartbeat(f.api);
  assert.equal(await handlerOf(f, "input")(createFakeInputEvent("list the files"), ctx), undefined);
  assert.equal(await handlerOf(f, "tool_call")(createFakeToolCallEvent("bash", { command: "ls" }), ctx), undefined);
  handlerOf(f, "agent_end")(createFakeAgentEndEvent([createFakeAssistantMessage([{ type: "text", text: "done" }])]), ctx);
  await sleep(100);
  const pretools = bodies(f.api, PRETOOL_PATH);
  return {
    heartbeat,
    prompt: pretools.find((b) => b.event_name === "user_prompt"),
    toolUse: pretools.find((b) => b.event_name === "tool_use"),
    turnLog: bodies(f.api, TURNLOG_PATH)[0],
  };
}

function assertTokenNeverSentToUnbound(api: MockApi): void {
  const everything = JSON.stringify(api.requests.map((r) => ({ headers: r.headers, body: r.body })));
  assert.equal(everything.includes(TOKEN), false, "the OAuth access token reached Unbound");
  assert.equal(everything.includes(REFRESH), false, "the OAuth refresh token reached Unbound");
}

test("anthropic OAuth: the full identity rides the heartbeat, the prompt check, the tool check and the turn log", async () => {
  const f = await fixture({ auth: { anthropic: oauth() } });
  try {
    const seen = await runTurn(f, createFakeCtx({ sessionId: "s-full" }));
    for (const [name, body] of Object.entries(seen)) {
      assert.ok(body !== undefined, `${name} was sent`);
      assert.deepEqual(body.account_identity, FULL, name);
    }
    assert.equal(f.profile.hits, 1, "one profile lookup per process, not per request");
    assertTokenNeverSentToUnbound(f.api);
  } finally {
    await f.cleanup();
  }
});

test("an API-key provider is auth_mode api_key and nothing account-shaped", async () => {
  const f = await fixture({ auth: { openai: { type: "api_key", key: "sk-openai-secret" } }, execFile: failingProbe });
  try {
    const seen = await runTurn(f, createFakeCtx({ sessionId: "s-apikey" }));
    for (const [name, body] of Object.entries(seen)) {
      assert.deepEqual(body?.account_identity, { auth_mode: "api_key" }, name);
    }
    assert.equal(f.profile.hits, 0);
    assert.equal(JSON.stringify(f.api.requests).includes("sk-openai-secret"), false);
  } finally {
    await f.cleanup();
  }
});

test("an expired token makes no profile call and is subscription only", async () => {
  const f = await fixture({ auth: { anthropic: oauth(Date.now() - 60_000) }, execFile: failingProbe });
  try {
    const seen = await runTurn(f, createFakeCtx({ sessionId: "s-expired" }));
    assert.deepEqual(seen.heartbeat.account_identity, { auth_mode: "subscription" });
    assert.deepEqual(seen.toolUse?.account_identity, { auth_mode: "subscription" });
    assert.equal(f.profile.hits, 0, "an expired token is never sent anywhere");
    assertTokenNeverSentToUnbound(f.api);
  } finally {
    await f.cleanup();
  }
});

for (const mode of ["500", "hang"] as const) {
  test(`a profile ${mode} leaves subscription only, within the deadline`, async () => {
    const f = await fixture({ auth: { anthropic: oauth() }, profileMode: mode, execFile: failingProbe, timeoutMs: 200 });
    try {
      const started = Date.now();
      assert.equal(
        await handlerOf(f, "session_start")(createFakeSessionStartEvent("startup"), createFakeCtx()),
        undefined,
      );
      assert.ok(Date.now() - started < 150, "session_start never waits for the lookup");
      const heartbeat = await waitForHeartbeat(f.api, 2_000);
      assert.ok(Date.now() - started < 1_500, "the heartbeat goes out once the deadline passes");
      assert.deepEqual(heartbeat.account_identity, { auth_mode: "subscription" });
      assert.equal(f.profile.hits, 1);
      assertTokenNeverSentToUnbound(f.api);
    } finally {
      await f.cleanup();
    }
  });
}

for (const [label, auth] of [
  ["missing", undefined],
  ["corrupt", "{not json"],
] as const) {
  test(`a ${label} auth.json sends no account_identity key at all`, async () => {
    const f = await fixture({ auth });
    try {
      const seen = await runTurn(f, createFakeCtx({ sessionId: `s-${label}` }));
      for (const [name, body] of Object.entries(seen)) {
        assert.ok(body !== undefined, `${name} was sent`);
        assert.equal(Object.hasOwn(body, "account_identity"), false, name);
      }
      assert.equal(f.profile.hits, 0);
    } finally {
      await f.cleanup();
    }
  });
}

test("device_serial is present when the probe returns one and absent when it fails", async () => {
  const ok = await fixture({ auth: { openai: { type: "api_key" } }, execFile: serialProbe });
  try {
    await handlerOf(ok, "session_start")(createFakeSessionStartEvent("startup"), createFakeCtx());
    assert.deepEqual((await waitForHeartbeat(ok.api)).account_identity, { auth_mode: "api_key", device_serial: SERIAL });
  } finally {
    await ok.cleanup();
  }
  const failing = await fixture({ auth: { openai: { type: "api_key" } }, execFile: failingProbe });
  try {
    await handlerOf(failing, "session_start")(createFakeSessionStartEvent("startup"), createFakeCtx());
    assert.deepEqual((await waitForHeartbeat(failing.api)).account_identity, { auth_mode: "api_key" });
  } finally {
    await failing.cleanup();
  }
});

test("the provider comes from ctx.model.provider when auth.json holds several", async () => {
  const auth = { anthropic: oauth(), openai: { type: "api_key" } };

  const viaOpenai = await fixture({ auth, execFile: failingProbe });
  try {
    const ctx = createFakeCtx({ modelProvider: "openai" });
    await handlerOf(viaOpenai, "session_start")(createFakeSessionStartEvent("startup"), ctx);
    assert.deepEqual((await waitForHeartbeat(viaOpenai.api)).account_identity, { auth_mode: "api_key" });
    assert.equal(viaOpenai.profile.hits, 0);
  } finally {
    await viaOpenai.cleanup();
  }

  const viaAnthropic = await fixture({ auth });
  try {
    const ctx = createFakeCtx({ modelProvider: "anthropic" });
    await handlerOf(viaAnthropic, "session_start")(createFakeSessionStartEvent("startup"), ctx);
    assert.deepEqual((await waitForHeartbeat(viaAnthropic.api)).account_identity, FULL);
    assertTokenNeverSentToUnbound(viaAnthropic.api);
  } finally {
    await viaAnthropic.cleanup();
  }

  const ambiguous = await fixture({ auth, execFile: failingProbe });
  try {
    await handlerOf(ambiguous, "session_start")(createFakeSessionStartEvent("startup"), createFakeCtx());
    const heartbeat = await waitForHeartbeat(ambiguous.api);
    assert.equal(Object.hasOwn(heartbeat, "account_identity"), false, "several providers and no model: no guess");
    assert.equal(ambiguous.profile.hits, 0);
  } finally {
    await ambiguous.cleanup();
  }
});

test("a keyless session never reads auth.json into a request or calls the profile endpoint", async () => {
  const f = await fixture({ auth: { anthropic: oauth() } });
  try {
    // A second extension over a HOME that DOES hold a live OAuth auth.json, but with no Unbound key:
    // the keyless path returns before the identity lookup starts.
    const home = mkdtempSync(join(tmpdir(), "pi-identity-nokey-"));
    mkdirSync(join(home, ".pi", "agent"), { recursive: true });
    writeFileSync(join(home, ".pi", "agent", "auth.json"), JSON.stringify({ anthropic: oauth() }));
    const handlers = new Map<string, AnyHandler>();
    const pi = {
      on(event: string, handler: AnyHandler) {
        handlers.set(event, handler);
        return () => {};
      },
    };
    await createExtension({
      env: {},
      homeDir: home,
      entrypoint: "pi/0.87.1",
      heartbeatGate: createHeartbeatGate({ now: Date.now, ttlMs: CACHE_TTL_MS }),
      identity: { profileUrl: f.profile.url, execFile: serialProbe },
    })(pi as unknown as ExtensionAPI);
    await handlers.get("session_start")?.(createFakeSessionStartEvent("startup"), createFakeCtx());
    await sleep(100);
    assert.equal(f.profile.hits, 0);
    rmSync(home, { recursive: true, force: true });
  } finally {
    await f.cleanup();
  }
});
