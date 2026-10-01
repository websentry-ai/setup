// Account identity — parity with the Claude Code hook's `account_identity` (`unbound.py`
// `read_account_identity` / `_device_serial`), derived from what the agent's credential store says
// (`AgentAuthSummary`, produced by `AgentProfile.readAuth`). The pi `auth.json` reader's own cases
// live with it, in `packages/pi/test/auth.test.ts`.
//
// What these cases pin down:
//
//   * **The OAuth token goes to its issuer and nowhere else.** `fetchAnthropicProfile` is the only
//     function that ever sees it, and nothing it returns contains it.
//   * **Every failure is an absence, never a throw.** A missing or corrupt `auth.json` is no identity
//     at all; a failed profile call is an identity without email/plan; a failed serial probe is an
//     identity without `device_serial`.
//   * **An expired token is not spent.** No network call is made with it.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildAccountIdentity,
  createAccountIdentityLoader,
  fetchAnthropicProfile,
  isValidSerial,
  readDeviceSerial,
  probeToolPath,
} from "../src/accountIdentity.ts";
import type { ExecFileLike } from "../src/accountIdentity.ts";
import { ANTHROPIC_OAUTH_BETA_VALUE } from "../src/constants.ts";
import type { AgentAuthSummary } from "../src/profile.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

/** The credential-store reader the loader is given; the test profile reads a pi-shaped `auth.json`. */
const readAuth = (agentDir: string | undefined, modelProvider: string | undefined): AgentAuthSummary | undefined =>
  TEST_PROFILE.readAuth?.(agentDir, modelProvider);

/** A store holding an Anthropic subscription sign-in for the session's provider. */
const OAUTH_ANTHROPIC: AgentAuthSummary = { provider: "anthropic", hasCredential: true, anthropicOAuth: true };
/** A store holding some other credential for `provider` (an API key, or a non-Anthropic OAuth). */
const otherCredential = (provider: string): AgentAuthSummary => ({ provider, hasCredential: true, anthropicOAuth: false });
/** A store that exists but names no provider for this session. */
const NO_PROVIDER: AgentAuthSummary = { provider: undefined, hasCredential: false, anthropicOAuth: false };

const TOKEN = "sk-ant-oat01-TEST-ACCESS-TOKEN-never-forward";
const PROFILE = {
  account: { uuid: "acct-1", email: "Dev@Example.COM", has_claude_max: true, has_claude_pro: false },
  organization: { uuid: "org-uuid-1", organization_type: "claude_max" },
};

interface ProfileServer {
  url: string;
  hits: { authorization: string | undefined; beta: string | undefined }[];
  close(): Promise<void>;
}

async function startProfileServer(
  respond: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<ProfileServer> {
  const hits: ProfileServer["hits"] = [];
  const server: Server = createServer((req, res) => {
    hits.push({
      authorization: req.headers.authorization,
      beta: req.headers["anthropic-beta"] as string | undefined,
    });
    respond(req, res);
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/api/oauth/profile`,
    hits,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections();
        server.close(() => done());
      }),
  };
}

const okProfile = (_req: IncomingMessage, res: ServerResponse): void => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(PROFILE));
};

function tempAgentDir(auth?: unknown): { dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), "pi-agent-"));
  if (auth !== undefined) {
    writeFileSync(join(dir, "auth.json"), typeof auth === "string" ? auth : JSON.stringify(auth), {
      mode: 0o600,
    });
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const future = (): number => Date.now() + 3_600_000;
const oauthAnthropic = (expires = future()) => ({
  anthropic: { type: "oauth", access: TOKEN, refresh: "refresh-secret", expires },
});

const noSerial: ExecFileLike = async () => undefined;
// "No serial" must hold on every runner: the Linux fallback reads /etc/machine-id via `readFile`, not
// `execFile`, so both probes are stubbed together — a GitHub runner has a machine-id.
const noSerialProbe = { execFile: noSerial, readFile: () => undefined } as const;

// --- profile ---------------------------------------------------------------------------------------

test("fetchAnthropicProfile sends the bearer and beta header to the profile endpoint and maps the answer", async () => {
  const server = await startProfileServer(okProfile);
  try {
    const profile = await fetchAnthropicProfile(TOKEN, { url: server.url, timeoutMs: 2_000 });
    assert.deepEqual(profile, { email: "Dev@Example.COM", orgId: "org-uuid-1", plan: "claude_max" });
    assert.equal(server.hits.length, 1);
    assert.equal(server.hits[0]?.authorization, `Bearer ${TOKEN}`);
    assert.equal(server.hits[0]?.beta, ANTHROPIC_OAUTH_BETA_VALUE);
  } finally {
    await server.close();
  }
});

test("a 500 from the profile endpoint is undefined, not a throw", async () => {
  const server = await startProfileServer((_req, res) => {
    res.writeHead(500);
    res.end("boom");
  });
  try {
    assert.equal(await fetchAnthropicProfile(TOKEN, { url: server.url, timeoutMs: 2_000 }), undefined);
  } finally {
    await server.close();
  }
});

test("a hanging profile endpoint is undefined within the deadline", async () => {
  const server = await startProfileServer(() => {
    // Never answers.
  });
  try {
    const started = Date.now();
    assert.equal(await fetchAnthropicProfile(TOKEN, { url: server.url, timeoutMs: 150 }), undefined);
    assert.ok(Date.now() - started < 2_000, "bounded by the deadline");
  } finally {
    await server.close();
  }
});

test("a redirect is refused, so the token cannot be bounced to another host", async () => {
  const target = await startProfileServer(okProfile);
  const server = await startProfileServer((_req, res) => {
    res.writeHead(302, { location: target.url });
    res.end();
  });
  try {
    assert.equal(await fetchAnthropicProfile(TOKEN, { url: server.url, timeoutMs: 2_000 }), undefined);
    assert.equal(target.hits.length, 0, "the redirect target never sees the token");
  } finally {
    await server.close();
    await target.close();
  }
});

test("a non-JSON or wrong-shaped profile is undefined or partial, never a throw", async () => {
  const bodies = ["not json", "[]", JSON.stringify({ account: "x", organization: 5 })];
  for (const body of bodies) {
    const server = await startProfileServer((_req, res) => {
      res.writeHead(200);
      res.end(body);
    });
    try {
      const profile = await fetchAnthropicProfile(TOKEN, { url: server.url, timeoutMs: 2_000 });
      assert.ok(profile === undefined || Object.keys(profile).length === 0, body);
    } finally {
      await server.close();
    }
  }
});

test("a throwing fetch implementation is undefined", async () => {
  const throwing = (() => {
    throw new Error("sync throw");
  }) as unknown as typeof fetch;
  assert.equal(await fetchAnthropicProfile(TOKEN, { fetch: throwing, timeoutMs: 100 }), undefined);
});

// --- building the identity --------------------------------------------------------------------------

test("anthropic OAuth + profile → the full Claude Code vocabulary", () => {
  const identity = buildAccountIdentity({
    auth: OAUTH_ANTHROPIC,
    profile: { email: "Dev@Example.COM", orgId: "org-uuid-1", plan: "claude_max" },
    deviceSerial: "C02XYZ",
  });
  assert.deepEqual(identity, {
    auth_mode: "subscription",
    user_email: "Dev@Example.COM",
    email_domain: "example.com",
    org_id: "org-uuid-1",
    plan: "claude_max",
    device_serial: "C02XYZ",
  });
});

test("anthropic OAuth without a profile is subscription only", () => {
  assert.deepEqual(
    buildAccountIdentity({ auth: OAUTH_ANTHROPIC }),
    { auth_mode: "subscription" },
  );
});

test("any other provider, or a non-OAuth anthropic entry, is api_key and nothing else", () => {
  for (const provider of ["openai", "anthropic", "openrouter"]) {
    assert.deepEqual(
      buildAccountIdentity({ auth: otherCredential(provider), profile: { email: "x@y.z", plan: "p" } }),
      { auth_mode: "api_key" },
      provider,
    );
  }
});

test("no auth.json is no identity at all, even with a serial", () => {
  assert.equal(buildAccountIdentity({ auth: undefined, deviceSerial: "C02" }), undefined);
});

test("auth.json with no chosen provider is the serial only, or nothing", () => {
  const auth = NO_PROVIDER;
  assert.deepEqual(buildAccountIdentity({ auth, deviceSerial: "C02" }), { device_serial: "C02" });
  assert.equal(buildAccountIdentity({ auth }), undefined);
});

// --- device serial ------------------------------------------------------------------------------------

test("placeholder serials are not serials", () => {
  for (const value of ["", "  ", "0", "To Be Filled By O.E.M.", "System Serial Number", "n/a"]) {
    assert.equal(isValidSerial(value), false, value);
  }
  assert.equal(isValidSerial("C02ABC123"), true);
});

test("macOS: the serial comes from system_profiler", async () => {
  const calls: string[] = [];
  const execFile: ExecFileLike = async (file, args) => {
    calls.push([file, ...args].join(" "));
    return "Hardware:\n\n    Model Name: MacBook Pro\n      Serial Number (system): C02ABC123\n";
  };
  assert.equal(await readDeviceSerial({ platform: "darwin", execFile }), "C02ABC123");
  assert.deepEqual(calls, ["/usr/sbin/system_profiler SPHardwareDataType"]);
});

test("linux: dmidecode first, then machine-id; placeholders fall through", async () => {
  const execFile: ExecFileLike = async () => "To Be Filled By O.E.M.\n";
  const serial = await readDeviceSerial({
    platform: "linux",
    execFile,
    readFile: (path) => (path === "/etc/machine-id" ? "abc123machine\n" : undefined),
  });
  assert.equal(serial, "abc123machine");
});

test("a failing probe is undefined, never a throw", async () => {
  const throwing: ExecFileLike = async () => {
    throw new Error("ENOENT");
  };
  assert.equal(await readDeviceSerial({ platform: "darwin", execFile: throwing }), undefined);
  assert.equal(
    await readDeviceSerial({ platform: "linux", execFile: throwing, readFile: () => undefined }),
    undefined,
  );
  assert.equal(await readDeviceSerial({ platform: "darwin", execFile: noSerial }), undefined);
});

test("a probe that never settles is undefined within the deadline", async () => {
  const hang: ExecFileLike = () => new Promise(() => {});
  // The deadline timer is unref'd on purpose (a pending identity must not hold `pi -p` open), so the
  // test keeps the loop alive itself — as pi's own event loop does in production.
  const keepAlive = setInterval(() => {}, 1_000);
  try {
    const started = Date.now();
    assert.equal(await readDeviceSerial({ platform: "darwin", execFile: hang, timeoutMs: 100 }), undefined);
    assert.ok(Date.now() - started < 2_000);
  } finally {
    clearInterval(keepAlive);
  }
});

// --- the loader ---------------------------------------------------------------------------------------

test("the loader computes once, caches the promise, and exposes the settled value", async () => {
  const server = await startProfileServer(okProfile);
  const agent = tempAgentDir(oauthAnthropic());
  let probes = 0;
  const execFile: ExecFileLike = async () => {
    probes += 1;
    return "Serial Number (system): C02ABC123";
  };
  try {
    const loader = createAccountIdentityLoader({
      agentDir: agent.dir,
      readAuth,
      profileUrl: server.url,
      timeoutMs: 2_000,
      platform: "darwin",
      execFile,
    });
    assert.equal(loader.current(), undefined, "nothing before start");
    const first = loader.start("anthropic");
    const second = loader.start("openai");
    assert.strictEqual(first, second, "one computation per loader");
    const identity = await first;
    assert.equal(identity?.user_email, "Dev@Example.COM");
    assert.equal(identity?.plan, "claude_max");
    assert.equal(identity?.device_serial, "C02ABC123");
    assert.deepEqual(loader.current(), identity);
    assert.equal(server.hits.length, 1);
    assert.equal(probes, 1);
    assert.equal(JSON.stringify(identity).includes(TOKEN), false, "the token is never in the identity");
  } finally {
    await server.close();
    agent.cleanup();
  }
});

test("an expired token makes no profile call", async () => {
  const server = await startProfileServer(okProfile);
  const agent = tempAgentDir(oauthAnthropic(Date.now() - 1_000));
  try {
    const loader = createAccountIdentityLoader({
      agentDir: agent.dir,
      readAuth,
      profileUrl: server.url,
      timeoutMs: 2_000,
      ...noSerialProbe,
    });
    assert.deepEqual(await loader.start("anthropic"), { auth_mode: "subscription" });
    assert.equal(server.hits.length, 0, "an expired token is never sent");
  } finally {
    await server.close();
    agent.cleanup();
  }
});

test("a missing auth.json skips the serial probe and the network entirely", async () => {
  const agent = tempAgentDir();
  let probes = 0;
  let fetches = 0;
  try {
    const loader = createAccountIdentityLoader({
      agentDir: agent.dir,
      readAuth,
      execFile: async () => {
        probes += 1;
        return "Serial Number: C02";
      },
      fetch: (async () => {
        fetches += 1;
        return new Response("{}");
      }) as typeof fetch,
    });
    assert.equal(await loader.start("anthropic"), undefined);
    assert.equal(probes, 0);
    assert.equal(fetches, 0);
  } finally {
    agent.cleanup();
  }
});

// --- probe binaries are addressed by absolute path (review MEDIUM: bare names resolve via cwd on Windows)

test("serial probes run absolute binaries, never bare names", async () => {
  const seen: string[] = [];
  const recordingExec: ExecFileLike = async (file) => {
    seen.push(file);
    return undefined;
  };
  for (const platform of ["darwin", "linux", "win32"]) {
    await readDeviceSerial({ platform, execFile: recordingExec, readFile: () => undefined, timeoutMs: 500 });
  }
  assert.ok(seen.length >= 3, `expected probes on all three platforms, saw ${seen.join(", ")}`);
  for (const file of seen) {
    assert.ok(/^(\/|[A-Za-z]:\\)/.test(file), `bare or relative probe name: ${file}`);
    assert.ok(!file.includes(".."), `traversal in probe path: ${file}`);
  }
  assert.ok(seen.includes("/usr/sbin/system_profiler"));
  assert.ok(seen.includes("/usr/sbin/dmidecode"));
  assert.ok(seen.some((f) => f.endsWith("\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")));
});

test("the Windows PowerShell path honours SystemRoot and falls back to C:\\Windows", () => {
  assert.equal(
    probeToolPath("powershell", { SystemRoot: "D:\\Win" }),
    "D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  );
  assert.equal(
    probeToolPath("powershell", {}),
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  );
});
