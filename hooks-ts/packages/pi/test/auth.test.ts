// pi's own readers: where its agent dir is, and what its `auth.json` says about the sign-in.
//
// These cases moved here with the code (`core/src/cache.ts` + `core/src/accountIdentity.ts` ->
// `pi/src/agentDir.ts` + `pi/src/auth.ts`): how pi lays out its directory and its credential store is
// a pi fact, so the cases live with the pi package. The assertions are the ones core's tests made.
//
// What they pin down:
//
//   * **The agent dir**: `PI_CODING_AGENT_DIR` (tilde-expanded, absolute only), else `~/.pi/agent`,
//     else nothing — and the policy cache path core derives from it through `PI_PROFILE`.
//   * **`auth.json` narrowing**: only `type` / `access` / `expires` are read into memory; the refresh
//     token and any API key are not.
//   * **Composition**: `readPiAuthSummary` feeding core's `buildAccountIdentity` gives exactly the
//     identities the pre-split code produced from the same raw `auth.json`.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, sep } from "node:path";
import test from "node:test";

import { buildAccountIdentity } from "../../core/src/accountIdentity.ts";
import { resolveCachePath } from "../../core/src/cache.ts";
import { ENV_PI_AGENT_DIR, resolvePiAgentDir } from "../src/agentDir.ts";
import { chooseProvider, readPiAuth, readPiAuthSummary } from "../src/auth.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TOKEN = "sk-ant-oat01-TEST-ACCESS-TOKEN-never-forward";

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

// --- agent dir -----------------------------------------------------------------------------------

test("the agent dir resolves exactly like the cache: env override, else ~/.pi/agent", () => {
  assert.equal(resolvePiAgentDir({}, "/home/dev"), "/home/dev/.pi/agent");
  assert.equal(resolvePiAgentDir({ [ENV_PI_AGENT_DIR]: "/opt/pi" }, "/home/dev"), "/opt/pi");
  assert.equal(resolvePiAgentDir({ [ENV_PI_AGENT_DIR]: "~/alt" }, "/home/dev"), "/home/dev/alt");
  assert.equal(resolvePiAgentDir({ [ENV_PI_AGENT_DIR]: "relative" }, "/home/dev"), "/home/dev/.pi/agent");
  assert.equal(resolvePiAgentDir({}, ""), undefined);
});

// --- auth.json -----------------------------------------------------------------------------------

test("readPiAuth reads provider → type/access/expires and nothing else", () => {
  const agent = tempAgentDir({
    ...oauthAnthropic(123),
    openai: { type: "api_key", key: "sk-openai" },
    junk: "not-an-object",
  });
  try {
    const auth = readPiAuth(agent.dir);
    assert.ok(auth !== undefined);
    assert.deepEqual(Object.keys(auth).sort(), ["anthropic", "openai"]);
    assert.equal(auth.anthropic?.type, "oauth");
    assert.equal(auth.anthropic?.expires, 123);
    assert.equal(auth.openai?.type, "api_key");
    assert.equal(JSON.stringify(auth).includes("refresh-secret"), false, "the refresh token is not kept");
    assert.equal(JSON.stringify(auth).includes("sk-openai"), false, "an API key is not kept");
  } finally {
    agent.cleanup();
  }
});

test("readPiAuth is undefined for a missing, corrupt, non-object or unresolvable auth.json", () => {
  for (const content of [undefined, "{not json", "[]", "null", "42"]) {
    const agent = tempAgentDir(content);
    try {
      assert.equal(readPiAuth(agent.dir), undefined, `content=${String(content)}`);
    } finally {
      agent.cleanup();
    }
  }
  assert.equal(readPiAuth(undefined), undefined);
  assert.equal(readPiAuth(""), undefined);
});

test("readPiAuth refuses a directory named auth.json rather than blocking or throwing", () => {
  const agent = tempAgentDir();
  try {
    mkdirSync(join(agent.dir, "auth.json"));
    assert.equal(readPiAuth(agent.dir), undefined);
  } finally {
    agent.cleanup();
  }
});

// --- provider choice ------------------------------------------------------------------------------

test("the session model's provider wins; else the single provider; else none", () => {
  const two = { anthropic: { type: "oauth" }, openai: { type: "api_key" } };
  assert.equal(chooseProvider(two, "openai"), "openai");
  assert.equal(chooseProvider(two, undefined), undefined, "ambiguous without a model");
  assert.equal(chooseProvider({ openai: { type: "api_key" } }, undefined), "openai");
  assert.equal(chooseProvider({ openai: { type: "api_key" } }, ""), "openai", "a blank provider is no provider");
});

// --- resolveCachePath, through pi's agent dir ---------------------------------------------------
//
// `resolveCachePath` is core's; the directory it joins onto is pi's, supplied by `PI_PROFILE`.

test("resolveCachePath: PI_CODING_AGENT_DIR wins over the home default", () => {
  const custom = join(sep, "custom", "agent");
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: custom }, join(sep, "home", "u"), PI_PROFILE),
    join(custom, ".unbound", "policy_cache.json"),
  );
});

test("resolveCachePath: falls back to <home>/.pi/agent when the env var is absent", () => {
  const home = join(sep, "home", "u");
  const path = resolveCachePath({}, home, PI_PROFILE);
  assert.equal(path, join(home, ".pi", "agent", ".unbound", "policy_cache.json"));
});

test("resolveCachePath: a leading tilde expands against the passed home dir", () => {
  const home = join(sep, "home", "u");
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: "~/relocated" }, home, PI_PROFILE),
    join(home, "relocated", ".unbound", "policy_cache.json"),
  );
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: "~" }, home, PI_PROFILE),
    join(home, ".unbound", "policy_cache.json"),
  );
});

test("resolveCachePath: a relative or blank env value falls back instead of resolving against cwd", () => {
  const home = join(sep, "home", "u");
  const fallback = join(home, ".pi", "agent", ".unbound", "policy_cache.json");
  // A repo-relative value must never be honoured: `join(cwd, ...)` would put the cache inside
  // whatever repository pi was started in, where the repo itself could plant one.
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "agent" }, home, PI_PROFILE), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "./agent" }, home, PI_PROFILE), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "   " }, home, PI_PROFILE), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "" }, home, PI_PROFILE), fallback);
});

test("resolveCachePath: a non-absolute resolved base is refused outright — no read, no write", () => {
  // `os.homedir()` can fail and the caller's fallback is "", exactly the config.ts hazard.
  assert.equal(resolveCachePath({}, "", PI_PROFILE), undefined);
  assert.equal(resolveCachePath({}, "relative/home", PI_PROFILE), undefined);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "agent" }, "", PI_PROFILE), undefined);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "~/x" }, "", PI_PROFILE), undefined);
  assert.equal(resolveCachePath({}, undefined as unknown as string, PI_PROFILE), undefined);
});

test("resolveCachePath: never throws, whatever the env holds", () => {
  assert.doesNotThrow(() => resolveCachePath(undefined as unknown as NodeJS.ProcessEnv, "/home/u", PI_PROFILE));
  assert.doesNotThrow(() => resolveCachePath({ [ENV_PI_AGENT_DIR]: 42 as unknown as string }, "/home/u", PI_PROFILE));
  const path = resolveCachePath({}, "/home/u", PI_PROFILE);
  assert.ok(path !== undefined && isAbsolute(path));
});

// --- composition: pi's reader feeding core's identity builder -----------------------------------
//
// Before the split, `buildAccountIdentity` took the raw `auth.json` map plus a provider. These are
// the same raw stores and the same expected identities, now going through `readPiAuthSummary`.

function identityFrom(
  rawAuth: unknown,
  provider: string | undefined,
  extra: { profile?: { email?: string; orgId?: string; plan?: string }; deviceSerial?: string } = {},
): ReturnType<typeof buildAccountIdentity> {
  const agent = tempAgentDir(rawAuth);
  try {
    return buildAccountIdentity({ auth: readPiAuthSummary(agent.dir, provider), ...extra });
  } finally {
    agent.cleanup();
  }
}

test("composition: anthropic OAuth + profile → the full Claude Code vocabulary", () => {
  assert.deepEqual(
    identityFrom({ anthropic: { type: "oauth" } }, "anthropic", {
      profile: { email: "Dev@Example.COM", orgId: "org-uuid-1", plan: "claude_max" },
      deviceSerial: "C02XYZ",
    }),
    {
      auth_mode: "subscription",
      user_email: "Dev@Example.COM",
      email_domain: "example.com",
      org_id: "org-uuid-1",
      plan: "claude_max",
      device_serial: "C02XYZ",
    },
  );
});

test("composition: anthropic OAuth without a profile is subscription only", () => {
  assert.deepEqual(identityFrom({ anthropic: { type: "oauth" } }, "anthropic"), { auth_mode: "subscription" });
});

test("composition: any other provider, or a non-OAuth anthropic entry, is api_key and nothing else", () => {
  const auth = { openai: { type: "api_key" }, anthropic: { type: "api_key" }, openrouter: { type: "oauth" } };
  for (const provider of ["openai", "anthropic", "openrouter"]) {
    assert.deepEqual(
      identityFrom(auth, provider, { profile: { email: "x@y.z", plan: "p" } }),
      { auth_mode: "api_key" },
      provider,
    );
  }
});

test("composition: no auth.json is no identity at all, even with a serial", () => {
  assert.equal(identityFrom(undefined, "anthropic", { deviceSerial: "C02" }), undefined);
});

test("composition: auth.json with no chosen provider is the serial only, or nothing", () => {
  const auth = { a: { type: "api_key" }, b: { type: "api_key" } };
  assert.deepEqual(identityFrom(auth, undefined, { deviceSerial: "C02" }), { device_serial: "C02" });
  assert.equal(identityFrom(auth, undefined), undefined);
});

test("composition: a provider with no entry in auth.json says nothing about the mode", () => {
  // The session's provider is known, but the store holds no credential for it (a key from the
  // environment, say). Not `api_key`: nothing in the store describes this sign-in.
  const auth = { anthropic: { type: "oauth" } };
  assert.deepEqual(identityFrom(auth, "openai", { deviceSerial: "C02" }), { device_serial: "C02" });
  assert.equal(identityFrom(auth, "openai"), undefined);
});

test("readPiAuthSummary: carries the token and expiry for the one profile request, and nothing else", () => {
  const agent = tempAgentDir({ ...oauthAnthropic(123), openai: { type: "api_key", key: "sk-openai" } });
  try {
    assert.deepEqual(readPiAuthSummary(agent.dir, "anthropic"), {
      provider: "anthropic",
      hasCredential: true,
      anthropicOAuth: true,
      accessToken: TOKEN,
      expiresAt: 123,
    });
    const other = readPiAuthSummary(agent.dir, "openai");
    assert.deepEqual(other, { provider: "openai", hasCredential: true, anthropicOAuth: false });
    assert.equal(JSON.stringify(other).includes("sk-openai"), false, "an API key is not kept");
    assert.equal(JSON.stringify(readPiAuthSummary(agent.dir, "anthropic")).includes("refresh-secret"), false);
  } finally {
    agent.cleanup();
  }
  assert.equal(readPiAuthSummary(undefined, "anthropic"), undefined, "no agent dir, no store");
});
