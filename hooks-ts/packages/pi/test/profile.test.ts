// PI_PROFILE — the values core is given instead of holding pi's literals itself.
//
// What these cases pin down:
//
//   * **The scalar fields, literally.** They are the wire: the app label, the errors `hook_source`,
//     the turn-log route, the key env var, the heartbeat's version key. A typo here re-routes or
//     re-labels every pi request, so each is asserted as a string, not against another constant.
//   * **The file-tool sets.** A name missing from them is a file tool evaluated on nothing.
//   * **TEST_PROFILE matches.** Core's tests inject their own profile (core may not import this
//     package); its five scalar fields must equal pi's, or core's assertions stop describing pi.
//   * **Every function is total.** A throw out of a pi handler is a BLOCK, so a profile function must
//     answer for any input — `null`, a Proxy whose getters throw, a non-string environment value.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { TEST_PROFILE } from "../../core/test/helpers/testProfile.ts";
import { nativeFileTools, resolveFilePath } from "../../core/src/payload.ts";
import type { AgentFileTools, AgentProfile } from "../../core/src/profile.ts";
import { PI_FILE_TOOLS, PI_NATIVE_FILE_TOOLS, PI_PROFILE } from "../src/profile.ts";

const SCALAR_FIELDS = ["appLabel", "hookSource", "turnLogPath", "envApiKey", "versionMetadataKey"] as const;

function scalars(profile: AgentProfile): Record<string, unknown> {
  return Object.fromEntries(SCALAR_FIELDS.map((field) => [field, profile[field]]));
}

/** An object on which every property read, `in` check and key listing throws. */
function hostile<T extends object>(): T {
  const boom = (): never => {
    throw new Error("hostile getter");
  };
  return new Proxy({}, { get: boom, has: boom, ownKeys: boom, getOwnPropertyDescriptor: boom }) as T;
}

/** Deliberately wrong-typed arguments, as an untyped host could pass them. */
const wrong = <T>(value: unknown): T => value as T;

function withAgentDir(authJson: string | undefined, run: (agentDir: string) => void): void {
  const agentDir = mkdtempSync(join(tmpdir(), "pi-profile-"));
  try {
    mkdirSync(agentDir, { recursive: true });
    if (authJson !== undefined) writeFileSync(join(agentDir, "auth.json"), authJson, { mode: 0o600 });
    run(agentDir);
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
}

test("PI_PROFILE: every scalar field is pi's wire value, literally", () => {
  assert.equal(PI_PROFILE.appLabel, "pi");
  assert.equal(PI_PROFILE.hookSource, "pi");
  assert.equal(PI_PROFILE.turnLogPath, "/v1/hooks/pi");
  assert.equal(PI_PROFILE.envApiKey, "UNBOUND_PI_API_KEY");
  assert.equal(PI_PROFILE.versionMetadataKey, "pi_version");
});

test("PI_PROFILE: frozen, so no caller can re-label a running session", () => {
  assert.equal(Object.isFrozen(PI_PROFILE), true);
  assert.equal(Object.isFrozen(PI_PROFILE.fileTools), true);
  assert.throws(() => {
    (PI_PROFILE as { appLabel: string }).appLabel = "other";
  }, TypeError);
  assert.equal(PI_PROFILE.appLabel, "pi");
});

test("PI_PROFILE.fileTools: defaulting = grep/find/ls, required = read/write/edit", () => {
  assert.deepEqual([...PI_PROFILE.fileTools.defaulting].sort(), ["find", "grep", "ls"]);
  assert.deepEqual([...PI_PROFILE.fileTools.required].sort(), ["edit", "read", "write"]);
  assert.equal(PI_PROFILE.fileTools.defaulting.has("bash"), false);
  assert.equal(PI_PROFILE.fileTools.required.has("bash"), false);
});

test("PI_PROFILE.fileTools.pathOf: returns input.path raw, whatever the tool", () => {
  assert.equal(PI_PROFILE.fileTools.pathOf("read", { path: "/etc/hosts" }), "/etc/hosts");
  assert.equal(PI_PROFILE.fileTools.pathOf("grep", { pattern: "x" }), undefined);
  // Raw means raw: validating the value is the caller's job.
  assert.equal(PI_PROFILE.fileTools.pathOf("read", { path: 42 }), 42);
});

test("TEST_PROFILE's scalar fields equal PI_PROFILE's", () => {
  assert.deepEqual(scalars(TEST_PROFILE), scalars(PI_PROFILE));
  assert.deepEqual([...TEST_PROFILE.fileTools.defaulting].sort(), [...PI_PROFILE.fileTools.defaulting].sort());
  assert.deepEqual([...TEST_PROFILE.fileTools.required].sort(), [...PI_PROFILE.fileTools.required].sort());
});

test("PI_PROFILE.resolveClientEntrypoint: pi/<version>, and pi/unknown when it cannot be read", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-profile-install-"));
  try {
    writeFileSync(join(root, "current-version"), "0.87.1\n");
    assert.equal(PI_PROFILE.resolveClientEntrypoint({ PI_MANAGED_INSTALL_ROOT: root }), "pi/0.87.1");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  assert.equal(PI_PROFILE.resolveClientEntrypoint({}), "pi/unknown");
});

test("PI_PROFILE.resolveAgentDir: PI_CODING_AGENT_DIR, else ~/.pi/agent, else undefined", () => {
  assert.equal(PI_PROFILE.resolveAgentDir({}, "/home/dev"), join("/home/dev", ".pi", "agent"));
  assert.equal(PI_PROFILE.resolveAgentDir({ PI_CODING_AGENT_DIR: "/opt/pi" }, "/home/dev"), "/opt/pi");
  // A relative home has no safe base: the cache and auth.json are simply not used.
  assert.equal(PI_PROFILE.resolveAgentDir({}, ""), undefined);
  assert.equal(PI_PROFILE.resolveAgentDir({}, "relative/home"), undefined);
});

test("PI_PROFILE.readAuth: summarises the session's provider entry", () => {
  const auth = JSON.stringify({
    anthropic: { type: "oauth", access: "tok-anthropic", refresh: "never-read", expires: 4_102_444_800_000 },
    openrouter: { type: "api_key", key: "never-read" },
  });
  withAgentDir(auth, (agentDir) => {
    assert.ok(PI_PROFILE.readAuth !== undefined);
    assert.deepEqual(PI_PROFILE.readAuth(agentDir, "anthropic"), {
      provider: "anthropic",
      hasCredential: true,
      anthropicOAuth: true,
      accessToken: "tok-anthropic",
      expiresAt: 4_102_444_800_000,
    });
    assert.deepEqual(PI_PROFILE.readAuth(agentDir, "openrouter"), {
      provider: "openrouter",
      hasCredential: true,
      anthropicOAuth: false,
    });
    // Two providers and no model provider: ambiguous, so no provider is guessed.
    assert.deepEqual(PI_PROFILE.readAuth(agentDir, undefined), {
      provider: undefined,
      hasCredential: false,
      anthropicOAuth: false,
    });
    // A provider the store has no entry for — including a name every object inherits.
    assert.deepEqual(PI_PROFILE.readAuth(agentDir, "constructor"), {
      provider: "constructor",
      hasCredential: false,
      anthropicOAuth: false,
    });
  });
});

test("PI_PROFILE.readAuth: a single provider is chosen without a model provider", () => {
  withAgentDir(JSON.stringify({ anthropic: { type: "api_key" } }), (agentDir) => {
    assert.deepEqual(PI_PROFILE.readAuth?.(agentDir, undefined), {
      provider: "anthropic",
      hasCredential: true,
      anthropicOAuth: false,
    });
  });
});

test("PI_PROFILE.readAuth: no store, or an unreadable one, is undefined", () => {
  assert.equal(PI_PROFILE.readAuth?.(undefined, "anthropic"), undefined);
  assert.equal(PI_PROFILE.readAuth?.("", "anthropic"), undefined);
  assert.equal(PI_PROFILE.readAuth?.("/nope/does/not/exist", "anthropic"), undefined);
  withAgentDir(undefined, (agentDir) => {
    assert.equal(PI_PROFILE.readAuth?.(agentDir, "anthropic"), undefined);
  });
  withAgentDir("not json", (agentDir) => {
    assert.equal(PI_PROFILE.readAuth?.(agentDir, "anthropic"), undefined);
  });
  withAgentDir("[]", (agentDir) => {
    assert.equal(PI_PROFILE.readAuth?.(agentDir, "anthropic"), undefined);
  });
});

test("PI_PROFILE.readAuth agrees with TEST_PROFILE.readAuth on the same store", () => {
  const auth = JSON.stringify({
    anthropic: { type: "oauth", access: "tok", expires: 4_102_444_800_000 },
    openrouter: { type: "api_key" },
    broken: "not an entry",
  });
  withAgentDir(auth, (agentDir) => {
    for (const provider of ["anthropic", "openrouter", "broken", "absent", undefined]) {
      assert.deepEqual(
        TEST_PROFILE.readAuth?.(agentDir, provider),
        PI_PROFILE.readAuth?.(agentDir, provider),
        String(provider),
      );
    }
  });
  assert.equal(
    TEST_PROFILE.resolveAgentDir({ PI_CODING_AGENT_DIR: "~/x" }, "/home/dev"),
    PI_PROFILE.resolveAgentDir({ PI_CODING_AGENT_DIR: "~/x" }, "/home/dev"),
  );
});

test("PI_PROFILE functions return rather than throw on hostile input", () => {
  const env = hostile<NodeJS.ProcessEnv>();
  const input = hostile<Record<string, unknown>>();

  // null / undefined where an object is expected
  assert.doesNotThrow(() => PI_PROFILE.fileTools.pathOf("read", wrong(null)));
  assert.equal(PI_PROFILE.fileTools.pathOf("read", wrong(null)), undefined);
  assert.equal(PI_PROFILE.fileTools.pathOf("read", wrong(undefined)), undefined);
  assert.equal(PI_PROFILE.resolveClientEntrypoint(wrong(null)), "pi/unknown");
  assert.equal(PI_PROFILE.resolveClientEntrypoint(wrong(undefined), wrong(null)), "pi/unknown");
  assert.equal(PI_PROFILE.resolveAgentDir(wrong(null), wrong(null)), undefined);
  assert.equal(PI_PROFILE.resolveAgentDir(wrong(undefined), "/home/dev"), join("/home/dev", ".pi", "agent"));
  assert.equal(PI_PROFILE.readAuth?.(wrong(null), wrong(null)), undefined);

  // a Proxy whose every trap throws
  assert.equal(PI_PROFILE.fileTools.pathOf("read", input), undefined);
  assert.equal(PI_PROFILE.fileTools.pathOf(wrong(input), input), undefined);
  assert.equal(PI_PROFILE.resolveClientEntrypoint(env, "/nope/cli.js"), "pi/unknown");
  assert.equal(PI_PROFILE.resolveClientEntrypoint(env, wrong(input)), "pi/unknown");
  assert.equal(PI_PROFILE.resolveAgentDir(env, "/home/dev"), undefined);
  assert.equal(PI_PROFILE.resolveAgentDir(env, wrong(input)), undefined);
  assert.equal(PI_PROFILE.readAuth?.(wrong(input), wrong(input)), undefined);

  // non-string environment values
  const numeric = wrong<NodeJS.ProcessEnv>({ PI_MANAGED_INSTALL_ROOT: 42, PI_CODING_AGENT_DIR: { nested: true } });
  assert.equal(PI_PROFILE.resolveClientEntrypoint(numeric), "pi/unknown");
  assert.equal(PI_PROFILE.resolveAgentDir(numeric, "/home/dev"), join("/home/dev", ".pi", "agent"));
  withAgentDir(JSON.stringify({ anthropic: { type: "oauth" } }), (agentDir) => {
    assert.doesNotThrow(() => PI_PROFILE.readAuth?.(agentDir, wrong(42)));
    assert.doesNotThrow(() => PI_PROFILE.readAuth?.(agentDir, wrong(input)));
  });
});

// --- the file-tool taxonomy, now owned by this package ------------------------------------------

test("PI_NATIVE_FILE_TOOLS: exactly the six names the API's PI_NATIVE_FILE_TOOLS lists", () => {
  // Spelled out, not derived: this list and the API's `taxonomy.ts` are a drift pair, and a name
  // added on one side only is either a file tool sent with no path or a round trip that checks nothing.
  assert.deepEqual([...PI_NATIVE_FILE_TOOLS].sort(), ["edit", "find", "grep", "ls", "read", "write"]);
  assert.equal(PI_PROFILE.fileTools, PI_FILE_TOOLS, "the profile carries the exported taxonomy");
  assert.equal(nativeFileTools(PI_PROFILE.fileTools), PI_NATIVE_FILE_TOOLS, "one set object, memoised per taxonomy");
  assert.equal(PI_NATIVE_FILE_TOOLS.has("bash"), false, "a shell tool is evaluated on its command");
});

test("resolveFilePath: a pathOf that throws reads as no path given", () => {
  const throwing: AgentFileTools = {
    defaulting: PI_FILE_TOOLS.defaulting,
    required: PI_FILE_TOOLS.required,
    pathOf(): unknown {
      throw new Error("hostile argument reader");
    },
  };
  assert.equal(resolveFilePath("grep", { path: "/a" }, "/cwd", throwing), "/cwd", "a defaulting tool still gets cwd");
  assert.equal(resolveFilePath("read", { path: "/a" }, "/cwd", throwing), undefined, "a required tool gets nothing");
  assert.equal(resolveFilePath("bash", { path: "/a" }, "/cwd", throwing), undefined);
});

test("nativeFileTools / resolveFilePath: a taxonomy that cannot be read declares no file tools", () => {
  assert.equal(nativeFileTools(wrong<AgentFileTools>(null)).size, 0);
  assert.equal(nativeFileTools(wrong<AgentFileTools>({})).size, 0);
  assert.equal(nativeFileTools(hostile<AgentFileTools>()).size, 0);
  assert.equal(resolveFilePath("read", { path: "/a" }, "/cwd", hostile<AgentFileTools>()), undefined);
  assert.equal(resolveFilePath("read", { path: "/a" }, "/cwd", wrong<AgentFileTools>(null)), undefined);
});
