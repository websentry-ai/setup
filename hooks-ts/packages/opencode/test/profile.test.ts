// OPENCODE_PROFILE, its directories, its file-tool taxonomy and its auth reader (13-03).
//
// What these cases pin down:
//
//   * **The scalar fields, literally.** They are the wire: app label, errors `hook_source`, turn-log
//     route, key env var, heartbeat version key, the extra tool-input key. Each is a string here.
//   * **The directories.** The policy cache lives under the opencode CONFIG dir, `auth.json` under
//     the DATA dir; only absolute bases are accepted, never one resolved against the process cwd.
//   * **The file tools** equal the API's `OPENCODE_NATIVE_FILE_TOOLS`, and each resolves the key the
//     tool actually reads (a `filePath` decoy on grep/glob cannot redirect the check).
//   * **No credential value leaves the auth reader** (HOOK-17).
//   * **Every function is total.**

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildAccountIdentity } from "../../core/src/accountIdentity.ts";
import { nativeFileTools, resolveFilePath } from "../../core/src/payload.ts";
import { readOpencodeAuthSummary } from "../src/auth.ts";
import {
  OPENCODE_FILE_TOOLS,
  OPENCODE_PROFILE,
  resolveOpencodeConfigDir,
  resolveOpencodeDataDir,
} from "../src/profile.ts";

/** An object on which every property read, `in` check and key listing throws. */
function hostile<T extends object>(): T {
  const boom = (): never => {
    throw new Error("hostile getter");
  };
  return new Proxy({}, { get: boom, has: boom, ownKeys: boom, getOwnPropertyDescriptor: boom }) as T;
}

const wrong = <T>(value: unknown): T => value as T;

// --- the pinned literals ------------------------------------------------------------------------

test("OPENCODE_PROFILE carries the pinned wire literals", () => {
  assert.equal(OPENCODE_PROFILE.appLabel, "opencode");
  assert.equal(OPENCODE_PROFILE.hookSource, "opencode-hook");
  assert.equal(OPENCODE_PROFILE.turnLogPath, "/v1/hooks/opencode");
  assert.equal(OPENCODE_PROFILE.envApiKey, "UNBOUND_OPENCODE_API_KEY");
  assert.equal(OPENCODE_PROFILE.versionMetadataKey, "opencode_version");
  assert.deepEqual(OPENCODE_PROFILE.extraToolInputKeys, ["include"]);
  assert.equal(OPENCODE_PROFILE.resolveClientEntrypoint({}, undefined), "opencode/unknown");
  assert.equal(OPENCODE_PROFILE.resolveClientEntrypoint(wrong(null), wrong(5)), "opencode/unknown");
  assert.equal(OPENCODE_PROFILE.resolveAgentDir, resolveOpencodeConfigDir);
  assert.equal(OPENCODE_PROFILE.fileTools, OPENCODE_FILE_TOOLS);
  assert.equal(typeof OPENCODE_PROFILE.readAuth, "function");
});

test("the profile, the file-tool object and the extra-key list are frozen", () => {
  assert.ok(Object.isFrozen(OPENCODE_PROFILE));
  assert.ok(Object.isFrozen(OPENCODE_FILE_TOOLS));
  assert.ok(Object.isFrozen(OPENCODE_PROFILE.extraToolInputKeys));
});

// --- directories --------------------------------------------------------------------------------

test("resolveOpencodeConfigDir: OPENCODE_CONFIG_DIR, then XDG_CONFIG_HOME, then ~/.config", () => {
  assert.equal(resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "/x" }, "/h"), "/x");
  assert.equal(resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "~/oc" }, "/h"), "/h/oc");
  assert.equal(resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "oc" }, "/h"), "/h/.config/opencode");
  assert.equal(
    resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "oc", XDG_CONFIG_HOME: "/c" }, "/h"),
    "/c/opencode",
  );
  assert.equal(resolveOpencodeConfigDir({ XDG_CONFIG_HOME: "/c" }, "/h"), "/c/opencode");
  assert.equal(resolveOpencodeConfigDir({ XDG_CONFIG_HOME: "rel" }, "/h"), "/h/.config/opencode");
  assert.equal(resolveOpencodeConfigDir({}, "/h"), "/h/.config/opencode");
  assert.equal(resolveOpencodeConfigDir({}, ""), undefined);
  assert.equal(resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "oc", XDG_CONFIG_HOME: "rel" }, ""), undefined);
  assert.equal(resolveOpencodeConfigDir({ OPENCODE_CONFIG_DIR: "~/oc" }, ""), undefined);
  assert.equal(resolveOpencodeConfigDir(wrong(null), wrong(null)), undefined);
  assert.equal(resolveOpencodeConfigDir(hostile(), "/h"), "/h/.config/opencode");
});

test("resolveOpencodeDataDir: XDG_DATA_HOME, then ~/.local/share", () => {
  assert.equal(resolveOpencodeDataDir({ XDG_DATA_HOME: "/d" }, "/h"), "/d/opencode");
  assert.equal(resolveOpencodeDataDir({ XDG_DATA_HOME: "rel" }, "/h"), "/h/.local/share/opencode");
  assert.equal(resolveOpencodeDataDir({}, "/h"), "/h/.local/share/opencode");
  assert.equal(resolveOpencodeDataDir({}, ""), undefined);
  assert.equal(resolveOpencodeDataDir({}, "rel"), undefined);
  assert.equal(resolveOpencodeDataDir(hostile(), wrong(undefined)), undefined);
});

// --- file tools ---------------------------------------------------------------------------------

test("the seven file tools equal the API's OPENCODE_NATIVE_FILE_TOOLS", () => {
  // ai-gateway src/services/classifier/deterministic/native/taxonomy.ts OPENCODE_NATIVE_FILE_TOOLS
  const API = ["read", "write", "edit", "grep", "glob", "apply_patch", "lsp"];
  assert.deepEqual([...nativeFileTools(OPENCODE_FILE_TOOLS)].sort(), [...API].sort());
  assert.deepEqual([...OPENCODE_FILE_TOOLS.defaulting].sort(), ["glob", "grep"]);
  assert.deepEqual([...OPENCODE_FILE_TOOLS.required].sort(), ["apply_patch", "edit", "lsp", "read", "write"]);
});

test("pathOf resolves the key each tool actually reads", () => {
  const { pathOf } = OPENCODE_FILE_TOOLS;
  assert.equal(pathOf("read", { filePath: "/a", path: "/b" }), "/a");
  assert.equal(pathOf("read", { path: "/b" }), "/b");
  assert.equal(pathOf("write", { filePath: "/w" }), "/w");
  assert.equal(pathOf("edit", { path: "/e" }), "/e");
  assert.equal(pathOf("lsp", { filePath: "/l" }), "/l");
  assert.equal(pathOf("grep", { filePath: "/decoy", path: "/real" }), "/real");
  assert.equal(pathOf("grep", { filePath: "/decoy" }), undefined);
  assert.equal(pathOf("glob", { filePath: "/decoy" }), undefined);
  assert.equal(pathOf("apply_patch", { filePath: "/t" }), "/t");
  assert.equal(pathOf("read", { filePath: 5 }), undefined);
  assert.equal(pathOf("read", { filePath: "" , path: "/b" }), "/b");
  assert.equal(pathOf("read", hostile()), undefined);
  assert.equal(pathOf("read", wrong(null)), undefined);
  assert.equal(pathOf("bash", { filePath: "/x" }), undefined);
});

test("resolveFilePath with OPENCODE_FILE_TOOLS: grep defaults to cwd, a decoy cannot redirect it", () => {
  assert.equal(resolveFilePath("grep", {}, "/repo", OPENCODE_FILE_TOOLS), "/repo");
  assert.equal(resolveFilePath("grep", { filePath: "/decoy" }, "/repo", OPENCODE_FILE_TOOLS), "/repo");
  assert.equal(resolveFilePath("glob", { path: "/g" }, "/repo", OPENCODE_FILE_TOOLS), "/g");
  assert.equal(resolveFilePath("read", {}, "/repo", OPENCODE_FILE_TOOLS), undefined);
  assert.equal(resolveFilePath("bash", { command: "ls" }, "/repo", OPENCODE_FILE_TOOLS), undefined);
});

// --- auth ---------------------------------------------------------------------------------------

const SECRETS = ["SECRET-K", "SECRET-R", "SECRET-A"];
const FIXTURE = {
  openrouter: { type: "api", key: "SECRET-K" },
  openai: { type: "oauth", refresh: "SECRET-R", access: "SECRET-A", expires: 9e12 },
};

function withDataDir(contents: string | undefined, fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "oc-data-"));
  try {
    mkdirSync(dir, { recursive: true });
    if (contents !== undefined) writeFileSync(join(dir, "auth.json"), contents, { mode: 0o600 });
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function assertNoSecret(result: unknown): void {
  const text = JSON.stringify(result) ?? "";
  for (const secret of SECRETS) assert.equal(text.includes(secret), false, `leaked ${secret}`);
}

test("readOpencodeAuthSummary: provider + auth mode only, never a credential value", () => {
  withDataDir(JSON.stringify(FIXTURE), (dir) => {
    const api = readOpencodeAuthSummary(dir, "openrouter", {});
    assert.deepEqual(api, { provider: "openrouter", hasCredential: true, anthropicOAuth: false });
    const oauth = readOpencodeAuthSummary(dir, "openai", {});
    assert.deepEqual(oauth, { provider: "openai", hasCredential: true, anthropicOAuth: true });
    assert.equal(oauth !== undefined && "accessToken" in oauth, false);
    assert.equal(oauth !== undefined && "expiresAt" in oauth, false);
    assert.deepEqual(readOpencodeAuthSummary(dir, "anthropic", {}), {
      provider: "anthropic",
      hasCredential: false,
      anthropicOAuth: false,
    });
    for (const provider of ["constructor", "__proto__", "toString"]) {
      assert.equal(readOpencodeAuthSummary(dir, provider, {})?.hasCredential, false, provider);
    }
    // Two entries and no provider: ambiguous, so no credential.
    assert.equal(readOpencodeAuthSummary(dir, undefined, {})?.hasCredential, false);
    for (const provider of ["openrouter", "openai", "anthropic", undefined, "constructor"]) {
      assertNoSecret(readOpencodeAuthSummary(dir, provider, {}));
    }
    assert.deepEqual(buildAccountIdentity({ auth: api }), { auth_mode: "api_key" });
    assert.deepEqual(buildAccountIdentity({ auth: oauth }), { auth_mode: "subscription" });
  });
});

test("readOpencodeAuthSummary: a single entry is chosen when no provider is named", () => {
  withDataDir(JSON.stringify({ openrouter: FIXTURE.openrouter }), (dir) => {
    assert.deepEqual(readOpencodeAuthSummary(dir, undefined, {}), {
      provider: "openrouter",
      hasCredential: true,
      anthropicOAuth: false,
    });
  });
});

test("readOpencodeAuthSummary: missing, malformed or non-object store is undefined", () => {
  withDataDir(undefined, (dir) => assert.equal(readOpencodeAuthSummary(dir, "openrouter", {}), undefined));
  withDataDir("{not json", (dir) => assert.equal(readOpencodeAuthSummary(dir, "openrouter", {}), undefined));
  withDataDir("[1,2]", (dir) => assert.equal(readOpencodeAuthSummary(dir, "openrouter", {}), undefined));
  withDataDir("\"str\"", (dir) => assert.equal(readOpencodeAuthSummary(dir, "openrouter", {}), undefined));
  assert.equal(readOpencodeAuthSummary(undefined, "openrouter", {}), undefined);
  assert.equal(readOpencodeAuthSummary("", "openrouter", {}), undefined);
  assert.equal(readOpencodeAuthSummary(wrong(5), wrong(5), wrong(null)), undefined);
  assert.equal(readOpencodeAuthSummary("/nonexistent/dir", "openrouter", hostile()), undefined);
});

test("readOpencodeAuthSummary: OPENCODE_AUTH_CONTENT overrides the file", () => {
  withDataDir(JSON.stringify(FIXTURE), (dir) => {
    const env = { OPENCODE_AUTH_CONTENT: JSON.stringify({ anthropic: { type: "api", key: "SECRET-K" } }) };
    assert.deepEqual(readOpencodeAuthSummary(dir, "anthropic", env), {
      provider: "anthropic",
      hasCredential: true,
      anthropicOAuth: false,
    });
    assert.equal(readOpencodeAuthSummary(dir, "openrouter", env)?.hasCredential, false);
    assertNoSecret(readOpencodeAuthSummary(dir, "anthropic", env));
    // With no data dir at all, the env content still answers.
    assert.equal(readOpencodeAuthSummary(undefined, "anthropic", env)?.hasCredential, true);
  });
});

test("OPENCODE_PROFILE.readAuth reads the data dir it is handed, secret-free", () => {
  withDataDir(JSON.stringify(FIXTURE), (dir) => {
    const summary = OPENCODE_PROFILE.readAuth?.(dir, "openai");
    assert.deepEqual(summary, { provider: "openai", hasCredential: true, anthropicOAuth: true });
    assertNoSecret(summary);
  });
});
