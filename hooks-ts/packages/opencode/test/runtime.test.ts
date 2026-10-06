// `createRuntime` (14-02): the adapter runtime built outside the v1 server factory, so the v2 entry
// shares one implementation of key resolution, scoped state, sessions, signals and identity with v1.
//
//   * construction does no I/O (no env read, no request);
//   * without a key the runtime is inert: no checker, nothing sent;
//   * a `readAuth` override replaces the opencode `auth.json` reader (HV2-07 provider-level
//     identity: the v2 entry never reads a credential store);
//   * two runtimes share no per-session state;
//   * `recordFor` returns one record per canonical directory.

import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";

import type { AgentAuthSummary } from "../../core/src/profile.ts";
import type { MockApi } from "../../core/test/helpers/mockApi.ts";
import { createRuntime } from "../src/plugin.ts";
import { makeDeps, startOpencodeMock, tick, waitFor } from "./helpers/fakeHost.ts";

let mock: MockApi;

before(async () => {
  mock = await startOpencodeMock("allow");
});

after(async () => {
  await mock.close();
});

test("createRuntime does no I/O at construction: no env read, no request", async () => {
  mock.requests.length = 0;
  const t = makeDeps(mock);
  try {
    let reads = 0;
    const env = new Proxy(t.deps.env ?? {}, {
      get(target, key) {
        reads += 1;
        return Reflect.get(target, key);
      },
    });
    const handle = createRuntime({ ...t.deps, env });
    assert.equal(typeof handle.runtime.init, "function");
    assert.equal(typeof handle.recordFor, "function");
    assert.equal(reads, 0, "env not read at construction");
    await tick(50);
    assert.equal(mock.requests.length, 0, "nothing sent at construction");
  } finally {
    t.cleanup();
  }
});

test("a runtime with no key is inert: no checker, signals send nothing", async () => {
  mock.requests.length = 0;
  const t = makeDeps(mock, { withKey: false });
  try {
    const { runtime } = createRuntime(t.deps);
    const resolved = runtime.init();
    assert.equal(resolved.status, "no_key");
    assert.equal(resolved.checker, undefined);
    assert.equal(runtime.recordingActive(), false);
    runtime.reportSignal("v2_status", "setup", "probe");
    runtime.reportOnce("v2_status", "setup", "probe");
    await tick(100);
    assert.equal(mock.requests.length, 0);
  } finally {
    t.cleanup();
  }
});

test("a readAuth override replaces the auth.json reader (identity without a credential-store read)", async () => {
  mock.requests.length = 0;
  const calls: Array<{ dir: string | undefined; provider: string | undefined }> = [];
  const t = makeDeps(mock, {
    readAuth: (dir: string | undefined, provider: string | undefined): AgentAuthSummary | undefined => {
      calls.push({ dir, provider });
      return undefined;
    },
  });
  try {
    // An auth.json the default reader WOULD read (api key → auth_mode "api_key").
    const dataDir = join(t.homeDir, ".local", "share", "opencode");
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, "auth.json"), JSON.stringify({ openrouter: { type: "api", key: "SECRET-K" } }));
    const { runtime } = createRuntime(t.deps);
    runtime.startIdentity("openrouter");
    assert.ok(await waitFor(() => calls.length > 0), "override called");
    assert.equal(calls[0]?.provider, "openrouter");
    await waitFor(() => runtime.identity() !== undefined, 500);
    assert.notEqual(runtime.identity()?.auth_mode, "api_key", "auth.json not consulted");
  } finally {
    t.cleanup();
  }
});

test("two runtimes share no per-session state", () => {
  const a = makeDeps(mock);
  const b = makeDeps(mock);
  try {
    const r1 = createRuntime(a.deps).runtime;
    const r2 = createRuntime(b.deps).runtime;
    r1.setModel("s1", "openrouter/x");
    r1.setParent("child", "s1");
    r1.markBeforeSeen("s1", "c1");
    assert.equal(r1.modelFor("s1"), "openrouter/x");
    assert.equal(r2.modelFor("s1"), undefined);
    assert.equal(r2.isChild("child"), false);
    assert.equal(r2.beforeSeen("s1", "c1"), false);
    assert.notEqual(r1.sessions, r2.sessions);
    assert.notEqual(r1.instances, r2.instances);
  } finally {
    a.cleanup();
    b.cleanup();
  }
});

test("recordFor returns one record per canonical directory, with the client and MCP names given", () => {
  const t = makeDeps(mock);
  try {
    const handle = createRuntime(t.deps);
    const client = { tag: "c" };
    const r1 = handle.recordFor("/repo", client, ["github", "linear"]);
    assert.equal(r1.directory, "/repo");
    assert.equal(r1.client, client);
    assert.deepEqual(r1.mcpServerNames, ["github", "linear"]);
    const r2 = handle.recordFor("/repo/", undefined, []);
    assert.equal(r2, r1, "same canonical directory, same record");
    // Names omitted: the previous snapshot is kept (v1 `server()` never resets them).
    const r3 = handle.recordFor("/repo", client);
    assert.deepEqual(r3.mcpServerNames, []);
    assert.notEqual(handle.recordFor("/other", client, []), r1);
  } finally {
    t.cleanup();
  }
});
