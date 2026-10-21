// A typed `!cmd` resolves its destination account in the folder it ran in — the event's cwd — rather
// than the session's. Its own file, so the extension's module-scope key state starts fresh.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { TURNLOG_PATH } from "../../core/src/constants.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import { createExtension } from "../src/index.ts";
import type { Deps } from "../src/index.ts";
import { createFakeCtx, createFakeUserBashEvent } from "./helpers/fakeCtx.ts";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;
const closedGate: Deps["heartbeatGate"] = { shouldSend: () => false, markSent: () => {} };
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

test("a !cmd's account comes from the folder it ran in, not the session's", async () => {
  process.env.GH_CONFIG_DIR = mkdtempSync(join(tmpdir(), "gh-"));
  const repo = mkdtempSync(join(tmpdir(), "repo-"));
  execFileSync("git", ["-C", repo, "init", "-q", "-b", "main"]);
  execFileSync("git", ["-C", repo, "remote", "add", "personal", "https://github.com/jdoe-dev/app.git"]);
  const homeDir = mkdtempSync(join(tmpdir(), "pi-userbash-"));
  const api = await startMockApi({ mode: "allow" });
  const handlers = new Map<string, AnyHandler>();
  try {
    await createExtension({
      env: { UNBOUND_PI_API_KEY: TEST_KEY, UNBOUND_GATEWAY_URL: api.url },
      homeDir,
      entrypoint: "pi/0.87.1",
      heartbeatGate: closedGate,
    })({ on: (event: string, handler: AnyHandler) => { handlers.set(event, handler); return () => {}; } } as unknown as ExtensionAPI);
    const ctx = createFakeCtx({ sessionId: "sess-userbash", cwd: mkdtempSync(join(tmpdir(), "elsewhere-")) });
    await (handlers.get("user_bash") as AnyHandler)(createFakeUserBashEvent("git push personal main", { cwd: repo }), ctx);
    await sleep(500);

    const body = api.requests.find((r) => r.path === TURNLOG_PATH)?.body as
      | { messages?: { tool_use?: { destination_account?: Record<string, string> }[] }[] }
      | undefined;
    const account = body?.messages?.flatMap((m) => m.tool_use ?? [])[0]?.destination_account;
    assert.equal(account?.account, "jdoe-dev");
  } finally {
    await api.close();
    rmSync(homeDir, { recursive: true, force: true });
  }
});
