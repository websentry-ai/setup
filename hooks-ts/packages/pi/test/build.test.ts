// INST-05 build assertions against the REAL pi build output: the parts that are specific to pi.
//
// There is no skip-if-missing guard anywhere in this file: a silently-skipped supply-chain
// assertion is worse than a red test. Run `npm run build` first.
//
// The target-independent supply-chain checks (WR-08: every bundled input is a workspace source,
// only external `node:` imports survive, `dist/<name>/` holds exactly one file, pure ESM, the size
// ceiling) live in `scripts/targets.build.test.ts` and run for EVERY entry in TARGETS, pi included,
// with pi's ceiling (204 800 bytes) carried on its TARGETS entry. `npm run test:build` runs both
// files (WR-04).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { TARGETS, distFileOf } from "../../../scripts/targets.mjs";

const repoRoot = resolve(import.meta.dirname, "..", "..", "..");
const PI_TARGET = TARGETS.find((target) => target.name === "pi");
const distFile = join(repoRoot, "dist", "pi", "index.js");

test("the pi bundle is a TARGETS entry, so the per-target supply-chain assertions cover it", () => {
  assert.ok(PI_TARGET !== undefined, "pi is missing from TARGETS - scripts/targets.build.test.ts would not check it");
  assert.equal(PI_TARGET.entry, "packages/pi/src/index.ts");
  assert.equal(join(repoRoot, distFileOf(PI_TARGET)), distFile);
  assert.equal(PI_TARGET.maxBytes, 204_800, "pi's size ceiling is unchanged");
});

/**
 * The full event surface, asserted from the REAL build output rather than from the sources.
 *
 * A handler that exists in `packages/pi/src` but does not survive into the bundle is enforcement (or,
 * for the three audit events, an audit trail) that silently does not run in production — and the
 * sources cannot tell us that. This is also the assertion that makes adding a seventh event a
 * deliberate act: a new registration fails here until it is named.
 */
const EXPECTED_EVENTS = [
  "agent_end",
  "input",
  "session_start",
  "tool_call",
  "tool_result",
  "user_bash",
] as const;

test("build output loads and registers all six events", async () => {
  const mod = await import(pathToFileURL(distFile).href);

  assert.equal(typeof mod.default, "function", "extension must default-export a factory");

  const registered: string[] = [];
  const stubApi = {
    on(event: string) {
      registered.push(event);
      return () => {};
    },
  };

  await mod.default(stubApi);

  assert.deepEqual(
    [...registered].sort(),
    [...EXPECTED_EVENTS],
    `the built bundle registers ${registered.join(", ")}`,
  );
  assert.equal(registered.length, EXPECTED_EVENTS.length, "and registers each of them exactly once");
});

test("build output: exactly one pi.events listener, on the adapter's approval channel — and none without a bus", async () => {
  // Revision 2: MCP enforcement rides the pi-mcp-adapter approval broker. The bundle subscribes to
  // exactly one `pi.events` channel, by string literal (no adapter import), and still registers the
  // same six `pi.on` events. A pi (or stub) without `events` loads fine and simply has no listener.
  const mod = await import(pathToFileURL(distFile).href);
  const registered: string[] = [];
  const channels: string[] = [];
  await mod.default({
    on(event: string) {
      registered.push(event);
      return () => {};
    },
    events: {
      on(channel: string) {
        channels.push(channel);
        return () => {};
      },
      emit() {},
    },
  });
  assert.deepEqual([...registered].sort(), [...EXPECTED_EVENTS]);
  assert.deepEqual(channels, ["pi-mcp-adapter:tool-approval-request"]);

  const content = readFileSync(distFile, "utf8");
  assert.equal(content.includes('from "pi-mcp-adapter"'), false, "the adapter is never imported");
});
