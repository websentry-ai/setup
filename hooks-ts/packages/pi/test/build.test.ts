// INST-05 build assertions against the REAL build output.
//
// Authored RED in Wave 0: `dist/pi/index.js` does not exist until the pi entry point lands in
// 08-03, so this file fails until then. That is deliberate - there is no skip-if-missing guard,
// because a silently-skipped supply-chain assertion is worse than a red test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = resolve(import.meta.dirname, "..", "..", "..");
const distDir = join(repoRoot, "dist", "pi");
const distFile = join(distDir, "index.js");

const MAX_BYTES = 204_800; // 200 KB: a value import of pi would blow past this by megabytes.

test("build emits exactly one file", () => {
  assert.deepEqual(readdirSync(distDir), ["index.js"]);
});

test("build output imports nothing outside node: and relative paths", () => {
  const content = readFileSync(distFile, "utf8");

  assert.equal(
    content.includes("@earendil-works"),
    false,
    "a value import of the pi package would inline the whole agent",
  );
  assert.equal(content.includes("require("), false, "output must be pure ESM");

  const specifiers: string[] = [];
  for (const match of content.matchAll(/\bfrom\s*["']([^"']+)["']/g)) {
    if (match[1] !== undefined) specifiers.push(match[1]);
  }
  for (const match of content.matchAll(/\bimport\s*["']([^"']+)["']/g)) {
    if (match[1] !== undefined) specifiers.push(match[1]);
  }

  for (const specifier of specifiers) {
    const allowed =
      specifier.startsWith("node:") || specifier.startsWith("./") || specifier.startsWith("../");
    assert.ok(
      allowed,
      `bare specifier ${JSON.stringify(specifier)} cannot resolve under pi's jiti loader`,
    );
  }
});

test("build output stays under the size ceiling", () => {
  const { size } = statSync(distFile);
  assert.ok(size < MAX_BYTES, `dist/pi/index.js is ${size} bytes, ceiling is ${MAX_BYTES}`);
});

test("build output loads and registers tool_call and session_start", async () => {
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

  assert.ok(registered.includes("tool_call"), `tool_call not registered (got ${registered.join(", ")})`);
  assert.ok(
    registered.includes("session_start"),
    `session_start not registered (got ${registered.join(", ")})`,
  );
});
