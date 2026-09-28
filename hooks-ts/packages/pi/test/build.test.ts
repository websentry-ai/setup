// INST-05 build assertions against the REAL build output.
//
// There is no skip-if-missing guard anywhere in this file: a silently-skipped supply-chain
// assertion is worse than a red test. Run `npm run build` first.
//
// WR-08: the supply-chain guard reads esbuild's own metafile (`dist/meta/pi.json`) rather than
// grepping the output for the vendor package name. The old substring assertion was satisfiable by
// fragmenting the string in source - which is exactly what `piVersion.ts` had to do to hold a
// package name it only ever uses as data. Neither metafile assertion below can be satisfied that
// way: every input must be a workspace source path, and every surviving import of the entry output
// must be an external `node:` builtin. A value import of the pi package fails both.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = resolve(import.meta.dirname, "..", "..", "..");
const distDir = join(repoRoot, "dist", "pi");
const distFile = join(distDir, "index.js");
// Deliberately NOT inside dist/pi - `build emits exactly one file` asserts that directory holds
// only index.js.
const metaFile = join(repoRoot, "dist", "meta", "pi.json");

const MAX_BYTES = 204_800; // 200 KB: a value import of pi would blow past this by megabytes.

interface Metafile {
  inputs: Record<string, unknown>;
  outputs: Record<string, { entryPoint?: string; imports?: { path: string; external?: boolean }[] }>;
}

function readMetafile(): Metafile {
  return JSON.parse(readFileSync(metaFile, "utf8")) as Metafile;
}

test("build emits exactly one file", () => {
  assert.deepEqual(readdirSync(distDir), ["index.js"]);
});

test("every bundled input is a workspace source file", () => {
  const meta = readMetafile();
  const inputs = Object.keys(meta.inputs);

  assert.ok(inputs.length > 0, "metafile recorded no inputs - the build did not run");
  for (const input of inputs) {
    assert.ok(
      input.startsWith("packages/"),
      `bundled a non-workspace input: ${input} (a value import of a dependency would appear here)`,
    );
  }
});

test("the bundle's only surviving imports are external node: builtins", () => {
  const meta = readMetafile();
  const outputs = Object.values(meta.outputs);
  const entry = outputs.find((o) => o.entryPoint !== undefined) ?? outputs[0];

  assert.ok(entry !== undefined, "metafile recorded no outputs");
  const imports = entry.imports ?? [];
  for (const imp of imports) {
    assert.equal(imp.external, true, `non-external import survived: ${imp.path}`);
    assert.ok(
      imp.path.startsWith("node:"),
      `bare specifier ${imp.path} cannot resolve under pi's jiti loader`,
    );
  }
});

test("build output imports nothing outside node: and relative paths", () => {
  const content = readFileSync(distFile, "utf8");

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
