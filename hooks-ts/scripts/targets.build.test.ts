// The target-independent build assertions (INST-05 / Phase 09 WR-08), run against the REAL build
// output of EVERY entry in TARGETS (WR-04).
//
// These are the supply-chain checks. They used to be hard-coded to `dist/pi` in
// `packages/pi/test/build.test.ts`, so a second target would have been drift-gated but never
// supply-chain-checked, and nothing would have flagged the gap. Iterating the table is what makes
// "add a target" a one-entry change here too. Agent-specific assertions (which events the bundle
// registers, for instance) stay in that agent's own `build.test.ts`.
//
// There is no skip-if-missing guard anywhere in this file: a silently-skipped supply-chain
// assertion is worse than a red test. Run `npm run build` first.
//
// The metafile (`dist/meta/<name>.json`) is the guard rather than a grep of the output for a
// vendor package name: that substring assertion was satisfiable by fragmenting the string in
// source. Neither metafile assertion below can be satisfied that way: every input must be a
// workspace source path, and every surviving import of the entry output must be an external
// `node:` builtin. A value import of an agent's package fails both.

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";

import { TARGETS, distFileOf, metaFileOf } from "./targets.mjs";

const hooksRoot = resolve(import.meta.dirname, "..");

interface Metafile {
  inputs: Record<string, unknown>;
  outputs: Record<string, { entryPoint?: string; imports?: { path: string; external?: boolean }[] }>;
}

function readMetafile(target: (typeof TARGETS)[number]): Metafile {
  return JSON.parse(readFileSync(join(hooksRoot, metaFileOf(target)), "utf8")) as Metafile;
}

test("there is at least one target to assert on", () => {
  assert.ok(TARGETS.length > 0, "TARGETS is empty - no build assertion below would run");
});

for (const target of TARGETS) {
  const distFile = join(hooksRoot, distFileOf(target));
  // `dist/<name>/`: must hold exactly the one file the committed artifact is compared against. The
  // metafile is deliberately NOT inside it.
  const distDir = resolve(distFile, "..");

  test(`${target.name}: build emits exactly one file`, () => {
    assert.deepEqual(readdirSync(distDir), ["index.js"]);
  });

  test(`${target.name}: every bundled input is a workspace source file`, () => {
    const meta = readMetafile(target);
    const inputs = Object.keys(meta.inputs);

    assert.ok(inputs.length > 0, "metafile recorded no inputs - the build did not run");
    for (const input of inputs) {
      assert.ok(
        input.startsWith("packages/"),
        `bundled a non-workspace input: ${input} (a value import of a dependency would appear here)`,
      );
    }
  });

  test(`${target.name}: the bundle's only surviving imports are external node: builtins`, () => {
    const meta = readMetafile(target);
    const outputs = Object.values(meta.outputs);
    const entry = outputs.find((o) => o.entryPoint !== undefined) ?? outputs[0];

    assert.ok(entry !== undefined, "metafile recorded no outputs");
    const imports = entry.imports ?? [];
    for (const imp of imports) {
      assert.equal(imp.external, true, `non-external import survived: ${imp.path}`);
      assert.ok(
        imp.path.startsWith("node:"),
        `bare specifier ${imp.path} cannot resolve under the agent's extension loader`,
      );
    }
  });

  test(`${target.name}: build output imports nothing outside node: and relative paths`, () => {
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
        `bare specifier ${JSON.stringify(specifier)} cannot resolve under the agent's extension loader`,
      );
    }
  });

  test(`${target.name}: build output stays under the size ceiling`, () => {
    assert.ok(Number.isInteger(target.maxBytes) && target.maxBytes > 0, "maxBytes is a positive integer");
    const { size } = statSync(distFile);
    assert.ok(size < target.maxBytes, `${distFileOf(target)} is ${size} bytes, ceiling is ${target.maxBytes}`);
  });
}
