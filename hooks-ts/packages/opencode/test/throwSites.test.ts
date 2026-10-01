// The single-raise-site gate (HOOK-09, Pitfall 1).
//
// On opencode v1 an error escaping `tool.execute.before` is a deny the model sees, and an error
// escaping any other hook is at best noise on the user's terminal. So `packages/opencode/src` may
// raise in exactly one place, `block.ts`, and `block(` may only be called from the decision files
// that are allowed to block: `before.ts` (model tools), `prompt.ts` (user prompts) and `userShell.ts`
// (user `!cmd`). Also banned outright: `Promise.reject(`, `process.exit`, any `Bun.` API and any use
// of the plugin input's `$` shell.
//
// Comments are stripped first (prose may describe the mechanism); the stripper is tested below so a
// stripper that removed too much cannot make every file look clean.

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import test from "node:test";

const SRC = resolve(import.meta.dirname, "..", "src");

const RAISE_FILE = "block.ts";
const ALLOWED_BLOCK_CALLERS: ReadonlySet<string> = new Set(["before.ts", "prompt.ts", "userShell.ts"]);

/**
 * Remove block comments (JSDoc included) and line comments. A `//` directly after a `:` is kept, so
 * a URL such as `https://host` inside a string survives. Same approach as core/test/agnostic.test.ts.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(?<!:)\/\/[^\n]*/g, "");
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (entry.name.endsWith(".ts")) out.push(path);
  }
  return out.sort();
}

function code(path: string): string {
  return stripComments(readFileSync(path, "utf8"));
}

const RAISE = /\bthrow\b/g;
/** A call of `block(`: not a member access, not the `function block(` definition. */
const BLOCK_CALL = /(?<![\w$.])(?<!function\s)block\(/g;

test("the comment stripper removes comments and nothing else", () => {
  const fixture = [
    "// a line comment that says throw",
    "/** a JSDoc that says throw and block( */",
    "/* a block",
    "   comment with Promise.reject( */",
    'const url = "https://api.example.com/v1";',
    "const kept = 1; // trailing throw note",
    "throw new Error(url);",
  ].join("\n");
  const stripped = stripComments(fixture);
  assert.ok(stripped.includes('"https://api.example.com/v1"'), "a URL in a string survives");
  assert.ok(stripped.includes("const kept = 1;"));
  assert.equal(stripped.match(RAISE)?.length, 1, "only the code raise survives");
  assert.ok(!stripped.includes("Promise.reject("));
  assert.ok(!stripped.includes("block("));
});

test("the block-call pattern matches calls only", () => {
  const sample = "export function block(message) {}\nblock(m);\nfoo.block(x);\nif (m) block(m);\nunblock(1);";
  assert.equal(sample.match(BLOCK_CALL)?.length, 2);
});

test("exactly one raise statement in packages/opencode/src, and it is in block.ts", () => {
  const files = sourceFiles(SRC);
  assert.ok(files.length > 0);
  const sites: string[] = [];
  for (const path of files) {
    const count = code(path).match(RAISE)?.length ?? 0;
    for (let i = 0; i < count; i += 1) sites.push(basename(path));
  }
  assert.deepEqual(sites, [RAISE_FILE]);
});

test("block( is called only from the allowed decision files", () => {
  const callers: string[] = [];
  for (const path of sourceFiles(SRC)) {
    if ((code(path).match(BLOCK_CALL)?.length ?? 0) > 0) callers.push(basename(path));
  }
  for (const caller of callers) {
    assert.ok(ALLOWED_BLOCK_CALLERS.has(caller), `${caller} calls block( but is not an allowed caller`);
  }
});

test("no Promise.reject(, process.exit, Bun. or plugin-input $ use", () => {
  const banned: ReadonlyArray<[string, RegExp]> = [
    ["Promise.reject(", /\bPromise\.reject\(/],
    ["process.exit", /\bprocess\.exit\b/],
    ["Bun.", /\bBun\./],
    ["$ member use", /\.\$(?![\w$])/],
  ];
  for (const path of sourceFiles(SRC)) {
    const text = code(path);
    for (const [name, pattern] of banned) {
      assert.ok(!pattern.test(text), `${basename(path)} contains ${name}`);
    }
  }
});
