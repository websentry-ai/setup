// The gate that keeps core agent-agnostic (CORE-01, ROADMAP Phase 12 success criterion 2).
//
// Every agent-specific fact reaches core through an injected `AgentProfile`. This test reads every
// source file under `packages/core/src`, removes the comments, and fails if anything that names pi
// is left: its app label, its key env var, its turn-log route, its directory and relocation
// variables, its SDK scope, its version metadata key, its tool names, or an import from the pi
// package.
//
// Comments are stripped first because core's comments legitimately describe pi's history and the
// server behaviour pi was built against; the rule is about code, not prose.
//
// The stripper is tested here too. A stripper that removed too much would make every file look
// clean, and this gate would pass while checking nothing.

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import test from "node:test";

const CORE_SRC = resolve(import.meta.dirname, "..", "src");

/**
 * Remove block comments (JSDoc included) and line comments. A `//` directly after a `:` is kept, so a
 * URL such as `https://host` inside a string survives.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(?<!:)\/\/[^\n]*/g, "");
}

interface Rule {
  name: string;
  pattern: RegExp;
}

const FORBIDDEN: readonly Rule[] = [
  { name: 'the app label as a string literal ("pi")', pattern: /["'`]pi["'`]/ },
  { name: "pi's key env var", pattern: /UNBOUND_PI_API_KEY/ },
  { name: "pi's turn-log route", pattern: /\/v1\/hooks\/pi\b/ },
  { name: "pi's agent-dir relocation variable", pattern: /PI_CODING_AGENT_DIR/ },
  { name: "pi's install-root variable", pattern: /PI_MANAGED_INSTALL_ROOT/ },
  { name: 'pi\'s directory name (".pi")', pattern: /["'`]\.pi["'`]/ },
  { name: "pi's SDK scope", pattern: /@earendil-works/ },
  { name: "pi's version metadata key", pattern: /pi_version/ },
  { name: "a piVersion identifier", pattern: /\bpiVersion\b/ },
  { name: "a PI_* constant", pattern: /\bPI_[A-Z0-9_]+\b/ },
  { name: "a pi reader", pattern: /\b(resolvePiAgentDir|readPiAuth|PiAuth\w*)\b/ },
  { name: "a pi tool name as a string literal", pattern: /["'`](grep|find|ls|read|write|edit)["'`]/ },
  { name: "an import from the pi package", pattern: /(?:from|import)\s*\(?\s*["'`][^"'`\n]*(?:\/pi\/|packages\/pi)[^"'`\n]*["'`]/ },
];

/** Every violation in `code` (already comment-stripped), as `rule: matched text`. */
function violations(code: string): string[] {
  const found: string[] = [];
  for (const rule of FORBIDDEN) {
    const match = rule.pattern.exec(code);
    if (match !== null) found.push(`${rule.name}: ${match[0]}`);
  }
  return found;
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

test("the comment stripper removes comments and nothing else", () => {
  const fixture = [
    '// the label is "pi" on the wire',
    "/** `UNBOUND_PI_API_KEY` is read first */",
    "/* a block",
    '   naming "grep" */',
    'const url = "https://api.example.com/v1";',
    "const kept = 1; // trailing PI_CODING_AGENT_DIR note",
  ].join("\n");
  const stripped = stripComments(fixture);

  assert.deepEqual(violations(stripped), [], "pi names inside comments are ignored");
  assert.ok(stripped.includes('"https://api.example.com/v1"'), "a URL in a string is not cut at its //");
  assert.ok(stripped.includes("const kept = 1;"), "code before a trailing comment survives");
});

test("each rule catches its literal in code, so the gate cannot pass by checking nothing", () => {
  const offenders: Record<string, string> = {
    'the app label as a string literal ("pi")': 'export const X = "pi";',
    "pi's key env var": 'const k = env["UNBOUND_PI_API_KEY"];',
    "pi's turn-log route": 'const route = "/v1/hooks/pi";',
    "pi's agent-dir relocation variable": 'const v = "PI_CODING_AGENT_DIR";',
    "pi's install-root variable": 'const v = "PI_MANAGED_INSTALL_ROOT";',
    'pi\'s directory name (".pi")': 'const segments = [".pi", "agent"];',
    "pi's SDK scope": 'const name = "@earendil-works/pi-coding-agent";',
    "pi's version metadata key": "const metadata = { pi_version: v };",
    "a piVersion identifier": "const piVersion = input.version;",
    "a PI_* constant": "export const PI_AUTH_FILE_NAME = name;",
    "a pi reader": "const auth = readPiAuth(dir);",
    "a pi tool name as a string literal": 'const tools = ["grep"];',
    "an import from the pi package": 'import { PI_PROFILE } from "../../pi/src/profile.ts";',
  };
  assert.deepEqual(Object.keys(offenders).sort(), FORBIDDEN.map((rule) => rule.name).sort(), "one offender per rule");

  for (const rule of FORBIDDEN) {
    const code = offenders[rule.name] as string;
    assert.ok(rule.pattern.test(stripComments(code)), `${rule.name} must match: ${code}`);
    // The same text inside a comment is prose, not code.
    assert.equal(rule.pattern.test(stripComments(`// ${code}`)), false, `${rule.name} must ignore a comment`);
  }
  // Names that merely contain the letters are not pi names.
  assert.deepEqual(violations('const a = ENV_API_KEY_GENERIC; const b = "api"; const c = "/v1/hooks/pretool";'), []);
});

test("packages/core/src names no agent: no pi literal and no pi import outside comments", () => {
  const files = sourceFiles(CORE_SRC);
  assert.ok(files.length >= 15, `expected core's source files under ${CORE_SRC}, found ${files.length}`);

  const failures: string[] = [];
  for (const file of files) {
    const code = stripComments(readFileSync(file, "utf8"));
    assert.ok(code.trim().length > 0, `${relative(CORE_SRC, file)} is empty once comments are removed`);
    for (const violation of violations(code)) failures.push(`${relative(CORE_SRC, file)} — ${violation}`);
  }
  assert.deepEqual(failures, [], "agent-specific values belong in the adapter's AgentProfile, not in core");
});
