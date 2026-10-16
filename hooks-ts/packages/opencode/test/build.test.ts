// Build assertions against the REAL opencode build output: the parts that are specific to opencode.
//
// There is no skip-if-missing guard anywhere in this file: a silently-skipped supply-chain
// assertion is worse than a red test. Run `npm run build` first.
//
// The target-independent supply-chain checks (dist/<name>/ holds one file, every input a workspace
// path, only external `node:` imports survive, pure ESM, the size ceiling carried on the TARGETS
// entry) run for every target in `scripts/targets.build.test.ts`. Some are repeated here on purpose
// with opencode's own numbers, because opencode's loader adds rules pi's does not have:
//
//   * EXACTLY one export, named `default` (`oc:opencode/src/plugin/index.ts:99-112`, 13-SPIKES.md
//     V1-2): the v1 legacy path rejects a non-function named export, so a stray `export const`
//     can turn into a silent load failure (= silent fail-open, Pitfall 3).
//   * No `Bun.` API use: the CLI is a Bun binary, but the desktop app and every Node import smoke
//     are not, and a Bun-only call would throw there.
//
// The bundle is evaluated ONLY in a child process whose environment is built from scratch: a temp
// HOME and XDG dirs, a gateway URL pointing at a dead loopback port, and no other variable (no
// `UNBOUND_*` key, no real home). A deferred report from the bundle can therefore never reach a
// real gateway with a real key, and nothing is read from or written to the developer's home.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { TARGETS, distFileOf, metaFileOf } from "../../../scripts/targets.mjs";

const hooksRoot = resolve(import.meta.dirname, "..", "..", "..");
const OPENCODE_TARGET = TARGETS.find((target) => target.name === "opencode");
const distFile = join(hooksRoot, "dist", "opencode", "index.js");
const metaFile = join(hooksRoot, "dist", "meta", "opencode.json");

/** The opencode bundle's own ceiling; the TARGETS entry carries the same number. */
const MAX_BYTES = 262_144;

/** `export default { id, server, setup }` (13-SPIKES.md V1-2 GO, dual entry). */
const EXPECTED_DEFAULT_KEYS = ["id", "server", "setup"] as const;

/**
 * Every hook `server()` registers, asserted from the REAL build output. `shell.env` is in the set
 * because V1-7 is GO (the user `!cmd` check). Adding or dropping a hook fails here until named.
 */
const EXPECTED_HOOKS = [
  "chat.message",
  "config",
  "dispose",
  "event",
  "shell.env",
  "tool.execute.after",
  "tool.execute.before",
] as const;

interface Metafile {
  inputs: Record<string, unknown>;
  outputs: Record<
    string,
    { entryPoint?: string; imports?: { path: string; external?: boolean }[]; exports?: string[] }
  >;
}

function readMetafile(): Metafile {
  return JSON.parse(readFileSync(metaFile, "utf8")) as Metafile;
}

function entryOutput(meta: Metafile): Metafile["outputs"][string] {
  const outputs = Object.values(meta.outputs);
  const entry = outputs.find((o) => o.entryPoint !== undefined) ?? outputs[0];
  assert.ok(entry !== undefined, "metafile recorded no outputs");
  return entry;
}

test("the opencode bundle is a TARGETS entry, so the per-target supply-chain assertions cover it", () => {
  assert.ok(OPENCODE_TARGET !== undefined, "opencode is missing from TARGETS");
  assert.equal(OPENCODE_TARGET.entry, "packages/opencode/src/index.ts");
  assert.equal(join(hooksRoot, distFileOf(OPENCODE_TARGET)), distFile);
  assert.equal(join(hooksRoot, metaFileOf(OPENCODE_TARGET)), metaFile);
  assert.equal(OPENCODE_TARGET.maxBytes, MAX_BYTES);
});

test("dist/opencode holds exactly index.js", () => {
  assert.deepEqual(readdirSync(resolve(distFile, "..")), ["index.js"]);
});

test("every bundled input is a workspace source file", () => {
  const inputs = Object.keys(readMetafile().inputs);
  assert.ok(inputs.length > 0, "metafile recorded no inputs - the build did not run");
  for (const input of inputs) {
    assert.ok(input.startsWith("packages/"), `bundled a non-workspace input: ${input}`);
  }
});

test("every surviving import is an external node: builtin", () => {
  for (const imp of entryOutput(readMetafile()).imports ?? []) {
    assert.equal(imp.external, true, `non-external import survived: ${imp.path}`);
    assert.ok(imp.path.startsWith("node:"), `bare specifier ${imp.path} cannot resolve under the loader`);
  }
});

test("the entry output's ONLY export is `default` (metafile)", () => {
  assert.deepEqual(entryOutput(readMetafile()).exports, ["default"]);
});

test("the output stays under the opencode size ceiling", () => {
  const { size } = statSync(distFile);
  assert.ok(size < MAX_BYTES, `dist/opencode/index.js is ${size} bytes, ceiling is ${MAX_BYTES}`);
});

test("the output uses no Bun API and no require()", () => {
  const content = readFileSync(distFile, "utf8");
  assert.doesNotMatch(content, /\bBun\.[A-Za-z]/, "a Bun-only API would throw under Node / desktop");
  assert.equal(content.includes("require("), false, "output must be pure ESM");
});

// --- the module, evaluated in an isolated child process ----------------------------------------

/**
 * The child script. It imports the bundle, then reports its shape, the hook set of a `server()`
 * call and the result of `setup()` with the 1.18 embedded-host ctx shape (no v2-only keys) and with
 * an empty ctx. Everything printed is JSON on one line.
 */
const CHILD_SCRIPT = `
const [artifactUrl, dir] = process.argv.slice(1);
const mod = await import(artifactUrl);
const d = mod.default;
const hooks = await d.server({ directory: dir, worktree: dir, client: {} });
const ctx118 = { options: {}, agent: {}, aisdk: {}, catalog: {}, command: {}, integration: {}, plugin: {}, reference: {}, skill: {} };
const setupEmpty = await d.setup({});
const setup118 = await d.setup(ctx118);
process.stdout.write(JSON.stringify({
  moduleKeys: Object.keys(mod),
  defaultKeys: Object.keys(d).sort(),
  id: d.id,
  types: { id: typeof d.id, server: typeof d.server, setup: typeof d.setup },
  hasTui: "tui" in d,
  hooks: Object.keys(hooks).sort(),
  setupEmpty: setupEmpty === undefined ? "undefined" : JSON.stringify(setupEmpty),
  setup118: setup118 === undefined ? "undefined" : JSON.stringify(setup118),
}) + "\\n");
`;

interface ChildReport {
  moduleKeys: string[];
  defaultKeys: string[];
  id: unknown;
  types: { id: string; server: string; setup: string };
  hasTui: boolean;
  hooks: string[];
  setupEmpty: string;
  setup118: string;
}

function runChild(home: string): Promise<{ stdout: string; stderr: string; ms: number }> {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "",
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_DATA_HOME: join(home, ".local", "share"),
    XDG_CACHE_HOME: join(home, ".cache"),
    XDG_STATE_HOME: join(home, ".local", "state"),
    // A dead loopback port: nothing the bundle might send can reach any gateway.
    UNBOUND_GATEWAY_URL: "http://127.0.0.1:9",
  };
  const started = Date.now();
  return new Promise((resolvePromise, reject) => {
    execFile(
      process.execPath,
      ["--input-type=module", "-e", CHILD_SCRIPT, pathToFileURL(distFile).href, home],
      { env, cwd: home, timeout: 10_000, killSignal: "SIGKILL", encoding: "utf8" },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`child failed (${String(err.message)}); stderr:\n${stderr}`));
          return;
        }
        resolvePromise({ stdout, stderr, ms: Date.now() - started });
      },
    );
  });
}

test("the built module loads in an isolated child: one default export, the full hook set, an inert setup", async (t) => {
  const home = mkdtempSync(join(tmpdir(), "unbound-opencode-build-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));

  const { stdout, ms } = await runChild(home);
  const report = JSON.parse(stdout.trim()) as ChildReport;

  assert.deepEqual(report.moduleKeys, ["default"], "the module's only export must be `default`");
  assert.equal(report.id, "unbound");
  assert.deepEqual(report.defaultKeys, [...EXPECTED_DEFAULT_KEYS]);
  assert.deepEqual(report.types, { id: "string", server: "function", setup: "function" });
  assert.equal(report.hasTui, false, "no `tui` entry: the TUI loader would pick the module up");
  assert.deepEqual(report.hooks, [...EXPECTED_HOOKS], `server() registered ${report.hooks.join(", ")}`);
  assert.equal(report.setupEmpty, "undefined");
  assert.equal(report.setup118, "undefined", "setup with the 1.18 embedded-host ctx is a no-op");
  assert.ok(ms < 10_000, `the child exited in ${ms} ms (timers must be unref'd)`);
});
