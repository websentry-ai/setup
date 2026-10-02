// CORE-03 — the build-target table and the per-target drift gate.
//
// Three things are pinned here:
//   1. TARGETS is well-formed, so a new entry that would collide or point nowhere fails before CI.
//   2. `checkTarget` reports every way a committed artifact / sidecar pair can rot. Each failure
//      mode is exercised on a temp directory: the gate is only worth having if it goes red.
//   3. The workflow names no target literally. That is what makes "add a target" a one-entry change
//      rather than a table entry plus two path filters plus two steps.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { checkTarget, runCheck, syncTarget } from "./artifacts.mjs";
import {
  TARGETS,
  artifactRelPath,
  distFileOf,
  isMainModule,
  metaFileOf,
  sidecarRelPath,
} from "./targets.mjs";

const hooksRoot = resolve(import.meta.dirname, "..");
// This file lives in hooks-ts/scripts, so the repo root is two levels up.
const workflowFile = resolve(import.meta.dirname, "..", "..", ".github", "workflows", "hooks-ts.yml");

const BUNDLE = "export default function () {}\n";

function sha256(bytes: string | Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface Triple {
  root: string;
  distFile: string;
  artifactFile: string;
  sidecarFile: string;
  artifactRelPath: string;
}

/** A correct dist / artifact / sidecar triple for a target called `demo`, in a fresh temp dir. */
function correctTriple(t: { after(fn: () => void): void }): Triple {
  const root = mkdtempSync(join(tmpdir(), "hooks-ts-targets-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const distFile = join(root, "hooks-ts", "dist", "demo", "index.js");
  const artifactFile = join(root, "demo", "index.js");
  const sidecarFile = join(root, "demo", "index.js.sha256");
  mkdirSync(join(root, "hooks-ts", "dist", "demo"), { recursive: true });
  mkdirSync(join(root, "demo"), { recursive: true });
  writeFileSync(distFile, BUNDLE);
  writeFileSync(artifactFile, BUNDLE);
  writeFileSync(sidecarFile, `${sha256(BUNDLE)}  demo/index.js\n`);

  return { root, distFile, artifactFile, sidecarFile, artifactRelPath: "demo/index.js" };
}

// --- the table ---------------------------------------------------------------------------------

test("TARGETS holds the pi target, built from the pi package entry", () => {
  const pi = TARGETS.find((target) => target.name === "pi");

  assert.ok(pi !== undefined, "the pi target is gone from TARGETS");
  assert.equal(pi.entry, "packages/pi/src/index.ts");
  // The ceiling `build.test.ts` held dist/pi/index.js under before the assertions became per-target.
  assert.equal(pi.maxBytes, 204_800);
  assert.ok(pi.banner.startsWith("/**\n * GENERATED FILE - DO NOT EDIT."));
  assert.ok(pi.banner.endsWith(" */"));
});

test("TARGETS holds the opencode target, built from the opencode package entry", () => {
  const opencode = TARGETS.find((target) => target.name === "opencode");

  assert.ok(opencode !== undefined, "the opencode target is gone from TARGETS");
  assert.equal(opencode.entry, "packages/opencode/src/index.ts");
  assert.equal(opencode.maxBytes, 262_144);
  assert.ok(opencode.banner.startsWith("/**\n * GENERATED FILE - DO NOT EDIT."));
  assert.ok(opencode.banner.endsWith(" */"));
  // The opencode build test greps the whole output (banner included) for a Bun API access.
  assert.doesNotMatch(opencode.banner, /\bBun\.[A-Za-z]/);
  // pi stays first: its artifact and sidecar paths keep their place in every listing.
  assert.deepEqual(
    TARGETS.map((target) => target.name),
    ["pi", "opencode"],
  );
});

test("TARGETS names are unique, path-safe, and every entry file exists", () => {
  assert.ok(TARGETS.length > 0, "TARGETS is empty - nothing would be built or gated");

  const names = TARGETS.map((target) => target.name);
  assert.equal(new Set(names).size, names.length, `duplicate target name in ${names.join(", ")}`);

  for (const target of TARGETS) {
    assert.match(target.name, /^[a-z][a-z0-9-]*$/, `target name ${JSON.stringify(target.name)}`);
    assert.ok(
      existsSync(join(hooksRoot, target.entry)),
      `${target.name}: entry ${target.entry} does not exist`,
    );
    assert.ok(target.banner.length > 0, `${target.name}: empty banner`);
    assert.ok(
      Number.isInteger(target.maxBytes) && target.maxBytes > 0,
      `${target.name}: maxBytes must be a positive integer, got ${String(target.maxBytes)}`,
    );
  }
});

test("TARGETS is frozen", () => {
  assert.ok(Object.isFrozen(TARGETS));
  for (const target of TARGETS) assert.ok(Object.isFrozen(target), `${target.name} is not frozen`);
});

test("every path of a target is derived from its name", () => {
  const target = { name: "demo", entry: "packages/demo/src/index.ts", banner: "/* demo */" };

  assert.equal(distFileOf(target), "dist/demo/index.js");
  // The metafile must stay OUTSIDE dist/<name>/: that directory holds exactly the one file the
  // committed artifact is compared against.
  assert.equal(metaFileOf(target), "dist/meta/demo.json");
  assert.equal(artifactRelPath(target), "demo/index.js");
  assert.equal(sidecarRelPath(target), "demo/index.js.sha256");
});

test("the targets CLI prints one value per line, and importing it prints nothing", () => {
  const run = (flag: string): string =>
    execFileSync(process.execPath, [join(hooksRoot, "scripts", "targets.mjs"), flag], {
      encoding: "utf8",
    });

  assert.equal(run("--names"), TARGETS.map((target) => `${target.name}\n`).join(""));
  assert.equal(run("--artifacts"), TARGETS.map((target) => `${artifactRelPath(target)}\n`).join(""));
  assert.equal(run("--sidecars"), TARGETS.map((target) => `${sidecarRelPath(target)}\n`).join(""));

  const imported = execFileSync(
    process.execPath,
    ["--input-type=module", "-e", `await import(${JSON.stringify(join(hooksRoot, "scripts", "targets.mjs"))});`, "--", "--names"],
    { encoding: "utf8" },
  );
  assert.equal(imported, "");
});

/** A symlink to the repo root in a fresh temp dir, so a script reached through it has a non-real argv[1]. */
function symlinkedRepo(t: { after(fn: () => void): void }): string {
  const dir = mkdtempSync(join(tmpdir(), "hooks-ts-symlink-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const link = join(dir, "repo");
  symlinkSync(resolve(hooksRoot, ".."), link, "dir");
  return link;
}

/** Run a script with node and report status + stdout, whether it exits 0 or not. */
function runNode(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const run = spawnSync(process.execPath, args, { encoding: "utf8", timeout: 60_000 });
  assert.equal(run.error, undefined, `node ${args.join(" ")} ran`);
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

test("WR-02: the targets CLI works when invoked through a symlinked path", (t) => {
  const link = symlinkedRepo(t);
  const viaLink = join(link, "hooks-ts", "scripts", "targets.mjs");
  assert.notEqual(realpathSync(viaLink), viaLink, "the invocation path really is a symlink");

  for (const flag of ["--names", "--artifacts", "--sidecars"]) {
    const direct = runNode([join(hooksRoot, "scripts", "targets.mjs"), flag]);
    const linked = runNode([viaLink, flag]);
    assert.equal(linked.status, 0, flag);
    assert.notEqual(linked.stdout, "", `${flag}: printed nothing through the symlink`);
    assert.equal(linked.stdout, direct.stdout, flag);
  }
  // And an unknown flag still fails through the symlink instead of silently exiting 0.
  assert.equal(runNode([viaLink, "--nope"]).status, 2);
});

test("WR-02: artifacts check runs the gate when invoked through a symlinked path", (t) => {
  const link = symlinkedRepo(t);
  const viaLink = join(link, "hooks-ts", "scripts", "artifacts.mjs");
  const direct = runNode([join(hooksRoot, "scripts", "artifacts.mjs"), "check"]);
  const linked = runNode([viaLink, "check"]);

  // Whatever the state of dist/ (this test does not build), the symlinked run must do exactly what
  // the direct run does: check every target, report each one, and exit with the same status.
  assert.equal(linked.status, direct.status, `same verdict (stdout: ${linked.stdout})`);
  assert.notEqual(linked.stdout, "", "a gate that printed nothing did not check anything");
  for (const target of TARGETS) {
    assert.match(linked.stdout, new RegExp(`(^OK ${target.name}:|^::error::${target.name}:)`, "m"), target.name);
  }
  assert.match(linked.stdout, new RegExp(`^checked ${TARGETS.length} target\\(s\\): `, "m"));
  // An unknown command still fails through the symlink.
  assert.equal(runNode([viaLink, "nope"]).status, 2);
});

test("WR-02: isMainModule compares real paths and is false for anything unresolvable", (t) => {
  const link = symlinkedRepo(t);
  const real = join(hooksRoot, "scripts", "targets.mjs");
  const url = pathToFileURL(real).href;
  assert.equal(isMainModule(url, real), true);
  assert.equal(isMainModule(url, join(link, "hooks-ts", "scripts", "targets.mjs")), true);
  assert.equal(isMainModule(url, join(hooksRoot, "scripts", "artifacts.mjs")), false);
  assert.equal(isMainModule(url, join(hooksRoot, "scripts", "does-not-exist.mjs")), false);
  assert.equal(isMainModule(url, ""), false);
  assert.equal(isMainModule(url, undefined), false);
  assert.equal(isMainModule("not a url", real), false);
});

test("WR-02: artifacts check never passes without having checked a target", (t) => {
  const logged: string[] = [];
  t.mock.method(console, "log", (line: unknown) => {
    logged.push(String(line));
  });
  assert.equal(runCheck([]), 1);
  assert.ok(logged.some((line) => line.includes("no build targets")), logged.join("\n"));
});

test("the targets CLI rejects an unknown flag rather than printing nothing", () => {
  assert.throws(() =>
    execFileSync(process.execPath, [join(hooksRoot, "scripts", "targets.mjs"), "--nope"], {
      encoding: "utf8",
      stdio: "pipe",
    }),
  );
});

// --- checkTarget -------------------------------------------------------------------------------

test("checkTarget reports nothing for a correct dist / artifact / sidecar triple", (t) => {
  assert.deepEqual(checkTarget(correctTriple(t)), []);
});

test("checkTarget reports a missing dist file (a target that was not built is a failure, not a skip)", (t) => {
  const triple = correctTriple(t);
  rmSync(triple.distFile);

  const problems = checkTarget(triple);
  assert.ok(problems.length >= 1);
  assert.ok(problems.some((p) => p.includes("fresh build")), problems.join(" | "));
});

test("checkTarget reports a missing committed artifact", (t) => {
  const triple = correctTriple(t);
  rmSync(triple.artifactFile);

  assert.ok(checkTarget(triple).length >= 1);
});

test("checkTarget reports an artifact that differs from the build by one byte", (t) => {
  const triple = correctTriple(t);
  const bytes = readFileSync(triple.artifactFile);
  bytes[0] = bytes[0]! ^ 0x01;
  writeFileSync(triple.artifactFile, bytes);

  const problems = checkTarget(triple);
  assert.ok(problems.length >= 1);
  assert.ok(problems.some((p) => p.includes("differs from a fresh build")), problems.join(" | "));
});

test("checkTarget reports a missing sidecar", (t) => {
  const triple = correctTriple(t);
  rmSync(triple.sidecarFile);

  const problems = checkTarget(triple);
  assert.equal(problems.length, 1, problems.join(" | "));
  assert.ok(problems[0]!.includes("sidecar"));
});

test("checkTarget reports a sidecar hash that matches neither the artifact nor the build", (t) => {
  const triple = correctTriple(t);
  writeFileSync(triple.sidecarFile, `${"0".repeat(64)}  demo/index.js\n`);

  const problems = checkTarget(triple);
  assert.ok(
    problems.some((p) => p.includes("does not match the committed artifact")),
    problems.join(" | "),
  );
  assert.ok(problems.some((p) => p.includes("does not match a fresh build")), problems.join(" | "));
});

test("checkTarget reports a sidecar that matches the artifact but not the build", (t) => {
  // Artifact and sidecar were refreshed together from an older build: `shasum -c` is green, and
  // only the comparison against the fresh build can see it.
  const triple = correctTriple(t);
  const stale = "export default function () { /* old */ }\n";
  writeFileSync(triple.artifactFile, stale);
  writeFileSync(triple.sidecarFile, `${sha256(stale)}  demo/index.js\n`);

  const problems = checkTarget(triple);
  assert.ok(problems.some((p) => p.includes("differs from a fresh build")), problems.join(" | "));
  assert.ok(
    problems.some((p) => p.includes("sidecar") && p.includes("fresh build")),
    problems.join(" | "),
  );
  assert.equal(
    problems.some((p) => p.includes("does not match the committed artifact")),
    false,
    problems.join(" | "),
  );
});

test("checkTarget reports a sidecar that names the wrong path", (t) => {
  const triple = correctTriple(t);
  writeFileSync(triple.sidecarFile, `${sha256(BUNDLE)}  other/index.js\n`);

  const problems = checkTarget(triple);
  assert.equal(problems.length, 1, problems.join(" | "));
  assert.ok(problems[0]!.includes("other/index.js"));
  assert.ok(problems[0]!.includes("demo/index.js"));
});

test("checkTarget reports a sidecar that is not in `<hex>  <path>\\n` form", (t) => {
  const hash = sha256(BUNDLE);
  const malformed = [
    "",
    `${hash}\n`, // bare digest: the installer accepts it, the committed form does not
    `${hash} demo/index.js\n`, // one space
    `${hash}  demo/index.js`, // no trailing newline
    `${hash}  demo/index.js\n\n`,
    `${hash.toUpperCase()}  demo/index.js\n`,
    `${hash.slice(1)}  demo/index.js\n`,
    `${hash} *demo/index.js\n`, // binary-mode marker
    `${hash}  demo/index.js\n${hash}  demo/index.js\n`,
  ];

  for (const text of malformed) {
    const triple = correctTriple(t);
    writeFileSync(triple.sidecarFile, text);

    const problems = checkTarget(triple);
    assert.equal(problems.length, 1, `${JSON.stringify(text)} -> ${problems.join(" | ")}`);
    assert.ok(problems[0]!.includes("form"), problems[0]);
  }
});

test("checkTarget never throws: an unreadable path is a problem string", (t) => {
  const triple = correctTriple(t);

  // A directory where a file is expected fails the read with EISDIR.
  const problems = checkTarget({ ...triple, artifactFile: triple.root, sidecarFile: triple.root });
  assert.ok(problems.length >= 2, problems.join(" | "));

  // And a caller that passes nonsense gets problems back, not a TypeError.
  const nonsense = checkTarget(undefined as unknown as Triple);
  assert.ok(nonsense.length >= 1);
});

// --- syncTarget --------------------------------------------------------------------------------

test("syncTarget writes the build as the artifact and a sidecar identical to shasum's output", (t) => {
  const triple = correctTriple(t);
  rmSync(join(triple.root, "demo"), { recursive: true });
  const fresh = "export default function () { /* new */ }\n";
  writeFileSync(triple.distFile, fresh);

  assert.deepEqual(syncTarget(triple), []);

  assert.equal(readFileSync(triple.artifactFile, "utf8"), fresh);
  // Byte-for-byte what a maintainer would have produced by hand from the repo root, which is the
  // form `shasum -a 256 -c` and the installer's sidecar parser both accept.
  const shasum = execFileSync("shasum", ["-a", "256", "demo/index.js"], {
    cwd: triple.root,
    encoding: "utf8",
  });
  assert.equal(readFileSync(triple.sidecarFile, "utf8"), shasum);
  assert.deepEqual(checkTarget(triple), []);
});

test("syncTarget reports a missing build instead of writing anything", (t) => {
  const triple = correctTriple(t);
  rmSync(triple.distFile);
  const before = readFileSync(triple.sidecarFile, "utf8");

  const problems = syncTarget(triple);
  assert.equal(problems.length, 1, problems.join(" | "));
  assert.equal(readFileSync(triple.sidecarFile, "utf8"), before);
  assert.equal(readFileSync(triple.artifactFile, "utf8"), BUNDLE);
});

// --- the workflow ------------------------------------------------------------------------------

test("the workflow gates targets through the table, with no target path spelled out", () => {
  const workflow = readFileSync(workflowFile, "utf8");

  for (const target of TARGETS) {
    assert.equal(
      workflow.includes(artifactRelPath(target)),
      false,
      `hooks-ts.yml names ${artifactRelPath(target)} literally - drive it from scripts/targets.mjs`,
    );
  }
  assert.ok(workflow.includes("artifacts:check"), "hooks-ts.yml does not run artifacts:check");
  assert.ok(
    workflow.includes("targets.mjs --sidecars"),
    "hooks-ts.yml does not verify the sidecars listed by targets.mjs",
  );
  // Path filters: any top-level <dir>/index.js(.sha256), on both triggers.
  assert.equal(workflow.split('"*/index.js"').length - 1, 2);
  assert.equal(workflow.split('"*/index.js.sha256"').length - 1, 2);
});
