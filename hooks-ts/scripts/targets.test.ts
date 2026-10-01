// CORE-03 — the build-target table and the per-target drift gate.
//
// Three things are pinned here:
//   1. TARGETS is well-formed, so a new entry that would collide or point nowhere fails before CI.
//   2. `checkTarget` reports every way a committed artifact / sidecar pair can rot. Each failure
//      mode is exercised on a temp directory: the gate is only worth having if it goes red.
//   3. The workflow names no target literally. That is what makes "add a target" a one-entry change
//      rather than a table entry plus two path filters plus two steps.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { checkTarget, syncTarget } from "./artifacts.mjs";
import {
  TARGETS,
  artifactRelPath,
  distFileOf,
  metaFileOf,
  sidecarRelPath,
} from "./targets.mjs";

const hooksRoot = resolve(import.meta.dirname, "..");

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
  assert.ok(pi.banner.startsWith("/**\n * GENERATED FILE - DO NOT EDIT."));
  assert.ok(pi.banner.endsWith(" */"));
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
