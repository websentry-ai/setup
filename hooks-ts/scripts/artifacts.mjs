// The drift gate between the build output and what is committed, for every target in TARGETS.
//
//   node scripts/artifacts.mjs check   compare; exit 1 on any difference (CI runs this)
//   node scripts/artifacts.mjs sync    copy dist -> repo root and rewrite the sidecars
//
// `dist/` is git-ignored, so each bundle is committed at `<repo>/<name>/index.js` next to a sidecar
// `<name>/index.js.sha256`. Users download that pair, and the installer refuses an artifact whose
// sha256 is not the one in the sidecar. So there are three things that must agree - the fresh
// build, the committed artifact and the committed sidecar - and `check` compares all of them:
//
//   artifact bytes  == build bytes       a stale artifact ships behaviour the source no longer has
//   sidecar hash    == sha256(artifact)  otherwise every install is refused
//   sidecar hash    == sha256(build)     catches artifact + sidecar refreshed together from an old build
//   sidecar path    == <name>/index.js   a sidecar naming another file is a sidecar for another artifact
//
// A target whose build output is missing is a failure, never a skip.
//
// node:crypto and node:fs only - this runs in CI before anything is trusted.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TARGETS, artifactRelPath, distFileOf, isMainModule, sidecarRelPath } from "./targets.mjs";

const REFRESH = "cd hooks-ts && npm run build && npm run artifacts:sync";

// Exactly what `shasum -a 256 <path>` prints: 64 lowercase hex, two spaces, the path, one newline.
const SIDECAR_LINE = /^([0-9a-f]{64}) {2}([^\s*][^\n]*)\n$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function reason(err) {
  return err instanceof Error ? err.message : String(err);
}

/** The file's bytes, or a problem string pushed onto `problems` and `undefined`. */
function readOrReport(file, what, problems) {
  try {
    return readFileSync(file);
  } catch (err) {
    problems.push(`${what} is missing or unreadable (${reason(err)})`);
    return undefined;
  }
}

/**
 * Every way the committed artifact and sidecar disagree with the fresh build.
 *
 * Pure apart from reading the three files, and total: a read error is a problem string, and so is
 * a caller passing something that is not a set of paths.
 *
 * @param {{ distFile: string, artifactFile: string, sidecarFile: string, artifactRelPath: string }} paths
 * @returns {string[]} one string per problem; empty when the triple is consistent
 */
export function checkTarget(paths) {
  const problems = [];
  try {
    const { distFile, artifactFile, sidecarFile, artifactRelPath: relPath } = paths;

    const dist = readOrReport(distFile, "the fresh build output", problems);
    const artifact = readOrReport(artifactFile, "the committed artifact", problems);
    const sidecarBytes = readOrReport(sidecarFile, "the sidecar", problems);

    if (dist !== undefined && artifact !== undefined && !dist.equals(artifact)) {
      problems.push(
        `the committed artifact differs from a fresh build (${artifact.length} bytes committed, ${dist.length} built)`,
      );
    }

    if (sidecarBytes !== undefined) {
      const match = SIDECAR_LINE.exec(sidecarBytes.toString("utf8"));
      if (match === null) {
        problems.push(`the sidecar is not in the form "<64 hex>  ${relPath}" followed by one newline`);
      } else {
        const [, hash, namedPath] = match;
        if (namedPath !== relPath) {
          problems.push(`the sidecar names ${namedPath}, expected ${relPath}`);
        }
        if (artifact !== undefined && hash !== sha256(artifact)) {
          problems.push(
            `the sidecar hash (${hash}) does not match the committed artifact (${sha256(artifact)})`,
          );
        }
        if (dist !== undefined && hash !== sha256(dist)) {
          problems.push(`the sidecar hash (${hash}) does not match a fresh build (${sha256(dist)})`);
        }
      }
    }
  } catch (err) {
    problems.push(`could not check the target (${reason(err)})`);
  }
  return problems;
}

/**
 * Copy the fresh build over the committed artifact and rewrite its sidecar.
 *
 * Nothing is written unless the build output could be read, so a failed build cannot blank a
 * committed artifact.
 *
 * @param {{ distFile: string, artifactFile: string, sidecarFile: string, artifactRelPath: string }} paths
 * @returns {string[]} one string per problem; empty on success
 */
export function syncTarget(paths) {
  const problems = [];
  try {
    const { distFile, artifactFile, sidecarFile, artifactRelPath: relPath } = paths;

    const dist = readOrReport(distFile, "the fresh build output", problems);
    if (dist === undefined) return problems;

    mkdirSync(dirname(artifactFile), { recursive: true });
    writeFileSync(artifactFile, dist);
    writeFileSync(sidecarFile, `${sha256(dist)}  ${relPath}\n`);
  } catch (err) {
    problems.push(`could not sync the target (${reason(err)})`);
  }
  return problems;
}

/** Absolute paths of one target's three files, from this script's own location. */
function pathsOf(target) {
  const hooksRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const repoRoot = resolve(hooksRoot, "..");
  return {
    distFile: join(hooksRoot, distFileOf(target)),
    artifactFile: join(repoRoot, artifactRelPath(target)),
    sidecarFile: join(repoRoot, sidecarRelPath(target)),
    artifactRelPath: artifactRelPath(target),
  };
}

/**
 * The `check` command. Exit code 0 only if at least one target was checked and every one passed:
 * a gate must never report success without having compared anything (WR-02), so an empty table is
 * a failure, and the last line always says how many targets were checked.
 *
 * @param {readonly { name: string }[]} [targets] defaults to TARGETS; injectable for the tests
 * @returns {0 | 1}
 */
export function runCheck(targets = TARGETS) {
  if (!Array.isArray(targets) || targets.length === 0) {
    console.log("::error::no build targets to check — TARGETS in scripts/targets.mjs is empty");
    return 1;
  }
  let failed = false;
  let checked = 0;
  for (const target of targets) {
    checked += 1;
    const paths = pathsOf(target);
    const problems = checkTarget(paths);
    for (const problem of problems) {
      failed = true;
      // `::error::` is a GitHub Actions annotation; locally it is just a prefixed line.
      console.log(`::error::${target.name}: ${problem} — run: ${REFRESH}`);
    }
    if (problems.length === 0) {
      const artifact = readFileSync(paths.artifactFile);
      console.log(
        `OK ${target.name}: ${paths.artifactRelPath} and its sidecar match a fresh build (${artifact.length} bytes, sha256 ${sha256(artifact)})`,
      );
    }
  }
  console.log(`checked ${checked} target(s): ${failed ? "FAILED" : "all OK"}`);
  return failed ? 1 : 0;
}

function runSync() {
  if (TARGETS.length === 0) {
    console.error("no build targets to sync — TARGETS in scripts/targets.mjs is empty");
    return 1;
  }
  let failed = false;
  for (const target of TARGETS) {
    const paths = pathsOf(target);
    const problems = syncTarget(paths);
    for (const problem of problems) {
      failed = true;
      console.error(`${target.name}: ${problem} — run: cd hooks-ts && npm run build`);
    }
    if (problems.length === 0) {
      console.log(`synced ${paths.artifactRelPath} and ${sidecarRelPath(target)}`);
    }
  }
  return failed ? 1 : 0;
}

// Compared as real paths, so a symlinked or absolute invocation still runs the gate (WR-02).
if (isMainModule(import.meta.url)) {
  const command = process.argv[2];
  if (command === "check") {
    process.exit(runCheck());
  } else if (command === "sync") {
    process.exit(runSync());
  } else {
    console.error("usage: node scripts/artifacts.mjs check|sync");
    process.exit(2);
  }
}
