// The single table of build targets.
//
// Everything that has to know which bundles exist reads it from here: `build.mjs` (what to build),
// `artifacts.mjs` (what to compare against the committed copy and its sidecar) and the CI workflow
// (which sidecars to hand to `shasum -c`, via the CLI at the bottom of this file), and the
// target-independent build assertions in `targets.build.test.ts` (run by `npm run test:build`),
// which iterate this table. Adding a target is one new entry in TARGETS and nothing else.
//
// Every path is derived from the target's name:
//
//   dist/<name>/index.js          the build output (relative to hooks-ts/)
//   dist/meta/<name>.json         esbuild's metafile - NEVER inside dist/<name>/, which must hold
//                                 exactly the one file the committed artifact is compared against
//   <name>/index.js               the committed artifact (relative to the repo root)
//   <name>/index.js.sha256        its integrity sidecar (relative to the repo root)
//
// Each target owns its banner: the banner states the contract of that agent's extension API, which
// is not the same from one agent to the next.
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const PI_BANNER = [
  "/**",
  " * GENERATED FILE - DO NOT EDIT.",
  " * Built from unbound-hooks-ts (packages/core + packages/pi) by scripts/build.mjs.",
  " *",
  " * Fail-open contract: when the Unbound API cannot be reached, times out, answers non-2xx or",
  " * returns unparseable JSON, the tool call is ALLOWED. pi treats a thrown handler as a block,",
  " * so every handler registered here catches everything and returns undefined on failure. The",
  " * single exception is an org whose last successful response asked for block-on-failure.",
  " *",
  " * Headless rule: with no UI available (pi -p / --mode json), a verdict that needs confirmation",
  " * BLOCKS, because there is no way to ask the user.",
  " *",
  " * Tested against pi 0.87.1 on Node >= 22.19.0.",
  " */",
].join("\n");

/**
 * name     - the directory name, both under dist/ and at the repo root. Lowercase, path-safe.
 * entry    - the bundle's entry point, relative to hooks-ts/.
 * banner   - the comment esbuild puts at the top of the output.
 * maxBytes - the size ceiling `scripts/targets.build.test.ts` holds the built bundle under. A value
 *            import of an agent's own package would blow past it by megabytes.
 */
export const TARGETS = Object.freeze([
  Object.freeze({ name: "pi", entry: "packages/pi/src/index.ts", banner: PI_BANNER, maxBytes: 204_800 }),
]);

/** Where the metafiles go, relative to hooks-ts/. */
export const META_DIR = "dist/meta";

/** The build output, relative to hooks-ts/. */
export function distFileOf(target) {
  return `dist/${target.name}/index.js`;
}

/** esbuild's metafile, relative to hooks-ts/. Read by the build assertions. */
export function metaFileOf(target) {
  return `${META_DIR}/${target.name}.json`;
}

/**
 * The committed artifact, relative to the repo root. This is also the path field of the sidecar,
 * because the sidecar is what `shasum -a 256 <name>/index.js` prints from the repo root.
 */
export function artifactRelPath(target) {
  return `${target.name}/index.js`;
}

/** The committed sidecar, relative to the repo root. */
export function sidecarRelPath(target) {
  return `${artifactRelPath(target)}.sha256`;
}

const LISTINGS = {
  "--names": (target) => target.name,
  "--artifacts": artifactRelPath,
  "--sidecars": sidecarRelPath,
};

/**
 * Is the module at `moduleUrl` the one Node was asked to run?
 *
 * Compared as REAL paths (WR-02). Node resolves symlinks for the main module's `import.meta.url`
 * but not for `process.argv[1]`, so a plain URL comparison is false whenever the script is reached
 * through a symlink (a checkout under a symlinked directory, `/tmp` -> `/private/tmp` on macOS) and
 * the CLI silently does nothing and exits 0. For a drift gate, "did nothing" reads as "passed".
 * Any failure to resolve either side is "not the main module", which a CLI below turns into nothing
 * only when it was genuinely imported.
 *
 * @param {string} moduleUrl the caller's `import.meta.url`
 * @param {string | undefined} [argv1] defaults to `process.argv[1]`
 */
export function isMainModule(moduleUrl, argv1 = process.argv[1]) {
  try {
    if (typeof argv1 !== "string" || argv1 === "") return false;
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

// CLI, for the shell loop in the workflow: one value per line. Guarded so that importing this
// module prints nothing.
if (isMainModule(import.meta.url)) {
  const flag = process.argv[2];
  const listing = typeof flag === "string" && Object.hasOwn(LISTINGS, flag) ? LISTINGS[flag] : undefined;
  if (listing === undefined) {
    // An unknown flag must not look like "there are no targets" to a shell loop.
    console.error(`usage: node scripts/targets.mjs ${Object.keys(LISTINGS).join("|")}`);
    process.exit(2);
  }
  for (const target of TARGETS) console.log(listing(target));
}
