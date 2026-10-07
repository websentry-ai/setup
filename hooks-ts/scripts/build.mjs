// Build every target in scripts/targets.mjs into one dependency-free ESM file each, at
// dist/<name>/index.js.
//
// Nothing is marked external: the only non-relative specifiers the sources are allowed to use are
// node: builtins (which esbuild leaves alone on platform=node) and type-only imports of the agent's
// own package (which vanish at compile time). A bare non-node: specifier surviving into the output
// would fail to resolve under the agent's loader (pi's jiti) and kill the extension at load.
//
// The metafile (WR-08) is the supply-chain guard: `packages/pi/test/build.test.ts` asserts that
// every recorded input is a `packages/` path and every surviving import of the entry output is an
// external `node:` builtin. It goes to dist/meta/<name>.json, NEVER dist/<name>/ - that directory
// must hold exactly one file, which is what the committed `<name>/index.js` is compared against.
//
// The option set is the same for every target; only the entry, the output path and the banner come
// from the table.
//
// `__UNBOUND_OPENCODE_BUILD__` is defined for every target as a content hash of the sources the
// bundle is built from (`packages/core/src` + `packages/<name>/src`): deterministic, so a rebuild
// of unchanged sources is byte-identical, and different for any source change. The opencode double-
// load sentinel uses it to tell another copy of the same build from a value a foreign plugin planted
// (13-REVIEW WR-04). A target whose sources never name it is unaffected.
import * as esbuild from "esbuild";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";

import { META_DIR, TARGETS, distFileOf, metaFileOf } from "./targets.mjs";

/** Every `.ts` file under `dir` (relative to hooks-ts/), sorted, as `/`-joined relative paths. */
function filesUnder(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) out.push(...filesUnder(path));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(path);
  }
  return out.sort();
}

/** sha256 over (path, content) of the target's sources; the first 32 hex characters. */
function buildTokenOf(target) {
  const hash = createHash("sha256");
  for (const file of [...filesUnder("packages/core/src"), ...filesUnder(`packages/${target.name}/src`)]) {
    hash.update(file).update("\0").update(readFileSync(file)).update("\0");
  }
  return hash.digest("hex").slice(0, 32);
}

let failed = false;

for (const target of TARGETS) {
  try {
    const result = await esbuild.build({
      define: { __UNBOUND_OPENCODE_BUILD__: JSON.stringify(buildTokenOf(target)) },
      entryPoints: [target.entry],
      bundle: true,
      platform: "node",
      target: "node22",
      format: "esm",
      outfile: distFileOf(target),
      legalComments: "none",
      logLevel: "warning",
      banner: { js: target.banner },
      metafile: true,
    });
    await mkdir(META_DIR, { recursive: true });
    await writeFile(metaFileOf(target), JSON.stringify(result.metafile));
    console.log(`built ${distFileOf(target)} (metafile: ${metaFileOf(target)})`);
  } catch (err) {
    failed = true;
    console.error(
      `build failed for target ${target.name}:`,
      err instanceof Error ? err.message : String(err),
    );
  }
}

if (failed) process.exit(1);
