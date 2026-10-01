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
import * as esbuild from "esbuild";
import { mkdir, writeFile } from "node:fs/promises";

import { META_DIR, TARGETS, distFileOf, metaFileOf } from "./targets.mjs";

let failed = false;

for (const target of TARGETS) {
  try {
    const result = await esbuild.build({
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
