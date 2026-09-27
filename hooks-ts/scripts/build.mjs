// Build the pi extension into one dependency-free ESM file at dist/pi/index.js.
//
// Nothing is marked external: the only non-relative specifiers the sources are allowed to use are
// node: builtins (which esbuild leaves alone on platform=node) and type-only imports of the pi
// package (which vanish at compile time). A bare non-node: specifier surviving into the output
// would fail to resolve under pi's jiti loader and kill the extension at load.
import * as esbuild from "esbuild";

const BANNER = [
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

try {
  await esbuild.build({
    entryPoints: ["packages/pi/src/index.ts"],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "esm",
    outfile: "dist/pi/index.js",
    legalComments: "none",
    logLevel: "warning",
    banner: { js: BANNER },
  });
  console.log("built dist/pi/index.js");
} catch (err) {
  console.error("build failed:", err instanceof Error ? err.message : String(err));
  process.exit(1);
}
