// Types for targets.mjs. The script stays plain .mjs so `npm run build` is `node scripts/build.mjs`
// with no loader flag; this file is what lets a .ts test import it under `tsc` (no allowJs).

export interface BuildTarget {
  /** Directory name under dist/ and at the repo root. */
  readonly name: string;
  /** Entry point, relative to hooks-ts/. */
  readonly entry: string;
  /** Comment placed at the top of the bundle. */
  readonly banner: string;
}

export declare const TARGETS: readonly BuildTarget[];
export declare const META_DIR: string;

/** `dist/<name>/index.js`, relative to hooks-ts/. */
export declare function distFileOf(target: BuildTarget): string;
/** `dist/meta/<name>.json`, relative to hooks-ts/. */
export declare function metaFileOf(target: BuildTarget): string;
/** `<name>/index.js`, relative to the repo root; also the sidecar's path field. */
export declare function artifactRelPath(target: BuildTarget): string;
/** `<name>/index.js.sha256`, relative to the repo root. */
export declare function sidecarRelPath(target: BuildTarget): string;
