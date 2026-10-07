// Types for artifacts.mjs (see targets.d.mts for why the scripts are .mjs with sibling types).

export interface ArtifactPaths {
  /** The fresh build output, e.g. `<hooks-ts>/dist/pi/index.js`. */
  readonly distFile: string;
  /** The committed artifact, e.g. `<repo>/pi/index.js`. */
  readonly artifactFile: string;
  /** The committed sidecar, e.g. `<repo>/pi/index.js.sha256`. */
  readonly sidecarFile: string;
  /** The path the sidecar must name, e.g. `pi/index.js`. */
  readonly artifactRelPath: string;
}

/** Every way the committed artifact / sidecar disagree with the fresh build. Never throws. */
export declare function checkTarget(paths: ArtifactPaths): string[];

/** Copy the build over the artifact and rewrite its sidecar. Returns problems; never throws. */
export declare function syncTarget(paths: ArtifactPaths): string[];

/**
 * The `check` command: 0 only if at least one target was checked and every one passed. An empty
 * table is a failure. Logs one line per target plus a "checked N target(s)" summary.
 */
export declare function runCheck(targets?: readonly { readonly name: string }[]): 0 | 1;
