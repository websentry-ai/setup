// `client_entrypoint: "pi/<version>"` — the pi version WITHOUT importing pi.
//
// pi exports `VERSION`, but that is a value import, and one value import of
// `@earendil-works/pi-coding-agent` inlines the entire agent into the bundle (§F6). No environment
// variable carries the version either (§A8), so there are exactly two dependency-free sources:
//
//   1. `$PI_MANAGED_INSTALL_ROOT/current-version` — written by the managed-install launcher.
//   2. Walking up from `process.argv[1]` to the pi package.json — covers `npm i -g` installs.
//   3. Otherwise `pi/unknown`, which is safe: `client_entrypoint` is free-form on the wire and an
//      unknown value buckets to 'other' server-side (it does NOT hit the claude-code-only headless
//      auto-allow path).
//
// The whole body is try/catch-total: a throw out of a pi handler is a BLOCK (§F1), and a version
// lookup must never be able to block a tool call (T-08-07).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { ENV_PI_INSTALL_ROOT } from "./constants.ts";

/** The package whose `version` we are after. Referenced as a string only — never imported. */
const PI_PACKAGE_NAME = "@earendil-works/pi-coding-agent";
const MAX_WALK_UP_LEVELS = 8;
const MAX_VERSION_CHARS = 32;

function readManagedInstallVersion(env: NodeJS.ProcessEnv): string | undefined {
  const root = env[ENV_PI_INSTALL_ROOT];
  if (typeof root !== "string" || root.length === 0) return undefined;
  try {
    const version = readFileSync(join(root, "current-version"), "utf8").trim();
    return version.length > 0 ? version : undefined;
  } catch {
    // Not a managed install (or the file vanished) — fall through to the argv walk-up.
    return undefined;
  }
}

function readVersionFromArgv(argv1: string | undefined): string | undefined {
  if (typeof argv1 !== "string" || argv1.length === 0) return undefined;
  let dir = dirname(argv1);
  for (let level = 0; level < MAX_WALK_UP_LEVELS; level += 1) {
    try {
      const parsed: unknown = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      if (parsed !== null && typeof parsed === "object") {
        const pkg = parsed as { name?: unknown; version?: unknown };
        if (pkg.name === PI_PACKAGE_NAME && typeof pkg.version === "string" && pkg.version.length > 0) {
          return pkg.version;
        }
      }
    } catch {
      // No readable package.json at this level — keep walking.
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

/**
 * Strip anything that is not a plausible semver character and cap the length, so a tampered
 * `current-version` file cannot inject arbitrary text into a header-adjacent wire field.
 */
function sanitizeVersion(version: string): string {
  const cleaned = version.replace(/[^A-Za-z0-9._+-]/g, "").slice(0, MAX_VERSION_CHARS);
  return cleaned.length > 0 ? cleaned : "unknown";
}

/** `"pi/0.87.1"`, or `"pi/unknown"` when the version cannot be determined. Never throws. */
export function resolveClientEntrypoint(env: NodeJS.ProcessEnv, argv1?: string): string {
  let version = "unknown";
  try {
    const found = readManagedInstallVersion(env) ?? readVersionFromArgv(argv1);
    if (found !== undefined) version = sanitizeVersion(found);
  } catch {
    version = "unknown";
  }
  return `pi/${version}`;
}
