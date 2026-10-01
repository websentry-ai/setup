// The opencode profile: every opencode-specific fact core needs, in one frozen object.
//
// Core takes an `AgentProfile` and never names an agent itself (`core/src/profile.ts`). The scalar
// values below are what opencode puts on the wire; `test/profile.test.ts` pins them literally.
//
// Directories. opencode keeps config and data apart (xdg-basedir, which resolves `~/.config` and
// `~/.local/share` on macOS too):
//
//   * config: `OPENCODE_CONFIG_DIR` (tilde-expanded) or `${XDG_CONFIG_HOME:-~/.config}/opencode`.
//     This is `resolveAgentDir`, so core's policy cache lives at `<config dir>/.unbound/`.
//   * data: `${XDG_DATA_HOME:-~/.local/share}/opencode`, where `auth.json` lives.
//
// Only absolute bases are accepted. A relative value falls back to the next source and is never
// resolved against the process cwd, for the same reason as pi's `agentDir.ts`: a cache joined from a
// relative base would land inside the repository opencode was started in, where a hostile repo could
// plant one. Phase 15's `opencode/setup.py` must resolve the same two directories.
//
// **Every function here is total.** Each member answers a safe default for any input.

import { isAbsolute, join } from "node:path";

import { expandTilde } from "../../core/src/cache.ts";
import type { AgentFileTools, AgentProfile } from "../../core/src/profile.ts";
import { readOpencodeAuthSummary } from "./auth.ts";
import {
  ENV_OPENCODE_CONFIG_DIR,
  ENV_XDG_CONFIG_HOME,
  ENV_XDG_DATA_HOME,
  OPENCODE_DIR_NAME,
  UNKNOWN_ENTRYPOINT,
  XDG_CONFIG_DEFAULT_SEGMENTS,
  XDG_DATA_DEFAULT_SEGMENTS,
} from "./constants.ts";

function readEnv(env: unknown, name: string): unknown {
  try {
    if (env === null || typeof env !== "object") return undefined;
    return (env as Record<string, unknown>)[name];
  } catch {
    return undefined;
  }
}

function absoluteOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 && isAbsolute(value) ? value : undefined;
}

/** `<xdg base or ~/<defaults>>/opencode`, or `undefined` when no absolute base exists. */
function xdgOpencodeDir(env: unknown, homeDir: unknown, envName: string, defaults: readonly string[]): string | undefined {
  const xdg = absoluteOrUndefined(readEnv(env, envName));
  if (xdg !== undefined) return join(xdg, OPENCODE_DIR_NAME);
  const home = absoluteOrUndefined(homeDir);
  return home === undefined ? undefined : join(home, ...defaults, OPENCODE_DIR_NAME);
}

/** opencode's config dir (core's `resolveAgentDir`). See the header for the order. */
export function resolveOpencodeConfigDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  try {
    const home = typeof homeDir === "string" ? homeDir : "";
    const override = absoluteOrUndefined(expandTilde(readEnv(env, ENV_OPENCODE_CONFIG_DIR), home));
    if (override !== undefined) return override;
    return xdgOpencodeDir(env, homeDir, ENV_XDG_CONFIG_HOME, XDG_CONFIG_DEFAULT_SEGMENTS);
  } catch {
    return undefined;
  }
}

/** opencode's data dir, where `auth.json` lives. See the header for the order. */
export function resolveOpencodeDataDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  try {
    return xdgOpencodeDir(env, homeDir, ENV_XDG_DATA_HOME, XDG_DATA_DEFAULT_SEGMENTS);
  } catch {
    return undefined;
  }
}

/** Search tools whose `path` is optional in opencode; `file_path` falls back to cwd. */
export const OPENCODE_PATH_DEFAULTING_TOOLS = ["grep", "glob"] as const;
/** File tools that always name a target. */
export const OPENCODE_PATH_REQUIRED_TOOLS = ["read", "write", "edit", "lsp", "apply_patch"] as const;

/**
 * The key(s) each tool actually reads its target from, in priority order. Mirrors ai-gateway
 * `src/services/effectiveCommand.ts` `OPENCODE_PATH_KEYS` (review CR-01): a key the tool ignores must
 * never be evaluated in place of the key it uses, so grep/glob read `path` only and a `filePath`
 * decoy cannot redirect the check.
 *
 * `apply_patch` reads `filePath` from the per-file input the ADAPTER builds: the adapter never
 * passes raw `apply_patch` args here; it parses the patch headers (`narrow.ts` `applyPatchTargets`)
 * and evaluates once per target with `{filePath: target}`.
 */
const PATH_KEYS: ReadonlyMap<string, readonly string[]> = new Map<string, readonly string[]>([
  ["read", ["filePath", "path"]],
  ["write", ["filePath", "path"]],
  ["edit", ["filePath", "path"]],
  ["lsp", ["filePath"]],
  ["apply_patch", ["filePath"]],
  ["grep", ["path"]],
  ["glob", ["path"]],
]);

/**
 * The file-tool taxonomy. The seven names are a drift pair with ai-gateway
 * `OPENCODE_NATIVE_FILE_TOOLS` (`src/services/classifier/deterministic/native/taxonomy.ts:163-171`):
 * a name here the API does not know is a round trip that evaluates nothing; a name the API knows that
 * is missing here is a file tool sent with no `file_path`.
 */
export const OPENCODE_FILE_TOOLS: AgentFileTools = Object.freeze({
  defaulting: new Set<string>(OPENCODE_PATH_DEFAULTING_TOOLS) as ReadonlySet<string>,
  required: new Set<string>(OPENCODE_PATH_REQUIRED_TOOLS) as ReadonlySet<string>,
  /** The first non-empty string under the tool's own keys; anything else is `undefined`. */
  pathOf(toolName: string, input: Record<string, unknown>): unknown {
    try {
      const keys = typeof toolName === "string" ? PATH_KEYS.get(toolName) : undefined;
      if (keys === undefined || input === null || typeof input !== "object") return undefined;
      for (const key of keys) {
        const value: unknown = input[key];
        if (typeof value === "string" && value.length > 0) return value;
      }
      return undefined;
    } catch {
      return undefined;
    }
  },
});

/** Extra tool-input keys forwarded for opencode: grep's `include` filter (the API reads it). */
const EXTRA_TOOL_INPUT_KEYS: readonly string[] = Object.freeze(["include"]);

export const OPENCODE_PROFILE: AgentProfile = Object.freeze({
  appLabel: "opencode",
  hookSource: "opencode-hook",
  turnLogPath: "/v1/hooks/opencode",
  envApiKey: "UNBOUND_OPENCODE_API_KEY",
  versionMetadataKey: "opencode_version",
  /**
   * Always `opencode/unknown` here: the host version is not on argv. The adapter learns it at runtime
   * from `session.created` (`oc:schema/src/v1/session.ts:558`) and builds `opencode/<version>` itself.
   */
  resolveClientEntrypoint(): string {
    return UNKNOWN_ENTRYPOINT;
  },
  resolveAgentDir: resolveOpencodeConfigDir,
  fileTools: OPENCODE_FILE_TOOLS,
  extraToolInputKeys: EXTRA_TOOL_INPUT_KEYS,
  /**
   * Core hands the loader a directory as `agentDir`; for opencode that must be the DATA dir (where
   * `auth.json` is), not the config dir. The plugin wires an env-aware closure (13-06) so
   * `OPENCODE_AUTH_CONTENT` is honoured; this default reads the file only.
   */
  readAuth(dataDir: string | undefined, modelProvider: string | undefined) {
    return readOpencodeAuthSummary(dataDir, modelProvider, {});
  },
});
