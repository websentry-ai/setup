// `mcp_server_config` for a brokered MCP call: the server's `url`, or `command` + `args`, as the
// pi-mcp-adapter loaded it — or NOTHING. Strict-or-omit (Revision 3).
//
// The gateway fingerprints a server from this config to decide whether it is sanctioned, so a wrong
// config is worse than none: if this reader and the adapter disagree about a file, an unsanctioned
// binary can borrow a sanctioned server's fingerprint. Two reviews reproduced exactly that, by making
// a lenient re-implementation of the adapter's parser and merge disagree with the real one (comment
// edge cases, `mcp-servers` fallbacks, an invalid `settings` that makes the adapter skip a file, a
// `socket` transport, a file edited after the adapter loaded it). Mirroring leniency keeps producing
// differentials, so this reader does the opposite: it describes a server ONLY when the configuration
// is in a shape whose meaning is unambiguous, and otherwise answers `undefined` — for every server.
//
// **Send** only when ALL of these hold:
//   * every existing source is plain strict JSON (`JSON.parse` on the raw text after an optional BOM;
//     comments are NOT stripped — a comment makes the file "unknown");
//   * every source is an object with only `mcpServers` (a plain object), `settings` (a plain object)
//     and `$schema` at the top level;
//   * no `settings` key that pulls in servers or files this reader does not see (`ancestorConfigRoots`,
//     `agentPluginPaths`, `hostConfigDiscovery`) or that the adapter validates and may reject (`jev`);
//   * every server definition, in every source, is a plain object with only keys from the adapter's
//     `ServerEntry` (`types.ts`) — and none of them uses `socket`;
//   * the server's merged definition has a string `url` XOR a string `command` (+ string-array `args`);
//   * the extension can resolve the same sources the adapter does: an absolute `cwd`, an agent dir
//     from `PI_CODING_AGENT_DIR` (absolute) or `~/.pi/agent`, no `PI_PACKAGE_DIR` (a rebranded build
//     relocates both), and no `--mcp-config` anywhere in pi's argv;
//   * the server name has no `__` (pi packages contribute servers named `<package>__<server>`, merged
//     below the config files, which this reader does not load);
//   * the snapshot is still valid (below).
//
// **Snapshot once.** The adapter loads its config once, at session init, and never watches it. So the
// sources are read once per extension instance — at the first `session_start` with a key, or at
// first need — and only with a usable cwd, and their file signatures recorded. If any signature later
// differs, the answer is `undefined` for the rest of the instance: the adapter is still running what
// it loaded, and this reader can no longer know what that was. A call with an unusable or different
// cwd omits for that call only (see `createMcpConfigReader`).
//
// **Reads cannot block.** `open(O_RDONLY | O_NONBLOCK)`, then `fstat` on the descriptor (regular file
// only, 1 MiB cap), then read from the same descriptor — one lookup, so a path swapped for a FIFO
// between a check and a read is not possible. Symlinks are followed, as the adapter follows them.
//
// **What is sent.** `env`, `headers`, bearer tokens and OAuth settings are never read into the result.
// `url` and `args` are sent as written — the fields the Claude Code hook sends — and a `url` query
// string or an `args` entry CAN itself carry a credential. That is parity egress, documented.
//
// Every exported function is total.

import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import { ENV_PI_AGENT_DIR } from "./agentDir.ts";
import {
  ENV_PI_MCP_CONFIG_MODE,
  MAX_MCP_CONFIG_BYTES,
  MCP_ADAPTER_CONFIG_FILE_NAME,
  MCP_CONFIG_FLAG,
} from "./constants.ts";

/** Every key of the adapter's `ServerEntry` (`types.ts:438-522`, 4.0.0), plus the inert `type`. */
const KNOWN_SERVER_KEYS: ReadonlySet<string> = new Set([
  "command", "args", "socket", "env", "inheritEnv", "cwd", "url", "caFile", "headers",
  "requestHeadersCommand", "auth", "bearerToken", "bearerTokenEnv", "bearerTokenStore", "oauth",
  "lifecycle", "idleTimeout", "requestTimeoutMs", "exposeResources", "directTools", "toolPrefix",
  "includeTools", "excludeTools", "searchKeywords", "approveTools", "debug", "trace", "httpTransport",
  "pluginDataDir", "literalEnv", "protocolVersion", "tasks", "disabled",
  // Not read by the adapter at all (no transport selection reads it); common in `.mcp.json` files.
  "type",
]);

/** Top-level keys a modelled source may have. Anything else (`imports`, `claudePlugins`, `mcp-servers`…) ⇒ omit. */
const KNOWN_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set(["mcpServers", "settings", "$schema"]);

/** `settings` keys that pull in sources this reader does not load, or that the adapter may reject. */
const UNMODELLED_SETTINGS_KEYS: readonly string[] = [
  "ancestorConfigRoots",
  "agentPluginPaths",
  "hostConfigDiscovery",
  "jev",
];

/** Set by a rebranded pi build; it moves both the agent dir and the project config dir. */
const ENV_PI_PACKAGE_DIR = "PI_PACKAGE_DIR";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

export interface McpConfigEnv {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  /** `process.argv` in production; injectable for tests. */
  argv?: readonly string[];
}

/** Does pi's argv carry the adapter's `--mcp-config` flag in any form? (⇒ omit; not modelled.) */
export function hasMcpConfigFlag(argv: readonly string[] | undefined): boolean {
  try {
    if (!Array.isArray(argv)) return false;
    return argv.some((arg) => arg === MCP_CONFIG_FLAG || (typeof arg === "string" && arg.startsWith(`${MCP_CONFIG_FLAG}=`)));
  } catch {
    return true;
  }
}

/**
 * The sources in the adapter's precedence order (later wins), or `undefined` when the extension cannot
 * be sure it resolves the same paths the adapter does.
 */
export function mcpConfigSources(options: McpConfigEnv, cwd: string): string[] | undefined {
  try {
    const env = options.env ?? {};
    const homeDir = options.homeDir;
    if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute(homeDir)) return undefined;
    if (typeof cwd !== "string" || cwd === "" || !isAbsolute(cwd)) return undefined;
    if (hasMcpConfigFlag(options.argv)) return undefined;
    const packageDir = env[ENV_PI_PACKAGE_DIR];
    if (typeof packageDir === "string" && packageDir !== "") return undefined;
    const agentEnv = env[ENV_PI_AGENT_DIR];
    let agentDir: string;
    if (typeof agentEnv === "string" && agentEnv !== "") {
      // The adapter `resolve()`s a relative value against its own cwd; not modelled.
      if (!isAbsolute(agentEnv)) return undefined;
      agentDir = agentEnv;
    } else {
      agentDir = join(homeDir, ".pi", "agent");
    }
    const adapterFile = join(agentDir, MCP_ADAPTER_CONFIG_FILE_NAME);
    const mode = env[ENV_PI_MCP_CONFIG_MODE];
    if (typeof mode === "string" && mode.trim().toLowerCase() === "exclusive") return [adapterFile];
    const sources: string[] = [];
    for (const path of [
      join(homeDir, ".config", "mcp", "mcp.json"),
      join(homeDir, ".agents", "mcp.json"),
      join(homeDir, ".agents", "mcp", "mcp.json"),
    ]) {
      if (path !== adapterFile) sources.push(path);
    }
    sources.push(adapterFile);
    const project = join(cwd, ".mcp.json");
    if (project !== adapterFile) sources.push(project);
    sources.push(join(cwd, ".pi", MCP_ADAPTER_CONFIG_FILE_NAME));
    return [...new Set(sources)];
  } catch {
    return undefined;
  }
}

/** One source, read: absent, its raw text, or "could not be read". */
type SourceRead = { kind: "absent" } | { kind: "text"; text: string } | { kind: "failed" };

function isMissing(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** `open(O_NONBLOCK)` → `fstat` (regular, capped) → read from the descriptor. Never blocks. */
function readSource(path: string): SourceRead {
  let fd: number | undefined;
  try {
    try {
      fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    } catch (error) {
      return isMissing(error) ? { kind: "absent" } : { kind: "failed" };
    }
    const stats = fstatSync(fd);
    if (!stats.isFile()) return { kind: "failed" };
    if (!Number.isFinite(stats.size) || stats.size > MAX_MCP_CONFIG_BYTES) return { kind: "failed" };
    // One byte past the cap, so a file that grew after `fstat` is caught rather than truncated.
    const buffer = Buffer.alloc(MAX_MCP_CONFIG_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read <= 0) break;
      total += read;
    }
    if (total > MAX_MCP_CONFIG_BYTES) return { kind: "failed" };
    return { kind: "text", text: buffer.subarray(0, total).toString("utf8") };
  } catch {
    return { kind: "failed" };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // nothing to do
      }
    }
  }
}

interface ServerFields {
  url?: string;
  command?: string;
  args?: string[];
  type?: string;
}

/** The merged, fully-modelled view — or `undefined` when anything in any source is not modelled. */
export type McpServerView = Map<string, ServerFields> | undefined;

/** Strict parse + shape check of one source. `null` = unmodelled ⇒ omit everything. */
function modelledServers(text: string): Record<string, Record<string, unknown>> | null | "empty" {
  const raw = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  // `readValidatedConfig:1044`: an empty file is skipped. (A comment-only file is not empty here:
  // comments are not stripped, so it fails the strict parse below and omits.)
  if (raw.trim() === "") return "empty";
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;
  for (const key of Object.keys(parsed)) if (!KNOWN_TOP_LEVEL_KEYS.has(key)) return null;
  if (Object.hasOwn(parsed, "settings")) {
    const settings = parsed.settings;
    if (!isPlainObject(settings)) return null;
    for (const key of UNMODELLED_SETTINGS_KEYS) if (Object.hasOwn(settings, key)) return null;
  }
  if (!Object.hasOwn(parsed, "mcpServers")) return {};
  const servers = parsed.mcpServers;
  if (!isPlainObject(servers)) return null;
  const out: Record<string, Record<string, unknown>> = {};
  for (const name of Object.keys(servers)) {
    const def = servers[name];
    if (!isPlainObject(def)) return null;
    for (const key of Object.keys(def)) if (!KNOWN_SERVER_KEYS.has(key)) return null;
    if (Object.hasOwn(def, "socket")) return null;
    // The fields the result is built from must be exactly the types the merge rule keys on.
    if (Object.hasOwn(def, "url") && typeof def.url !== "string") return null;
    if (Object.hasOwn(def, "command") && typeof def.command !== "string") return null;
    if (Object.hasOwn(def, "args") && !(Array.isArray(def.args) && def.args.every((a) => typeof a === "string"))) {
      return null;
    }
    Object.defineProperty(out, name, { value: def, enumerable: true, writable: true, configurable: true });
  }
  return out;
}

/**
 * Read and merge every source, or `undefined`. The merge is `mergeServerMaps` (`config.ts:826-882`)
 * restricted to the modelled fields: a later `command` drops an inherited `url`; a later `url` drops
 * an inherited `command`/`args`; then the later definition's fields win.
 */
export function readMcpServerView(sources: readonly string[] | undefined): McpServerView {
  try {
    if (sources === undefined) return undefined;
    const merged = new Map<string, ServerFields>();
    for (const path of sources) {
      const read = readSource(path);
      if (read.kind === "absent") continue;
      if (read.kind === "failed") return undefined;
      const servers = modelledServers(read.text);
      if (servers === null) return undefined;
      if (servers === "empty") continue;
      for (const name of Object.keys(servers)) {
        const def = servers[name]!;
        const base: ServerFields = { ...(merged.get(name) ?? {}) };
        if (typeof def.command === "string") delete base.url;
        else if (typeof def.url === "string") {
          delete base.command;
          delete base.args;
        }
        if (typeof def.url === "string") base.url = def.url;
        if (typeof def.command === "string") base.command = def.command;
        if (Array.isArray(def.args)) base.args = [...(def.args as string[])];
        if (typeof def.type === "string") base.type = def.type;
        merged.set(name, base);
      }
    }
    return merged;
  } catch {
    return undefined;
  }
}

/** `{url, type?}` or `{command, args?, type?}` for exactly `serverName`, or `undefined`. */
export function projectServerConfig(view: McpServerView, serverName: string): Record<string, unknown> | undefined {
  try {
    if (view === undefined || typeof serverName !== "string" || serverName === "") return undefined;
    if (serverName.includes("__")) return undefined;
    const def = view.get(serverName);
    if (def === undefined) return undefined;
    const hasUrl = typeof def.url === "string" && def.url !== "";
    const hasCommand = typeof def.command === "string" && def.command !== "";
    // Both (a definition that set both at once) or neither: the transport is not unambiguous.
    if (hasUrl === hasCommand) return undefined;
    if (hasUrl) return typeof def.type === "string" ? { url: def.url, type: def.type } : { url: def.url };
    const out: Record<string, unknown> = { command: def.command };
    if (Array.isArray(def.args)) out.args = [...def.args];
    if (typeof def.type === "string") out.type = def.type;
    return out;
  } catch {
    return undefined;
  }
}

/** Link and target identity per path — dev, inode, size, mtime, ctime — or a sentinel. Total. */
export function signatureOf(paths: readonly string[]): string {
  const parts: string[] = [];
  for (const path of paths) {
    let part = `${path}=`;
    for (const stat of [lstatSync, statSync]) {
      try {
        const s = stat(path);
        part += `${s.dev}:${s.ino}:${s.size}:${s.mtimeMs}:${s.ctimeMs};`;
      } catch {
        part += "-;";
      }
    }
    parts.push(part);
  }
  return parts.join("|");
}

export interface McpConfigReader {
  /** Take the snapshot now, if none was taken yet (the adapter loads at session init). */
  snapshot(cwd: string): void;
  /** The config for exactly `serverName`, or `undefined` (see the header for every reason). */
  serverConfig(serverName: string, cwd: string): Record<string, unknown> | undefined;
}

/**
 * One snapshot per instance, taken only with a USABLE cwd.
 *
 *   * An unusable cwd (empty, relative, a throwing `ctx.cwd` — or a broker request before any
 *     `session_start`) omits the config for THAT call only and takes no snapshot, so the next call with
 *     a real cwd can still take one. Latching on it would omit every MCP config for the rest of the
 *     process, and a sanctioned-list org would then deny every MCP call.
 *   * A different real cwd than the snapshot's omits for that call only and leaves the snapshot alone:
 *     the snapshot describes what the adapter loaded for ITS cwd, and nothing about the other one is
 *     known. It does not weaken CR-02 — no other cwd's files are ever read or sent.
 *   * A changed file signature is permanent: the adapter is still running what it loaded, so nothing
 *     this reader could re-read describes it any more (review CR-02).
 */
export function createMcpConfigReader(options: McpConfigEnv): McpConfigReader {
  let snap: { cwd: string; sources: string[]; signature: string; view: McpServerView } | undefined;
  let invalidated = false;

  /** Take the snapshot when `cwd` is usable; `false` (and no snapshot) otherwise. */
  function take(cwd: string): boolean {
    const safeCwd = typeof cwd === "string" ? cwd : "";
    const sources = mcpConfigSources(options, safeCwd);
    if (sources === undefined) return false;
    const signature = signatureOf(sources);
    const view = readMcpServerView(sources);
    // A file that changed while it was being read: never trust that view.
    if (signatureOf(sources) !== signature) invalidated = true;
    snap = { cwd: safeCwd, sources, signature, view };
    return true;
  }

  return {
    snapshot(cwd: string): void {
      try {
        if (snap === undefined) take(cwd);
      } catch {
        // No snapshot: the next call with a usable cwd tries again.
      }
    },
    serverConfig(serverName: string, cwd: string): Record<string, unknown> | undefined {
      try {
        if (snap === undefined && !take(cwd)) return undefined;
        if (invalidated || snap === undefined || snap.view === undefined) return undefined;
        if (signatureOf(snap.sources) !== snap.signature) {
          invalidated = true;
          return undefined;
        }
        if (cwd !== snap.cwd) return undefined;
        return projectServerConfig(snap.view, serverName);
      } catch {
        return undefined;
      }
    },
  };
}
