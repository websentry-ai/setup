// `mcp_server_config` for a brokered MCP call: the server's `url`, or `command` + `args`, read from the
// pi-mcp-adapter's own config files by the broker's EXACT `serverName` — or nothing.
//
// The gateway fingerprints a server from this config to decide whether it is sanctioned, so a wrong
// config is worse than none: a project file the adapter honours but this reader ignored would let an
// unsanctioned binary borrow a sanctioned server's fingerprint (review CR-02). So the reader sees the
// files the way the adapter does, and when it cannot be sure, it says nothing:
//
//   * **Same files, same order** (`config.ts getConfigSources` / `loadMcpConfigWithSources`, adapter
//     4.0.0; later wins, merged per field per server): `~/.config/mcp/mcp.json`, `~/.agents/mcp.json`,
//     `~/.agents/mcp/mcp.json`, the adapter's own file (`<agentDir>/mcp-adapter.json`, or the path
//     given to pi's `--mcp-config` flag), `<cwd>/.mcp.json`, `<cwd>/.pi/mcp-adapter.json`.
//     `PI_MCP_CONFIG_MODE=exclusive` reads only the adapter's own file. A global path that IS the
//     adapter's own file is read once, at the adapter-file position, as the adapter does.
//   * **Same parsing**: a UTF-8 BOM, `//` and `/* */` comments and trailing commas are all accepted
//     (`utils.ts parseJsonWithComments`, ported below without the dependency); symlinks are FOLLOWED
//     (dotfile managers make every config a link). The FIFO protection `safeRead.ts` exists for is
//     kept by `stat`ing the TARGET and reading only a regular file under a generous 16 MiB cap.
//   * **Unknown ⇒ omitted.** If ANY source exists but cannot be read or parsed, if any source pulls in
//     servers this reader does not model (`imports`, `settings.ancestorConfigRoots`), or if the server
//     is not found, the answer is `undefined` and the request goes without `mcp_server_config`. The
//     gateway then treats the server as unknown (a null fingerprint), which in a sanctioning org is a
//     deny — fail-closed for the one case where guessing could have meant a spoof.
//
// **What is sent, and what is not.** `env`, `headers`, bearer tokens and OAuth settings are never even
// read into memory. `url` and `args` are sent as written — the same fields the Claude Code hook sends
// — and a `url` query string or an `args` entry CAN itself carry a credential (`?api_key=…`,
// `-e TOKEN=…`). That is parity egress, documented rather than claimed away.
//
// Memoised against each source's `stat` signature, one entry (the most recent cwd + flags) kept, so a
// warm lookup is six `stat`s. Every exported function is total.

import { readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { resolvePiAgentDir } from "../../core/src/cache.ts";
import {
  ENV_PI_MCP_CONFIG_MODE,
  MAX_MCP_CONFIG_BYTES,
  MCP_ADAPTER_CONFIG_FILE_NAME,
  MCP_CONFIG_FLAG,
} from "../../core/src/constants.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Strip `//` and `/* *\/` comments and trailing commas outside strings — the behaviour of
 * `strip-json-comments` with `{trailingCommas: true}`, which is what the adapter parses with. Comments
 * become whitespace; a comma followed only by whitespace/comments and then `}` or `]` is removed. An
 * unterminated block comment runs to the end, as there. Total on any string.
 */
export function stripJsonComments(text: string): string {
  const out: string[] = [];
  let pendingComma = -1;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      // A string, copied verbatim with its escapes.
      let j = i + 1;
      while (j < n) {
        const d = text[j]!;
        if (d === "\\") {
          j += 2;
          continue;
        }
        j += 1;
        if (d === '"') break;
      }
      out.push(text.slice(i, Math.min(j, n)));
      pendingComma = -1;
      i = j;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") {
      let j = i + 2;
      while (j < n && text[j] !== "\n" && text[j] !== "\r") j += 1;
      out.push(" ");
      i = j;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      out.push(" ");
      i = end === -1 ? n : end + 2;
      continue;
    }
    if (c === ",") {
      pendingComma = out.length;
      out.push(c);
      i += 1;
      continue;
    }
    if (c === "}" || c === "]") {
      if (pendingComma >= 0) out[pendingComma] = " ";
      pendingComma = -1;
      out.push(c);
      i += 1;
      continue;
    }
    if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") pendingComma = -1;
    out.push(c);
    i += 1;
  }
  return out.join("");
}

/** `parseJsonWithComments` (`utils.ts:13-15`): BOM, comments, trailing commas. Throws on bad JSON. */
export function parseJsonc(raw: string): unknown {
  const text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  return JSON.parse(stripJsonComments(text)) as unknown;
}

/** The `--mcp-config <path>` / `--mcp-config=<path>` value from argv, resolved like the adapter does. */
export function mcpConfigOverride(argv: readonly string[] | undefined): string | undefined {
  try {
    if (!Array.isArray(argv)) return undefined;
    let value: string | undefined;
    for (let i = 0; i < argv.length; i += 1) {
      const arg = argv[i];
      if (arg === MCP_CONFIG_FLAG) {
        const next = argv[i + 1];
        if (typeof next === "string" && next !== "") value = next;
      } else if (typeof arg === "string" && arg.startsWith(`${MCP_CONFIG_FLAG}=`)) {
        const inline = arg.slice(MCP_CONFIG_FLAG.length + 1);
        if (inline !== "") value = inline;
      }
    }
    return value === undefined ? undefined : resolve(value);
  } catch {
    return undefined;
  }
}

export interface McpConfigEnv {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  /** `process.argv` in production; injectable for tests. */
  argv?: readonly string[];
}

/** The sources in precedence order (later wins), as the adapter lists them. */
export function mcpConfigSources(options: McpConfigEnv, cwd: string): string[] {
  try {
    const env = options.env ?? {};
    const homeDir = typeof options.homeDir === "string" ? options.homeDir : "";
    const agentDir = resolvePiAgentDir(env, homeDir);
    const userPath =
      mcpConfigOverride(options.argv) ??
      (agentDir === undefined ? undefined : join(agentDir, MCP_ADAPTER_CONFIG_FILE_NAME));
    const mode = env[ENV_PI_MCP_CONFIG_MODE];
    if (typeof mode === "string" && mode.trim().toLowerCase() === "exclusive") {
      return userPath === undefined ? [] : [userPath];
    }
    const sources: string[] = [];
    if (homeDir !== "" && isAbsolute(homeDir)) {
      for (const path of [
        join(homeDir, ".config", "mcp", "mcp.json"),
        join(homeDir, ".agents", "mcp.json"),
        join(homeDir, ".agents", "mcp", "mcp.json"),
      ]) {
        // `getConfigSources:640-665`: a global path that is the adapter's own file is read at that
        // file's position instead.
        if (path !== userPath) sources.push(path);
      }
    }
    if (userPath !== undefined) sources.push(userPath);
    if (typeof cwd === "string" && cwd !== "" && isAbsolute(cwd)) {
      const project = join(cwd, ".mcp.json");
      if (project !== userPath) sources.push(project);
      sources.push(join(cwd, ".pi", MCP_ADAPTER_CONFIG_FILE_NAME));
    }
    return [...new Set(sources)];
  } catch {
    return [];
  }
}

/** One source, read: absent, a parsed value, or "could not be read/parsed". */
type SourceRead = { kind: "absent" } | { kind: "parsed"; value: unknown } | { kind: "failed" };

function isMissing(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** `stat` (follows links) → regular file within the cap → read → JSONC parse. Never blocks on a FIFO. */
function readSource(path: string): SourceRead {
  let size: number;
  try {
    const stats = statSync(path);
    if (!stats.isFile()) return { kind: "failed" };
    size = stats.size;
  } catch (error) {
    return isMissing(error) ? { kind: "absent" } : { kind: "failed" };
  }
  if (!Number.isFinite(size) || size > MAX_MCP_CONFIG_BYTES) return { kind: "failed" };
  try {
    const text = readFileSync(path, "utf8");
    // `readValidatedConfig:1044`: a file that is empty once comments are stripped is skipped, not an error.
    const stripped = stripJsonComments(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    if (stripped.trim() === "") return { kind: "absent" };
    return { kind: "parsed", value: parseJsonc(text) };
  } catch {
    return { kind: "failed" };
  }
}

interface ServerFields {
  url?: string;
  command?: string;
  args?: string[];
  type?: string;
}

/** The merged view: per-server kept fields, or `undefined` when the view cannot be trusted. */
type MergedServers = Map<string, ServerFields> | undefined;

function serversOf(parsed: Record<string, unknown>): Record<string, unknown> | undefined {
  if (isRecord(parsed.mcpServers)) return parsed.mcpServers;
  if (isRecord(parsed["mcp-servers"])) return parsed["mcp-servers"] as Record<string, unknown>;
  return undefined;
}

/** Read and merge every source. `undefined` = some source failed, or pulls in what is not modelled. */
export function readMcpServers(options: McpConfigEnv, cwd: string): MergedServers {
  try {
    const merged = new Map<string, ServerFields>();
    for (const path of mcpConfigSources(options, cwd)) {
      const read = readSource(path);
      if (read.kind === "absent") continue;
      if (read.kind === "failed") return undefined;
      const parsed = read.value;
      // `validateConfig:1052`: a non-object file contributes no servers.
      if (!isRecord(parsed)) continue;
      // Servers this reader cannot see (host imports, ancestor project files) could redefine a name.
      if (Array.isArray(parsed.imports) && parsed.imports.length > 0) return undefined;
      const settings = parsed.settings;
      if (isRecord(settings) && Array.isArray(settings.ancestorConfigRoots) && settings.ancestorConfigRoots.length > 0) {
        return undefined;
      }
      const servers = serversOf(parsed);
      if (servers === undefined) continue;
      for (const name of Object.keys(servers)) {
        const raw = servers[name];
        if (!isRecord(raw)) continue;
        const base: ServerFields = { ...(merged.get(name) ?? {}) };
        // `mergeServerMaps:826-880`: a later `command` drops an inherited `url`, a later `url` drops
        // an inherited `command`/`args`, so a repointed server is never described half-and-half.
        if (typeof raw.command === "string") delete base.url;
        if (typeof raw.url === "string") {
          delete base.command;
          delete base.args;
        }
        if (typeof raw.url === "string") base.url = raw.url;
        if (typeof raw.command === "string") base.command = raw.command;
        if (Array.isArray(raw.args)) {
          if (raw.args.every((arg) => typeof arg === "string")) base.args = [...(raw.args as string[])];
          else delete base.args;
        }
        if (typeof raw.type === "string") base.type = raw.type;
        merged.set(name, base);
      }
    }
    return merged;
  } catch {
    return undefined;
  }
}

/** `{url, type?}` or `{command, args?, type?}` for `serverName`, or `undefined`. */
export function projectServerConfig(servers: MergedServers, serverName: string): Record<string, unknown> | undefined {
  try {
    if (servers === undefined || typeof serverName !== "string" || serverName === "") return undefined;
    if (!servers.has(serverName)) return undefined;
    const def = servers.get(serverName)!;
    if (typeof def.url === "string" && def.url !== "") {
      return typeof def.type === "string" ? { url: def.url, type: def.type } : { url: def.url };
    }
    if (typeof def.command === "string" && def.command !== "") {
      const out: Record<string, unknown> = { command: def.command };
      if (Array.isArray(def.args)) out.args = [...def.args];
      if (typeof def.type === "string") out.type = def.type;
      return out;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** `mtimeMs:size` per source path (following links), or a sentinel. Total. */
function signatureOf(paths: readonly string[]): string {
  const parts: string[] = [];
  for (const path of paths) {
    try {
      const stats = statSync(path);
      parts.push(`${path}=${stats.mtimeMs}:${stats.size}:${stats.isFile() ? "f" : "x"}`);
    } catch {
      parts.push(`${path}=-`);
    }
  }
  return parts.join("|");
}

export interface McpConfigReader {
  /** The config for exactly `serverName` as the adapter would load it from `cwd`, or `undefined`. */
  serverConfig(serverName: string, cwd: string): Record<string, unknown> | undefined;
}

/** The memoised reader: one entry (most recent cwd/flags), re-read when any source's stat moves. */
export function createMcpConfigReader(options: McpConfigEnv): McpConfigReader {
  let memo: { key: string; servers: MergedServers } | undefined;
  return {
    serverConfig(serverName: string, cwd: string): Record<string, unknown> | undefined {
      try {
        const safeCwd = typeof cwd === "string" ? cwd : "";
        const sources = mcpConfigSources(options, safeCwd);
        const key = `${safeCwd}\u0000${signatureOf(sources)}`;
        if (memo === undefined || memo.key !== key) {
          memo = { key, servers: readMcpServers(options, safeCwd) };
        }
        return projectServerConfig(memo.servers, serverName);
      } catch {
        return undefined;
      }
    },
  };
}
