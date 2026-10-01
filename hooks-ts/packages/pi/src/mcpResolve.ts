// pi-mcp-adapter call resolution: one pi `tool_call` in, the MCP (server, original tool, args) it will
// actually run out — or `undefined`.
//
// pi has no native MCP. MCP tools reach it through the `pi-mcp-adapter` extension (4.0.0 at the time
// of writing), in three shapes, and the gateway can only enforce an MCP policy once the call is named
// as the adapter will run it:
//
//   | pi tool name          | input                       | what the adapter runs                    |
//   | --------------------- | --------------------------- | ---------------------------------------- |
//   | `mcp` (proxy)         | `{tool, args?, server?}`    | `executeCall` (`proxy-modes.ts:1194`)    |
//   | `mcp__<namespace>`    | `{tool, args?}`             | `namespace-tools.ts:110-175`             |
//   | `<prefix>_<tool>`     | the MCP tool's own args     | a direct tool (`direct-tool-surface.ts`) |
//
// **Names are mapped FORWARD, never parsed.** With `toolPrefix: "mcp"` a direct tool is
// `mcp__<server>_<tool>` (one underscore), and a namespace wrapper is `mcp__<namespace(server)>` — so
// `mcp__x_y` is either server `x_y`'s wrapper or server `x`'s tool `y`, and dashes in server names
// fold into the same underscores. Splitting the string would guess. Instead every candidate name is
// computed from the servers and tools the adapter itself knows about (its config files plus
// `mcp-cache.json`), with the adapter's own naming functions ported below, and a name is resolved
// only when exactly one (server, tool) produces it.
//
// **Fail-safe means "today's behaviour".** Wherever the adapter itself would refuse (ambiguous match,
// unparseable args, a missing `tool`, a non-call `action`) or the mapping is ambiguous, the answer is
// `undefined` and the caller keeps today's path for an unevaluable custom tool: no request, allowed.
// Resource reads (`read_<x>`) and `mcpScript` are never resolved — the gateway has no shape for the
// first, and the second can call several tools per invocation, so no single pretool check describes it.
//
// **Only the config subset that names servers is read**, with the adapter's precedence (later wins,
// merged per field per server — `config.ts loadMcpConfigWithSources:424-503`, `mergeServerMaps:826`):
// `~/.config/mcp/mcp.json`, `~/.agents/mcp.json`, `~/.agents/mcp/mcp.json`, `<agentDir>/mcp-adapter.json`,
// `<cwd>/.mcp.json`, `<cwd>/.pi/mcp-adapter.json`; `PI_MCP_CONFIG_MODE=exclusive` reads only the
// agent-dir file. Imports, plugins and opt-in ancestor files are not read (a documented gap). Of each
// server only `url`, `command`, `args`, `type`, `toolPrefix` and `disabled` are kept — `env`, `headers`,
// `bearerToken`, `oauth` and everything else are never even held, so they cannot be sent.
//
// **Cost on the `tool_call` path.** pi awaits every tool call, and this runs for every non-native one,
// so: the eight native/shell names return before any filesystem access; every read goes through
// `readSmallRegularFile` (lstat first, regular files only, size-capped — never blocks on a FIFO); and
// the parsed config and cache are memoised against each file's lstat `mtimeMs`+`size`, keeping only the
// most recent cwd's entry. Warm, a resolve costs seven lstats.
//
// Every exported function is total. A throw here would surface inside `tool_call`, where pi reads it
// as a BLOCK. No `pi-mcp-adapter` import: the bundle stays dependency-free, so the small pure naming
// helpers are ported with their source lines cited.

import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import { resolvePiAgentDir } from "../../core/src/cache.ts";
import {
  ENV_PI_MCP_CONFIG_MODE,
  MAX_CONFIG_BYTES,
  MAX_MCP_CACHE_BYTES,
  MCP_ADAPTER_CONFIG_FILE_NAME,
  MCP_CACHE_FILE_NAME,
  MCP_NAMESPACE_TOOL_PREFIX,
  MCP_PROXY_NON_CALL_ACTIONS,
  MCP_PROXY_TOOL_NAME,
} from "../../core/src/constants.ts";
import { readSmallRegularFile } from "../../core/src/safeRead.ts";
import type { McpCallInfo } from "../../core/src/types.ts";

export type McpCall = McpCallInfo;

/** The adapter's prefix modes (`types.ts:540`). */
export type ToolPrefix = "server" | "none" | "short" | "mcp";

const TOOL_PREFIXES: ReadonlySet<string> = new Set(["server", "none", "short", "mcp"]);

/** One server, reduced to what naming and `mcp_server_config` need. */
export interface McpServerDef {
  url?: string;
  command?: string;
  args?: string[];
  type?: string;
  toolPrefix?: ToolPrefix;
  disabled?: boolean;
}

export interface McpAdapterConfig {
  servers: Map<string, McpServerDef>;
  settings: { toolPrefix?: ToolPrefix; namespaceProxyTools?: boolean };
}

/** Server name → the ORIGINAL MCP tool names the cache lists for it. */
export type McpCache = Map<string, string[]>;

const EMPTY_CONFIG = (): McpAdapterConfig => ({ servers: new Map(), settings: {} });

/**
 * pi's own tools. The adapter refuses direct names that collide with builtins
 * (`direct-tool-surface.ts:10`), so none of these can ever be an MCP call — and they are most of the
 * traffic, so they must not cost a single syscall.
 */
const NATIVE_TOOL_NAMES: ReadonlySet<string> = new Set([
  "bash",
  "powershell",
  "read",
  "write",
  "edit",
  "grep",
  "find",
  "ls",
]);

/** `direct-tool-surface.ts:10` — names a direct tool can never be registered under. */
const BUILTIN_NAMES: ReadonlySet<string> = new Set(["read", "bash", "edit", "write", "grep", "find", "ls", "mcp"]);

const NON_CALL_ACTIONS: ReadonlySet<string> = new Set(MCP_PROXY_NON_CALL_ACTIONS);

// --- Ported naming helpers (pi-mcp-adapter 4.0.0 `types.ts`) -----------------------------------------

const ENCODED_SERVER_NAMESPACE_MARKER = "_mcpns_";
const MAX_SERVER_NAMESPACE_LENGTH = 59;

/** `types.ts:561-566` `encodeServerNamespace`. */
function encodeServerNamespace(name: string): string {
  return Array.from(name, (character) => {
    if (character === "_") return "__";
    return /^[A-Za-z0-9]$/.test(character) ? character : `_${character.codePointAt(0)!.toString(16)}_`;
  }).join("");
}

/** `types.ts:546-558` `formatServerNamespace`, verbatim. */
export function formatServerNamespace(serverName: string): string {
  const normalized = serverName.replace(/-/g, "_");
  const safe = /^[A-Za-z0-9_]*$/.test(normalized) && !normalized.startsWith(ENCODED_SERVER_NAMESPACE_MARKER);
  const body = safe ? normalized : encodeServerNamespace(normalized);
  const namespace = safe ? body : `${ENCODED_SERVER_NAMESPACE_MARKER}${body}`;
  if (namespace.length <= MAX_SERVER_NAMESPACE_LENGTH) return namespace;
  const digest = createHash("sha256").update(namespace, "utf8").digest("hex").slice(0, 16);
  const hashPrefix = `${ENCODED_SERVER_NAMESPACE_MARKER}_h_`;
  const head = body.slice(0, MAX_SERVER_NAMESPACE_LENGTH - hashPrefix.length - digest.length - 1);
  return `${hashPrefix}${head}_${digest}`;
}

/** `types.ts:855-860` `sanitizeServerPrefix`. */
function sanitizeServerPrefix(serverName: string, preserveProviderValid = true): string {
  const validCharacters = preserveProviderValid ? /^[A-Za-z0-9_-]$/ : /^[A-Za-z0-9]$/;
  return Array.from(serverName, (char) =>
    validCharacters.test(char) ? char : `_${char.codePointAt(0)!.toString(16)}_`,
  ).join("");
}

/** `types.ts:862-874` `getServerPrefix`. */
export function getServerPrefix(serverName: string, mode: ToolPrefix): string {
  if (mode === "none") return "";
  if (mode === "short") {
    let short = sanitizeServerPrefix(serverName.replace(/-?mcp$/i, ""));
    if (!short) short = "mcp";
    return short;
  }
  if (mode === "mcp") return `mcp__${sanitizeServerPrefix(serverName)}`;
  return sanitizeServerPrefix(serverName);
}

/** `types.ts:879-890` `formatToolName`. */
export function formatToolName(toolName: string, serverName: string, prefix: ToolPrefix): string {
  const p = getServerPrefix(serverName, prefix);
  const sanitized = toolName.replace(/\./g, "_");
  if (p && sanitized.startsWith(`${p}_`) && sanitized.length > p.length + 1) {
    return sanitized;
  }
  return p ? `${p}_${sanitized}` : sanitized;
}

/** `types.ts:892-897` `resolveToolPrefix`: per-server, then global, then `"server"`. */
function resolveToolPrefix(definition: McpServerDef | undefined, globalPrefix?: ToolPrefix): ToolPrefix {
  return definition?.toolPrefix ?? globalPrefix ?? "server";
}

/** `types.ts:972-977` `getLegacyServerPrefix`. */
function getLegacyServerPrefix(serverName: string, mode: ToolPrefix): string {
  if (mode === "none") return "";
  if (mode === "short") return sanitizeServerPrefix(serverName.replace(/-?mcp$/i, ""), false) || "mcp";
  if (mode === "mcp") return `mcp__${sanitizeServerPrefix(serverName, false)}`;
  return sanitizeServerPrefix(serverName, false);
}

/** `types.ts:979-983` `formatLegacyToolName`. */
function formatLegacyToolName(toolName: string, serverName: string, prefix: ToolPrefix): string {
  const serverPrefix = getLegacyServerPrefix(serverName, prefix);
  const sanitizedToolName = toolName.replace(/[.-]/g, "_");
  return serverPrefix ? `${serverPrefix}_${sanitizedToolName}` : sanitizedToolName;
}

/** `types.ts:985-1010` `getToolNameCandidates` (with the legacy forms, as the call path uses it). */
export function getToolNameCandidates(toolName: string, serverName: string, prefix: ToolPrefix): Set<string> {
  const candidates = new Set<string>([
    toolName,
    formatToolName(toolName, serverName, prefix),
    formatToolName(toolName, serverName, "server"),
    formatToolName(toolName, serverName, "short"),
    formatToolName(toolName, serverName, "mcp"),
  ]);
  const legacyToolName = toolName.replace(/-/g, "_");
  candidates.add(legacyToolName);
  candidates.add(formatToolName(legacyToolName, serverName, prefix));
  candidates.add(formatToolName(legacyToolName, serverName, "server"));
  candidates.add(formatToolName(legacyToolName, serverName, "short"));
  candidates.add(formatToolName(legacyToolName, serverName, "mcp"));
  candidates.add(formatLegacyToolName(toolName, serverName, prefix));
  candidates.add(formatLegacyToolName(toolName, serverName, "server"));
  candidates.add(formatLegacyToolName(toolName, serverName, "short"));
  candidates.add(formatLegacyToolName(toolName, serverName, "mcp"));
  candidates.add(formatToolName(toolName, serverName, prefix).replace(/-/g, "_"));
  candidates.add(formatToolName(toolName, serverName, "server").replace(/-/g, "_"));
  candidates.add(formatToolName(toolName, serverName, "short").replace(/-/g, "_"));
  candidates.add(formatToolName(toolName, serverName, "mcp").replace(/-/g, "_"));
  return candidates;
}

// --- Config + cache readers ---------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseJson(text: string | undefined): unknown {
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** The six config sources, in precedence order (later wins). Absolute paths only. */
export function mcpConfigPaths(env: NodeJS.ProcessEnv, homeDir: string, cwd: string): string[] {
  try {
    const agentDir = resolvePiAgentDir(env, homeDir);
    const adapterFile = agentDir === undefined ? undefined : join(agentDir, MCP_ADAPTER_CONFIG_FILE_NAME);
    const mode = env?.[ENV_PI_MCP_CONFIG_MODE];
    if (typeof mode === "string" && mode.trim().toLowerCase() === "exclusive") {
      return adapterFile === undefined ? [] : [adapterFile];
    }
    const paths: string[] = [];
    if (typeof homeDir === "string" && homeDir !== "" && isAbsolute(homeDir)) {
      paths.push(join(homeDir, ".config", "mcp", "mcp.json"));
      paths.push(join(homeDir, ".agents", "mcp.json"));
      paths.push(join(homeDir, ".agents", "mcp", "mcp.json"));
    }
    if (adapterFile !== undefined) paths.push(adapterFile);
    if (typeof cwd === "string" && cwd !== "" && isAbsolute(cwd)) {
      paths.push(join(cwd, ".mcp.json"));
      paths.push(join(cwd, ".pi", MCP_ADAPTER_CONFIG_FILE_NAME));
    }
    // The adapter de-duplicates sources that resolve to the same file (`getConfigSources:640-720`);
    // reading one twice would only re-apply the same values, but the first occurrence is kept anyway.
    return [...new Set(paths)];
  } catch {
    return [];
  }
}

/** One source's server entry, projected to the kept fields. `args` that is not all strings is dropped. */
function projectServer(raw: unknown): (McpServerDef & { argsInvalid?: true }) | undefined {
  if (!isRecord(raw)) return undefined;
  const out: McpServerDef & { argsInvalid?: true } = {};
  if (typeof raw.url === "string") out.url = raw.url;
  if (typeof raw.command === "string") out.command = raw.command;
  if (Array.isArray(raw.args)) {
    if (raw.args.every((arg) => typeof arg === "string")) out.args = [...(raw.args as string[])];
    else out.argsInvalid = true;
  }
  if (typeof raw.type === "string") out.type = raw.type;
  if (typeof raw.toolPrefix === "string" && TOOL_PREFIXES.has(raw.toolPrefix)) {
    out.toolPrefix = raw.toolPrefix as ToolPrefix;
  }
  if (typeof raw.disabled === "boolean") out.disabled = raw.disabled;
  return out;
}

/**
 * Merge one source into the accumulated config, per field per server, later wins — and, like
 * `mergeServerMaps:826-880`, a later `command` drops an inherited `url` and a later `url` drops an
 * inherited `command`/`args`, so a repointed server is never described half-and-half.
 */
function mergeSource(target: McpAdapterConfig, parsed: unknown): void {
  if (!isRecord(parsed)) return;
  const servers = isRecord(parsed.mcpServers)
    ? parsed.mcpServers
    : isRecord(parsed["mcp-servers"])
      ? (parsed["mcp-servers"] as Record<string, unknown>)
      : undefined;
  if (servers !== undefined) {
    for (const [name, raw] of Object.entries(servers)) {
      const next = projectServer(raw);
      if (next === undefined) continue;
      const base: McpServerDef = { ...(target.servers.get(name) ?? {}) };
      if (typeof next.command === "string") delete base.url;
      if (typeof next.url === "string") {
        delete base.command;
        delete base.args;
      }
      if (next.argsInvalid === true) delete base.args;
      const { argsInvalid: _ignored, ...fields } = next;
      target.servers.set(name, { ...base, ...fields });
    }
  }
  const settings = parsed.settings;
  if (isRecord(settings)) {
    if (typeof settings.toolPrefix === "string" && TOOL_PREFIXES.has(settings.toolPrefix)) {
      target.settings.toolPrefix = settings.toolPrefix as ToolPrefix;
    }
    if (typeof settings.namespaceProxyTools === "boolean") {
      target.settings.namespaceProxyTools = settings.namespaceProxyTools;
    }
  }
}

/** Read and merge the adapter's config sources. Total: any failure is an empty config. */
export function readMcpAdapterConfig(env: NodeJS.ProcessEnv, homeDir: string, cwd: string): McpAdapterConfig {
  const config = EMPTY_CONFIG();
  try {
    for (const path of mcpConfigPaths(env, homeDir, cwd)) {
      mergeSource(config, parseJson(readSmallRegularFile(path, MAX_CONFIG_BYTES)));
    }
    return config;
  } catch {
    return EMPTY_CONFIG();
  }
}

/** `<agentDir>/mcp-cache.json` as server → original tool names. `resources` are ignored. Total. */
export function readMcpCache(agentDir: string | undefined): McpCache {
  const cache: McpCache = new Map();
  try {
    if (typeof agentDir !== "string" || agentDir === "") return cache;
    const parsed = parseJson(readSmallRegularFile(join(agentDir, MCP_CACHE_FILE_NAME), MAX_MCP_CACHE_BYTES));
    if (!isRecord(parsed) || !isRecord(parsed.servers)) return cache;
    for (const [server, entry] of Object.entries(parsed.servers)) {
      if (!isRecord(entry) || !Array.isArray(entry.tools)) continue;
      const names: string[] = [];
      for (const tool of entry.tools) {
        if (isRecord(tool) && typeof tool.name === "string" && tool.name !== "") names.push(tool.name);
      }
      cache.set(server, names);
    }
    return cache;
  } catch {
    return new Map();
  }
}

// --- Resolution ---------------------------------------------------------------------------------

/** The secret-free `mcp_server_config`: `{url, type?}` or `{command, args?, type?}`, or nothing. */
function projectServerConfig(def: McpServerDef | undefined): Record<string, unknown> | undefined {
  if (def === undefined) return undefined;
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
}

/**
 * The proxy's argument parsing (`index.ts:1934-1955`): absent or `""` → `{}`, a string is JSON that
 * must parse to an object, anything else must already be one. `undefined` = the adapter would throw.
 */
function parseArgs(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined || value === "") return {};
  let args: unknown = value;
  if (typeof value === "string") {
    try {
      args = JSON.parse(value) as unknown;
    } catch {
      return undefined;
    }
  }
  return isRecord(args) ? args : undefined;
}

interface Universe {
  config: McpAdapterConfig;
  cache: McpCache;
  /** Every enabled server known to config ∪ cache, in a stable order. */
  servers: string[];
}

function universeOf(config: McpAdapterConfig, cache: McpCache): Universe {
  const names = new Set<string>([...config.servers.keys(), ...cache.keys()]);
  const servers = [...names].filter((name) => config.servers.get(name)?.disabled !== true);
  return { config, cache, servers };
}

function prefixOf(u: Universe, server: string): ToolPrefix {
  return resolveToolPrefix(u.config.servers.get(server), u.config.settings.toolPrefix);
}

/**
 * A tool requested on a KNOWN server → its original name, mirroring `getCandidateToolMatch`
 * (`proxy-modes.ts:137-147`): the exact prefixed name, then the candidate set; two hits is the
 * adapter's "ambiguous" (`undefined`). With nothing cached it degrades to the best server-level
 * answer: the requested name minus `<prefix>_`, so sanction and server-scoped policy still apply.
 */
function toolOnServer(u: Universe, server: string, requested: string): string | undefined {
  const prefix = prefixOf(u, server);
  const tools = u.cache.get(server) ?? [];
  const exact = tools.filter((tool) => formatToolName(tool, server, prefix) === requested);
  if (exact.length > 0) return exact.length === 1 ? exact[0] : undefined;
  const candidates = tools.filter((tool) => getToolNameCandidates(tool, server, prefix).has(requested));
  if (candidates.length > 1) return undefined;
  if (candidates.length === 1) return candidates[0];
  const p = getServerPrefix(server, prefix);
  if (p !== "" && requested.startsWith(`${p}_`) && requested.length > p.length + 1) {
    return requested.slice(p.length + 1);
  }
  return requested;
}

/** The unique element, or `undefined` for none and for many. */
function only<T>(items: readonly T[]): T | undefined {
  return items.length === 1 ? items[0] : undefined;
}

function resolveProxy(u: Universe, input: Record<string, unknown>): Omit<McpCall, "serverConfig"> | undefined {
  const tool = input.tool;
  if (typeof tool !== "string" || tool === "") return undefined;
  if (typeof input.action === "string" && NON_CALL_ACTIONS.has(input.action)) return undefined;
  const args = parseArgs(input.args);
  if (args === undefined) return undefined;

  const requestedServer = input.server;
  if (typeof requestedServer === "string" && requestedServer !== "") {
    if (!u.servers.includes(requestedServer)) return undefined;
    const original = toolOnServer(u, requestedServer, tool);
    return original === undefined ? undefined : { server: requestedServer, tool: original, args };
  }
  if (requestedServer !== undefined && requestedServer !== "") return undefined;

  // `executeCall:1236-1262`, step by step. More than one hit at any step is the adapter's own
  // "ambiguous" and nothing runs; exactly one ends the search.
  const prefixed: { server: string; tool: string }[] = [];
  const original: { server: string; tool: string }[] = [];
  for (const server of u.servers) {
    const prefix = prefixOf(u, server);
    for (const name of u.cache.get(server) ?? []) {
      if (formatToolName(name, server, prefix) === tool) prefixed.push({ server, tool: name });
      if (name === tool) original.push({ server, tool: name });
    }
  }
  if (prefixed.length > 1) return undefined;
  if (prefixed.length === 1) return { ...prefixed[0]!, args };
  if (original.length > 1) return undefined;
  if (original.length === 1) return { ...original[0]!, args };

  // `getPrefixedServerScope:149-163` — CONFIGURED servers only, so it works with a cold cache.
  const scoped = u.servers
    .filter((server) => u.config.servers.has(server))
    .map((server) => ({ server, prefix: getServerPrefix(server, prefixOf(u, server)) }))
    .filter(({ prefix }) => prefix.length > 0 && tool.startsWith(`${prefix}_`))
    .sort((a, b) => b.prefix.length - a.prefix.length);
  if (scoped.length > 0) {
    const longest = scoped[0]!.prefix.length;
    const best = only(scoped.filter(({ prefix }) => prefix.length === longest));
    if (best === undefined) return undefined;
    const resolved = toolOnServer(u, best.server, tool);
    return resolved === undefined ? undefined : { server: best.server, tool: resolved, args };
  }

  const candidates: { server: string; tool: string }[] = [];
  for (const server of u.servers) {
    const prefix = prefixOf(u, server);
    for (const name of u.cache.get(server) ?? []) {
      if (getToolNameCandidates(name, server, prefix).has(tool)) candidates.push({ server, tool: name });
    }
  }
  const match = only(candidates);
  return match === undefined ? undefined : { ...match, args };
}

/** Servers whose namespace wrapper is exactly `toolName`. */
function namespaceOwners(u: Universe, toolName: string): string[] {
  if (u.config.settings.namespaceProxyTools === false) return [];
  if (!toolName.startsWith(MCP_NAMESPACE_TOOL_PREFIX)) return [];
  return u.servers.filter((server) => MCP_NAMESPACE_TOOL_PREFIX + formatServerNamespace(server) === toolName);
}

/** (server, original tool) pairs whose direct-tool name is exactly `toolName` (`direct-tool-surface.ts:140-155`). */
function directOwners(u: Universe, toolName: string): { server: string; tool: string }[] {
  if (BUILTIN_NAMES.has(toolName)) return [];
  const owners: { server: string; tool: string }[] = [];
  for (const server of u.servers) {
    const prefix = prefixOf(u, server);
    for (const name of u.cache.get(server) ?? []) {
      if (formatToolName(name, server, prefix) === toolName) owners.push({ server, tool: name });
    }
  }
  return owners;
}

function withConfig(u: Universe, call: Omit<McpCall, "serverConfig">): McpCall {
  const serverConfig = projectServerConfig(u.config.servers.get(call.server));
  return serverConfig === undefined ? { ...call } : { ...call, serverConfig };
}

/**
 * Resolve one pi tool call against an already-read config and cache. Pure and total: `undefined` for
 * every non-MCP, ambiguous, refused or unreadable case.
 */
export function resolveMcpCall(
  toolName: string,
  input: unknown,
  config: McpAdapterConfig,
  cache: McpCache,
): McpCall | undefined {
  try {
    if (typeof toolName !== "string" || toolName === "" || NATIVE_TOOL_NAMES.has(toolName)) return undefined;
    const u = universeOf(config, cache);
    if (u.servers.length === 0) return undefined;

    if (toolName === MCP_PROXY_TOOL_NAME) {
      if (!isRecord(input)) return undefined;
      const call = resolveProxy(u, input);
      return call === undefined ? undefined : withConfig(u, call);
    }

    // A name that is both a namespace wrapper and a direct tool — or that two servers claim — is
    // exactly the collision forward-mapping exists to catch. Unique ownership or nothing.
    const namespaces = namespaceOwners(u, toolName);
    const directs = directOwners(u, toolName);
    if (namespaces.length + directs.length !== 1) return undefined;

    const namespaceServer = only(namespaces);
    if (namespaceServer !== undefined) {
      if (!isRecord(input)) return undefined;
      const tool = input.tool;
      // `namespace-tools.ts:123-128`: a wrapper call without `tool` is the adapter's `missing_tool`.
      if (typeof tool !== "string" || tool === "") return undefined;
      const args = parseArgs(input.args);
      if (args === undefined) return undefined;
      const original = toolOnServer(u, namespaceServer, tool);
      return original === undefined ? undefined : withConfig(u, { server: namespaceServer, tool: original, args });
    }

    const direct = only(directs);
    if (direct === undefined) return undefined;
    // A direct tool's input IS the MCP arguments.
    return withConfig(u, { server: direct.server, tool: direct.tool, args: isRecord(input) ? input : {} });
  } catch {
    return undefined;
  }
}

// --- The memoised resolver ----------------------------------------------------------------------

/** `mtimeMs:size` per path, or a sentinel for anything lstat cannot see. Total. */
function signatureOf(paths: readonly string[]): string {
  const parts: string[] = [];
  for (const path of paths) {
    try {
      const stats = lstatSync(path);
      parts.push(`${path}=${stats.mtimeMs}:${stats.size}:${stats.isFile() ? "f" : "x"}`);
    } catch {
      parts.push(`${path}=-`);
    }
  }
  return parts.join("|");
}

export interface McpResolver {
  resolve(toolName: string, input: unknown, cwd: string): McpCall | undefined;
}

export interface McpResolverOptions {
  env: NodeJS.ProcessEnv;
  homeDir: string;
}

/**
 * The resolver `tool_call` uses: config and cache read lazily, memoised against each file's lstat
 * signature, one entry (the most recent cwd) kept. Native and shell tool names return before any
 * filesystem access. Total.
 */
export function createMcpResolver(options: McpResolverOptions): McpResolver {
  let memo: { cwd: string; signature: string; config: McpAdapterConfig; cache: McpCache } | undefined;

  return {
    resolve(toolName: string, input: unknown, cwd: string): McpCall | undefined {
      try {
        if (typeof toolName !== "string" || toolName === "" || NATIVE_TOOL_NAMES.has(toolName)) {
          return undefined;
        }
        const env = options.env ?? {};
        const homeDir = typeof options.homeDir === "string" ? options.homeDir : "";
        const safeCwd = typeof cwd === "string" ? cwd : "";
        const agentDir = resolvePiAgentDir(env, homeDir);
        const configPaths = mcpConfigPaths(env, homeDir, safeCwd);
        const cachePath = agentDir === undefined ? undefined : join(agentDir, MCP_CACHE_FILE_NAME);
        const signature = signatureOf(cachePath === undefined ? configPaths : [...configPaths, cachePath]);

        if (memo === undefined || memo.cwd !== safeCwd || memo.signature !== signature) {
          memo = {
            cwd: safeCwd,
            signature,
            config: readMcpAdapterConfig(env, homeDir, safeCwd),
            cache: readMcpCache(agentDir),
          };
        }
        return resolveMcpCall(toolName, input, memo.config, memo.cache);
      } catch {
        return undefined;
      }
    },
  };
}
