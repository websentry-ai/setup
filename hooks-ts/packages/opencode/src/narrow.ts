// Pure readers over opencode tool calls: the places where silent non-enforcement hides (PITFALLS
// Pitfall 8). Each helper answers one question exactly, from untrusted model arguments:
//
//   * `shellCommandOf` / `shellCwdOf` — the command a shell tool runs and the directory it runs in
//     (`workdir ?? instance directory`). A wrong cwd mis-resolves every relative path in a policy.
//   * `applyPatchTargets` — EVERY file an `apply_patch` touches. Checking only the first header would
//     let a second file in the same patch through unchecked.
//   * `resolveMcpTool` / `mcpResourceTarget` — which configured MCP server a tool id belongs to.
//     opencode's key is `sanitize(server) + "_" + sanitize(tool)`, which is lossy (a server name may
//     itself contain `_`), so the id is matched against the CONFIGURED server names by longest prefix
//     and never split on `_`. Unknown means no MCP attribution, not a guess.
//   * `argsDigest` — a key-order-independent fingerprint of a call's args, so the adapter can notice
//     args that changed after they were checked.
//
// Every export is total: any input, including null, wrong types and getters that raise, gets a safe
// answer (`""`, `undefined`, an empty target list). Nothing in this file raises.

import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import { MAX_PATCH_TARGETS } from "./constants.ts";

/** The shell tool id: `bash` until opencode 2.0 (`oc:opencode/src/tool/shell/id.ts`). */
export const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash"]);

/** The sub-agent tool; its prompt is the child session's first message, not a command. */
export const TASK_TOOL = "task";

/** The three MCP resource tools, which carry their server as an argument instead of in the id. */
export const MCP_RESOURCE_TOOLS: ReadonlySet<string> = new Set([
  "list_mcp_resources",
  "list_mcp_resource_templates",
  "read_mcp_resource",
]);

/** opencode's built-in tool ids (FEATURES §1 tool table). Any other id is a plugin or MCP tool. */
export const BUILTIN_TOOLS: ReadonlySet<string> = new Set([
  "bash",
  "read",
  "write",
  "edit",
  "apply_patch",
  "glob",
  "grep",
  "webfetch",
  "websearch",
  TASK_TOOL,
  "todowrite",
  "skill",
  "question",
  "invalid",
  "lsp",
  "plan_exit",
  "execute",
  ...MCP_RESOURCE_TOOLS,
]);

/**
 * The patch header prefixes that name a file, in the order ai-gateway's
 * `src/services/effectiveCommand.ts` `PATCH_HEADER_PREFIXES` lists them.
 */
export const PATCH_HEADER_PREFIXES: readonly string[] = Object.freeze([
  "*** Add File:",
  "*** Update File:",
  "*** Delete File:",
  "*** Move to:",
]);

/** The most MCP server names compared for one tool id. A real config has a handful. */
const MAX_MCP_SERVERS = 1024;
/** `argsDigest` gives up past this nesting depth. */
const MAX_DIGEST_DEPTH = 32;
/** `argsDigest` gives up once the canonical form passes this many characters. */
const MAX_DIGEST_CHARS = 1024 * 1024;

function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function nonBlank(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

// --- shell --------------------------------------------------------------------------------------

/** The command a shell tool call runs, or `""` when this is not a shell call or has no command. */
export function shellCommandOf(tool: string, args: unknown): string {
  try {
    if (typeof tool !== "string" || !SHELL_TOOLS.has(tool)) return "";
    const command = readField(args, "command");
    return typeof command === "string" ? command : "";
  } catch {
    return "";
  }
}

/**
 * Where a shell call runs: its `workdir` when that is an absolute path, else the instance
 * `directory`. A relative workdir is not resolved here (the adapter has no safe base to resolve it
 * against that matches the tool's own resolution), so the instance directory stands.
 */
export function shellCwdOf(args: unknown, directory: string): string {
  const fallback = typeof directory === "string" ? directory : "";
  try {
    const workdir = readField(args, "workdir");
    return typeof workdir === "string" && workdir.length > 0 && isAbsolute(workdir) ? workdir : fallback;
  } catch {
    return fallback;
  }
}

// --- apply_patch --------------------------------------------------------------------------------

/**
 * Every distinct file path an `apply_patch` text names on an Add/Update/Delete/Move-to header line,
 * in first-seen order. The same superset rule as the server: a header is accepted on any line and
 * after leading whitespace, the rest of the line is trimmed, CRLF is accepted. A malformed patch can
 * only add targets, never hide one. Past `MAX_PATCH_TARGETS` distinct paths the list stops and
 * `capped` is true, so the adapter can signal it rather than silently check a prefix.
 */
export function applyPatchTargets(patchText: unknown): { targets: string[]; capped: boolean } {
  try {
    if (typeof patchText !== "string" || patchText === "") return { targets: [], capped: false };
    const seen = new Set<string>();
    for (const raw of patchText.split(/\r?\n/)) {
      const line = raw.trimStart();
      if (!line.startsWith("***")) continue;
      const prefix = PATCH_HEADER_PREFIXES.find((p) => line.startsWith(p));
      if (prefix === undefined) continue;
      const path = line.slice(prefix.length).trim();
      if (path === "" || seen.has(path)) continue;
      if (seen.size >= MAX_PATCH_TARGETS) return { targets: [...seen], capped: true };
      seen.add(path);
    }
    return { targets: [...seen], capped: false };
  } catch {
    return { targets: [], capped: false };
  }
}

// --- MCP ----------------------------------------------------------------------------------------

/** opencode's MCP key sanitiser, exactly: `oc:opencode/src/mcp/catalog.ts:117`. */
export function sanitizeMcpName(value: string): string {
  return typeof value === "string" ? value.replace(/[^a-zA-Z0-9_-]/g, "_") : "";
}

/**
 * The configured MCP server an opencode tool id belongs to, and the tool part of the id.
 *
 * The id is `sanitize(server) + "_" + sanitize(tool)`. A configured name matches when that prefix
 * starts the id and leaves a non-empty remainder; the LONGEST matching prefix wins, so `my_server`
 * beats `my` for `my_server_list_files`. The returned `server` is the configured (original) name.
 * Two configured names that sanitise to the same prefix collide in opencode itself (both register
 * the same key); here the lexicographically smaller original name is returned, so the answer is
 * deterministic. No match is `undefined`: the caller sends no MCP attribution rather than a guess.
 */
export function resolveMcpTool(
  toolId: string,
  serverNames: readonly string[],
): { server: string; tool: string } | undefined {
  try {
    if (typeof toolId !== "string" || toolId === "" || !Array.isArray(serverNames)) return undefined;
    let best: { server: string; prefixLength: number } | undefined;
    const count = Math.min(serverNames.length, MAX_MCP_SERVERS);
    for (let i = 0; i < count; i += 1) {
      const name: unknown = serverNames[i];
      if (typeof name !== "string" || name === "") continue;
      const prefix = `${sanitizeMcpName(name)}_`;
      if (toolId.length <= prefix.length || !toolId.startsWith(prefix)) continue;
      if (
        best === undefined ||
        prefix.length > best.prefixLength ||
        (prefix.length === best.prefixLength && name < best.server)
      ) {
        best = { server: name, prefixLength: prefix.length };
      }
    }
    return best === undefined ? undefined : { server: best.server, tool: toolId.slice(best.prefixLength) };
  } catch {
    return undefined;
  }
}

/** For an MCP resource tool, its `server` argument as the attribution; `undefined` otherwise. */
export function mcpResourceTarget(tool: string, args: unknown): { server: string; tool: string } | undefined {
  try {
    if (typeof tool !== "string" || !MCP_RESOURCE_TOOLS.has(tool)) return undefined;
    const server = nonBlank(readField(args, "server"));
    return server === undefined ? undefined : { server, tool };
  } catch {
    return undefined;
  }
}

// --- args digest --------------------------------------------------------------------------------

// Canonical JSON with recursively sorted object keys, with JSON's own rules for values it cannot
// represent (omitted in an object, `null` in an array, non-finite numbers as `null`). `undefined`
// result = give up: a cycle, too deep, too large, a bigint, or anything that raised. The size budget
// is charged once per output character (leaves for their text, containers for their brackets, keys
// and separators), so nesting does not count a value twice.
function canonical(value: unknown, depth: number, ancestors: Set<object>, budget: { left: number }): string | undefined {
  const charge = (text: string): string | undefined => {
    budget.left -= text.length;
    return budget.left < 0 ? undefined : text;
  };
  if (value === null) return charge("null");
  switch (typeof value) {
    case "string":
      // Checked before serialising, so a huge string is refused without building its JSON form.
      if (value.length > budget.left) return undefined;
      return charge(JSON.stringify(value));
    case "number":
      return charge(Number.isFinite(value) ? String(value) : "null");
    case "boolean":
      return charge(value ? "true" : "false");
    case "bigint":
      return undefined;
    case "undefined":
    case "function":
    case "symbol":
      return "";
    default:
      break;
  }
  const obj = value as object;
  if (depth >= MAX_DIGEST_DEPTH || ancestors.has(obj)) return undefined;
  ancestors.add(obj);
  const parts: string[] = [];
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const part = canonical(item, depth + 1, ancestors, budget);
      if (part === undefined) return undefined;
      const element = part === "" ? charge("null") : part;
      if (element === undefined || charge(",") === undefined) return undefined;
      parts.push(element);
    }
    ancestors.delete(obj);
    return charge("[]") === undefined ? undefined : `[${parts.join(",")}]`;
  }
  for (const key of Object.keys(obj).sort()) {
    const part = canonical((obj as Record<string, unknown>)[key], depth + 1, ancestors, budget);
    if (part === undefined) return undefined;
    if (part === "") continue;
    const label = charge(`${JSON.stringify(key)}:,`);
    if (label === undefined) return undefined;
    parts.push(`${JSON.stringify(key)}:${part}`);
  }
  ancestors.delete(obj);
  return charge("{}") === undefined ? undefined : `{${parts.join(",")}}`;
}

/**
 * sha256 (hex) of the args in canonical form: the same digest for the same content whatever the key
 * order, a different digest after any in-place change. `undefined` for a cyclic structure, nesting
 * deeper than 32, a canonical form over 1 MiB, or anything that raised while being read.
 */
export function argsDigest(args: unknown): string | undefined {
  try {
    const text = canonical(args, 0, new Set<object>(), { left: MAX_DIGEST_CHARS });
    if (text === undefined || text === "") return undefined;
    return createHash("sha256").update(text).digest("hex");
  } catch {
    return undefined;
  }
}
