// The v2 decision side (opencode `@opencode/cli` 2.x): tool calls (HV2-02), approval (HV2-03), MCP
// (HV2-04) and user prompts (HV2-05). Every decision is made by the v1 code (`decideBeforeVerdict`,
// `decidePrompt`) through a thin shim that turns each v2 hook object into the v1 `input`/`output`
// shape; only the LEVER differs, and each lever is the one 14-SPIKES.md proved on 2.0.22:
//
//   * **Built-in tools — `permission.hook("evaluate")`.** The check runs in `tool.execute.before`
//     (it has the tool, the full input and the call id first) and its decision is kept by call id.
//     `evaluate` fires next for the same call (`source.id` == the before hook's `id`) and applies it:
//     deny / unavailable → `effect = "deny"` + `message` (the reason reaches the model verbatim as
//     `permission.rejected`); confirm → `effect = "ask"` + `message` (opencode's own approval,
//     HV2-03 NATIVE). Nothing raises on this path, so no throw can ever land on an allow.
//   * **MCP and other non-built-in tools — a raise from `tool.execute.before`.** An evaluate-deny on
//     an MCP id replaces the reason with "Unable to execute <id>" (HV2-04), so a blocked MCP call is
//     raised through `block.ts` (the package's single raise statement) with the verdict text, which
//     the host hands to the model verbatim. An ask on MCP was not exercised by the spikes, so it
//     blocks with the v1 approval sentence (14-SPIKES Decision HV2-03). This is the one v2-specific
//     raise site; `test/throwSites.test.ts` names this file as an allowed caller of `block(`.
//   * **Prompts — mutate `session.hook("prompt")`'s `prompt`.** On a would-block verdict the text is
//     replaced with a self-contained block notice and attachments are cleared; the original never
//     reaches the provider (HV2-05 BLOCK lever=session.prompt-mutate). No raise: a raise there is an
//     empty HTTP 500 for the client.
//
// v2 naming (14-SPIKES V2-11): `shell` is v1 `bash`, `subagent` is v1 `task` (audited, never denied,
// as on v1), file tools carry `path` (the opencode profile already reads it), and `execute` is the
// Code Mode wrapper, which never asserts itself: each inner MCP call reaches `tool.execute.before`
// with its own `<server>_<tool>` id (and the outer call id) and is checked there.
//
// Every capability can also be built audit-only (`V2Capabilities`), so a later host that breaks a
// lever can be shipped as "checked and reported, not enforced": the call is decided and recorded,
// never blocked, and `v2_not_enforcing` is reported once per runtime.
//
// Every handler is total: a fault allows. Nothing here awaits anything unbounded beyond the core
// decision itself (which carries core's deadline).

import { sanitizeReason } from "../../core/src/verdict.ts";
import { decideBeforeVerdict } from "./before.ts";
import type { BeforeDecision } from "./before.ts";
import { block } from "./block.ts";
import {
  SIGNAL_V2_NOT_ENFORCING,
  V2_CAPABILITIES,
} from "./constants.ts";
import type { V2Capabilities } from "./constants.ts";
import type {
  V2ContextLike,
  V2PermissionEvaluate,
  V2ToolBefore,
} from "./hostTypesV2.ts";
import { mcpCandidates } from "./narrow.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { APPROVAL_PREFIX } from "./verdicts.ts";

/** v2's shell tool (v1 `bash`). */
export const V2_SHELL_TOOL = "shell";
/** v2's sub-agent tool (v1 `task`). */
export const V2_SUBAGENT_TOOL = "subagent";
/** The Code Mode wrapper: never asserts; its inner MCP calls are checked one by one. */
export const V2_CODE_MODE_TOOL = "execute";

/** The tools 2.0.22 offers the model (14-SPIKES V2-11). Any other id is MCP or a plugin tool. */
export const V2_BUILTIN_TOOLS: ReadonlySet<string> = new Set([
  "edit",
  "glob",
  "grep",
  "question",
  "read",
  V2_SHELL_TOOL,
  "skill",
  V2_SUBAGENT_TOOL,
  "webfetch",
  "websearch",
  "write",
  V2_CODE_MODE_TOOL,
]);

/** The most call decisions kept per registration; the oldest is dropped first. */
const MAX_PENDING_CALLS = 1024;
/** How long a non-built-in call waits for the host's MCP server list before it is checked anyway. */
const MCP_LIST_TIMEOUT_MS = 1_000;
/** At most one awaited MCP server-list read per directory in this window. */
const MCP_LIST_INTERVAL_MS = 10_000;

const APPROVAL_NATIVE_TAIL = "Approve it only if you expect it.";
function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function readString(value: unknown, key: string): string {
  const field = readField(value, key);
  return typeof field === "string" ? field : "";
}

/** The v1 tool id a v2 tool id is decided as: `shell` → `bash`, `subagent` → `task`. Total. */
export function v1ToolName(tool: string): string {
  if (tool === V2_SHELL_TOOL) return "bash";
  if (tool === V2_SUBAGENT_TOOL) return "task";
  return typeof tool === "string" ? tool : "";
}

/** The message on opencode's own approval card (HV2-03 NATIVE): no "cannot ask" tail. Total. */
export function nativeApprovalMessage(reason?: unknown): string {
  try {
    const clean = sanitizeReason(reason)?.trim();
    if (clean === undefined || clean === "") return `${APPROVAL_PREFIX}. ${APPROVAL_NATIVE_TAIL}`;
    const end = /[.!?]$/.test(clean) ? "" : ".";
    return `${APPROVAL_PREFIX}: ${clean}${end} ${APPROVAL_NATIVE_TAIL}`;
  } catch {
    return `${APPROVAL_PREFIX}. ${APPROVAL_NATIVE_TAIL}`;
  }
}

/**
 * A v1-shaped client for a directory record on v2: `mcp.status()` answers from `ctx.mcp.list()`, in
 * the `{ data: { <name>: status } }` shape `runtime.refreshMcpNames` reads. No `tui`: no v2 toast
 * channel was proven (14-SPIKES human item 6), so `notify()` is a no-op. Total.
 */
export function v2HostClient(ctx: V2ContextLike, directory: string): { mcp: { status(): Promise<unknown> } } {
  return {
    mcp: {
      status: async (): Promise<unknown> => {
        try {
          const names = await listMcpNames(ctx, directory);
          if (names === undefined) return undefined;
          const data: Record<string, true> = {};
          for (const name of names) data[name] = true;
          return { data };
        } catch {
          return undefined;
        }
      },
    },
  };
}

/** `ctx.mcp.list()` server names, or `undefined` when unavailable. Total. */
async function listMcpNames(ctx: V2ContextLike, directory: string): Promise<string[] | undefined> {
  try {
    const mcp = ctx.mcp;
    const list = readField(mcp, "list");
    if (typeof list !== "function") return undefined;
    const answer: unknown = await (list as (this: unknown, input?: unknown) => unknown).call(
      mcp,
      directory === "" ? undefined : { location: { directory } },
    );
    const data = readField(answer, "data");
    if (!Array.isArray(data)) return undefined;
    const names: string[] = [];
    for (const server of data.slice(0, 1024)) {
      const name = readString(server, "name");
      if (name !== "" && !names.includes(name)) names.push(name);
    }
    return names;
  } catch {
    return undefined;
  }
}

/** Resolve `promise`, or `undefined` after `ms` (unref'd timer). Never rejects. */
function bounded<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise<T | undefined>((resolve) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      timer = setTimeout(() => resolve(undefined), ms);
      timer.unref?.();
    } catch {
      // No timer: the promise's own settlement resolves this.
    }
    promise.then(
      (value) => {
        if (timer !== undefined) clearTimeout(timer);
        resolve(value);
      },
      () => {
        if (timer !== undefined) clearTimeout(timer);
        resolve(undefined);
      },
    );
  });
}

/** One model tool call's decision, kept from `execute.before` until `evaluate` applies it. */
interface PendingCall {
  decision: Promise<BeforeDecision>;
  /** A native approval was already requested for this call (one card per call). */
  asked: boolean;
}

const NO_DECISION: BeforeDecision = Object.freeze({ message: undefined, kind: undefined });

/**
 * Register the v2 decision handlers on `ctx` (one `setup` = one directory, 14-SPIKES V2-12).
 * `recordFor` gives the directory record the v1 decision code reads (client, MCP names, notices).
 * Registers nothing for a capability whose value is `"none"`, and nothing at all without the
 * `tool` / `permission` / `session` domains. Never raises; a registration that rejects is ignored.
 */
export function registerV2Enforcement(
  ctx: V2ContextLike,
  runtime: Runtime,
  recordFor: (directory: string) => DirectoryRecord,
  capabilities: V2Capabilities = V2_CAPABILITIES,
): void {
  try {
    const directory = readString(readField(ctx, "location"), "directory");
    const pending = new Map<string, PendingCall>();

    const keyOf = (sessionID: string, callID: string): string => `${sessionID}\u0000${callID}`;
    const remember = (key: string, call: PendingCall): void => {
      pending.delete(key);
      pending.set(key, call);
      while (pending.size > MAX_PENDING_CALLS) {
        const oldest = pending.keys().next().value;
        if (oldest === undefined) break;
        pending.delete(oldest);
      }
    };
    const record = (): DirectoryRecord => recordFor(directory);

    /** Before a non-built-in call: learn the host's MCP server names if this id matches none. */
    const learnMcpNames = async (tool: string, rec: DirectoryRecord): Promise<void> => {
      try {
        if (mcpCandidates(tool, runtime.mcpServerNamesFor(rec)).length > 0) return;
        const now = runtime.deps.now();
        const last = rec.mcpRefreshedAt;
        if (last !== undefined && now - last < MCP_LIST_INTERVAL_MS) return;
        rec.mcpRefreshedAt = now;
        const names = await bounded(listMcpNames(ctx, directory), MCP_LIST_TIMEOUT_MS);
        if (names !== undefined) rec.liveMcpServerNames = names;
      } catch {
        // The call is sent unattributed; the server still sees the raw id.
      }
    };

    /**
     * The decision for one `execute.before`: the message to RAISE with (non-built-in tools under an
     * enforcing MCP capability only), or `undefined`. Built-in decisions are kept for `evaluate`.
     */
    const decideToolCall = async (event: V2ToolBefore): Promise<string | undefined> => {
      try {
        const tool = readString(event, "tool");
        const sessionID = readString(event, "sessionID");
        const callID = readString(event, "id");
        if (tool === "" || tool === V2_CODE_MODE_TOOL) return undefined;
        const builtin = V2_BUILTIN_TOOLS.has(tool);
        if (!builtin && capabilities.mcp === "none") return undefined;

        const rec = record();
        if (!builtin) await learnMcpNames(tool, rec);
        const decision = decideBeforeVerdict(
          { tool: v1ToolName(tool), sessionID, callID },
          { args: readField(event, "input") },
          { runtime, record: rec },
        ).catch((): BeforeDecision => NO_DECISION);
        if (builtin && sessionID !== "" && callID !== "") remember(keyOf(sessionID, callID), { decision, asked: false });

        const { message } = await decision;
        if (message === undefined) return undefined;
        if (capabilities.tools === "audit") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool, "tools");
          return undefined;
        }
        if (builtin) return undefined;
        if (capabilities.mcp !== "enforce") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool, "mcp");
          return undefined;
        }
        // deny / unavailable → the verdict text; confirm → the v1 approval sentence (MCP ask is
        // unproven on v2, so it blocks as on v1).
        return message;
      } catch {
        return undefined;
      }
    };

    /** Apply a kept built-in decision to one `permission.evaluate`. Only ever tightens. Total. */
    const applyEvaluate = async (event: V2PermissionEvaluate): Promise<void> => {
      try {
        const source = readField(event, "source");
        const callID = readString(source, "id");
        const sessionID = readString(event, "sessionID");
        if (callID === "" || sessionID === "") return;
        const call = pending.get(keyOf(sessionID, callID));
        if (call === undefined) return;
        const decision = await call.decision;
        if (decision.message === undefined) return;
        if (capabilities.tools === "audit") return;
        // Never loosen: a host (or user rule) deny stands as it is.
        if (readField(event, "effect") === "deny") return;
        if (decision.kind === "confirm") {
          if (capabilities.ask === "native") {
            if (call.asked) return;
            call.asked = true;
            event.effect = "ask";
            event.message = nativeApprovalMessage(decision.reason);
            return;
          }
          if (capabilities.ask === "deny") {
            event.effect = "deny";
            event.message = decision.message;
            return;
          }
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, readString(event, "action"), "ask");
          return;
        }
        // deny, unavailable (fail-closed org): refuse with the verdict text.
        event.effect = "deny";
        event.message = decision.message;
      } catch {
        // Allow.
      }
    };

    const tool = ctx.tool;
    if (tool !== undefined && typeof tool.hook === "function") {
      // The raise happens outside the decision's guard, and only with a verdict message.
      void Promise.resolve(
        tool.hook("execute.before", async (event: V2ToolBefore): Promise<void> => {
          const message = await decideToolCall(event).catch(() => undefined);
          if (typeof message === "string" && message.length > 0) block(message);
        }),
      ).catch(() => undefined);
    }
    const permission = ctx.permission;
    if (permission !== undefined && typeof permission.hook === "function") {
      void Promise.resolve(permission.hook("evaluate", (event: V2PermissionEvaluate) => applyEvaluate(event))).catch(
        () => undefined,
      );
    }
  } catch {
    // Registration is best-effort; a host that refuses a hook leaves that capability unregistered.
  }
}
