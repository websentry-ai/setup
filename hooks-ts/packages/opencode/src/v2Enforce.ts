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
//   * **User `!cmd` shell — a raise from `shell.hook("create.before")`.** The user shell route
//     (`POST /api/session/:id/shell`) fires only `shell.create.before {command, cwd, …}`, before the
//     spawn, with no session or call id; a raise there is an empty HTTP 500 and nothing spawns
//     (14-SPIKES V2-10). The same hook also fires for the MODEL's `shell` tool, after its
//     `execute.before` and before its `evaluate`, so `execute.before(shell)` marks its command
//     (bounded, short-lived, consumed once) and a matching spawn is not checked again. Any other
//     command is a user command, checked as `bash` through v1's `checkUserCommand` (userShell.ts)
//     and raised through `block.ts` on a would-block verdict (no native approval exists there).
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
  SIGNAL_V2_PROMPT_WARN_ONLY,
  V2_CAPABILITIES,
} from "./constants.ts";
import type { V2Capabilities } from "./constants.ts";
import type {
  V2ContextLike,
  V2PermissionEvaluate,
  V2SessionInfo,
  V2SessionPrompt,
  V2ShellCreateBefore,
  V2ToolBefore,
} from "./hostTypesV2.ts";
import { mcpCandidates } from "./narrow.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { decidePrompt } from "./prompt.ts";
import { checkUserCommand } from "./userShell.ts";
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
/** How long the prompt hook waits for `ctx.session.get` before falling back (it answered in ~6 ms). */
const SESSION_GET_TIMEOUT_MS = 1_000;
/** How long a non-built-in call waits for the host's MCP server list before it is checked anyway. */
const MCP_LIST_TIMEOUT_MS = 1_000;
/** At most one awaited MCP server-list read per directory in this window. */
const MCP_LIST_INTERVAL_MS = 10_000;
/** The most sessions remembered for the once-per-session warn-only report. */
const MAX_WARNED_SESSIONS = 1024;
/** The most model shell commands awaiting their `shell.create.before`. */
const MAX_PENDING_SHELLS = 256;
/**
 * How long a model shell command stays marked. The spawn hook follows `execute.before` once its
 * decision is in (core's deadline is ~20 s); a mark that outlives this is dropped, so a stale one
 * can never exempt a later user command.
 */
const PENDING_SHELL_TTL_MS = 60_000;

const APPROVAL_NATIVE_TAIL = "Approve it only if you expect it.";
const PROMPT_BLOCK_TAIL =
  "(Unbound replaced the user's message because a policy blocked it; the original was not sent. " +
  "Tell the user their message was blocked by Unbound policy and do nothing else.)";

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

/** The text a blocked prompt is replaced with (HV2-05): the verdict, then what the model should do. */
export function promptBlockNotice(message: string): string {
  const text = typeof message === "string" && message !== "" ? message : "Blocked by Unbound policy.";
  return `${text}\n\n${PROMPT_BLOCK_TAIL}`;
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
 * `tool` / `permission` / `session` / `shell` domains. Never raises; a registration that rejects is
 * ignored. Returns false when registering raised (the rest was not registered), else true.
 */
export function registerV2Enforcement(
  ctx: V2ContextLike,
  runtime: Runtime,
  recordFor: (directory: string) => DirectoryRecord,
  capabilities: V2Capabilities = V2_CAPABILITIES,
): boolean {
  try {
    const directory = readString(readField(ctx, "location"), "directory");
    const pending = new Map<string, PendingCall>();
    const warned = new Set<string>();
    /** Model shell commands seen in `execute.before`, oldest first: `[command, marked at]`. */
    const modelShells: Array<[string, number]> = [];
    let userShellSeq = 0;

    const nowSafe = (): number => {
      try {
        const value = runtime.deps.now();
        return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
      } catch {
        return Date.now();
      }
    };
    /** Mark a model shell call's command (synchronously, before its decision is awaited). Total. */
    const markModelShell = (event: unknown): void => {
      try {
        if (readString(event, "tool") !== V2_SHELL_TOOL) return;
        const command = readString(readField(event, "input"), "command");
        if (command === "") return;
        modelShells.push([command, nowSafe()]);
        while (modelShells.length > MAX_PENDING_SHELLS) modelShells.shift();
      } catch {
        // Unmarked: at worst the model's spawn is checked once more as a user command.
      }
    };
    /** Consume a live mark for `command`: true when this spawn is the model's own shell call. */
    const takeModelShell = (command: string): boolean => {
      const now = nowSafe();
      while (modelShells.length > 0 && now - (modelShells[0]?.[1] ?? now) > PENDING_SHELL_TTL_MS) modelShells.shift();
      const index = modelShells.findIndex(([marked]) => marked === command);
      if (index < 0) return false;
      modelShells.splice(index, 1);
      return true;
    };

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

    /** The session info (`parentID`, `model`) for a prompt, bounded; `undefined` when unknown. */
    const sessionInfo = async (sessionID: string): Promise<V2SessionInfo | undefined> => {
      try {
        const session = ctx.session;
        const get = readField(session, "get");
        if (typeof get !== "function" || sessionID === "") return undefined;
        const answer = await bounded(
          Promise.resolve((get as (this: unknown, input: unknown) => unknown).call(session, { sessionID })),
          SESSION_GET_TIMEOUT_MS,
        );
        return answer !== null && typeof answer === "object" ? (answer as V2SessionInfo) : undefined;
      } catch {
        return undefined;
      }
    };

    /** The prompt check (HV2-05). Mutates the prompt only on a would-block verdict. Total. */
    const handlePrompt = async (event: V2SessionPrompt): Promise<void> => {
      try {
        const sessionID = readString(event, "sessionID");
        const prompt = readField(event, "prompt");
        const text = readField(prompt, "text");
        // Root vs child (14-SPIKES child-session probe): a child's prompt fires BEFORE its
        // `session.created`, so the parent comes from `ctx.session.get`; `runtime.isChild` (filled
        // from events) is the fallback inside `decidePrompt`.
        const info = await sessionInfo(sessionID);
        if (info !== undefined) runtime.setParent(sessionID, readField(info, "parentID"));
        const model = readField(info, "model");
        const providerID = readString(model, "providerID");
        const modelID = readString(model, "id");
        const input =
          providerID !== "" && modelID !== "" ? { sessionID, model: { providerID, modelID } } : { sessionID };
        const output = { parts: typeof text === "string" ? [{ type: "text", text }] : [] };

        const message = await decidePrompt(input, output, { runtime, record: record() });
        if (message === undefined) return;
        if (capabilities.prompt === "block") {
          const target = prompt as Record<string, unknown>;
          target.text = promptBlockNotice(message);
          if ("files" in target) target.files = [];
          if ("agents" in target) target.agents = [];
          if ("skills" in target) target.skills = [];
          return;
        }
        // Warn-only: checked and reported, never blocked; once per session.
        if (sessionID !== "" && !warned.has(sessionID)) {
          warned.add(sessionID);
          while (warned.size > MAX_WARNED_SESSIONS) {
            const oldest = warned.values().next().value;
            if (oldest === undefined) break;
            warned.delete(oldest);
          }
          runtime.reportSignal(SIGNAL_V2_PROMPT_WARN_ONLY, "prompt", "would_block");
        }
      } catch {
        // Allow.
      }
    };

    /** A user `!cmd`: the message to RAISE with (enforcing), or `undefined`. Total. */
    const decideUserShell = async (event: V2ShellCreateBefore): Promise<string | undefined> => {
      try {
        const command = readString(event, "command");
        if (command === "" || takeModelShell(command)) return undefined;
        userShellSeq += 1;
        const callID = `v2_${nowSafe().toString(36)}_${userShellSeq}`;
        const message = await checkUserCommand(command, readString(event, "cwd"), "", callID, {
          runtime,
          record: record(),
        });
        if (message === undefined) return undefined;
        if (capabilities.userShell !== "enforce") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, "bash", "user_shell");
          return undefined;
        }
        return message;
      } catch {
        return undefined;
      }
    };

    const tool = ctx.tool;
    if (tool !== undefined && typeof tool.hook === "function") {
      // The raise happens outside the decision's guard, and only with a verdict message.
      void Promise.resolve(
        tool.hook("execute.before", async (event: V2ToolBefore): Promise<void> => {
          // Synchronous, before any await: the spawn hook of this very call may follow.
          markModelShell(event);
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
    const session = ctx.session;
    if (session !== undefined && typeof session.hook === "function") {
      void Promise.resolve(session.hook("prompt", (event: V2SessionPrompt) => handlePrompt(event))).catch(
        () => undefined,
      );
    }
    const shell = ctx.shell;
    if (capabilities.userShell !== "none" && shell !== undefined && typeof shell.hook === "function") {
      void Promise.resolve(
        shell.hook("create.before", async (event: V2ShellCreateBefore): Promise<void> => {
          const message = await decideUserShell(event).catch(() => undefined);
          if (typeof message === "string" && message.length > 0) block(message);
        }),
      ).catch(() => undefined);
    }
    return true;
  } catch {
    // Registration is best-effort; a host that refuses a hook leaves the rest unregistered, and the
    // caller (setup) reports it.
    return false;
  }
}
