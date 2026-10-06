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
//     `execute.before` and before its `evaluate`, so `execute.before(shell)` marks its command once
//     its decision is in, immediately before it returns (nothing is awaited between that return and
//     the host's spawn hook for the same call). A mark is bounded, lives a few seconds, is bound to
//     the command AND the working directory, is consumed once, and is dropped when its session is
//     interrupted; a call whose session was interrupted while it was being decided never marks.
//     The host also tells the spawns apart by `timeout`: the model tool spawns with its own
//     (non-zero) timeout, the user routes with `0` (re-observed on 2.0.24). So a spawn with
//     `timeout: 0` never consumes a mark, and a DENIED call's mark (it is still spawned through
//     `create.before` before `evaluate` refuses it) is consumed only by a spawn with a positive
//     timeout. Any other spawn is a user command, checked as `bash` through v1's `checkUserCommand`
//     (userShell.ts) and raised through `block.ts` on a would-block verdict (no native approval
//     exists there).
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

import { isAbsolute, resolve } from "node:path";

import { directoryKey } from "../../core/src/sessionState.ts";
import { sanitizeReason } from "../../core/src/verdict.ts";
import { decideBeforeVerdict } from "./before.ts";
import type { BeforeDecision } from "./before.ts";
import { block } from "./block.ts";
import {
  SIGNAL_INIT_DEGRADED,
  SIGNAL_USER_SHELL_UNCHECKED,
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
import { checkUserCommandVerdict } from "./userShell.ts";
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
/** The most sessions whose last interrupt time is remembered. */
const MAX_INTERRUPTED_SESSIONS = 1024;
/**
 * How long a model shell command stays marked. The mark is set only once the call's decision is in,
 * immediately before `execute.before` returns, and the host's spawn hook for that call follows with
 * nothing awaited in between (only later plugins' before hooks). A mark that outlives this is
 * dropped: the model's spawn is then checked once more (never skipped), and a stale mark can never
 * exempt a later user command.
 */
export const PENDING_SHELL_TTL_MS = 5_000;

/** One model `shell` call whose spawn hook may follow (set once its decision is in). */
export interface ModelShellMark {
  command: string;
  /** The directory the call spawns in (`directoryKey`), or `""` when unknown (command-only match). */
  cwd: string;
  /** When the mark was set (`deps.now()`). */
  at: number;
  sessionID: string;
  /**
   * The call was decided deny / unavailable: `evaluate` refuses it after its spawn hook ran, so only
   * the tool's own spawn (a positive `timeout`) may consume the mark, never a user route.
   */
  denied: boolean;
}

/** The most sessions whose directory is remembered, and the most event ids kept for de-duplication. */
const MAX_SESSION_DIRS = 1024;
const MAX_SEEN_EVENTS = 4096;

/**
 * Process-wide v2 state every directory's registrations share (v2.ts keeps one per process).
 *
 * Directory awareness (WR-03), as observed on 2.0.24 with two directories in one process: hook
 * callbacks (`tool`, `permission`, `session.prompt`, `shell`) fire only in the registration of the
 * call's own location, but `ctx.event.subscribe()` delivers EVERY location's events to every
 * registration. So:
 *
 *   * an event is handled by the registration of its own location (`event.location.directory`, else
 *     the session's directory from `session.created` / `ctx.session.get`), and by exactly one
 *     registration when its owner cannot be told (`claimEvent`, by event id);
 *   * a hook input object is decided once process-wide (`claimHookInput`), so a host that ever fired
 *     one call's hooks in every registration would still check it once. A hook call is never skipped
 *     because of the session map: that map can be stale (a session can move to another location),
 *     and a wrong skip would let a call run unchecked;
 *   * model shell marks are process-wide, so no directory's user-shell handler raises for a command
 *     another directory's before hook marked.
 */
export interface V2Scope {
  /** Model shell commands awaiting their `shell.create.before`, oldest first (bounded). */
  readonly modelShells: ModelShellMark[];
  /** session id → when it was last interrupted (bounded, insertion-ordered). */
  readonly interrupted: Map<string, number>;
  /** `directoryKey`s of the directories with live registrations (v2.ts's set). */
  readonly directories: Set<string>;
  /** session id → `directoryKey` of its location (bounded, insertion-ordered; latest wins). */
  readonly sessionDirs: Map<string, string>;
  /** Event ids already handled by some registration (bounded, insertion-ordered). */
  readonly seenEvents: Set<string>;
  /** Per hook name: the input objects some registration already handled. */
  readonly seenHookInputs: Map<string, WeakSet<object>>;
  /**
   * The host asserted a permission with no `source` (WR-07): the evaluate correlation is broken, so
   * from then on a built-in call's block is raised from `execute.before` instead.
   */
  evaluateWithoutSource: boolean;
  /** Sessions whose `session.created` arrived without a `parentID` (bounded, insertion-ordered). */
  readonly confirmedRoots: Set<string>;
  /** Called on every model tool call and prompt (v2.ts: send `v2_status` once a key exists, IN-06). */
  onActivity: (() => void) | undefined;
  /**
   * Code Mode (IN-05): every inner MCP call reaches the hooks with the OUTER call id. Per
   * `session\0outer id`: how many inner calls were numbered, and the numbered ids still awaiting a
   * result, oldest first (bounded).
   */
  readonly codeMode: Map<string, CodeModeCalls>;
}

/** The inner calls of one outer Code Mode call. */
export interface CodeModeCalls {
  /** How many inner calls were numbered. */
  next: number;
  /** Numbered ids awaiting a result, oldest first. */
  open: string[];
  /** More than one inner call was open at once since the open set was last empty. */
  overlapped: boolean;
}

/** The most outer Code Mode calls tracked, and the most open inner calls per outer call. */
const MAX_CODE_MODE_CALLS = 1024;
const MAX_OPEN_INNER_CALLS = 256;

/**
 * Number one inner Code Mode call: the first keeps the outer id, later ones get `<id>#<n>`. The
 * decision, its audit entry and its digest all use the numbered id, and so does the result
 * (`takeCodeModeResult`), so the turn log pairs them. Total: a fault keeps the outer id.
 */
export function openCodeModeCall(scope: V2Scope, sessionID: string, callID: string): string {
  try {
    if (sessionID === "" || callID === "") return callID;
    const key = `${sessionID}\u0000${callID}`;
    const entry: CodeModeCalls = scope.codeMode.get(key) ?? { next: 0, open: [], overlapped: false };
    scope.codeMode.delete(key);
    scope.codeMode.set(key, entry);
    while (scope.codeMode.size > MAX_CODE_MODE_CALLS) {
      const oldest = scope.codeMode.keys().next().value;
      if (oldest === undefined) break;
      scope.codeMode.delete(oldest);
    }
    const id = entry.next === 0 ? callID : `${callID}#${entry.next}`;
    entry.next += 1;
    entry.open.push(id);
    while (entry.open.length > MAX_OPEN_INNER_CALLS) entry.open.shift();
    if (entry.open.length > 1) entry.overlapped = true;
    return id;
  } catch {
    return callID;
  }
}

/** An inner call that was blocked before it ran: no result will come for it. Total. */
export function closeCodeModeCall(scope: V2Scope, sessionID: string, callID: string, numbered: string): void {
  try {
    const open = scope.codeMode.get(`${sessionID}\u0000${callID}`)?.open;
    const index = open?.indexOf(numbered) ?? -1;
    if (open !== undefined && index >= 0) open.splice(index, 1);
  } catch {
    // It ages out.
  }
}

/**
 * The numbered id an inner call's result is recorded under: the oldest open one. `concurrent` is
 * true when other inner calls of the same outer call were open at the same time (in this batch), so
 * results may complete out of order and the args digest must not be compared (it may belong to a
 * sibling). `undefined` when
 * nothing was numbered for this id (the caller falls back). Total.
 */
export function takeCodeModeResult(
  scope: V2Scope,
  sessionID: string,
  callID: string,
): { callID: string; concurrent: boolean } | undefined {
  try {
    const entry = scope.codeMode.get(`${sessionID}\u0000${callID}`);
    if (entry === undefined || entry.open.length === 0) return undefined;
    const concurrent = entry.overlapped || entry.open.length > 1;
    const numbered = entry.open.shift();
    // The batch drained: the next inner call starts a fresh, comparable sequence.
    if (entry.open.length === 0) entry.overlapped = false;
    return numbered === undefined ? undefined : { callID: numbered, concurrent };
  } catch {
    return undefined;
  }
}

/** `scope.onActivity`, guarded. Total. */
function noteActivity(scope: V2Scope): void {
  try {
    scope.onActivity?.();
  } catch {
    // A status report is never worth a fault.
  }
}

/** A fresh, empty scope; `directories` is the caller's live registration set when it has one. */
export function createV2Scope(directories: Set<string> = new Set<string>()): V2Scope {
  return {
    modelShells: [],
    interrupted: new Map<string, number>(),
    directories,
    sessionDirs: new Map<string, string>(),
    seenEvents: new Set<string>(),
    seenHookInputs: new Map<string, WeakSet<object>>(),
    evaluateWithoutSource: false,
    confirmedRoots: new Set<string>(),
    onActivity: undefined,
    codeMode: new Map<string, CodeModeCalls>(),
  };
}

/** A `session.created` without a `parentID`: the session is a root (bounded). Total. */
export function noteRootSession(scope: V2Scope, sessionID: unknown): void {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    scope.confirmedRoots.delete(sessionID);
    scope.confirmedRoots.add(sessionID);
    while (scope.confirmedRoots.size > MAX_CONFIRMED_ROOTS) {
      const oldest = scope.confirmedRoots.values().next().value;
      if (oldest === undefined) break;
      scope.confirmedRoots.delete(oldest);
    }
  } catch {
    // Unconfirmed: the prompt is checked, never replaced.
  }
}

/** Remember a session's location (bounded). Total. */
export function noteSessionDirectory(scope: V2Scope, sessionID: unknown, directory: unknown): void {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    const key = directoryKey(directory);
    if (key === undefined) return;
    scope.sessionDirs.delete(sessionID);
    scope.sessionDirs.set(sessionID, key);
    while (scope.sessionDirs.size > MAX_SESSION_DIRS) {
      const oldest = scope.sessionDirs.keys().next().value;
      if (oldest === undefined) break;
      scope.sessionDirs.delete(oldest);
    }
  } catch {
    // Unknown location: the event falls back to the id claim.
  }
}

/**
 * Claim one hook input for this registration: true the first time the object is seen process-wide
 * (and for anything that is not an object), false when another registration already handled the
 * very same call. Total: a fault claims (the call is checked).
 */
export function claimHookInput(scope: V2Scope, hook: string, input: unknown): boolean {
  try {
    if (input === null || typeof input !== "object") return true;
    let seen = scope.seenHookInputs.get(hook);
    if (seen === undefined) {
      seen = new WeakSet<object>();
      scope.seenHookInputs.set(hook, seen);
    }
    if (seen.has(input)) return false;
    seen.add(input);
    return true;
  } catch {
    return true;
  }
}

/**
 * Should the registration for `ownDirectory` handle this bus event? Not when the event belongs to
 * ANOTHER directory that has its own live registration (its location, else its session's); else
 * exactly one registration handles it (claimed by event id). Total: a fault handles it.
 */
export function claimEvent(scope: V2Scope, ownDirectory: string, event: unknown): boolean {
  try {
    const own = directoryKey(ownDirectory);
    const data = readField(event, "data");
    const located =
      directoryKey(readString(readField(event, "location"), "directory")) ??
      directoryKey(readString(readField(data, "location"), "directory"));
    const owner = located ?? scope.sessionDirs.get(readString(data, "sessionID"));
    if (owner !== undefined && owner !== own && scope.directories.has(owner)) return false;
    const id = readString(event, "id");
    if (id === "") return true;
    if (scope.seenEvents.has(id)) return false;
    scope.seenEvents.add(id);
    while (scope.seenEvents.size > MAX_SEEN_EVENTS) {
      const oldest = scope.seenEvents.values().next().value;
      if (oldest === undefined) break;
      scope.seenEvents.delete(oldest);
    }
    return true;
  } catch {
    return true;
  }
}

/**
 * A session was interrupted (`session.execution.interrupted`): its pending model shell marks are
 * dropped, and a call of that session still being decided will not mark (its spawn never comes).
 * Total.
 */
export function noteInterrupted(scope: V2Scope, sessionID: string, at: number): void {
  try {
    if (typeof sessionID !== "string" || sessionID === "") return;
    scope.interrupted.delete(sessionID);
    scope.interrupted.set(sessionID, at);
    while (scope.interrupted.size > MAX_INTERRUPTED_SESSIONS) {
      const oldest = scope.interrupted.keys().next().value;
      if (oldest === undefined) break;
      scope.interrupted.delete(oldest);
    }
    for (let i = scope.modelShells.length - 1; i >= 0; i -= 1) {
      if (scope.modelShells[i]?.sessionID === sessionID) scope.modelShells.splice(i, 1);
    }
  } catch {
    // A mark we could not drop expires on its own.
  }
}

/**
 * The `{dispose}` handles of one directory's hook registrations (`ctx.<domain>.hook(...)` resolves to
 * one, `registration.d.ts`). The setup cleanup disposes them all: a host that keeps a location's
 * hooks after its cleanup must not end up with two sets after the next setup (WR-02). A
 * registration that resolves after `dispose()` is disposed as it arrives. Total.
 */
export interface V2Registrations {
  /** Keep the handle a `hook(...)` call resolves to; a rejected registration is ignored. */
  track(registration: unknown): void;
  /** Dispose every handle kept so far and every one that arrives later. Idempotent. */
  dispose(): void;
  /** How many handles are currently kept (test seam). */
  size(): number;
}

function disposeOne(registration: unknown): void {
  try {
    const dispose = readField(registration, "dispose");
    if (typeof dispose !== "function") return;
    void Promise.resolve((dispose as (this: unknown) => unknown).call(registration)).catch(() => undefined);
  } catch {
    // A handle that cannot be disposed stays with the host.
  }
}

export function createV2Registrations(): V2Registrations {
  const kept: unknown[] = [];
  let disposed = false;
  return {
    track(registration: unknown): void {
      try {
        void Promise.resolve(registration).then(
          (handle) => {
            if (disposed) disposeOne(handle);
            else kept.push(handle);
          },
          () => undefined,
        );
      } catch {
        // Not trackable: nothing to dispose either.
      }
    },
    dispose(): void {
      disposed = true;
      for (const handle of kept.splice(0, kept.length)) disposeOne(handle);
    },
    size: () => kept.length,
  };
}

/**
 * The directory a model shell call spawns in: an absolute `workdir`; else the session's directory
 * (`scope.sessionDirs`), or this registration's when it is the only one, with a relative `workdir`
 * resolved under it. `""` (command-only match) when the base is ambiguous. Total.
 */
function modelShellCwd(input: unknown, sessionID: string, directory: string, scope: V2Scope): string {
  try {
    const workdir = readField(input, "workdir");
    if (typeof workdir === "string" && workdir !== "" && isAbsolute(workdir)) return directoryKey(workdir) ?? "";
    const base = scope.sessionDirs.get(sessionID) ?? (scope.directories.size > 1 ? undefined : directoryKey(directory));
    if (base === undefined) return "";
    if (typeof workdir === "string" && workdir !== "") return directoryKey(resolve(base, workdir)) ?? "";
    return base;
  } catch {
    return "";
  }
}

const APPROVAL_NATIVE_TAIL = "Approve it only if you expect it.";
/** The text opencode 2.x puts before a subagent's prompt (14-SPIKES child-session probe). */
export const SUBAGENT_PROMPT_PREFIX = "You are a subagent spawned by another session.\n";
/** The most sessions remembered as confirmed roots. */
const MAX_CONFIRMED_ROOTS = 1024;
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

/**
 * `ctx.mcp.list()` server names, or `undefined` when unavailable. Total.
 *
 * The argument is `McpListInput` (`{location?: {directory?}}`, `@opencode/client` 2.0.24
 * `generated/types.d.ts`; checked in `conformance/v2.ts`). A 2.0.24 host answers the scoped call with
 * the location's servers (14-REVIEW WR-06 probe). If a host ever rejects it or answers without a
 * server list, the unscoped call is tried once before giving up.
 */
async function listMcpNames(ctx: V2ContextLike, directory: string): Promise<string[] | undefined> {
  const scoped = directory === "" ? undefined : await listMcpNamesWith(ctx, { location: { directory } });
  return scoped ?? (await listMcpNamesWith(ctx, undefined));
}

async function listMcpNamesWith(ctx: V2ContextLike, input: unknown): Promise<string[] | undefined> {
  try {
    const mcp = ctx.mcp;
    const list = readField(mcp, "list");
    if (typeof list !== "function") return undefined;
    const answer: unknown = await (list as (this: unknown, input?: unknown) => unknown).call(mcp, input);
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
  /** The permission action the host asserts for this tool (`write` asserts `edit`). */
  action: string;
}

/** The permission action a v2 built-in tool asserts (14-SPIKES V2-2 table). */
function permissionActionOf(tool: string): string {
  return tool === "write" ? "edit" : tool;
}

const NO_DECISION: BeforeDecision = Object.freeze({ message: undefined, kind: undefined });

/** What one `execute.before` concluded: the message to raise with, and the verdict kind. */
interface ToolCallOutcome {
  raise: string | undefined;
  kind: BeforeDecision["kind"];
  /** The numbered id of a non-built-in (Code Mode inner) call, when one was opened. */
  numbered?: string;
}

const NO_OUTCOME: ToolCallOutcome = Object.freeze({ raise: undefined, kind: undefined });

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
  scope: V2Scope = createV2Scope(),
  registrations: V2Registrations = createV2Registrations(),
): boolean {
  try {
    const directory = readString(readField(ctx, "location"), "directory");
    const pending = new Map<string, PendingCall>();
    const warned = new Set<string>();
    const modelShells = scope.modelShells;
    let userShellSeq = 0;

    const nowSafe = (): number => {
      try {
        const value = runtime.deps.now();
        return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
      } catch {
        return Date.now();
      }
    };
    /**
     * Mark a model shell call's command once its decision is in (CR-01): called right before
     * `execute.before` returns, never for a call that raised, and never when the call's session was
     * interrupted while it was being decided (its spawn will not come). Total.
     */
    const markModelShell = (event: unknown, kind: BeforeDecision["kind"], started: number): void => {
      try {
        if (readString(event, "tool") !== V2_SHELL_TOOL) return;
        const input = readField(event, "input");
        const command = readString(input, "command");
        if (command === "") return;
        const sessionID = readString(event, "sessionID");
        const interruptedAt = sessionID === "" ? undefined : scope.interrupted.get(sessionID);
        if (interruptedAt !== undefined && interruptedAt >= started) return;
        modelShells.push({
          command,
          cwd: modelShellCwd(input, sessionID, directory, scope),
          at: nowSafe(),
          sessionID,
          denied: kind === "deny" || kind === "unavailable",
        });
        while (modelShells.length > MAX_PENDING_SHELLS) modelShells.shift();
      } catch {
        // Unmarked: at worst the model's spawn is checked once more as a user command.
      }
    };
    /**
     * Consume a live mark for this spawn: true when it is the model's own shell call. The command
     * must match, and the directory too when both are known. A `timeout: 0` spawn (a user route on
     * 2.0.24) never consumes a mark; a denied call's mark needs a positive timeout (the tool's own
     * spawn). Total: a fault is "not the model's" (checked).
     */
    const takeModelShell = (command: string, cwdRaw: string, timeout: unknown): boolean => {
      try {
        const now = nowSafe();
        while (modelShells.length > 0 && now - (modelShells[0]?.at ?? now) > PENDING_SHELL_TTL_MS) modelShells.shift();
        if (timeout === 0) return false;
        const cwd = directoryKey(cwdRaw) ?? "";
        const toolSpawn = typeof timeout === "number" && Number.isFinite(timeout) && timeout > 0;
        const index = modelShells.findIndex(
          (mark) =>
            mark.command === command &&
            (mark.cwd === "" || cwd === "" || mark.cwd === cwd) &&
            (!mark.denied || toolSpawn),
        );
        if (index < 0) return false;
        modelShells.splice(index, 1);
        return true;
      } catch {
        return false;
      }
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
     * enforcing MCP capability only), or `undefined`, plus the verdict kind it came from. Built-in
     * decisions are kept for `evaluate`.
     */
    const decideToolCall = async (event: V2ToolBefore): Promise<ToolCallOutcome> => {
      try {
        const tool = readString(event, "tool");
        const sessionID = readString(event, "sessionID");
        const callID = readString(event, "id");
        if (tool === "" || tool === V2_CODE_MODE_TOOL) return NO_OUTCOME;
        const builtin = V2_BUILTIN_TOOLS.has(tool);
        if (!builtin && capabilities.mcp === "none") return NO_OUTCOME;

        const rec = record();
        if (!builtin) await learnMcpNames(tool, rec);
        // Inner Code Mode calls share the outer id: each gets its own numbered id (IN-05).
        const numbered = builtin ? callID : openCodeModeCall(scope, sessionID, callID);
        const decision = decideBeforeVerdict(
          { tool: v1ToolName(tool), sessionID, callID: numbered },
          { args: readField(event, "input") },
          { runtime, record: rec },
        ).catch((): BeforeDecision => NO_DECISION);
        // A built-in decision is applied at `evaluate`, found by session + call id. Without either
        // id (a call from outside the provider loop), or once the host was seen asserting without
        // a `source`, it cannot be found there: the block is raised here instead (WR-07; a raise
        // from `execute.before` is proven to block built-ins, 14-SPIKES V2-2).
        const correlatable = sessionID !== "" && callID !== "" && !scope.evaluateWithoutSource;
        if (builtin && sessionID !== "" && callID !== "") {
          remember(keyOf(sessionID, callID), { decision, asked: false, action: permissionActionOf(tool) });
        }

        const { message, kind } = await decision;
        if (message === undefined) return { raise: undefined, kind };
        if (capabilities.tools === "audit") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool, "tools");
          return { raise: undefined, kind };
        }
        if (builtin) return { raise: correlatable ? undefined : message, kind };
        if (capabilities.mcp !== "enforce") {
          runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, tool, "mcp");
          return { raise: undefined, kind };
        }
        // deny / unavailable → the verdict text; confirm → the v1 approval sentence (MCP ask is
        // unproven on v2, so it blocks as on v1).
        return { raise: message, kind, numbered };
      } catch {
        return NO_OUTCOME;
      }
    };

    /** Apply a kept built-in decision to one `permission.evaluate`. Only ever tightens. Total. */
    const applyEvaluate = async (event: V2PermissionEvaluate): Promise<void> => {
      try {
        const source = readField(event, "source");
        const callID = readString(source, "id");
        const sessionID = readString(event, "sessionID");
        if (callID === "") {
          await applyUncorrelated(event, sessionID);
          return;
        }
        if (sessionID === "") return;
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

    /**
     * An `evaluate` with no `source` (WR-07; never seen on 2.0.22 / 2.0.24). Reported once; from then
     * on built-in blocks are raised from `execute.before`. For this assertion, the strictest kept
     * verdict of the same session and permission action is applied (only ever tightens), and those
     * calls are consumed. Total.
     */
    const applyUncorrelated = async (event: V2PermissionEvaluate, sessionID: string): Promise<void> => {
      try {
        if (!scope.evaluateWithoutSource) {
          scope.evaluateWithoutSource = true;
          runtime.reportOnce(SIGNAL_INIT_DEGRADED, "permission.evaluate", "evaluate_no_source");
        }
        if (sessionID === "" || capabilities.tools === "audit") return;
        if (readField(event, "effect") === "deny") return;
        const action = readString(event, "action");
        const prefix = `${sessionID}\u0000`;
        const matched: Array<[string, PendingCall]> = [];
        for (const [key, call] of pending) {
          if (key.startsWith(prefix) && call.action === action) matched.push([key, call]);
        }
        let strictest: BeforeDecision | undefined;
        for (const [key, call] of matched) {
          const decision = await call.decision;
          if (decision.message === undefined) continue;
          pending.delete(key);
          if (strictest === undefined || (strictest.kind === "confirm" && decision.kind !== "confirm")) strictest = decision;
        }
        if (strictest?.message === undefined) return;
        event.effect = "deny";
        event.message = strictest.message;
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
        // `session.created`, so the parent comes from `ctx.session.get`. A prompt is treated as a
        // root only when that is confirmed (IN-03): `get` answered without a `parentID`, or the
        // session's `session.created` arrived without one. A known child (or a prompt carrying the
        // host's subagent preamble) is not checked; an unconfirmed one is checked, never replaced.
        const info = await sessionInfo(sessionID);
        let root: boolean;
        if (info !== undefined) {
          runtime.setParent(sessionID, readField(info, "parentID"));
          noteSessionDirectory(scope, sessionID, readString(readField(info, "location"), "directory"));
          root = !runtime.isChild(sessionID);
        } else if (runtime.isChild(sessionID)) {
          return;
        } else if (typeof text === "string" && text.startsWith(SUBAGENT_PROMPT_PREFIX)) {
          return;
        } else {
          root = sessionID !== "" && scope.confirmedRoots.has(sessionID);
        }
        const model = readField(info, "model");
        const providerID = readString(model, "providerID");
        const modelID = readString(model, "id");
        const input =
          providerID !== "" && modelID !== "" ? { sessionID, model: { providerID, modelID } } : { sessionID };
        const output = { parts: typeof text === "string" ? [{ type: "text", text }] : [] };

        const message = await decidePrompt(input, output, { runtime, record: record() });
        if (message === undefined) return;
        if (!root) {
          // Not known to be a root: the host did not say. A subagent prompt must never be replaced,
          // so this one is left as it is and the would-be block is reported.
          runtime.reportSignal(SIGNAL_V2_NOT_ENFORCING, "prompt", "parent_unknown");
          return;
        }
        if (capabilities.prompt === "block") {
          const notice = promptBlockNotice(message);
          let replaced = false;
          try {
            const target = prompt as Record<string, unknown>;
            target.text = notice;
            if ("files" in target) target.files = [];
            if ("agents" in target) target.agents = [];
            if ("skills" in target) target.skills = [];
            replaced = target.text === notice;
          } catch {
            replaced = false;
          }
          // A prompt the host handed over unmodifiable (frozen, a setter that ignores the write) is
          // not blocked: never silently (IN-04).
          if (!replaced) runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, "prompt", "prompt_mutate_failed");
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
        if (command === "" || takeModelShell(command, readString(event, "cwd"), readField(event, "timeout"))) return undefined;
        userShellSeq += 1;
        const callID = `v2_${nowSafe().toString(36)}_${userShellSeq}`;
        const { message, kind } = await checkUserCommandVerdict(command, readString(event, "cwd"), "", callID, {
          runtime,
          record: record(),
        });
        if (message === undefined) return undefined;
        // WR-04: the spawn hook cannot tell a user `!cmd` from the non-session `POST /api/shell` (same
        // input, `timeout: 0`, no session id; 2.0.24). A policy verdict (deny, approval) on the
        // command still blocks it, but a fail-closed `unavailable` never blocks a spawn that carries
        // no session id: it is reported instead.
        if (kind === "unavailable") {
          runtime.reportSignal(SIGNAL_USER_SHELL_UNCHECKED, "bash", "unavailable_not_applied");
          return undefined;
        }
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
      registrations.track(
        tool.hook("execute.before", async (event: V2ToolBefore): Promise<void> => {
          if (!claimHookInput(scope, "tool.execute.before", event)) return;
          noteActivity(scope);
          const started = nowSafe();
          const outcome = await decideToolCall(event).catch((): ToolCallOutcome => NO_OUTCOME);
          const message = outcome.raise;
          if (typeof message === "string" && message.length > 0) {
            // Blocked before it ran: no result will come for this inner call.
            if (outcome.numbered !== undefined) {
              closeCodeModeCall(scope, readString(event, "sessionID"), readString(event, "id"), outcome.numbered);
            }
            block(message);
          }
          // Only now, with the decision in and right before returning: the host's spawn hook for
          // THIS call follows with nothing awaited in between (CR-01).
          markModelShell(event, outcome.kind, started);
        }),
      );
    }
    const permission = ctx.permission;
    if (permission !== undefined && typeof permission.hook === "function") {
      registrations.track(
        permission.hook("evaluate", async (event: V2PermissionEvaluate): Promise<void> => {
          if (claimHookInput(scope, "permission.evaluate", event)) await applyEvaluate(event);
        }),
      );
    }
    const session = ctx.session;
    if (session !== undefined && typeof session.hook === "function") {
      registrations.track(
        session.hook("prompt", async (event: V2SessionPrompt): Promise<void> => {
          if (!claimHookInput(scope, "session.prompt", event)) return;
          noteActivity(scope);
          await handlePrompt(event);
        }),
      );
    }
    const shell = ctx.shell;
    if (capabilities.userShell !== "none" && shell !== undefined && typeof shell.hook === "function") {
      registrations.track(
        shell.hook("create.before", async (event: V2ShellCreateBefore): Promise<void> => {
          if (!claimHookInput(scope, "shell.create.before", event)) return;
          const message = await decideUserShell(event).catch(() => undefined);
          if (typeof message === "string" && message.length > 0) block(message);
        }),
      );
    }
    return true;
  } catch {
    // Registration is best-effort; a host that refuses a hook leaves the rest unregistered, and the
    // caller (setup) reports it.
    return false;
  }
}
