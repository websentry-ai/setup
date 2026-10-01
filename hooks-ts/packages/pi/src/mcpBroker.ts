// MCP enforcement through the pi-mcp-adapter approval broker (adapter >= 2.21.0).
//
// The adapter emits `pi-mcp-adapter:tool-approval-request` on the shared `pi.events` bus for EVERY
// resolved MCP call — proxy, direct, `mcpScript`, resource and iframe — after it has connected and
// resolved the call, with the exact `serverName`, `originalToolName`, `prefixedToolName`, `args` and
// `origin` (`tool-approval.ts requestBrokerApproval`, README "Tool Approval"). That is the only place
// the adapter's own resolution is visible, so enforcement happens there. Re-deriving it from the
// adapter's files at `tool_call` time was reproduced to fail open four ways (review CR-01..CR-04).
//
// The adapter's contract, and why each rule below exists:
//
//   * **Claim synchronously.** `requestBrokerApproval` emits, then closes the claim window on the
//     next line. pi's bus wraps a listener in an `async` function, but its body runs synchronously
//     inside `emit` up to the first `await` — and this listener has none. So the listener only
//     snapshots the request, checks the key, and claims.
//   * **Claim only when we will decide.** No key, or a key the gateway rejected (latched): no claim,
//     so the adapter falls back to its own approval settings exactly as if we were not installed.
//   * **Never throw, never answer anything else.** The adapter reads a thrown handler or an unknown
//     value as `deny`. Every path of the claimed handler returns one of `allow_once` / `deny` /
//     `abstain`, and any fault is `abstain` — an internal error must not block.
//
// The adapter package is never imported: the event name is a string literal and the request is
// typed structurally here, so the bundle stays dependency-free.
//
// **Audit correlation.** The broker request carries no `toolCallId`. So `tool_call` remembers in-flight
// non-native calls (`InflightCalls`) with their name AND their serialised arguments — read both as a
// wrapper (`input.tool` + `input.args`) and as a direct tool (the whole input), because a direct tool
// under `toolPrefix: "mcp"` is named `mcp__<server>_<tool>` just like a wrapper — and the broker
// handler claims the oldest entry whose name matches and whose arguments are equal (stable key order)
// — so two overlapping calls to the same tool with different arguments cannot swap ids. Entries
// expire after `MCP_INFLIGHT_MAX_AGE_MS`. No match (an `mcpScript` call, a resource read, an iframe, a
// direct tool whose arguments the adapter reshaped) mints an `mcpb_…` id, and that decision is posted
// as its own one-call turn log rather than entering the shared turn store. Correlation is audit only:
// it never feeds a verdict.
//
// **Another broker first.** The first synchronous claim wins. If another permission extension (or a
// host-managed runtime) claimed before us, `claim()` returns `false`: the call is decided without
// Unbound. That is reported once, through bypass telemetry, and no policy request is made.

import { randomBytes } from "node:crypto";

import { MCP_BROKER_ID_PREFIX, MCP_NAMESPACE_TOOL_PREFIX, MCP_PROXY_TOOL_NAME } from "../../core/src/constants.ts";
import type { McpApprovalAnswer } from "./decide.ts";

/** The answers the adapter accepts; anything else it reads as `deny`. */
const ANSWERS: ReadonlySet<string> = new Set(["allow_once", "deny", "abstain"]);

/** The request, snapshotted at emit time — its getters are never touched again after the claim. */
export interface McpBrokerCall {
  serverName: string;
  originalToolName: string;
  prefixedToolName: string;
  args: Record<string, unknown>;
  origin: string;
  signal: AbortSignal | undefined;
}

export interface McpBrokerDeps {
  /** Synchronous: is there a key, and is it not latched? Only then is the request claimed. */
  active(): boolean;
  /** Decide a claimed call. May throw or reject; the wrapper turns that into `abstain`. */
  decide(call: McpBrokerCall): Promise<McpApprovalAnswer>;
  /** Another broker claimed first (our `claim()` returned `false`). Called at most once per listener. */
  preempted?(call: McpBrokerCall): void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Read the request once. `undefined` for anything that is not a well-formed broker request. */
function snapshot(data: unknown): (McpBrokerCall & { claim: (handler: () => Promise<string>) => unknown }) | undefined {
  if (!isRecord(data)) return undefined;
  const claim = data.claim;
  if (typeof claim !== "function") return undefined;
  const serverName = data.serverName;
  const originalToolName = data.originalToolName;
  if (typeof serverName !== "string" || serverName === "") return undefined;
  if (typeof originalToolName !== "string" || originalToolName === "") return undefined;
  const prefixedToolName = typeof data.prefixedToolName === "string" ? data.prefixedToolName : "";
  const args = isRecord(data.args) ? data.args : {};
  const origin = typeof data.origin === "string" ? data.origin : "";
  const signal = data.signal;
  return {
    serverName,
    originalToolName,
    prefixedToolName,
    args,
    origin,
    signal: signal instanceof AbortSignal ? signal : undefined,
    claim: (handler) => (claim as (h: () => Promise<string>) => unknown).call(data, handler),
  };
}

/**
 * The `pi.events` listener. Synchronous and total: it returns `undefined` on every path, claims at
 * most once, and the handler it claims with never rejects and only ever resolves to one of the three
 * answers above.
 */
export function createMcpApprovalListener(deps: McpBrokerDeps): (data: unknown) => void {
  let reportedPreemption = false;
  return (data: unknown): void => {
    try {
      const request = snapshot(data);
      if (request === undefined) return;
      if (!deps.active()) return;
      const { claim, ...call } = request;
      const claimed = claim(async (): Promise<McpApprovalAnswer> => {
        try {
          // Cheap honour of the adapter's signal: a call already aborted is not worth a round trip.
          if (call.signal?.aborted === true) return "abstain";
          const answer = await deps.decide(call);
          return typeof answer === "string" && ANSWERS.has(answer) ? answer : "abstain";
        } catch {
          return "abstain";
        }
      });
      // `false`: someone else is deciding this call. No request — report it once.
      if (claimed === false && !reportedPreemption) {
        reportedPreemption = true;
        try {
          deps.preempted?.(call);
        } catch {
          // telemetry is never worth a throw
        }
      }
    } catch {
      // A malformed request or a throwing getter: no claim, so the adapter's own approval applies.
    }
  };
}

// --- In-flight correlation (audit only) ---------------------------------------------------------

/** JSON with object keys sorted at every level, or `undefined` when it cannot be serialised. Total. */
export function stableKey(value: unknown): string | undefined {
  try {
    const seen = new Set<unknown>();
    const walk = (v: unknown, depth: number): unknown => {
      if (depth > 64) throw new Error("too deep");
      if (v === null || typeof v !== "object") return v;
      if (seen.has(v)) throw new Error("cycle");
      seen.add(v);
      let out: unknown;
      if (Array.isArray(v)) out = v.map((item) => walk(item, depth + 1));
      else {
        const sorted: Record<string, unknown> = {};
        for (const key of Object.keys(v as Record<string, unknown>).sort()) {
          Object.defineProperty(sorted, key, {
            value: walk((v as Record<string, unknown>)[key], depth + 1),
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
        out = sorted;
      }
      seen.delete(v);
      return out;
    };
    const text = JSON.stringify(walk(value, 0));
    return typeof text === "string" ? text : undefined;
  } catch {
    return undefined;
  }
}

/** `isWrapperName`: the proxy (`mcp`) or a name that MAY be a namespace wrapper (`mcp__…`). */
function mayBeWrapper(toolName: string): boolean {
  return toolName === MCP_PROXY_TOOL_NAME || toolName.startsWith(MCP_NAMESPACE_TOOL_PREFIX);
}

/**
 * The arguments a call carries if it is a WRAPPER (`mcp`, `mcp__<ns>`): `input.args` — an object, a
 * JSON string, or absent ⇒ `{}`, as the adapter parses them. `undefined` when they cannot be keyed.
 */
function wrapperArgsKey(input: unknown): string | undefined {
  try {
    const raw = isRecord(input) ? input.args : undefined;
    if (raw === undefined || raw === "") return stableKey({});
    if (typeof raw === "string") return stableKey(JSON.parse(raw) as unknown);
    return stableKey(raw);
  } catch {
    return undefined;
  }
}

/** The arguments a call carries if it is a DIRECT tool: its whole input. */
function directArgsKey(input: unknown): string | undefined {
  return stableKey(isRecord(input) ? input : {});
}

interface InflightEntry {
  toolCallId: string;
  toolName: string;
  /** `input.tool` for the proxy / namespace wrappers, when it is a string. */
  tool: string | undefined;
  /**
   * Both readings of the arguments, because the NAME cannot say which shape the call has: a direct
   * tool under `toolPrefix: "mcp"` is `mcp__<server>_<tool>`, which looks like a namespace wrapper
   * but carries its arguments at the top level. The broker's `prefixedToolName` settles it at claim
   * time. `undefined` = that reading cannot be compared ⇒ never matched that way.
   */
  directKey: string | undefined;
  wrapperKey: string | undefined;
  sessionId: string;
  at: number;
}

export interface InflightCalls {
  remember(entry: { toolCallId: unknown; toolName: unknown; input: unknown }, sessionId: string): void;
  forget(toolCallId: unknown): void;
  /** Drop entries from any session other than `sessionId` (`""` = unknown: drops nothing). */
  keepSession(sessionId: string): void;
  /** The oldest entry matching name AND arguments, consumed — or `undefined`. */
  claim(prefixedToolName: string, originalToolName: string, args: unknown): string | undefined;
  size(): number;
}

/** A bounded, age-expiring FIFO of in-flight non-native tool calls. Every method is total. */
export function createInflightCalls(max: number, maxAgeMs: number, now: () => number = Date.now): InflightCalls {
  let entries: InflightEntry[] = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : 1;
  const expire = (): void => {
    const cutoff = now() - maxAgeMs;
    entries = entries.filter((entry) => entry.at >= cutoff);
  };
  return {
    remember(entry, sessionId) {
      try {
        if (typeof entry.toolCallId !== "string" || entry.toolCallId === "") return;
        if (typeof entry.toolName !== "string" || entry.toolName === "") return;
        let tool: string | undefined;
        if (isRecord(entry.input) && typeof entry.input.tool === "string") tool = entry.input.tool;
        expire();
        entries.push({
          toolCallId: entry.toolCallId,
          toolName: entry.toolName,
          tool,
          directKey: directArgsKey(entry.input),
          wrapperKey: mayBeWrapper(entry.toolName) ? wrapperArgsKey(entry.input) : undefined,
          sessionId: typeof sessionId === "string" ? sessionId : "",
          at: now(),
        });
        while (entries.length > cap) entries.shift();
      } catch {
        // Audit only.
      }
    },
    forget(toolCallId) {
      try {
        if (typeof toolCallId !== "string") return;
        entries = entries.filter((entry) => entry.toolCallId !== toolCallId);
      } catch {
        // Audit only.
      }
    },
    keepSession(sessionId) {
      try {
        if (typeof sessionId !== "string" || sessionId === "") return;
        entries = entries.filter((entry) => entry.sessionId === "" || entry.sessionId === sessionId);
      } catch {
        // Audit only.
      }
    },
    claim(prefixedToolName, originalToolName, args) {
      try {
        expire();
        const argsKey = stableKey(isRecord(args) ? args : {});
        if (argsKey === undefined) return undefined;
        const index = entries.findIndex((entry) => {
          // Direct: the pi tool IS the adapter's prefixed tool, and its whole input is the arguments.
          if (prefixedToolName !== "" && entry.toolName === prefixedToolName && entry.directKey === argsKey) {
            return true;
          }
          // Wrapper: `input.tool` names the tool, `input.args` carries the arguments.
          return (
            mayBeWrapper(entry.toolName) &&
            entry.wrapperKey === argsKey &&
            entry.tool !== undefined &&
            (entry.tool === originalToolName || (prefixedToolName !== "" && entry.tool === prefixedToolName))
          );
        });
        if (index === -1) return undefined;
        const [found] = entries.splice(index, 1);
        return found?.toolCallId;
      } catch {
        return undefined;
      }
    },
    size() {
      return entries.length;
    },
  };
}

/** A fresh audit id for a brokered call no `tool_call` matched. */
export function mintBrokerId(): string {
  return MCP_BROKER_ID_PREFIX + randomBytes(10).toString("hex");
}
