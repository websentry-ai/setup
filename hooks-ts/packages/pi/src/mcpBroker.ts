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
// non-native calls (`InflightCalls`), and the broker handler claims the oldest matching one for its
// `tool_use_id` — so the turn log pairs the decision with the call's output. No match (an `mcpScript`
// call, a resource read, an iframe) mints an `mcpb_…` id. Correlation is audit only: it never feeds a
// verdict, and a wrong or missing match costs output pairing, nothing else.

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
  return (data: unknown): void => {
    try {
      const request = snapshot(data);
      if (request === undefined) return;
      if (!deps.active()) return;
      const { claim, ...call } = request;
      claim(async (): Promise<McpApprovalAnswer> => {
        try {
          // Cheap honour of the adapter's signal: a call already aborted is not worth a round trip.
          if (call.signal?.aborted === true) return "abstain";
          const answer = await deps.decide(call);
          return typeof answer === "string" && ANSWERS.has(answer) ? answer : "abstain";
        } catch {
          return "abstain";
        }
      });
    } catch {
      // A malformed request or a throwing getter: no claim, so the adapter's own approval applies.
    }
  };
}

// --- In-flight correlation (audit only) ---------------------------------------------------------

interface InflightEntry {
  toolCallId: string;
  toolName: string;
  /** `input.tool` for the proxy / namespace wrappers, when it is a string. */
  tool: string | undefined;
  sessionId: string;
}

export interface InflightCalls {
  remember(entry: { toolCallId: unknown; toolName: unknown; input: unknown }, sessionId: string): void;
  forget(toolCallId: unknown): void;
  /** Drop entries from any session other than `sessionId` (`""` = unknown: drops nothing). */
  keepSession(sessionId: string): void;
  /** The oldest matching entry's id, consumed — or `undefined`. */
  claim(prefixedToolName: string, originalToolName: string): string | undefined;
  size(): number;
}

/** A bounded FIFO of in-flight non-native tool calls. Every method is total. */
export function createInflightCalls(max: number): InflightCalls {
  let entries: InflightEntry[] = [];
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : 1;
  return {
    remember(entry, sessionId) {
      try {
        if (typeof entry.toolCallId !== "string" || entry.toolCallId === "") return;
        if (typeof entry.toolName !== "string" || entry.toolName === "") return;
        let tool: string | undefined;
        if (isRecord(entry.input) && typeof entry.input.tool === "string") tool = entry.input.tool;
        entries.push({
          toolCallId: entry.toolCallId,
          toolName: entry.toolName,
          tool,
          sessionId: typeof sessionId === "string" ? sessionId : "",
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
    claim(prefixedToolName, originalToolName) {
      try {
        const index = entries.findIndex((entry) => {
          if (prefixedToolName !== "" && entry.toolName === prefixedToolName) return true;
          const wrapper =
            entry.toolName === MCP_PROXY_TOOL_NAME || entry.toolName.startsWith(MCP_NAMESPACE_TOOL_PREFIX);
          return (
            wrapper &&
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
