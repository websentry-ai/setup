// The v2 recording side (opencode `@opencode/cli` 2.x): heartbeat, tool audit, turn log (HV2-06 GO)
// and provider-level account identity (HV2-07 PROVIDER-LEVEL). It reuses record.ts unchanged: each
// v2 event 14-SPIKES.md recorded is translated into the v1 `{ event: { type, properties } }` shape
// `handleEvent` reads, so heartbeat gating, the turn record, the child roll-up and the hash-only
// audit have one implementation.
//
// v2 event → v1 shape (14-SPIKES `## v2 contract`, events table):
//
//   * `session.created {sessionID, parentID?, model?, version?, location?}` → `session.created`
//     (`info.version` = `data.version`, else `ctx.app.version`). The model's provider also starts
//     the provider-level identity.
//   * `session.text.ended {sessionID, assistantMessageID, ordinal, text}` → an assistant
//     `message.updated` plus a text `message.part.updated` (one part per message + ordinal).
//   * `session.execution.succeeded` / `interrupted` / `failed {sessionID}` → `session.idle`: the
//     turn end on 2.0.x, where `session.idle` is never emitted. `failed` (a provider error, observed
//     on 2.0.24 in 14-05) must end the turn too, or its record would roll into the next one.
//   * `session.tool.input.started {id, name}` → the call's tool name (the only tool event with one);
//     `session.tool.failed {id, error}` → an errored tool part (hash-only, one result per call).
//   * `session.step.started {model}` → the session's model; `mcp.status.changed` → the next
//     unattributed MCP call re-reads the server list.
//
// Hooks: `tool.hook("execute.after")` (the success audit + the args tamper check, as v1's
// `tool.execute.after`; an `error` status is the same errored-part audit) and
// `session.hook("model.request")` (the HV2-07 identity source: `model.providerID`).
//
// Identity is provider-level only: `v2ProviderIdentity` is the `readAuth` override the v2 setup
// passes to the runtime, and it reads nothing. opencode 2.x keeps credentials in its local database
// (14-SPIKES V2-8), which this adapter never opens.
//
// Code Mode (14-SPIKES V2-3): every inner MCP call reaches the hooks with the OUTER call id. The
// first result under an id is recorded under that id (and tamper-checked); later ones get
// `<id>#<n>` and are not compared, since their digest may belong to a sibling call. The wrapper's own
// result is not recorded: no call was recorded for it (its inner calls are).
//
// Every handler is total, and the event loop never rejects. Bookkeeping is synchronous; every network
// call is record.ts's fire-and-forget.

import type { AgentAuthSummary } from "../../core/src/profile.ts";
import type {
  V2BusEvent,
  V2ContextLike,
  V2SessionModelRequest,
  V2ToolAfter,
} from "./hostTypesV2.ts";
import type { DirectoryRecord, Runtime } from "./plugin.ts";
import { handleEvent, outputParts, recordResult, sanitizeHostVersion, toolExecuteAfter } from "./record.ts";
import type { RecordContext } from "./record.ts";
import {
  claimEvent,
  claimHookInput,
  createV2Registrations,
  createV2Scope,
  noteInterrupted,
  noteRootSession,
  noteSessionDirectory,
  V2_BUILTIN_TOOLS,
  V2_CODE_MODE_TOOL,
  v1ToolName,
} from "./v2Enforce.ts";
import type { V2Registrations, V2Scope } from "./v2Enforce.ts";

/** HV2-06 is GO on 2.0.22: no recording piece is missing. A PARTIAL host would list them here. */
export const V2_RECORDING_GAPS: readonly string[] = Object.freeze([]);

/** The most call ids whose tool name (or after-count) is remembered; the oldest is dropped first. */
const MAX_TRACKED_CALLS = 1024;
/** A provider id the identity loader is started with: a plain token (kept in the process). */
const PROVIDER_ID = /^[A-Za-z0-9._-]{1,64}$/;

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

/**
 * The `readAuth` override of the v2 entry (HV2-07 PROVIDER-LEVEL): nothing is read from disk. The
 * provider id stays in the process; no auth mode is claimed (14-REVIEW WR-05): v2 never says whether
 * a sign-in is an API key or an Anthropic subscription, and a provider id is not an auth mode. So the
 * identity carries only the device serial. `undefined` for anything that is not a plain provider id.
 * Pure and total.
 */
export function v2ProviderIdentity(provider: string | undefined): AgentAuthSummary | undefined {
  try {
    if (typeof provider !== "string" || !PROVIDER_ID.test(provider)) return undefined;
    return { provider, hasCredential: false, anthropicOAuth: false };
  } catch {
    return undefined;
  }
}

/** `runtime.deps.now()`, or `Date.now()` when it is unusable. Total. */
function nowOf(runtime: Runtime): number {
  try {
    const value = runtime.deps.now();
    return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
  } catch {
    return Date.now();
  }
}

/** Insertion-ordered bounded map write. */
function remember<V>(map: Map<string, V>, key: string, value: V): void {
  map.delete(key);
  map.set(key, value);
  while (map.size > MAX_TRACKED_CALLS) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
}

/** `{providerID, id}` → `provider/id`, or `undefined`. */
function modelOf(model: unknown): { provider: string; model: string } | undefined {
  const provider = readString(model, "providerID");
  const id = readString(model, "id");
  if (provider === "" || id === "") return undefined;
  return { provider, model: `${provider}/${id}` };
}

/**
 * Register the v2 recording handlers on `ctx` (one `setup` = one directory, 14-SPIKES V2-12).
 * Returns the function that stops the event subscription (the setup cleanup calls it), or
 * `undefined` when a registration raised (the caller reports it; nothing further is registered).
 * Never raises.
 */
export function registerV2Recording(
  ctx: V2ContextLike,
  runtime: Runtime,
  recordFor: (directory: string) => DirectoryRecord,
  scope: V2Scope = createV2Scope(),
  registrations: V2Registrations = createV2Registrations(),
): (() => void) | undefined {
  let controller: AbortController | undefined;
  let stopped = false;
  const stop = (): void => {
    stopped = true;
    try {
      controller?.abort();
    } catch {
      // Already stopped.
    }
  };
  try {
    const directory = readString(readField(ctx, "location"), "directory");
    const app = readField(ctx, "app");
    const appVersion = sanitizeHostVersion(readField(app, "version"));
    // The host version is known at setup on v2 (`ctx.app.version`): every request carries it.
    if (appVersion !== undefined && runtime.hostVersion === undefined) runtime.hostVersion = appVersion;

    const toolNames = new Map<string, string>();
    const afterCounts = new Map<string, number>();
    const keyOf = (sessionID: string, id: string): string => `${sessionID}\u0000${id}`;
    const context = (): RecordContext => ({ runtime, record: recordFor(directory) });
    const emit = (type: string, properties: unknown): void => {
      handleEvent({ event: { type, properties } }, context());
    };

    /** Model + identity from a v2 model ref. Total. */
    const noteModel = (sessionID: string, model: unknown): void => {
      try {
        const found = modelOf(model);
        if (found === undefined) return;
        if (sessionID !== "") runtime.setModel(sessionID, found.model);
        runtime.startIdentity(found.provider);
      } catch {
        // Identity and model are decoration.
      }
    };

    /** An errored tool result, hash-only, once per call (record.ts `markResulted`). Total. */
    const recordError = (sessionID: string, callID: string, tool: string, message: string): void => {
      emit("message.part.updated", {
        sessionID,
        part: { type: "tool", tool, callID, sessionID, state: { status: "error", error: message } },
      });
    };

    const onEvent = (event: unknown): void => {
      try {
        const type = readString(event, "type");
        const data = readField(event, "data");
        const sessionID = readString(data, "sessionID");
        switch (type) {
          case "session.created": {
            const location = readField(data, "location");
            const eventLocation = readField(event, "location");
            const dir = readString(location, "directory") || readString(eventLocation, "directory") || directory;
            const version = readField(data, "version") ?? readField(app, "version");
            const parentID = readField(data, "parentID");
            noteSessionDirectory(scope, sessionID, dir);
            if (typeof parentID !== "string" || parentID === "") noteRootSession(scope, sessionID);
            noteModel(sessionID, readField(data, "model"));
            emit("session.created", {
              sessionID,
              info: { id: sessionID, directory: dir, version, ...(typeof parentID === "string" ? { parentID } : {}) },
            });
            return;
          }
          case "session.step.started":
            noteModel(sessionID, readField(data, "model"));
            return;
          case "session.text.ended": {
            const messageID = readString(data, "assistantMessageID");
            const text = readField(data, "text");
            const ordinal = readField(data, "ordinal");
            if (messageID === "" || typeof text !== "string") return;
            emit("message.updated", { sessionID, info: { id: messageID, sessionID, role: "assistant" } });
            emit("message.part.updated", {
              sessionID,
              part: { id: `${messageID}:${typeof ordinal === "number" ? ordinal : 0}`, sessionID, messageID, type: "text", text },
            });
            return;
          }
          case "session.execution.interrupted":
            // A call of this session still being decided will not spawn: no shell mark (CR-01).
            noteInterrupted(scope, sessionID, nowOf(runtime));
            emit("session.idle", { sessionID });
            return;
          case "session.execution.succeeded":
          case "session.execution.failed":
            emit("session.idle", { sessionID });
            return;
          case "session.deleted":
            emit("session.deleted", { sessionID });
            return;
          case "session.tool.input.started": {
            const id = readString(data, "id");
            const name = readString(data, "name");
            if (id !== "" && name !== "") remember(toolNames, keyOf(sessionID, id), name);
            return;
          }
          case "session.tool.failed": {
            const id = readString(data, "id");
            if (sessionID === "" || id === "") return;
            const name = toolNames.get(keyOf(sessionID, id)) ?? "";
            if (name === V2_CODE_MODE_TOOL) return;
            const error = readField(data, "error");
            recordError(sessionID, id, v1ToolName(name), readString(error, "message"));
            return;
          }
          case "mcp.status.changed":
            // A server connected or changed: the next unattributed call reads the live list again.
            recordFor(directory).mcpRefreshedAt = undefined;
            return;
          default:
            return;
        }
      } catch {
        // An event we cannot read is an event we ignore.
      }
    };

    const afterHandler = async (event: V2ToolAfter): Promise<void> => {
      try {
        if (!claimHookInput(scope, "tool.execute.after", event)) return;
        const tool = readString(event, "tool");
        const sessionID = readString(event, "sessionID");
        const id = readString(event, "id");
        if (tool === "" || tool === V2_CODE_MODE_TOOL || sessionID === "" || id === "") return;
        const name = v1ToolName(tool);
        const status = readField(event, "status");
        let callID = id;
        if (!V2_BUILTIN_TOOLS.has(tool)) {
          // Code Mode inner calls share the outer id: number the later ones.
          const key = keyOf(sessionID, id);
          const seen = afterCounts.get(key) ?? 0;
          remember(afterCounts, key, seen + 1);
          if (seen > 0) callID = `${id}#${seen}`;
        }
        if (status === "error") {
          const error = readField(readField(event, "error"), "error");
          recordError(sessionID, callID, name, readString(error, "reason") || readString(error, "_tag"));
          return;
        }
        if (callID !== id) {
          // Not compared: this id's remembered digest may belong to a sibling inner call.
          recordResult(context(), sessionID, callID, name, false, outputParts(readField(event, "result")));
          return;
        }
        await toolExecuteAfter(context())(
          { tool: name, sessionID, callID: id, args: readField(event, "input") },
          { output: readField(event, "result") },
        );
      } catch {
        // Never raise from the after-hook.
      }
    };

    const modelRequest = async (event: V2SessionModelRequest): Promise<void> => {
      try {
        if (!claimHookInput(scope, "session.model.request", event)) return;
        const kind = readField(event, "kind");
        if (kind !== undefined && kind !== "primary") {
          // A title / compaction call names the same provider; it never sets the session's model.
          runtime.startIdentity(readString(readField(event, "model"), "providerID") || undefined);
          return;
        }
        noteModel(readString(event, "sessionID"), readField(event, "model"));
      } catch {
        // Decoration only.
      }
    };

    const tool = ctx.tool;
    if (tool !== undefined && typeof tool.hook === "function") {
      registrations.track(tool.hook("execute.after", afterHandler));
    }
    const session = ctx.session;
    if (session !== undefined && typeof session.hook === "function") {
      registrations.track(session.hook("model.request", modelRequest));
    }

    const events = ctx.event;
    if (events !== undefined && typeof events.subscribe === "function") {
      controller = new AbortController();
      const iterable = events.subscribe({ signal: controller.signal });
      void (async (): Promise<void> => {
        try {
          for await (const event of iterable as AsyncIterable<V2BusEvent>) {
            if (stopped) break;
            // Every registration receives every location's events (2.0.24): handle only our own,
            // and an event of unknown ownership in exactly one registration (WR-03).
            if (claimEvent(scope, directory, event)) onEvent(event);
          }
        } catch {
          // The stream ended badly: recording stops, enforcement is unaffected.
        }
      })().catch(() => undefined);
    }
    return stop;
  } catch {
    stop();
    return undefined;
  }
}
