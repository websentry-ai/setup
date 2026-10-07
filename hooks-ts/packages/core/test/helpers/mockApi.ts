// Scripted in-process mock of the Unbound API (`/v1/hooks/*`).
//
// One responder table, two entry points: unit tests call `startMockApi()` on an ephemeral port,
// and `scripts/mock-api.mjs` starts the same server on a fixed port for a manual agent smoke test.
// Zero dependencies - `node:http` only.
//
// THE ENTRY GATE (see `hasEvaluableInput` below) is the reason this mock is trustworthy.
// The real API only reaches its command-policy evaluator through a Path-2 gate
// (`preToolUseHandler.ts:846-861`):
//
//   isAllowedToolName(tool_name,'pi') && (!!command || (PI_NATIVE_FILE_TOOLS.includes(tool_name) && !!file_path))
//
// Anything else falls through to a `no_policy` allow (`:1008-1012`). The API has a second evaluating
// path for MCP calls (Path 3): a request that carries an explicit, non-blank `metadata.mcp_server`
// is evaluated as an MCP call, whatever its command and file path. So the gate this mock models is
// "a non-blank command, a non-blank file_path, OR a non-blank mcp_server". A mock that denies every
// request regardless would make a file-tool test that forgets `metadata.file_path` pass
// VACUOUSLY - green locally, unenforced in production. Modelling the gate means such a test
// fails instead. That is this model's entire purpose; do not "simplify" it away.

import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";

/** Every scripted behaviour of `POST /v1/hooks/pretool`. */
export type MockMode =
  | "allow"
  | "deny"
  | "denyNoReason"
  | "ask"
  | "approval"
  | "failBlock"
  | "500"
  | "malformed"
  | "hang"
  | "attributed"
  | "errors"
  // `tools_to_check` has three distinguishable states, because the policy cache treats them
  // differently: a list (check these), `[]` (no file policies at all) and an absent key (the
  // response carried no opinion, so a cached value must stand).
  | "toolsList"
  | "toolsEmpty"
  | "toolsOmitted"
  | "401"
  // A deny that reaches a tool call: `deny` ONLY for `event_name: "tool_use"`, and `allow` for every
  // other event (`user_prompt`, `session_start`). Under plain `deny` a headless smoke is blocked at
  // the prompt check before the model can call any tool, so the tool-deny path is never exercised.
  | "denyTools";

/** Scripted behaviour of `POST /v1/hooks/errors`, independent of `MockMode`. */
export type MockErrorsMode = "ok" | "500" | "hang";

/** Scripted behaviour of `POST /v1/hooks/<agent>` (the agent turn log), independent of `MockMode`. */
export type MockTurnLogMode = "ok" | "401" | "hang";

export interface CapturedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  /** Parsed JSON when the body parses, otherwise the raw string. */
  body: unknown;
}

export interface StartMockApiOptions {
  mode?: MockMode;
  errorsMode?: MockErrorsMode;
  turnLogMode?: MockTurnLogMode;
  /** 0 (default) binds an ephemeral port; the standalone runner passes a fixed one. */
  port?: number;
}

export interface MockApi {
  /** e.g. `http://127.0.0.1:54321` - no trailing slash, ready for `UNBOUND_GATEWAY_URL`. */
  url: string;
  port: number;
  requests: CapturedRequest[];
  setMode(mode: MockMode): void;
  setErrorsMode(mode: MockErrorsMode): void;
  setTurnLogMode(mode: MockTurnLogMode): void;
  close(): Promise<void>;
}

/** What an attributed deny reason looks like once the gateway appends its footer. */
export const ATTRIBUTION_SUFFIX = "\n\nEnforced by Unbound · Trace ID abc";

/** Marker naming why a request was allowed without evaluation. Assert on it, never on bare allow. */
export const ENTRY_GATE_MARKER = "no_evaluable_input";

/** `tools_to_check` under `toolsList`: a strict subset, so a `grep` skip is observable. */
export const TOOLS_LIST = ["read", "write"] as const;

/** The deny reason `denyTools` answers a tool call with. */
export const DENY_TOOLS_REASON = "Smoke: tool calls are blocked.";

/** The `event_name` of a tool call; the only event `denyTools` denies. */
const TOOL_USE_EVENT = "tool_use";

/**
 * The two `event_name`s the gate never applies to: neither carries a command by design, and the
 * server routes both to handlers that answer without the Path-2 gate.
 */
const GATE_EXEMPT_EVENTS: ReadonlySet<string> = new Set(["user_prompt", "session_start"]);

const JSON_CONTENT_TYPE = "application/json";
const HANG = "hang" as const;

/** The 401 body shape the API returns for a rejected key. */
const INVALID_API_KEY_BODY = { error: "invalidApiKey" } as const;

interface ScriptedResponse {
  status: number;
  body: string;
  contentType: string;
}

function json(status: number, payload: unknown): ScriptedResponse {
  return { status, body: JSON.stringify(payload), contentType: JSON_CONTENT_TYPE };
}

function isNonBlankString(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * The client half of the server's Path-2 entry gate: does this request carry anything the command
 * policy engine could possibly evaluate?
 *
 * `true` when `pre_tool_use_data.command` is a non-blank string, or `metadata.file_path` is (Path 2),
 * or `metadata.mcp_server` is (Path 3: an explicitly attributed MCP call is evaluated even with no
 * command and no file path). Read defensively off an arbitrary parsed body - a test may post a
 * string, `null`, or a half-built object, and the mock must answer rather than throw.
 */
export function hasEvaluableInput(body: unknown): boolean {
  const data = (body as { pre_tool_use_data?: unknown } | null | undefined)?.pre_tool_use_data as
    | { command?: unknown; metadata?: unknown }
    | null
    | undefined;
  if (isNonBlankString(data?.command)) return true;
  const metadata = data?.metadata as { file_path?: unknown; mcp_server?: unknown } | null | undefined;
  return isNonBlankString(metadata?.file_path) || isNonBlankString(metadata?.mcp_server);
}

/** The request's `event_name`, or `undefined` when it has none. */
function eventNameOf(body: unknown): string | undefined {
  const eventName = (body as { event_name?: unknown } | null | undefined)?.event_name;
  return typeof eventName === "string" ? eventName : undefined;
}

/** Is the Path-2 gate relevant to this request at all? `user_prompt` / `session_start` bypass it. */
function isGatedRequest(body: unknown): boolean {
  const eventName = eventNameOf(body);
  return !(eventName !== undefined && GATE_EXEMPT_EVENTS.has(eventName));
}

/** The `no_policy` allow a request with nothing evaluable falls through to, plus a named reason. */
function entryGateResponse(): ScriptedResponse {
  return json(200, {
    decision: "allow",
    policy_check_failure_action: "allow",
    _entry_gate: ENTRY_GATE_MARKER,
  });
}

/** The policy metadata the command path attaches alongside a verdict when `pull_policies` is set. */
function policyPayload(toolsToCheck: readonly string[] | undefined): Record<string, unknown> {
  return {
    decision: "allow",
    policy_check_failure_action: "allow",
    ...(toolsToCheck === undefined ? {} : { tools_to_check: [...toolsToCheck] }),
    repo_policies: [],
    unbound_attribution_enabled: false,
  };
}

/**
 * The pretool responder table. `requestIndex` is 0-based across the lifetime of the server and is
 * only consulted by `failBlock`, which answers once and then hangs so a test can prime the
 * last-good `policy_check_failure_action` and then force a failure.
 *
 * `body` is the parsed request body. It is consulted ONLY by the entry gate, which runs before the
 * mode switch and overrides every mode - including `401` and `hang`. That is deliberate: a request
 * the server would never have evaluated must not be able to produce a deny, a 401 or a timeout in
 * a test, because none of those could happen in production either.
 */
export function pretoolResponse(
  mode: MockMode,
  requestIndex: number,
  body?: unknown,
): ScriptedResponse | typeof HANG {
  if (body !== undefined && isGatedRequest(body) && !hasEvaluableInput(body)) {
    return entryGateResponse();
  }

  switch (mode) {
    case "allow":
    case "errors":
      return json(200, { decision: "allow", policy_check_failure_action: "allow" });
    case "deny":
      return json(200, { decision: "deny", reason: "Reading secrets is blocked." });
    case "denyTools":
      return eventNameOf(body) === TOOL_USE_EVENT
        ? json(200, { decision: "deny", reason: DENY_TOOLS_REASON })
        : json(200, { decision: "allow", policy_check_failure_action: "allow" });
    case "denyNoReason":
      return json(200, { decision: "deny" });
    case "ask":
      return json(200, { decision: "ask", reason: "Unusual command." });
    case "approval":
      return json(200, { decision: "approval_required", reason: "Needs admin approval." });
    case "failBlock":
      return requestIndex === 0
        ? json(200, { decision: "allow", policy_check_failure_action: "block" })
        : HANG;
    case "500":
      return json(500, { error: "boom" });
    case "malformed":
      // Lies about its content type on purpose: the client must survive a JSON.parse failure.
      return { status: 200, body: "not json", contentType: JSON_CONTENT_TYPE };
    case "hang":
      return HANG;
    case "attributed":
      return json(200, { decision: "deny", reason: `Reading secrets is blocked.${ATTRIBUTION_SUFFIX}` });
    case "toolsList":
      return json(200, policyPayload(TOOLS_LIST));
    case "toolsEmpty":
      // `[]` is a real answer: "this org has no file policies". It must not be confusable with
      // an absent key, which means "this response carried no opinion".
      return json(200, policyPayload([]));
    case "toolsOmitted":
      return json(200, policyPayload(undefined));
    case "401":
      // Pretool only. `/v1/hooks/errors` keeps its independent MockErrorsMode, because WR-01's
      // test asserts that ZERO errors requests are attempted once the latch trips - a 401 on that
      // route would never be observed. `setErrorsMode("500")` covers a failing errors endpoint.
      return json(401, INVALID_API_KEY_BODY);
  }
}

/**
 * The agents whose turn-log route (`POST /v1/hooks/<agent>`, `AgentProfile.turnLogPath`) this mock
 * serves. The real API registers one handler per agent, so an agent that is not listed here 404s —
 * exactly what a mistyped or not-yet-shipped route does in production. Add a name when its adapter
 * exists.
 */
export const TURNLOG_AGENTS: ReadonlySet<string> = new Set(["pi", "opencode"]);

/** `/v1/hooks/<agent>`: one lowercase path segment. Which names are served is `TURNLOG_AGENTS`. */
const TURNLOG_ROUTE = /^\/v1\/hooks\/([a-z][a-z0-9-]*)$/;

/**
 * The agent a path is the turn-log route of, or `undefined`. `pretool` and `errors` match the route
 * shape but are never agents: they keep their own handlers, which the server checks first, and the
 * explicit set membership means neither could be served as a turn log even if that order changed.
 */
export function turnLogAgentOf(path: string): string | undefined {
  const agent = TURNLOG_ROUTE.exec(path)?.[1];
  return agent !== undefined && TURNLOG_AGENTS.has(agent) ? agent : undefined;
}

/** The agent turn-log responder. Mirrors `hooksHandlerFactory.ts:46-50,86-89`. */
export function turnLogResponse(mode: MockTurnLogMode): ScriptedResponse | typeof HANG {
  if (mode === "hang") return HANG;
  // A missing/invalid Authorization header is a 401 here, unlike pretool which fails open.
  if (mode === "401") return json(401, INVALID_API_KEY_BODY);
  // The API answers immediately and logs afterwards, so the 200 says nothing about a row.
  return json(200, { success: true, message: "Request logged successfully" });
}

export function errorsResponse(
  mode: MockErrorsMode,
  body: unknown,
): ScriptedResponse | typeof HANG {
  if (mode === "hang") return HANG;
  if (mode === "500") return json(500, { error: "errors endpoint down" });
  const errors = (body as { errors?: unknown })?.errors;
  return json(200, { success: true, accepted: Array.isArray(errors) ? errors.length : 0 });
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolveBody(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseBody(raw: string): unknown {
  if (raw === "") return "";
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

export async function startMockApi(opts: StartMockApiOptions = {}): Promise<MockApi> {
  let mode: MockMode = opts.mode ?? "allow";
  let errorsMode: MockErrorsMode = opts.errorsMode ?? "ok";
  let turnLogMode: MockTurnLogMode = opts.turnLogMode ?? "ok";
  const requests: CapturedRequest[] = [];
  /** Sockets deliberately left without a response, so `close()` can destroy them. */
  const heldSockets = new Set<Socket>();
  let pretoolCount = 0;

  const send = (res: ServerResponse, scripted: ScriptedResponse): void => {
    res.writeHead(scripted.status, {
      "content-type": scripted.contentType,
      "content-length": Buffer.byteLength(scripted.body),
    });
    res.end(scripted.body);
  };

  const hold = (res: ServerResponse): void => {
    const socket = res.socket;
    if (socket) heldSockets.add(socket);
    // Deliberately never respond: the client's own AbortSignal must be the only way out.
  };

  const server: Server = createServer((req, res) => {
    void (async () => {
      const raw = await readBody(req);
      const path = (req.url ?? "/").split("?")[0] ?? "/";
      const parsed = parseBody(raw);
      requests.push({
        method: req.method ?? "GET",
        path,
        headers: req.headers,
        body: parsed,
      });

      if (req.method === "POST" && path === "/v1/hooks/pretool") {
        const scripted = pretoolResponse(mode, pretoolCount, parsed);
        pretoolCount += 1;
        if (scripted === HANG) hold(res);
        else send(res, scripted);
        return;
      }

      if (req.method === "POST" && path === "/v1/hooks/errors") {
        const scripted = errorsResponse(errorsMode, parsed);
        if (scripted === HANG) hold(res);
        else send(res, scripted);
        return;
      }

      // The agent turn log. Checked after pretool and errors, which keep precedence; the captured
      // request above already carries the real path, so a test can tell the agents apart.
      if (req.method === "POST" && turnLogAgentOf(path) !== undefined) {
        const scripted = turnLogResponse(turnLogMode);
        if (scripted === HANG) hold(res);
        else send(res, scripted);
        return;
      }

      if (req.method === "GET" && path === "/health") {
        send(res, json(200, { status: "ok" }));
        return;
      }

      send(res, json(404, { error: "no scripted route", path }));
    })();
  });

  await new Promise<void>((listening, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, "127.0.0.1", () => listening());
  });

  const address = server.address() as AddressInfo | null;
  if (address === null) throw new Error("mock api failed to bind");
  const port = address.port;

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    setMode(next: MockMode) {
      mode = next;
      pretoolCount = 0;
    },
    setErrorsMode(next: MockErrorsMode) {
      errorsMode = next;
    },
    setTurnLogMode(next: MockTurnLogMode) {
      turnLogMode = next;
    },
    async close() {
      for (const socket of heldSockets) socket.destroy();
      heldSockets.clear();
      // fetch keeps connections alive, so a plain close() would never call back.
      server.closeAllConnections();
      await new Promise<void>((closed, reject) => {
        server.close((err) => (err ? reject(err) : closed()));
      });
    },
  };
}
