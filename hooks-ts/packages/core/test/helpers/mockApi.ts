// Scripted in-process mock of the Unbound API (`/v1/hooks/*`).
//
// One responder table, two entry points: unit tests call `startMockApi()` on an ephemeral port,
// and `scripts/mock-api.mjs` starts the same server on a fixed port for the manual pi smoke test.
// Zero dependencies - `node:http` only.

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
  | "errors";

/** Scripted behaviour of `POST /v1/hooks/errors`, independent of `MockMode`. */
export type MockErrorsMode = "ok" | "500" | "hang";

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
  close(): Promise<void>;
}

/** What an attributed deny reason looks like once the gateway appends its footer. */
export const ATTRIBUTION_SUFFIX = "\n\nEnforced by Unbound · Trace ID abc";

const JSON_CONTENT_TYPE = "application/json";
const HANG = "hang" as const;

interface ScriptedResponse {
  status: number;
  body: string;
  contentType: string;
}

function json(status: number, payload: unknown): ScriptedResponse {
  return { status, body: JSON.stringify(payload), contentType: JSON_CONTENT_TYPE };
}

/**
 * The pretool responder table. `requestIndex` is 0-based across the lifetime of the server and is
 * only consulted by `failBlock`, which answers once and then hangs so a test can prime the
 * last-good `policy_check_failure_action` and then force a failure.
 */
export function pretoolResponse(
  mode: MockMode,
  requestIndex: number,
): ScriptedResponse | typeof HANG {
  switch (mode) {
    case "allow":
    case "errors":
      return json(200, { decision: "allow", policy_check_failure_action: "allow" });
    case "deny":
      return json(200, { decision: "deny", reason: "Reading secrets is blocked." });
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
  }
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
      requests.push({
        method: req.method ?? "GET",
        path,
        headers: req.headers,
        body: parseBody(raw),
      });

      if (req.method === "POST" && path === "/v1/hooks/pretool") {
        const scripted = pretoolResponse(mode, pretoolCount);
        pretoolCount += 1;
        if (scripted === HANG) hold(res);
        else send(res, scripted);
        return;
      }

      if (req.method === "POST" && path === "/v1/hooks/errors") {
        const scripted = errorsResponse(errorsMode, parseBody(raw));
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
