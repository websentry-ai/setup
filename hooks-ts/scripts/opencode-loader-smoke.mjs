// Real-loader smoke for the opencode plugin bundle (CORE-05, Pitfall 10).
//
//   node scripts/opencode-loader-smoke.mjs --cli <opencode binary> --artifact <index.js> --line v1|v2
//                                          [--timeout-ms N] [--keep]
//
// Loads the bundle through a REAL opencode CLI, from an isolated config home, following the
// headless loader recipe in 13-SPIKES.md:
//
//   1. a fresh temp dir holds HOME and every XDG base; every `UNBOUND_*` variable is dropped (the
//      child env is built from scratch, not inherited); the artifact is copied to
//      `<XDG_CONFIG_HOME>/opencode/plugins/unbound.js`;
//   2. an inline loopback mock gateway records every request (UNBOUND_GATEWAY_URL + a synthetic key);
//   3. `opencode serve --hostname 127.0.0.1 --port <free>` runs with cwd AND `PWD` set to a temp
//      project (opencode resolves its project directory from `PWD`).
//
// Evidence per line:
//
//   v1 (opencode-ai 1.x): plugins load lazily on the first HTTP request for a directory, so the
//      smoke waits for the port, then `POST /session?directory=<proj>` (no model needed). Pass =
//      the mock receives a pretool `event_name: "session_start"` with `unbound_app_label:
//      "opencode"` and a non-empty `pre_tool_use_data.metadata.opencode_version` (the plugin's heartbeat), AND no
//      `failed to load plugin` line names unbound.js. The v1 host must NOT produce a `v2_status`
//      (or the retired `api_family_inactive`) report: its embedded v2 core host's `setup` call must
//      stay inert.
//      Then a REAL, model-free block: `POST /session/:id/shell` runs a user shell command that the
//      mock denies (every tool_use is denied); pass = the mock saw the `bash` tool_use with that
//      command AND the command's marker file was never created (13-REVIEW WR-07, spike V1-7).
//   v2 (@opencode/cli 2.x): an authenticated `GET /api/agent?directory=<proj>` (basic auth with a
//      random per-run `OPENCODE_SERVER_PASSWORD`, never printed) makes the CLI load plugins and
//      call `setup(ctx)`; it never calls `server`. The active v2 entry (Phase 14) must then:
//        * report exactly ONE `v2_status` on `/v1/hooks/errors` whose detail is the shipped
//          capability set (`EXPECTED_V2_STATUS`, kept equal to `v2StatusDetail(V2_CAPABILITIES)` by
//          packages/opencode/test/v2Setup.test.ts), and no `api_family_inactive`;
//        * send a `session_start` heartbeat for `POST /api/session` (model-free) whose
//          `opencode_version` is the CLI's own version;
//        * REALLY block a user shell, model-free: `POST /api/session/:id/shell` with a command the
//          mock denies must reach the mock as a `bash` tool_use and must not run (no marker file);
//          v2 answers a blocked user shell with an empty HTTP 500 (14-SPIKES V2-10);
//        * REALLY block through the levers every v2 enforcement depends on (14-REVIEW WR-01), with a
//          loopback fake provider scripting the model's tool calls (no key, no model): a built-in
//          `shell` call denied through `permission.evaluate` (`permission.rejected` + our reason
//          reach the provider, the command does not run, it is checked once), a Code Mode MCP call
//          raised from `tool.execute.before` (server `smoke-mcp.v2`, sanitised by opencode), and a
//          prompt replaced through `session.prompt` (the original text never reaches the provider).
//
// The child process GROUP is always killed on exit. On failure the last 50 lines of the isolated
// opencode logs (paths inside the temp home only) and the mock's request list are printed. Lines
// mentioning a password (the v2 server prints a generated basic-auth password) are elided.
// Plain ESM, `node:` built-ins only: runs unchanged under Node and Bun.

import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/** The v2 entry's `v2_status` detail for the shipped `V2_CAPABILITIES` (14-SPIKES verdicts). */
export const EXPECTED_V2_STATUS =
  "tools:enforce/ask:native/mcp:enforce/prompt:block/recording:full/identity:provider/shell:enforce";

// --- arguments ------------------------------------------------------------------------------------

function parseArgs(argv) {
  const out = { cli: undefined, artifact: undefined, line: undefined, timeoutMs: 180_000, keep: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--cli") out.cli = argv[++i];
    else if (a === "--artifact") out.artifact = argv[++i];
    else if (a === "--line") out.line = argv[++i];
    else if (a === "--timeout-ms") out.timeoutMs = Number(argv[++i]);
    else if (a === "--keep") out.keep = true;
    else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  if (!out.cli || !out.artifact || (out.line !== "v1" && out.line !== "v2") || !(out.timeoutMs > 0)) {
    console.error("usage: opencode-loader-smoke.mjs --cli <path> --artifact <path> --line v1|v2 [--timeout-ms N] [--keep]");
    process.exit(2);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const cliPath = resolve(args.cli);
const artifactPath = resolve(args.artifact);
const started = Date.now();

// --- isolated home --------------------------------------------------------------------------------

const tempRoot = mkdtempSync(join(tmpdir(), `unbound-opencode-loader-${args.line}-`));
const home = join(tempRoot, "home");
const xdg = {
  XDG_CONFIG_HOME: join(home, ".config"),
  XDG_DATA_HOME: join(home, ".local", "share"),
  XDG_CACHE_HOME: join(home, ".cache"),
  XDG_STATE_HOME: join(home, ".local", "state"),
};
const projectDir = join(tempRoot, "proj");
const pluginsDir = join(xdg.XDG_CONFIG_HOME, "opencode", "plugins");
for (const dir of [home, ...Object.values(xdg), projectDir, pluginsDir]) mkdirSync(dir, { recursive: true });

// Nothing below inherits UNBOUND_* from this process either.
for (const name of Object.keys(process.env)) {
  if (name.startsWith("UNBOUND_")) delete process.env[name];
}

// --- the inline mock gateway ------------------------------------------------------------------------

/** @type {{ method: string, path: string, body: any }[]} */
const requests = [];
/** The v2 prompt leg's text marker: the mock denies a prompt carrying it; it must never reach the provider. */
const PROMPT_MARKER = "UNBOUND-SMOKE-PROMPT-MARKER";
/** The v2 MCP leg's server name: it contains characters opencode sanitises (`smoke-mcp_v2_<tool>`). */
const MCP_SERVER = "smoke-mcp.v2";
const MCP_SANITISED = "smoke-mcp_v2";

// --- the v2 model-free legs: a loopback OpenAI-compatible provider and a stdio MCP server ----------
//
// 14-01 harness, inlined. The provider answers the first request of a turn that offers tools with
// the leg's scripted tool call, and every other request with short text; it keeps every request body
// so the smoke can assert what reached "the model". The MCP server has one tool, `echo_marker`, which
// writes `<proj>/mcp-ran-<n>.txt`.

/** @type {any[]} */
const providerBodies = [];
/** @type {{ tool: string, args: object } | undefined} */
let providerScript;
let providerCalls = 0;

const provider = createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      body = {};
    }
    providerCalls += 1;
    if ((req.url ?? "").includes("/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ object: "list", data: [{ id: "fake-model", object: "model" }] }));
      return;
    }
    providerBodies.push(body);
    const messages = Array.isArray(body?.messages) ? body.messages : [];
    const last = messages[messages.length - 1];
    const hasTools = Array.isArray(body?.tools) && body.tools.length > 0;
    const call = hasTools && last?.role !== "tool" && providerScript !== undefined ? providerScript : undefined;
    if (call !== undefined) providerScript = undefined; // one tool call per leg
    const id = `chatcmpl-${providerCalls}`;
    const created = Math.floor(Date.now() / 1000);
    const base = { id, object: "chat.completion.chunk", created, model: body?.model };
    const deltas = call
      ? [
          { role: "assistant", content: null, tool_calls: [{ index: 0, id: `call_smoke_${providerCalls}`, type: "function", function: { name: call.tool, arguments: "" } }] },
          { tool_calls: [{ index: 0, function: { arguments: JSON.stringify(call.args) } }] },
        ]
      : [{ role: "assistant", content: last?.role === "tool" ? "done after tool" : "ok" }];
    if (body?.stream) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      for (const delta of deltas) res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
      res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: call ? "tool_calls" : "stop" }] })}\n\n`);
      res.write(`data: ${JSON.stringify({ ...base, choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`);
      res.end("data: [DONE]\n\n");
      return;
    }
    const message = call
      ? { role: "assistant", content: null, tool_calls: [{ id: `call_smoke_${providerCalls}`, type: "function", function: { name: call.tool, arguments: JSON.stringify(call.args) } }] }
      : { role: "assistant", content: deltas[0].content };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id, object: "chat.completion", created, model: body?.model, choices: [{ index: 0, message, finish_reason: call ? "tool_calls" : "stop" }] }));
  });
});

const MCP_SERVER_SOURCE = `
const { writeFileSync } = require("node:fs");
const { join } = require("node:path");
let buf = "";
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
process.stdin.on("data", (c) => {
  buf += c.toString("utf8");
  let i;
  while ((i = buf.indexOf("\\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let m;
    try { m = JSON.parse(line); } catch { continue; }
    if (m.id === undefined) continue;
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: (m.params && m.params.protocolVersion) || "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "smoke", version: "0.0.1" } } });
    else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo_marker", description: "Writes a marker file.", inputSchema: { type: "object", properties: { n: { type: "string" } }, required: ["n"] } }] } });
    else if (m.method === "tools/call") {
      const n = String((m.params && m.params.arguments && m.params.arguments.n) || "x").replace(/[^A-Za-z0-9_-]/g, "");
      writeFileSync(join(process.argv[2], "mcp-ran-" + n + ".txt"), "ran\\n");
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "written " + n }] } });
    } else if (m.method === "ping") send({ jsonrpc: "2.0", id: m.id, result: {} });
    else send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } });
  }
});
`;

const mock = createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      body = undefined;
    }
    const path = (req.url ?? "").split("?")[0];
    requests.push({ method: req.method ?? "", path, body });
    let payload = {};
    if (req.method === "POST" && path === "/v1/hooks/pretool") {
      // Every tool_use is denied; a user prompt carrying PROMPT_MARKER is denied (v2 prompt leg).
      payload =
        body?.event_name === "tool_use"
          ? { decision: "deny", reason: "smoke" }
          : body?.event_name === "user_prompt" && JSON.stringify(body).includes(PROMPT_MARKER)
            ? { decision: "deny", reason: "smoke prompt" }
            : { decision: "allow", policy_check_failure_action: "allow" };
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  });
});

await new Promise((ok, ko) => {
  mock.on("error", ko);
  mock.listen(0, "127.0.0.1", ok);
});
const mockUrl = `http://127.0.0.1:${mock.address().port}`;

function freePort() {
  return new Promise((ok, ko) => {
    const s = createNetServer();
    s.on("error", ko);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => ok(port));
    });
  });
}

// --- the child ------------------------------------------------------------------------------------

let child;
let cleanedUp = false;

function killGroup(signal) {
  if (child?.pid === undefined) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    // already gone
  }
}

async function cleanup() {
  if (cleanedUp) return;
  cleanedUp = true;
  if (child !== undefined && child.exitCode === null && child.signalCode === null) {
    killGroup("SIGTERM");
    const deadline = Date.now() + 5_000;
    while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
      await sleep(100);
    }
    killGroup("SIGKILL");
  } else {
    // The leader may be gone while a grandchild lives on in the group.
    killGroup("SIGKILL");
  }
  for (const server of [mock, provider]) {
    try {
      server.closeAllConnections?.();
      server.close();
    } catch {
      // best effort
    }
  }
  if (!args.keep) {
    try {
      rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
}

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => {
    void cleanup().then(() => process.exit(1));
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function redactLine(line) {
  return /password/i.test(line) ? "[line mentioning a password elided]" : line;
}

function tail(file, n) {
  try {
    return readFileSync(file, "utf8").split("\n").slice(-n).map(redactLine).join("\n");
  } catch {
    return "(unreadable)";
  }
}

function logFiles() {
  const dir = join(xdg.XDG_DATA_HOME, "opencode", "log");
  const files = [];
  try {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isFile()) files.push(p);
    }
  } catch {
    // no log dir yet
  }
  return files;
}

/** Every `failed to load plugin` line that names our file, from stderr and the isolated logs. */
function loadFailures() {
  const lines = [];
  for (const file of [join(tempRoot, "srv.err"), join(tempRoot, "srv.out"), ...logFiles()]) {
    let text = "";
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      if (/failed to load plugin/i.test(line) && line.includes("unbound.js")) lines.push(redactLine(line));
    }
  }
  return lines;
}

function summarizeRequests() {
  return requests.map((r) => ({
    method: r.method,
    path: r.path,
    event_name: r.body?.event_name,
    unbound_app_label: r.body?.unbound_app_label,
    client_entrypoint: r.body?.client_entrypoint,
    opencode_version: r.body?.pre_tool_use_data?.metadata?.opencode_version,
    errors: Array.isArray(r.body?.errors) ? r.body.errors.map((e) => e?.category ?? e?.message) : undefined,
    hook_source: r.body?.hook_source,
  }));
}

async function fail(reason) {
  console.error(`opencode-loader-smoke FAILED (line=${args.line}, ${Date.now() - started} ms): ${reason}`);
  console.error(`--- srv.err (last 50 lines) ---\n${tail(join(tempRoot, "srv.err"), 50)}`);
  for (const f of logFiles()) console.error(`--- ${f} (last 50 lines) ---\n${tail(f, 50)}`);
  console.error(`--- mock requests ---\n${JSON.stringify(summarizeRequests(), null, 2)}`);
  if (args.keep) console.error(`temp home kept at ${tempRoot}`);
  await cleanup();
  process.exit(1);
}

const overall = setTimeout(() => {
  void fail(`overall timeout after ${args.timeoutMs} ms`);
}, args.timeoutMs);

if (!existsSync(cliPath)) await fail(`CLI not found: ${cliPath}`);
if (!existsSync(artifactPath)) await fail(`artifact not found: ${artifactPath}`);
copyFileSync(artifactPath, join(pluginsDir, "unbound.js"));

if (args.line === "v2") {
  // The model-free legs' fake provider and MCP server (v2 config schema, 14-SPIKES "Config").
  await new Promise((ok, ko) => {
    provider.on("error", ko);
    provider.listen(0, "127.0.0.1", ok);
  });
  const mcpScript = join(tempRoot, "mcp-server.cjs");
  writeFileSync(mcpScript, MCP_SERVER_SOURCE);
  writeFileSync(
    join(xdg.XDG_CONFIG_HOME, "opencode", "opencode.json"),
    JSON.stringify({
      providers: {
        fake: {
          name: "Fake",
          package: "@opencode/ai/providers/openai-compatible",
          settings: { baseURL: `http://127.0.0.1:${provider.address().port}/v1`, apiKey: "dummy-not-a-secret" },
          models: { "fake-model": { name: "Fake Model", capabilities: { tools: true } } },
        },
      },
      model: "fake/fake-model",
      mcp: { servers: { [MCP_SERVER]: { type: "local", command: [process.execPath, mcpScript, projectDir] } } },
    }),
  );
}

const port = await freePort();
const serverPassword = randomBytes(24).toString("hex");
const env = {
  PATH: process.env.PATH ?? "",
  ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
  HOME: home,
  ...xdg,
  PWD: projectDir,
  OPENCODE_DISABLE_AUTOUPDATE: "1",
  OPENCODE_DISABLE_LSP_DOWNLOAD: "1",
  OPENCODE_DISABLE_SHARE: "1",
  OPENCODE_DISABLE_CLAUDE_CODE: "1",
  OPENCODE_DISABLE_EXTERNAL_SKILLS: "1",
  UNBOUND_GATEWAY_URL: mockUrl,
  UNBOUND_OPENCODE_API_KEY: "test",
  // v2 serves its API under basic auth with a generated password unless one is given. A random
  // per-run one (never printed) lets the smoke authenticate. v2 leg only: on v1 it would put the
  // unauthenticated recipe requests behind auth.
  ...(args.line === "v2" ? { OPENCODE_SERVER_USERNAME: "opencode", OPENCODE_SERVER_PASSWORD: serverPassword } : {}),
};

const serveArgs =
  args.line === "v1"
    ? ["serve", "--hostname", "127.0.0.1", "--port", String(port), "--print-logs", "--log-level", "INFO"]
    : ["serve", "--hostname", "127.0.0.1", "--port", String(port)];

child = spawn(cliPath, serveArgs, {
  cwd: projectDir,
  env,
  detached: true,
  stdio: ["ignore", openSync(join(tempRoot, "srv.out"), "w"), openSync(join(tempRoot, "srv.err"), "w")],
});
child.on("error", (err) => {
  void fail(`spawn failed: ${err.message}`);
});

async function waitFor(predicate, label, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      await fail(`opencode exited early (code=${child.exitCode}, signal=${child.signalCode}) while waiting for ${label}`);
    }
    const value = predicate();
    if (value) return value;
    await sleep(200);
  }
  await fail(`timed out waiting for ${label}`);
  return undefined;
}

/** Like `httpOk`, but also returns the parsed JSON body (`undefined` when it is not JSON). */
async function httpJson(method, path, body, extraHeaders = {}) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, json };
  } catch {
    return { status: undefined, json: undefined };
  }
}

async function httpOk(method, path, body, extraHeaders = {}) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    await res.arrayBuffer();
    return res.status;
  } catch {
    return undefined;
  }
}

const budget = () => Math.max(1_000, args.timeoutMs - (Date.now() - started) - 2_000);

/**
 * Retry a request until the server is READY: no answer (not listening yet) and any 5xx (listening
 * but still booting - v2 answers 503 for a few hundred ms) both mean "try again". The first answer
 * below 500 is returned, with the not-ready statuses seen on the way. Only the readiness request is
 * retried; nothing after it is.
 */
async function untilReady(request, label) {
  const notReady = [];
  const until = Date.now() + budget();
  while (Date.now() < until) {
    if (child.exitCode !== null || child.signalCode !== null) {
      await fail(`opencode exited early (code=${child.exitCode}, signal=${child.signalCode}) while waiting for ${label}`);
    }
    const status = await request();
    if (status !== undefined && status < 500) return { status, notReady };
    if (status !== undefined && notReady[notReady.length - 1] !== status) notReady.push(status);
    await sleep(250);
  }
  await fail(`the server never answered ${label} below 500 (not-ready statuses seen: ${JSON.stringify(notReady)})`);
  return { status: undefined, notReady };
}

if (args.line === "v1") {
  // 1. The first HTTP request boots the instance for the cwd: server() runs (cold home: the CLI
  //    first npm-installs @opencode-ai/plugin into the config dir, so this can take a while).
  const ready = await untilReady(() => httpOk("GET", "/session"), "GET /session");
  console.log(
    `listening: GET /session -> ${ready.status} after ${Date.now() - started} ms` +
      (ready.notReady.length > 0 ? ` (not ready before: ${ready.notReady.join(",")})` : ""),
  );

  // 2. A session for the project directory: session.created reaches the plugin's `event`.
  const dirQuery = `directory=${encodeURIComponent(projectDir)}`;
  const createdRes = await httpJson("POST", `/session?${dirQuery}`, {});
  const created = createdRes.status;
  console.log(`POST /session -> ${created}`);
  if (created !== 200) await fail(`POST /session answered ${created}`);
  const sessionID = typeof createdRes.json?.id === "string" ? createdRes.json.id : undefined;
  if (sessionID === undefined) await fail("POST /session returned no session id");

  const heartbeat = await waitFor(
    () =>
      requests.find(
        (r) =>
          r.path === "/v1/hooks/pretool" &&
          r.body?.event_name === "session_start" &&
          r.body?.unbound_app_label === "opencode" &&
          typeof r.body?.pre_tool_use_data?.metadata?.opencode_version === "string" &&
          r.body.pre_tool_use_data.metadata.opencode_version.length > 0,
      ),
    "the plugin's session_start heartbeat at the mock",
    budget(),
  );
  // 3. A REAL block on the real host, with no model (13-REVIEW WR-07; spike V1-7). The user-shell
  //    route `POST /session/:id/shell` publishes the bash part, then fires `shell.env`, where the
  //    plugin checks the command; the mock denies every tool_use (the repo mock's `denyTools`
  //    behaviour), so the plugin must throw and opencode must not spawn the command. The model ref
  //    is only stamped on the messages; no provider is called. Pass = the mock saw a tool_use for
  //    `bash` with exactly this command AND the marker file does not exist.
  const marker = join(projectDir, "ran.txt");
  const shellCommand = `echo smoke > ${marker}`;
  const shellRes = await httpJson("POST", `/session/${encodeURIComponent(sessionID)}/shell?${dirQuery}`, {
    agent: "build",
    model: { providerID: "smoke", modelID: "smoke" },
    command: shellCommand,
  });
  console.log(`POST /session/:id/shell -> ${shellRes.status} (a blocked user shell answers a generic 500)`);
  const denied = await waitFor(
    () =>
      requests.find(
        (r) =>
          r.path === "/v1/hooks/pretool" &&
          r.body?.event_name === "tool_use" &&
          r.body?.pre_tool_use_data?.tool_name === "bash" &&
          r.body?.pre_tool_use_data?.command === shellCommand,
      ),
    "the plugin's tool_use check of the user shell command at the mock",
    budget(),
  );
  // The spawn would have happened by now; give a slow host a moment before asserting the absence.
  await sleep(1_500);
  if (existsSync(marker)) await fail(`the denied user shell command ran: ${marker} exists`);

  // Give a deferred (wrong) v2 report a moment to show up before asserting its absence.
  await sleep(1_000);
  const failures = loadFailures();
  if (failures.length > 0) await fail(`load failure logged:\n${failures.join("\n")}`);
  const inactive = requests.filter((r) => JSON.stringify(r.body ?? {}).includes("api_family_inactive"));
  if (inactive.length > 0) await fail("a v1 host produced an api_family_inactive report (setup must be inert on 1.18)");
  const v2Status = requests.filter((r) => JSON.stringify(r.body ?? {}).includes("v2_status"));
  if (v2Status.length > 0) await fail("a v1 host produced a v2_status report (setup must be inert on 1.18)");

  clearTimeout(overall);
  console.log(
    `heartbeat: event_name=${heartbeat.body.event_name} unbound_app_label=${heartbeat.body.unbound_app_label} ` +
      `opencode_version=${heartbeat.body.pre_tool_use_data.metadata.opencode_version} client_entrypoint=${heartbeat.body.client_entrypoint}`,
  );
  console.log(
    `real block: tool_use tool_name=${denied.body.pre_tool_use_data.tool_name} denied by the mock; ${marker} was not created`,
  );
  console.log(`mock requests: ${JSON.stringify(summarizeRequests())}`);
  console.log(`no "failed to load plugin" line names unbound.js; no v2_status and no api_family_inactive report`);
  console.log(`OK line=v1 (${Date.now() - started} ms)`);
} else {
  // v2: plugins load lazily too, when an authenticated API request boots the location services for
  // a directory (13-SPIKES V2-1 run); setup(ctx) runs then, and the v2_status report arrives on
  // /v1/hooks/errors from a later macrotask.
  let cliVersion = "";
  try {
    const printed = execFileSync(cliPath, ["--version"], { env, encoding: "utf8", timeout: 30_000 });
    cliVersion = (/(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)/.exec(printed) ?? [])[1] ?? "";
  } catch {
    cliVersion = "";
  }
  if (cliVersion === "") await fail("could not read the CLI version (`--version`)");
  const auth = { authorization: `Basic ${Buffer.from(`opencode:${serverPassword}`).toString("base64")}` };
  const dirHeaders = { ...auth, "x-opencode-directory": projectDir };
  const agentPath = `/api/agent?directory=${encodeURIComponent(projectDir)}`;
  const ready = await untilReady(() => httpOk("GET", agentPath, undefined, dirHeaders), "GET /api/agent");
  const answered = ready.status;
  console.log(
    `listening: GET /api/agent -> ${answered} after ${Date.now() - started} ms` +
      (ready.notReady.length > 0 ? ` (not ready before: ${ready.notReady.join(",")})` : ""),
  );
  if (answered === 401) await fail("GET /api/agent answered 401: the basic-auth override was not honoured");

  const isStatus = (r) => r.path === "/v1/hooks/errors" && JSON.stringify(r.body ?? {}).includes("v2_status");
  const report = await waitFor(() => requests.find(isStatus), "the v2_status report at the mock", budget());
  const statusMessage = String(report.body?.errors?.[0]?.message ?? "");
  if (!statusMessage.includes(`v2_status: ${EXPECTED_V2_STATUS} for tool=setup`)) {
    await fail(`v2_status detail differs from the shipped capabilities: ${JSON.stringify(statusMessage)}`);
  }

  // 2. A session (no model call): session.created reaches the plugin's event subscription.
  const createdRes = await httpJson("POST", "/api/session", { location: { directory: projectDir } }, dirHeaders);
  console.log(`POST /api/session -> ${createdRes.status}`);
  const body = createdRes.json;
  const idOf = (v) => (typeof v?.id === "string" && v.id.startsWith("ses") ? v.id : undefined);
  const sessionID = idOf(body) ?? idOf(body?.data) ?? idOf(body?.info) ?? idOf(body?.session);
  if (createdRes.status !== 200 || sessionID === undefined) {
    const shape = body !== null && typeof body === "object" ? Object.keys(body).join(",") : typeof body;
    await fail(`POST /api/session answered ${createdRes.status} without a session id (body keys: ${shape})`);
  }
  const heartbeat = await waitFor(
    () =>
      requests.find(
        (r) =>
          r.path === "/v1/hooks/pretool" &&
          r.body?.event_name === "session_start" &&
          r.body?.unbound_app_label === "opencode" &&
          r.body?.pre_tool_use_data?.metadata?.opencode_version === cliVersion,
      ),
    `the v2 session_start heartbeat with opencode_version=${cliVersion} at the mock`,
    budget(),
  );

  // 3. A REAL block on the real v2 host, model-free (14-SPIKES V2-10): the user shell route fires
  //    `shell.create.before` before the spawn; the mock denies every tool_use, so the plugin must
  //    raise and nothing may spawn. Pass = the mock saw the `bash` tool_use with exactly this
  //    command AND the marker file does not exist.
  const marker = join(projectDir, "ran.txt");
  const shellCommand = `echo smoke > ${marker}`;
  const shellRes = await httpJson("POST", `/api/session/${encodeURIComponent(sessionID)}/shell`, { command: shellCommand }, dirHeaders);
  console.log(`POST /api/session/:id/shell -> ${shellRes.status} (a blocked user shell answers an empty 500)`);
  const denied = await waitFor(
    () =>
      requests.find(
        (r) =>
          r.path === "/v1/hooks/pretool" &&
          r.body?.event_name === "tool_use" &&
          r.body?.pre_tool_use_data?.tool_name === "bash" &&
          r.body?.pre_tool_use_data?.command === shellCommand,
      ),
    "the plugin's tool_use check of the v2 user shell command at the mock",
    budget(),
  );
  await sleep(1_500);
  if (existsSync(marker)) await fail(`the denied v2 user shell command ran: ${marker} exists`);

  // 4. Model-free REAL blocks on the levers every v2 enforcement depends on (14-REVIEW WR-01), with
  //    the fake provider scripting the model's tool calls:
  //      a. a built-in `shell` call denied through the PERMISSION hook: it must not run, the
  //         provider's follow-up must carry `permission.rejected` with our reason, and the call must
  //         have been checked exactly once (the tool's own spawn is not re-checked as a user shell);
  //      b. an MCP call (Code Mode) raised from `tool.execute.before`: the server name `smoke-mcp.v2`
  //         is sanitised by opencode, so this also proves the attribution; it must not run and the
  //         reason must reach the provider;
  //      c. a prompt replaced through the PROMPT hook: the provider must receive the block notice
  //         and never the original text.
  const modelRef = { id: "fake-model", providerID: "fake" };
  const dirQuery = `directory=${encodeURIComponent(projectDir)}`;
  const turn = async (label, script, text) => {
    const created = await httpJson("POST", "/api/session", { location: { directory: projectDir }, model: modelRef }, dirHeaders);
    const id = idOf(created.json) ?? idOf(created.json?.data);
    if (id === undefined) await fail(`${label}: POST /api/session answered ${created.status} without a session id`);
    providerScript = script;
    const from = providerBodies.length;
    const prompted = await httpJson("POST", `/api/session/${encodeURIComponent(id)}/prompt`, { text }, dirHeaders);
    if (prompted.status !== 200) await fail(`${label}: POST /prompt answered ${prompted.status}`);
    const waited = await httpOk("POST", `/api/experimental/session/${encodeURIComponent(id)}/wait`, {}, dirHeaders);
    if (waited !== 204 && waited !== 200) await fail(`${label}: the turn did not end (wait answered ${waited})`);
    providerScript = undefined;
    return JSON.stringify(providerBodies.slice(from));
  };
  const toolUses = (name) =>
    requests.filter((r) => r.path === "/v1/hooks/pretool" && r.body?.event_name === "tool_use" && r.body?.pre_tool_use_data?.tool_name === name);

  // a. built-in, permission hook
  const shellMarker = join(projectDir, "ran-model-shell.txt");
  const modelCommand = `echo model > ${shellMarker}`;
  const sentA = await turn("built-in deny", { tool: "shell", args: { command: modelCommand } }, "run the command");
  if (existsSync(shellMarker)) await fail(`the denied model shell call ran: ${shellMarker} exists`);
  if (!sentA.includes("permission.rejected") || !sentA.includes("Blocked by Unbound policy: smoke")) {
    await fail("the provider did not receive permission.rejected with the Unbound reason for the denied shell call");
  }
  const modelChecks = toolUses("bash").filter((r) => r.body?.pre_tool_use_data?.command === modelCommand);
  if (modelChecks.length !== 1) await fail(`the model shell call was checked ${modelChecks.length} times (expected once)`);

  // b. MCP, raise from tool.execute.before (Code Mode)
  let connected = false;
  for (let i = 0; i < 60 && !connected; i += 1) {
    const listed = await httpJson("GET", `/api/mcp?${dirQuery}`, undefined, dirHeaders);
    connected = JSON.stringify(listed.json ?? "").includes('"connected"');
    if (!connected) await sleep(250);
  }
  if (!connected) await fail(`the smoke MCP server ${MCP_SERVER} never connected`);
  const mcpMarker = join(projectDir, "mcp-ran-m1.txt");
  const sentB = await turn("MCP raise", { tool: "execute", args: { code: `return await tools["${MCP_SANITISED}"].echo_marker({ n: "m1" })` } }, "call the tool");
  if (existsSync(mcpMarker)) await fail(`the denied MCP call ran: ${mcpMarker} exists`);
  const mcpCheck = toolUses(`${MCP_SANITISED}_echo_marker`)[0];
  if (mcpCheck === undefined) await fail("the MCP call was never checked");
  const mcpMeta = mcpCheck.body?.pre_tool_use_data?.metadata ?? {};
  if (mcpMeta.mcp_server !== MCP_SERVER || mcpMeta.mcp_tool !== "echo_marker") {
    await fail(`the MCP call was not attributed to ${MCP_SERVER}/echo_marker: ${JSON.stringify({ server: mcpMeta.mcp_server, tool: mcpMeta.mcp_tool })}`);
  }
  if (!sentB.includes("Blocked by Unbound policy: smoke")) await fail("the MCP block reason did not reach the provider");

  // c. prompt, replaced through the prompt hook
  const sentC = await turn("prompt block", undefined, `${PROMPT_MARKER} please help`);
  if (sentC.includes(PROMPT_MARKER)) await fail("the blocked prompt's original text reached the provider");
  if (!sentC.includes("Blocked by Unbound policy: smoke prompt")) await fail("the provider did not receive the prompt block notice");
  console.log(
    `model-free legs: built-in shell denied via permission.rejected (checked once); MCP ${MCP_SANITISED}_echo_marker ` +
      `attributed to ${MCP_SERVER} and raised; prompt replaced by the block notice`,
  );

  // Give a second (wrong) status report a moment to show up before counting.
  await sleep(1_000);
  const failures = loadFailures();
  if (failures.length > 0) await fail(`load failure logged:\n${failures.join("\n")}`);
  const statuses = requests.filter(isStatus);
  if (statuses.length !== 1) await fail(`expected exactly one v2_status report, saw ${statuses.length}`);
  const inactive = requests.filter((r) => JSON.stringify(r.body ?? {}).includes("api_family_inactive"));
  if (inactive.length > 0) await fail("the v2 entry sent the retired api_family_inactive report");

  clearTimeout(overall);
  console.log(`v2_status: hook_source=${report.body.hook_source} message=${JSON.stringify(statusMessage)}`);
  console.log(
    `heartbeat: event_name=${heartbeat.body.event_name} opencode_version=${heartbeat.body.pre_tool_use_data.metadata.opencode_version} ` +
      `client_entrypoint=${heartbeat.body.client_entrypoint} (CLI ${cliVersion})`,
  );
  console.log(
    `real block: tool_use tool_name=${denied.body.pre_tool_use_data.tool_name} denied by the mock; ${marker} was not created`,
  );
  console.log(`mock requests: ${JSON.stringify(summarizeRequests())}`);
  console.log(`OK line=v2 (${Date.now() - started} ms)`);
}

await cleanup();
process.exit(0);
