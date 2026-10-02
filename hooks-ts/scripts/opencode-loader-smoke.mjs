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
//      `failed to load plugin` line names unbound.js. The v1 host must NOT produce an
//      `api_family_inactive` report (its embedded v2 core host's `setup` call must stay inert).
//   v2 (@opencode/cli 2.x): an authenticated `GET /api/agent?directory=<proj>` (basic auth with a
//      random per-run `OPENCODE_SERVER_PASSWORD`, never printed) makes the CLI load plugins and
//      call `setup(ctx)`; it never calls `server`. Pass = the
//      mock receives a `/v1/hooks/errors` report naming `api_family_inactive`. Phase 14 owns v2
//      enforcement; this leg only proves the bundle loads there and says it is inactive.
//
// The child process GROUP is always killed on exit. On failure the last 50 lines of the isolated
// opencode logs (paths inside the temp home only) and the mock's request list are printed. Lines
// mentioning a password (the v2 server prints a generated basic-auth password) are elided.
// Plain ESM, `node:` built-ins only: runs unchanged under Node and Bun.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

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
      payload =
        body?.event_name === "tool_use"
          ? { decision: "deny", reason: "smoke" }
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
  try {
    mock.closeAllConnections?.();
    mock.close();
  } catch {
    // best effort
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
  const created = await httpOk("POST", `/session?directory=${encodeURIComponent(projectDir)}`, {});
  console.log(`POST /session -> ${created}`);
  if (created !== 200) await fail(`POST /session answered ${created}`);

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
  // Give a deferred (wrong) v2 report a moment to show up before asserting its absence.
  await sleep(1_000);
  const failures = loadFailures();
  if (failures.length > 0) await fail(`load failure logged:\n${failures.join("\n")}`);
  const inactive = requests.filter((r) => JSON.stringify(r.body ?? {}).includes("api_family_inactive"));
  if (inactive.length > 0) await fail("a v1 host produced an api_family_inactive report (setup must be inert on 1.18)");

  clearTimeout(overall);
  console.log(
    `heartbeat: event_name=${heartbeat.body.event_name} unbound_app_label=${heartbeat.body.unbound_app_label} ` +
      `opencode_version=${heartbeat.body.pre_tool_use_data.metadata.opencode_version} client_entrypoint=${heartbeat.body.client_entrypoint}`,
  );
  console.log(`mock requests: ${JSON.stringify(summarizeRequests())}`);
  console.log(`no "failed to load plugin" line names unbound.js; no api_family_inactive report`);
  console.log(`OK line=v1 (${Date.now() - started} ms)`);
} else {
  // v2: plugins load lazily too, when an authenticated API request boots the location services for
  // a directory (13-SPIKES V2-1 run); setup(ctx) runs then, and the inactive-family report arrives
  // on /v1/hooks/errors from a later macrotask.
  const auth = { authorization: `Basic ${Buffer.from(`opencode:${serverPassword}`).toString("base64")}` };
  const agentPath = `/api/agent?directory=${encodeURIComponent(projectDir)}`;
  const ready = await untilReady(
    () => httpOk("GET", agentPath, undefined, { ...auth, "x-opencode-directory": projectDir }),
    "GET /api/agent",
  );
  const answered = ready.status;
  console.log(
    `listening: GET /api/agent -> ${answered} after ${Date.now() - started} ms` +
      (ready.notReady.length > 0 ? ` (not ready before: ${ready.notReady.join(",")})` : ""),
  );
  if (answered === 401) await fail("GET /api/agent answered 401: the basic-auth override was not honoured");

  const report = await waitFor(
    () =>
      requests.find(
        (r) => r.path === "/v1/hooks/errors" && JSON.stringify(r.body ?? {}).includes("api_family_inactive"),
      ),
    "the api_family_inactive report at the mock",
    budget(),
  );
  const failures = loadFailures();
  if (failures.length > 0) await fail(`load failure logged:\n${failures.join("\n")}`);
  const heartbeats = requests.filter((r) => r.body?.event_name === "session_start");

  clearTimeout(overall);
  console.log(`api_family_inactive: hook_source=${report.body.hook_source} errors=${JSON.stringify(report.body.errors?.map((e) => e?.message))}`);
  console.log(`session_start heartbeats on v2: ${heartbeats.length} (server() is never called by a v2 host)`);
  console.log(`mock requests: ${JSON.stringify(summarizeRequests())}`);
  console.log(`OK line=v2 (${Date.now() - started} ms)`);
}

await cleanup();
process.exit(0);
