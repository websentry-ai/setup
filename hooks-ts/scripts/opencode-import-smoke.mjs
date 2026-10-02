// Import smoke for the built opencode plugin bundle (CORE-05, RES-09, RES-10).
//
//   node scripts/opencode-import-smoke.mjs <artifact>     # e.g. ../opencode/index.js
//   bun  scripts/opencode-import-smoke.mjs <artifact>
//
// Runs unchanged under Node and Bun: plain ESM, `node:` built-ins only. It proves, on the real
// bytes, what opencode's loaders rely on:
//
//   * the module's only export is `default`, an `{ id: "unbound", server, setup }` object (no `tui`);
//   * `server()` resolves a hook set, and every hook RESOLVES on garbage input (an error escaping
//     `tool.execute.before` / `chat.message` would block on opencode v1);
//   * a deny from a gateway blocks a bash call with the verdict text, and the request carried
//     `event_name: "tool_use"` and `unbound_app_label: "opencode"`;
//   * `setup` resolves.
//
// Isolation, BEFORE anything is imported: HOME and every XDG base point into a fresh temp dir, every
// `UNBOUND_*` variable is deleted, and the gateway URL is an inline loopback mock started here. A
// deferred report from the bundle can never reach a real gateway with a real key, and nothing is
// read from or written to the real home.
//
// Exit 0 and print `OK` on success; exit 1 with a reason otherwise. A hard overall timeout applies.

import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const OVERALL_TIMEOUT_MS = 30_000;
const PER_CALL_TIMEOUT_MS = 8_000;
const DENY_REASON = "smoke";
const EXPECTED_DENY_PREFIX = `Blocked by Unbound policy: ${DENY_REASON}`;

const runtime =
  typeof process.versions.bun === "string" ? `bun ${process.versions.bun}` : `node ${process.version}`;

let tempRoot;
let server;

function cleanup() {
  try {
    server?.closeAllConnections?.();
    server?.close();
  } catch {
    // best effort
  }
  try {
    if (tempRoot !== undefined) rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // best effort
  }
}

function fail(reason) {
  console.error(`opencode-import-smoke FAILED (runtime=${runtime}): ${reason}`);
  cleanup();
  process.exit(1);
}

const overall = setTimeout(() => fail(`overall timeout after ${OVERALL_TIMEOUT_MS} ms`), OVERALL_TIMEOUT_MS);

// --- isolation: before any import of the artifact ----------------------------------------------

const artifactArg = process.argv[2];
if (typeof artifactArg !== "string" || artifactArg === "") {
  fail("usage: opencode-import-smoke.mjs <artifact>");
}
const artifactPath = resolve(artifactArg);

tempRoot = mkdtempSync(join(tmpdir(), "unbound-opencode-import-smoke-"));
const home = join(tempRoot, "home");
const projectDir = join(tempRoot, "proj");
for (const dir of [home, projectDir]) mkdirSync(dir, { recursive: true });

for (const name of Object.keys(process.env)) {
  if (name.startsWith("UNBOUND_")) delete process.env[name];
}
process.env.HOME = home;
process.env.XDG_CONFIG_HOME = join(home, ".config");
process.env.XDG_DATA_HOME = join(home, ".local", "share");
process.env.XDG_CACHE_HOME = join(home, ".cache");
process.env.XDG_STATE_HOME = join(home, ".local", "state");
delete process.env.OPENCODE_CONFIG_DIR;
delete process.env.OPENCODE_AUTH_CONTENT;

// --- the inline mock gateway --------------------------------------------------------------------

/** @type {{ method: string, path: string, body: any }[]} */
const requests = [];

function startMock() {
  return new Promise((resolvePromise, reject) => {
    const srv = createServer((req, res) => {
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
              ? { decision: "deny", reason: DENY_REASON }
              : { decision: "allow", policy_check_failure_action: "allow" };
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      });
    });
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => resolvePromise(srv));
  });
}

server = await startMock();
const port = server.address().port;
process.env.UNBOUND_GATEWAY_URL = `http://127.0.0.1:${port}`;
process.env.UNBOUND_OPENCODE_API_KEY = "test";

// --- helpers ------------------------------------------------------------------------------------

function withTimeout(promise, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} did not settle in ${PER_CALL_TIMEOUT_MS} ms`)), PER_CALL_TIMEOUT_MS);
    }),
  ]).finally(() => clearTimeout(timer));
}

/** Call a hook and report how it settled, never throwing. */
async function settle(fn, label, ...args) {
  try {
    const value = await withTimeout(Promise.resolve().then(() => fn(...args)), label);
    return { ok: true, value };
  } catch (err) {
    return { ok: false, error: err };
  }
}

// --- the checks ---------------------------------------------------------------------------------

let mod;
try {
  mod = await import(pathToFileURL(artifactPath).href);
} catch (err) {
  fail(`import failed: ${err instanceof Error ? err.message : String(err)}`);
}

const moduleKeys = Object.keys(mod);
if (JSON.stringify(moduleKeys) !== JSON.stringify(["default"])) {
  fail(`module exports ${JSON.stringify(moduleKeys)}, expected ["default"]`);
}
const plugin = mod.default;
if (plugin === null || typeof plugin !== "object") fail("default export is not an object");
if (plugin.id !== "unbound") fail(`default.id is ${JSON.stringify(plugin.id)}, expected "unbound"`);
if (typeof plugin.server !== "function") fail("default.server is not a function");
if (typeof plugin.setup !== "function") fail("default.setup is not a function (dual entry, 13-SPIKES V1-2)");
if ("tui" in plugin) fail("default has a `tui` entry");
const defaultKeys = Object.keys(plugin).sort();
if (JSON.stringify(defaultKeys) !== JSON.stringify(["id", "server", "setup"])) {
  fail(`default keys ${JSON.stringify(defaultKeys)}, expected ["id","server","setup"]`);
}

const created = await settle(plugin.server, "server()", { directory: projectDir, worktree: projectDir, client: {} });
if (!created.ok) fail(`server() rejected: ${String(created.error?.message ?? created.error)}`);
const hooks = created.value;
if (hooks === null || typeof hooks !== "object") fail("server() did not resolve an object");
const hookNames = Object.keys(hooks).sort();
if (!hookNames.includes("tool.execute.before")) fail(`no tool.execute.before in ${hookNames.join(", ")}`);

// Garbage input: every hook must resolve. `dispose` goes last, because it releases the directory.
const GARBAGE = [undefined, null, {}];
const ordered = [...hookNames.filter((n) => n !== "dispose"), ...hookNames.filter((n) => n === "dispose")];
for (const name of ordered) {
  if (name === "dispose") continue;
  for (const g of GARBAGE) {
    const r = await settle(hooks[name], `${name}(${JSON.stringify(g) ?? "undefined"})`, g, g);
    if (!r.ok) {
      fail(`${name} rejected on garbage ${JSON.stringify(g) ?? "undefined"}: ${String(r.error?.message ?? r.error)}`);
    }
  }
}

// A deny from the gateway blocks a bash call with the verdict text.
const denied = await settle(
  hooks["tool.execute.before"],
  "tool.execute.before(bash)",
  { tool: "bash", sessionID: "s", callID: "c" },
  { args: { command: "echo smoke" } },
);
if (denied.ok) fail("tool.execute.before resolved for a denied bash call (expected a block)");
const denyMessage = String(denied.error?.message ?? denied.error);
if (!denyMessage.startsWith(EXPECTED_DENY_PREFIX)) {
  fail(`deny message ${JSON.stringify(denyMessage)} does not start with ${JSON.stringify(EXPECTED_DENY_PREFIX)}`);
}
const toolUse = requests.find(
  (r) => r.path === "/v1/hooks/pretool" && r.body?.event_name === "tool_use" && r.body?.unbound_app_label === "opencode",
);
if (toolUse === undefined) {
  fail(`the mock saw no tool_use with unbound_app_label "opencode"; saw ${JSON.stringify(requests.map((r) => [r.path, r.body?.event_name, r.body?.unbound_app_label]))}`);
}

// dispose, on garbage too.
if (typeof hooks.dispose === "function") {
  for (const g of GARBAGE) {
    const r = await settle(hooks.dispose, "dispose", g);
    if (!r.ok) fail(`dispose rejected: ${String(r.error?.message ?? r.error)}`);
  }
}

// setup resolves (inert on anything that is not a v2 ctx).
const setupResult = await settle(plugin.setup, "setup({})", {});
if (!setupResult.ok) fail(`setup rejected: ${String(setupResult.error?.message ?? setupResult.error)}`);
if (setupResult.value !== undefined) fail(`setup resolved ${JSON.stringify(setupResult.value)}, expected undefined`);

clearTimeout(overall);
console.log(`hooks=${hookNames.join(",")}`);
console.log(`deny=${JSON.stringify(denyMessage)}`);
console.log(`mock_requests=${requests.length} (tool_use app_label=${toolUse.body.unbound_app_label})`);
console.log(`runtime=${runtime}`);
console.log("OK");
cleanup();
process.exit(0);
