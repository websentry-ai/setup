// The child half of the wire oracle. One process, one extension entry, one scenario.
//
//   node --experimental-strip-types wireScenarioChild.ts <entryPath> <scenarioName>
//
// Prints exactly ONE line of JSON on stdout (a `RawTranscript`) and exits 0; on any error prints
// `{"error": ...}` and exits 1.
//
// **Everything environmental is pinned before the entry is imported**, because the entry's default
// export is built at import time (`homedir()` is read there) and because this process must not be
// able to see the developer's real `~/.pi`, `~/.unbound`, keys or gateway (T-12-01):
//
//   * `HOME` → a fresh temp dir; every ambient `UNBOUND_*` / `PI_*` / proxy variable is deleted;
//   * `PATH` → an empty temp dir, so no probe binary resolves by name;
//   * `PI_MANAGED_INSTALL_ROOT` → a temp dir whose `current-version` is `0.87.1`, which makes
//     `client_entrypoint` deterministic instead of a function of how this test was launched;
//   * the gateway is the loopback mock on an ephemeral port, and the keys are the synthetic ones.
//
// The entry is loaded with a dynamic `import()` for exactly that reason. Nothing under `core/src` or
// `pi/src` is imported statically here — the oracle drives the extension through the same door pi
// does (`default(pi)` + `pi.on`), so it keeps working when the internals are rearranged.

import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { startMockApi } from "../../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../../core/test/helpers/mockApi.ts";
import {
  createFakeAgentEndEvent,
  createFakeAssistantMessage,
  createFakeCtx,
  createFakeInputEvent,
  createFakeSessionStartEvent,
  createFakeToolCallEvent,
  createFakeToolResultEvent,
  createFakeUserBashEvent,
} from "./fakeCtx.ts";
import {
  CWD_PLACEHOLDER,
  SCENARIOS,
  SCENARIO_KEYS,
  SESSION_ID,
  UNDEFINED_MARKER,
  isScenarioName,
} from "./wireScenario.ts";
import type { FileRecord, RawTranscript, RequestRecord, ScenarioDef, Step, StepRecord } from "./wireScenario.ts";

type AnyHandler = (event: unknown, ctx: unknown) => unknown;

const PINNED_PI_VERSION = "0.87.1";
/** A step is settled once the mock has seen no new request for this long. */
const QUIET_MS = 300;
const POLL_MS = 25;
/** The cap on waiting for quiet. */
const SETTLE_CAP_MS = 5_000;
/** The cap on waiting for a step's `minRequests` — longer, because it waits on a real probe. */
const MIN_REQUESTS_CAP_MS = 20_000;

const AMBIENT_PREFIXES = ["UNBOUND_", "PI_"];
const AMBIENT_NAMES = new Set(
  ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY"].flatMap(
    (name) => [name, name.toLowerCase()],
  ),
);

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

function scrubAmbientEnv(): void {
  for (const name of Object.keys(process.env)) {
    if (AMBIENT_NAMES.has(name) || AMBIENT_PREFIXES.some((prefix) => name.toUpperCase().startsWith(prefix))) {
      delete process.env[name];
    }
  }
}

function writePrivateJson(dir: string, file: string, value: unknown): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const path = join(dir, file);
  writeFileSync(path, JSON.stringify(value, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Every regular file under `dir`, recursively, as absolute paths. */
function listFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const path = join(dir, entry);
    const stat = lstatSync(path);
    if (stat.isDirectory()) out.push(...listFiles(path));
    else out.push(path);
  }
  return out;
}

function parseOrRaw(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function substituteCwd<T>(value: T, cwd: string): T {
  if (typeof value === "string") return value.split(CWD_PLACEHOLDER).join(cwd) as T;
  if (Array.isArray(value)) return value.map((item) => substituteCwd(item, cwd)) as T;
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) out[key] = substituteCwd(child, cwd);
  return out as T;
}

function headerOf(headers: Record<string, string | string[] | undefined>, name: string): string | null {
  const value = headers[name];
  if (value === undefined) return null;
  return Array.isArray(value) ? value.join(", ") : value;
}

/** `undefined` anywhere in a return value would vanish in JSON; make it visible instead. */
function recordable(value: unknown): unknown {
  if (value === undefined) return UNDEFINED_MARKER;
  if (Array.isArray(value)) return value.map(recordable);
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) out[key] = recordable(child);
  return out;
}

function eventFor(step: Step): unknown {
  switch (step.event) {
    case "session_start":
      return createFakeSessionStartEvent(step.reason);
    case "input":
      return createFakeInputEvent(step.text);
    case "tool_call":
      return createFakeToolCallEvent(step.toolName, step.input, step.toolCallId);
    case "tool_result":
      return createFakeToolResultEvent(step.toolName, {
        toolCallId: step.toolCallId,
        input: step.input,
        content: [{ type: "text", text: step.text }],
        isError: step.isError ?? false,
      });
    case "agent_end":
      return createFakeAgentEndEvent([createFakeAssistantMessage([{ type: "text", text: step.assistantText }])]);
    case "user_bash":
      return createFakeUserBashEvent(step.command, {
        excludeFromContext: step.excludeFromContext ?? false,
      });
  }
}

/**
 * Wait until the requests a step caused have all arrived: at least `minRequests` of them, and then
 * no new one for `QUIET_MS`. This is what puts a fire-and-forget POST in the step that dispatched
 * it, and so what makes the request ORDER in the transcript deterministic.
 */
async function settle(mock: MockApi, before: number, minRequests: number): Promise<void> {
  const startedAt = Date.now();
  while (mock.requests.length - before < minRequests) {
    if (Date.now() - startedAt > MIN_REQUESTS_CAP_MS) {
      throw new Error(`expected at least ${minRequests} request(s), saw ${mock.requests.length - before}`);
    }
    await sleep(POLL_MS);
  }
  const quietFrom = Date.now();
  let seen = mock.requests.length;
  let lastChange = Date.now();
  while (Date.now() - lastChange < QUIET_MS && Date.now() - quietFrom < SETTLE_CAP_MS) {
    await sleep(POLL_MS);
    if (mock.requests.length !== seen) {
      seen = mock.requests.length;
      lastChange = Date.now();
    }
  }
}

async function run(entryArg: string, scenarioName: string): Promise<RawTranscript> {
  if (!isScenarioName(scenarioName)) throw new Error(`unknown scenario: ${scenarioName}`);
  const scenario: ScenarioDef = SCENARIOS[scenarioName];
  // Resolved against the launch cwd BEFORE anything moves; a relative entry path is the common case.
  const entryPath = resolve(entryArg);

  // `realpath`: on macOS the temp dir is a symlink (`/var` → `/private/var`), and a path the
  // extension canonicalises must still start with the root the normaliser replaces.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "pi-wire-")));
  let mock: MockApi | undefined;
  try {
    const home = join(root, "home");
    const cwd = join(root, "work");
    const emptyBin = join(root, "bin");
    const installRoot = join(root, "pi-install");
    for (const dir of [home, cwd, emptyBin, installRoot]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(installRoot, "current-version"), `${PINNED_PI_VERSION}\n`);

    mock = await startMockApi();

    scrubAmbientEnv();
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.PATH = emptyBin;
    process.env.PI_MANAGED_INSTALL_ROOT = installRoot;
    if (scenario.gatewayVia === "env") process.env.UNBOUND_GATEWAY_URL = mock.url;
    if (scenario.keys.includes("pi")) process.env.UNBOUND_PI_API_KEY = SCENARIO_KEYS.pi;
    if (scenario.keys.includes("generic")) process.env.UNBOUND_API_KEY = SCENARIO_KEYS.generic;

    const config: Record<string, unknown> = {};
    if (scenario.keys.includes("config")) config.api_key = SCENARIO_KEYS.config;
    if (scenario.gatewayVia === "config") config.gateway_url = mock.url;
    if (Object.keys(config).length > 0) writePrivateJson(join(home, ".unbound"), "config.json", config);
    if (scenario.authJson !== undefined) writePrivateJson(join(home, ".pi", "agent"), "auth.json", scenario.authJson);

    // Whatever exists now was planted here; whatever appears later, the extension wrote.
    const seeded = new Set(listFiles(home));

    const mod = (await import(pathToFileURL(entryPath).href)) as { default?: unknown };
    if (typeof mod.default !== "function") throw new Error(`${entryPath} has no default-exported factory`);
    const handlers = new Map<string, AnyHandler>();
    const registered: string[] = [];
    const stubPi = {
      on(name: string, handler: AnyHandler) {
        registered.push(name);
        handlers.set(name, handler);
        return () => {};
      },
    };
    await (mod.default as (pi: unknown) => unknown)(stubPi);

    const steps: StepRecord[] = [];
    let mode: MockMode = "allow";
    for (const step of scenario.steps) {
      if (step.mode !== undefined) {
        mode = step.mode;
        mock.setMode(mode);
      }
      const handler = handlers.get(step.event);
      if (handler === undefined) throw new Error(`no handler registered for ${step.event}`);
      const ctx = createFakeCtx({ cwd, sessionId: SESSION_ID, ...step.ctx });
      const before = mock.requests.length;

      const event = substituteCwd(eventFor(step), cwd);
      // A user-typed command carries its own cwd on the event; pin it to the scenario's.
      if (step.event === "user_bash") (event as { cwd: string }).cwd = cwd;
      const returned = await handler(event, ctx);
      await settle(mock, before, step.minRequests ?? 0);

      const requests: RequestRecord[] = mock.requests.slice(before).map((request) => ({
        method: request.method,
        path: request.path,
        authorization: headerOf(request.headers, "authorization"),
        content_type: headerOf(request.headers, "content-type"),
        body: request.body,
      }));
      steps.push({
        step: step.name,
        event: step.event,
        mode,
        returned: recordable(returned),
        notices: ctx.notifyCalls.map((call) => ({ message: call.message, type: call.type ?? null })),
        confirms: ctx.confirmCalls.map((call) => ({
          title: call.title,
          message: call.message,
          timeout: call.opts?.timeout ?? null,
          has_signal: call.opts?.signal !== undefined,
        })),
        requests,
      });
    }

    const files_written: FileRecord[] = listFiles(home)
      .filter((path) => !seeded.has(path))
      .sort()
      .map((path) => ({
        path,
        mode: (lstatSync(path).mode & 0o777).toString(8),
        content: parseOrRaw(readFileSync(path, "utf8")),
      }));

    return { scenario: scenarioName, root, gateway: mock.url, registered, steps, files_written };
  } finally {
    try {
      await mock?.close();
    } catch {
      // Closing is best-effort; the process is about to exit.
    }
    rmSync(root, { recursive: true, force: true });
  }
}

function finish(line: string, code: number): void {
  process.stdout.write(`${line}\n`, () => process.exit(code));
}

const [entryArg, scenarioArg] = process.argv.slice(2);
if (entryArg === undefined || scenarioArg === undefined) {
  finish(JSON.stringify({ error: "usage: wireScenarioChild.ts <entryPath> <scenarioName>" }), 1);
} else {
  run(entryArg, scenarioArg).then(
    (transcript) => finish(JSON.stringify(transcript), 0),
    (err: unknown) => finish(JSON.stringify({ error: err instanceof Error ? (err.stack ?? err.message) : String(err) }), 1),
  );
}
