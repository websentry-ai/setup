// The CORE-02 oracle's harness: WHAT the pi extension is asked to do (the scenario table), HOW each
// scenario is run (one child process each), and how a raw transcript becomes a comparable one (the
// normaliser).
//
// Why a child per scenario: `policyState`, `keyState`, `turnStore` and the heartbeat gate are
// module-scope singletons, and two of them only move one way (a latched key never un-latches, a sent
// heartbeat never un-sends). In one process the scenarios would be order-dependent and would also
// poison the rest of the suite. A child process is the only reset that is real, and it is also the
// only way to load the COMMITTED artifact (`pi/index.js`) and the source entry side by side.
//
// Why the normaliser is narrow: every field it hides is a field the oracle can no longer see. It
// replaces only what was PROVEN to differ between two captures of the same code (see
// `VOLATILE_KEYS`), plus the three things that differ by construction: the temp root, the mock's
// ephemeral port, and the platform-dependent device serial.

import { spawn } from "node:child_process";
import { join, resolve } from "node:path";

import type { MockMode } from "../../../core/test/helpers/mockApi.ts";
import { TEST_KEY } from "../../../core/test/helpers/testKey.ts";

// --- paths ---------------------------------------------------------------------------------------

const HELPERS_DIR = import.meta.dirname;
const PI_TEST_DIR = resolve(HELPERS_DIR, "..");
/** `hooks-ts/` — the npm workspace root. */
export const WORKSPACE_ROOT = resolve(PI_TEST_DIR, "..", "..", "..");
/** The frozen pre-refactor transcript. Written only under `UNBOUND_WRITE_GOLDEN=1`. */
export const GOLDEN_PATH = join(PI_TEST_DIR, "fixtures", "pi-wire-golden.json");
/**
 * The SECOND golden (review WR-05): the `EXTRA_SCENARIOS` below, captured by running the
 * pre-refactor ARTIFACT (`git show <EXTRA_GOLDEN_BASE>:pi/index.js`) through this same harness.
 * Written only under `UNBOUND_WRITE_EXTRA_GOLDEN=1`. The first golden is never touched by it.
 */
export const EXTRA_GOLDEN_PATH = join(PI_TEST_DIR, "fixtures", "pi-wire-golden-extra.json");
/** The commit the first golden was captured from, and whose artifact the second one is captured from. */
export const EXTRA_GOLDEN_BASE = "a9f621e";
/** The source entry the refactor will change. */
export const SOURCE_ENTRY = join(WORKSPACE_ROOT, "packages", "pi", "src", "index.ts");
/** The committed, installable bundle — one directory above the workspace, beside `setup.py`. */
export const ARTIFACT_ENTRY = resolve(WORKSPACE_ROOT, "..", "pi", "index.js");
const CHILD_PATH = join(HELPERS_DIR, "wireScenarioChild.ts");

const CHILD_TIMEOUT_MS = 60_000;

// --- keys ----------------------------------------------------------------------------------------

/** Which tier a key was planted in. Order is the resolver's precedence, highest first. */
export type KeyTier = "pi" | "generic" | "config";

/**
 * One distinguishable synthetic key per tier, so the `Authorization` header a request carries names
 * the tier that won. All derive from `TEST_KEY`; none is a credential anywhere but the loopback mock.
 */
export const SCENARIO_KEYS: Readonly<Record<KeyTier, string>> = {
  pi: TEST_KEY,
  generic: `${TEST_KEY}_generic`,
  config: `${TEST_KEY}_config`,
};

// --- the scenario table ---------------------------------------------------------------------------

/** `{CWD}` inside any string of a step is replaced by the scenario's working directory. */
export const CWD_PLACEHOLDER = "{CWD}";
export const SESSION_ID = "sess-wire-1";

interface StepBase {
  /** Unique within its scenario; the transcript is keyed by it for readable diffs. */
  name: string;
  /** Applied to the mock BEFORE the step runs. Omitted ⇒ the mode is left as it was. */
  mode?: MockMode;
  /** Overrides for the fake `ctx`. Default: an interactive TUI session whose confirm says yes. */
  ctx?: { mode?: "tui" | "rpc" | "json" | "print"; hasUI?: boolean; confirmResult?: boolean };
  /**
   * The number of requests this step must have caused before it may be considered settled. Only for
   * a fire-and-forget POST that is dispatched after an asynchronous wait longer than the quiet
   * window (the heartbeat waiting on the device-serial probe).
   */
  minRequests?: number;
}

export type Step = StepBase &
  (
    | { event: "session_start"; reason: "startup" | "reload" | "new" | "resume" | "fork" }
    | { event: "input"; text: string }
    | { event: "tool_call"; toolName: string; toolCallId: string; input: Record<string, unknown> }
    | { event: "tool_result"; toolName: string; toolCallId: string; input: Record<string, unknown>; text: string; isError?: boolean }
    | { event: "agent_end"; assistantText: string }
    | { event: "user_bash"; command: string; excludeFromContext?: boolean }
  );

export interface ScenarioDef {
  /** Tiers a key is planted in. Empty ⇒ no key anywhere. */
  keys: readonly KeyTier[];
  /** Where the mock's URL is planted. `config` exercises the `~/.unbound/config.json` URL tier. */
  gatewayVia: "env" | "config";
  /** Written verbatim to `<home>/<authJsonDir>/auth.json` when present. */
  authJson?: Record<string, unknown>;
  steps: readonly Step[];

  // --- Used only by EXTRA_SCENARIOS (WR-05). Every one is optional and changes nothing when absent,
  // so the frozen first golden's scenarios produce exactly the transcripts they always did.

  /**
   * `PI_CODING_AGENT_DIR`, set before the entry is imported. `{HOME}` is replaced by the fake home;
   * a value starting `~/` is passed as is, to exercise the resolver's own expansion.
   */
  agentDirEnv?: string;
  /** Where `authJson` goes, relative to the fake home. Default `.pi/agent`. */
  authJsonDir?: string;
  /**
   * A `policy_cache.json` planted before the entry is imported, at `<home>/<dir>/.unbound/`.
   * `identity: "matching"` binds it to the mock's URL and the pi-tier key, the way the extension
   * itself would; `"foreign"` binds it to another key, which the extension must ignore. Every
   * `{NOW}` value in `snapshot` is replaced by the epoch-ms time of planting (a fresh stamp).
   */
  seedCache?: { dir: string; identity: "matching" | "foreign"; snapshot: Record<string, unknown> };
  /**
   * Record planted files too in `files_written` (at their end-of-scenario content), so a cache the
   * extension rewrote — or left alone — is visible. Default: only files the extension created.
   */
  recordSeeded?: boolean;
  /** Record what each step wrote to the process's stderr (the headless notice mirror). */
  captureStderr?: boolean;
}

/** `{HOME}` inside `agentDirEnv`. */
export const HOME_PLACEHOLDER = "{HOME}";
/** `{NOW}` inside a `seedCache.snapshot` value. */
export const NOW_PLACEHOLDER = "{NOW}";

const bash = (name: string, id: string, command: string, extra: Partial<StepBase> = {}): Step => ({
  name,
  event: "tool_call",
  toolName: "bash",
  toolCallId: id,
  input: { command },
  ...extra,
});

const bashResult = (name: string, id: string, command: string, text: string): Step => ({
  name,
  event: "tool_result",
  toolName: "bash",
  toolCallId: id,
  input: { command },
  text,
});

export const SCENARIOS = {
  // The whole happy path of one turn: heartbeat, prompt check, command checks (the first carrying
  // `pull_policies`), a deny, both file-tool shapes, the results, and the turn log.
  "allow-deny-turn": {
    keys: ["pi", "generic", "config"],
    gatewayVia: "env",
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "allow", minRequests: 1 },
      { name: "prompt", event: "input", text: "list the files and clean up /tmp/x" },
      bash("bash-ls-allow", "toolu_wire_1", "ls -la"),
      bash("bash-rm-deny", "toolu_wire_2", "rm -rf /tmp/x", { mode: "deny" }),
      {
        name: "read-with-path",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_3",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts`, offset: 1, limit: 50 },
        mode: "allow",
      },
      {
        name: "grep-no-path",
        event: "tool_call",
        toolName: "grep",
        toolCallId: "toolu_wire_4",
        input: { pattern: "TODO", ignoreCase: true },
      },
      bashResult("result-ls", "toolu_wire_1", "ls -la", "total 0\nsrc\n"),
      {
        name: "result-read",
        event: "tool_result",
        toolName: "read",
        toolCallId: "toolu_wire_3",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts`, offset: 1, limit: 50 },
        text: "export const app = 1;\n",
      },
      {
        name: "result-grep",
        event: "tool_result",
        toolName: "grep",
        toolCallId: "toolu_wire_4",
        input: { pattern: "TODO", ignoreCase: true },
        text: "No matches found",
        isError: true,
      },
      { name: "agent-end", event: "agent_end", assistantText: "Listed the files; the cleanup was blocked by policy." },
    ],
  },

  // A verdict that needs a human: yes, no, and nobody to ask.
  "ask-confirm": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      bash("confirm-yes", "toolu_wire_1", "git push --force", { mode: "ask", ctx: { hasUI: true, confirmResult: true } }),
      bash("confirm-no", "toolu_wire_2", "git push --force", { ctx: { hasUI: true, confirmResult: false } }),
      bash("no-ui", "toolu_wire_3", "git push --force", { ctx: { mode: "print", hasUI: false } }),
    ],
  },

  // Fail-open, self-reported, then out of circuit: the fourth call makes no request at all.
  "fail-open-breaker": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      bash("fail-1", "toolu_wire_1", "ls", { mode: "500" }),
      bash("fail-2", "toolu_wire_2", "ls"),
      bash("fail-3-opens", "toolu_wire_3", "ls"),
      bash("open-no-request", "toolu_wire_4", "ls"),
    ],
  },

  // An org that opted out of fail-open: one success teaches `block`, then a failure is a block.
  "fail-closed": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      bash("teach-block", "toolu_wire_1", "ls", { mode: "failBlock" }),
      bash("fail-blocks", "toolu_wire_2", "ls", { mode: "500" }),
    ],
  },

  // Two rejections latch the session inert; after that, silence on every route.
  "revoked-key": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      bash("reject-1", "toolu_wire_1", "ls", { mode: "401" }),
      bash("reject-2-latches", "toolu_wire_2", "ls"),
      bash("latched-no-request", "toolu_wire_3", "ls"),
      { name: "latched-prompt", event: "input", text: "anything" },
      { name: "latched-agent-end", event: "agent_end", assistantText: "done" },
    ],
  },

  // No key anywhere: one notice, and zero requests whatever fires.
  "no-key": {
    keys: [],
    gatewayVia: "env",
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "deny" },
      { name: "session-start-again", event: "session_start", reason: "new" },
      { name: "prompt", event: "input", text: "do something" },
      bash("tool-call", "toolu_wire_1", "rm -rf /"),
      bashResult("tool-result", "toolu_wire_1", "rm -rf /", "ok"),
      { name: "user-bash", event: "user_bash", command: "rm -rf /" },
      { name: "agent-end", event: "agent_end", assistantText: "done" },
    ],
  },

  // A command the human typed, allowed and denied, with and without `!!`.
  "user-bash": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      { name: "allow", event: "user_bash", command: "git status", mode: "allow" },
      { name: "deny", event: "user_bash", command: "cat ~/.aws/credentials", mode: "deny" },
      { name: "deny-excluded", event: "user_bash", command: "cat ~/.aws/credentials", excludeFromContext: true },
    ],
  },

  // `tools_to_check: [read, write]` learned on the first call, so a `grep` and an `edit` cost
  // nothing, a `read` is still checked, and the snapshot is on disk at 0600.
  "cache-skip": {
    keys: ["pi"],
    gatewayVia: "env",
    steps: [
      bash("learn-tools", "toolu_wire_1", "ls", { mode: "toolsList" }),
      {
        name: "grep-skipped",
        event: "tool_call",
        toolName: "grep",
        toolCallId: "toolu_wire_2",
        input: { pattern: "secret", path: `${CWD_PLACEHOLDER}/src` },
      },
      {
        name: "edit-skipped",
        event: "tool_call",
        toolName: "edit",
        toolCallId: "toolu_wire_3",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts`, edits: [{ oldText: "a", newText: "b" }] },
      },
      {
        name: "read-checked",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_4",
        input: { path: "src/app.ts" },
      },
      {
        name: "write-checked",
        event: "tool_call",
        toolName: "write",
        toolCallId: "toolu_wire_5",
        input: { path: `${CWD_PLACEHOLDER}/out.txt`, content: "file contents that must not leave the machine" },
      },
    ],
  },

  // The generic env var wins over the config file when the pi-specific one is absent.
  "key-tier-generic": {
    keys: ["generic", "config"],
    gatewayVia: "env",
    steps: [bash("check", "toolu_wire_1", "ls", { mode: "allow" })],
  },

  // The config file alone supplies both the key and the gateway URL.
  "key-tier-config": {
    keys: ["config"],
    gatewayVia: "config",
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "allow", minRequests: 1 },
      bash("check", "toolu_wire_1", "ls"),
    ],
  },

  // A non-OAuth provider entry in pi's `auth.json`: every request names the sign-in as `api_key`.
  "identity-api-key": {
    keys: ["pi"],
    gatewayVia: "env",
    authJson: { openai: { type: "api_key" } },
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "allow", minRequests: 1 },
      { name: "prompt", event: "input", text: "hello" },
      bash("check", "toolu_wire_1", "ls"),
      { name: "user-bash", event: "user_bash", command: "pwd" },
      { name: "agent-end", event: "agent_end", assistantText: "hi" },
    ],
  },
} as const satisfies Record<string, ScenarioDef>;

/**
 * WR-05: paths the first table cannot see, each captured from the PRE-refactor artifact into the
 * second golden. A separate table, so the first golden (which must cover exactly `SCENARIOS`) is
 * never edited.
 */
export const EXTRA_SCENARIOS = {
  // The agent-dir relocation variable, absolute: the cache AND auth.json both follow it, and nothing
  // is written under the `~/.pi/agent` default.
  "agent-dir-env-absolute": {
    keys: ["pi"],
    gatewayVia: "env",
    agentDirEnv: `${HOME_PLACEHOLDER}/alt-agent`,
    authJsonDir: "alt-agent",
    authJson: { openai: { type: "api_key" } },
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "allow", minRequests: 1 },
      { name: "prompt", event: "input", text: "hello" },
      bash("learn-tools", "toolu_wire_1", "ls", { mode: "toolsList" }),
      {
        name: "read-checked",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_2",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts` },
      },
    ],
  },

  // The same variable in `~/` form: the resolver expands it against the home directory.
  "agent-dir-env-tilde": {
    keys: ["pi"],
    gatewayVia: "env",
    agentDirEnv: "~/tilde-agent",
    steps: [bash("learn-tools", "toolu_wire_1", "ls", { mode: "toolsList" })],
  },

  // WR-02 on the wire: a matching, fresh cache that says "no file policies" is hydrated, but the
  // first file tool is still SENT with `pull_policies`; only after the server confirms `[]` is the
  // next one skipped.
  "hydrated-cache-pulls": {
    keys: ["pi"],
    gatewayVia: "env",
    seedCache: {
      dir: ".pi/agent",
      identity: "matching",
      snapshot: { fetched_at: NOW_PLACEHOLDER, tools_synced_at: NOW_PLACEHOLDER, tools_to_check: [], policy_check_failure_action: "allow" },
    },
    recordSeeded: true,
    steps: [
      {
        name: "read-1-pulled",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_1",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts` },
        mode: "toolsEmpty",
      },
      {
        name: "read-2-skipped",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_2",
        input: { path: `${CWD_PLACEHOLDER}/src/other.ts` },
      },
    ],
  },

  // A hydrated `block` failure action applies from the very first call of the session.
  "hydrated-cache-fail-closed": {
    keys: ["pi"],
    gatewayVia: "env",
    seedCache: {
      dir: ".pi/agent",
      identity: "matching",
      snapshot: { fetched_at: NOW_PLACEHOLDER, tools_synced_at: NOW_PLACEHOLDER, tools_to_check: ["read"], policy_check_failure_action: "block" },
    },
    recordSeeded: true,
    steps: [bash("fail-blocks", "toolu_wire_1", "ls", { mode: "500" })],
  },

  // A cache bound to another key is ignored: the same failure is fail-open.
  "foreign-cache-ignored": {
    keys: ["pi"],
    gatewayVia: "env",
    seedCache: {
      dir: ".pi/agent",
      identity: "foreign",
      snapshot: { fetched_at: NOW_PLACEHOLDER, tools_synced_at: NOW_PLACEHOLDER, tools_to_check: [], policy_check_failure_action: "block" },
    },
    recordSeeded: true,
    steps: [
      bash("fail-allows", "toolu_wire_1", "ls", { mode: "500" }),
      {
        name: "read-checked",
        event: "tool_call",
        toolName: "read",
        toolCallId: "toolu_wire_2",
        input: { path: `${CWD_PLACEHOLDER}/src/app.ts` },
        mode: "allow",
      },
    ],
  },

  // Headless (`pi -p`): every notice is mirrored to stderr, since there is no UI to show it.
  "headless-stderr": {
    keys: ["pi"],
    gatewayVia: "env",
    captureStderr: true,
    steps: [
      { name: "prompt-deny", event: "input", text: "read the secrets", mode: "deny", ctx: { mode: "print", hasUI: false } },
      bash("bash-deny", "toolu_wire_1", "cat ~/.aws/credentials", { ctx: { mode: "print", hasUI: false } }),
      bash("bash-ask-no-ui", "toolu_wire_2", "git push --force", { mode: "ask", ctx: { mode: "print", hasUI: false } }),
      bash("reject-1", "toolu_wire_3", "ls", { mode: "401", ctx: { mode: "print", hasUI: false } }),
      bash("reject-2-latches", "toolu_wire_4", "ls", { ctx: { mode: "print", hasUI: false } }),
    ],
  },

  // Headless with no key: the one-time notice goes to stderr.
  "headless-no-key": {
    keys: [],
    gatewayVia: "env",
    captureStderr: true,
    steps: [
      { name: "session-start", event: "session_start", reason: "startup", mode: "deny", ctx: { mode: "print", hasUI: false } },
      { name: "session-start-again", event: "session_start", reason: "new", ctx: { mode: "print", hasUI: false } },
    ],
  },
} as const satisfies Record<string, ScenarioDef>;

export type ScenarioName = keyof typeof SCENARIOS;
export const SCENARIO_NAMES: readonly ScenarioName[] = Object.keys(SCENARIOS) as ScenarioName[];
export type ExtraScenarioName = keyof typeof EXTRA_SCENARIOS;
export const EXTRA_SCENARIO_NAMES: readonly ExtraScenarioName[] = Object.keys(EXTRA_SCENARIOS) as ExtraScenarioName[];

export function isScenarioName(name: string): name is ScenarioName {
  return Object.hasOwn(SCENARIOS, name);
}

export function isExtraScenarioName(name: string): name is ExtraScenarioName {
  return Object.hasOwn(EXTRA_SCENARIOS, name);
}

/** A scenario from either table. The two tables share no name (asserted by the equivalence test). */
export function scenarioDef(name: string): ScenarioDef | undefined {
  if (isScenarioName(name)) return SCENARIOS[name];
  if (isExtraScenarioName(name)) return EXTRA_SCENARIOS[name];
  return undefined;
}

// --- transcript shapes ----------------------------------------------------------------------------

/** What `undefined` is recorded as: JSON has no way to say it, and `null` is a different answer. */
export const UNDEFINED_MARKER = "<undefined>";

export interface RequestRecord {
  method: string;
  path: string;
  authorization: string | null;
  content_type: string | null;
  body: unknown;
}

export interface StepRecord {
  step: string;
  event: string;
  /** The mock's pretool mode while the step ran. */
  mode: string;
  /** The handler's return value, or `UNDEFINED_MARKER`. */
  returned: unknown;
  notices: { message: string; type: string | null }[];
  confirms: { title: string; message: string; timeout: number | null; has_signal: boolean }[];
  requests: RequestRecord[];
  /** What the step wrote to stderr. Present only for a scenario with `captureStderr`. */
  stderr?: string[];
}

export interface FileRecord {
  /** Absolute; the normaliser rewrites the temp root to `<ROOT>`. */
  path: string;
  /** Permission bits, octal, e.g. `"600"`. */
  mode: string;
  /** Parsed JSON when the file parses, otherwise the raw text. */
  content: unknown;
}

export interface Transcript {
  scenario: string;
  /** Handler names in registration order. */
  registered: string[];
  steps: StepRecord[];
  /** Every file the extension created under the fake home — in practice, the policy cache or nothing. */
  files_written: FileRecord[];
}

/** The child's raw output: a transcript plus the two per-run values the normaliser needs. */
export interface RawTranscript extends Transcript {
  root: string;
  gateway: string;
}

// --- the runner -----------------------------------------------------------------------------------

/** Run one scenario against one extension entry in a fresh process and return its NORMALISED transcript. */
export function runScenario(entryPath: string, name: ScenarioName | ExtraScenarioName): Promise<Transcript> {
  return new Promise<Transcript>((resolveRun, rejectRun) => {
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", CHILD_PATH, entryPath, name],
      { cwd: WORKSPACE_ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectRun(new Error(`scenario ${name} timed out after ${CHILD_TIMEOUT_MS} ms\n${stderr}`));
    }, CHILD_TIMEOUT_MS);

    child.on("error", (err) => {
      clearTimeout(timer);
      rejectRun(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const lastLine = stdout.trim().split("\n").at(-1) ?? "";
      if (code !== 0) {
        rejectRun(new Error(`scenario ${name} exited ${code}: ${lastLine}\n${stderr}`));
        return;
      }
      try {
        resolveRun(normalizeTranscript(JSON.parse(lastLine) as RawTranscript));
      } catch (err) {
        rejectRun(new Error(`scenario ${name} printed no transcript: ${String(err)}\n${stdout}\n${stderr}`));
      }
    });
  });
}

// --- the normaliser -------------------------------------------------------------------------------

export const VOLATILE = "<VOLATILE>";

/**
 * Keys whose VALUES are replaced by `<VOLATILE>` wherever they occur.
 *
 * Determined empirically: every scenario was captured twice from the same code, and this is exactly
 * the set of keys whose values differed. Nothing is here "to be safe" — a key in this set is a field
 * the oracle cannot see, so adding one needs the same evidence.
 */
export const VOLATILE_KEYS: ReadonlySet<string> = new Set<string>([
  // `/v1/hooks/errors` entries: the ISO time the failure was reported.
  "timestamp",
  // `/v1/hooks/pi` turn log: ISO start and end of the turn.
  "requestInitialized",
  "requestCompleted",
  // `policy_cache.json`: epoch-ms stamps of the last successful response / last tool-list sync.
  "fetched_at",
  "tools_synced_at",
]);

/** A wall-clock duration embedded in an error message: `... after 12ms`. */
const ELAPSED_SUFFIX = /after \d+ms/g;
/**
 * The id the adapter mints for a user-typed command (pi gives `user_bash` none): random per call.
 * Matched by VALUE rather than by key, because the key is `tool_use_id` and every other
 * `tool_use_id` in a transcript is a fixed input the oracle must keep seeing.
 */
const MINTED_USER_BASH_ID = /ubash_[0-9a-f]{20}/g;

interface NormalizeContext {
  root: string;
  gateway: string;
  /** Minted id → its ordinal within this transcript, so "the turn log names the same id" survives. */
  mintedIds: Map<string, number>;
}

function normalizeString(value: string, raw: NormalizeContext): string {
  let out = value.split(raw.root).join("<ROOT>").split(raw.gateway).join("<GATEWAY>");
  // Longest first: the generic and config keys both start with the pi key.
  for (const tier of ["generic", "config", "pi"] as const) {
    out = out.split(SCENARIO_KEYS[tier]).join(`<KEY:${tier}>`);
  }
  out = out.replace(MINTED_USER_BASH_ID, (id) => {
    let ordinal = raw.mintedIds.get(id);
    if (ordinal === undefined) {
      ordinal = raw.mintedIds.size + 1;
      raw.mintedIds.set(id, ordinal);
    }
    return `ubash_<MINTED:${ordinal}>`;
  });
  return out.replace(ELAPSED_SUFFIX, "after <N>ms");
}

function normalizeValue(value: unknown, raw: NormalizeContext): unknown {
  if (typeof value === "string") return normalizeString(value, raw);
  if (Array.isArray(value)) return value.map((item) => normalizeValue(item, raw));
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (VOLATILE_KEYS.has(key)) {
      out[key] = VOLATILE;
      continue;
    }
    if (key === "account_identity" && child !== null && typeof child === "object" && !Array.isArray(child)) {
      // Presence as well as value is platform-dependent (macOS probes `system_profiler`, Linux reads
      // `/etc/machine-id`, a container may have neither), so the field is removed, not masked.
      const { device_serial: _dropped, ...rest } = child as Record<string, unknown>;
      out[key] = normalizeValue(rest, raw);
      continue;
    }
    out[key] = normalizeValue(child, raw);
  }
  return out;
}

/** Strip everything that differs between two runs of the same code, and nothing else. */
export function normalizeTranscript(raw: RawTranscript): Transcript {
  const { root, gateway, ...transcript } = raw;
  return normalizeValue(transcript, { root, gateway, mintedIds: new Map() }) as Transcript;
}
