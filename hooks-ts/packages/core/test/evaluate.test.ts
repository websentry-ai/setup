// The adapter-facing evaluation API (`evaluate.ts`) and its contract:
//
//   * `evaluateToolCall` and `evaluatePrompt` never throw and never reject, for any input;
//   * an error never becomes a deny, a confirm or an unavailable — it is an allow or a skip;
//   * a checker that never settles is bounded by a deadline, which honours the org's failure action;
//   * `verdictMessage` is the one string an adapter may throw, and it is total too.
//
// An adapter whose host blocks by throwing depends on every line of this: there, any accidental
// throw is a block the model sees.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  DENY_PREFIX,
  ENGINE_UNAVAILABLE_REASON,
  EVALUATE_DEADLINE_SLACK_MS,
  GENERIC_DENY_REASON,
  KEY_REJECTED_BLOCK_REASON,
  PRETOOL_TIMEOUT_MS,
} from "../src/constants.ts";
import { evaluatePrompt, evaluateToolCall, verdictMessage } from "../src/evaluate.ts";
import type { DecisionEntry, EvaluateDeps, PromptInput, ToolCallInput, ToolEvaluation } from "../src/evaluate.ts";
import type { CheckHooks, PolicyChecker } from "../src/policy.ts";
import { createPolicyState } from "../src/policyState.ts";
import type { PolicyState } from "../src/policyState.ts";
import type { AgentProfile } from "../src/profile.ts";
import type { PretoolRequestBody } from "../src/types.ts";
import type { PolicyOutcome } from "../src/verdict.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

const NOW = 1_700_000_000_000;
const TTL_MS = 300_000;

interface Recorded {
  payload: PretoolRequestBody;
  toolName: string;
  hooks: CheckHooks | undefined;
}

interface StubChecker extends PolicyChecker {
  calls: Recorded[];
}

/** A checker that records what it was asked and answers `outcome`. */
function stubChecker(outcome: unknown = { kind: "allow" }): StubChecker {
  const calls: Recorded[] = [];
  return {
    calls,
    async checkTool(payload, toolName, hooks) {
      calls.push({ payload, toolName, hooks });
      return outcome as PolicyOutcome;
    },
  };
}

/** A state a server response has taught `tools`, at `NOW`. */
function confirmedState(tools: string[], failureAction: "allow" | "block" = "allow"): PolicyState {
  const state = createPolicyState();
  state.recordSuccess({ decision: "allow", policy_check_failure_action: failureAction, tools_to_check: tools }, NOW);
  return state;
}

interface Harness {
  deps: EvaluateDeps;
  checker: StubChecker;
  decisions: DecisionEntry[];
}

function harness(overrides: Partial<EvaluateDeps> = {}, outcome: unknown = { kind: "allow" }): Harness {
  const checker = stubChecker(outcome);
  const decisions: DecisionEntry[] = [];
  const deps: EvaluateDeps = {
    checker,
    profile: TEST_PROFILE,
    entrypoint: "agent/1.2.3",
    state: createPolicyState(),
    now: () => NOW,
    onDecision: (entry) => decisions.push(entry),
    deadlineMs: 2_000,
    ...overrides,
  };
  return { deps, checker, decisions };
}

function shellCall(overrides: Partial<ToolCallInput> = {}): ToolCallInput {
  return {
    toolName: "bash",
    toolCallId: "toolu_1",
    command: "git push --force",
    toolInput: { command: "git push --force" },
    cwd: "/work/project",
    sessionId: "session-1",
    model: "model-x",
    ...overrides,
  };
}

function fileCall(toolName: string, toolInput: Record<string, unknown>): ToolCallInput {
  return shellCall({ toolName, command: "", toolInput });
}

function promptInput(overrides: Partial<PromptInput> = {}): PromptInput {
  return {
    text: "delete the production database",
    source: "interactive",
    cwd: "/work/project",
    sessionId: "session-1",
    model: "model-x",
    hasUI: true,
    ...overrides,
  };
}

/** An object whose every property read throws. */
function throwingProxy<T extends object>(): T {
  return new Proxy({}, {
    get() {
      throw new Error("hostile getter");
    },
    has() {
      throw new Error("hostile has");
    },
    ownKeys() {
      throw new Error("hostile ownKeys");
    },
  }) as T;
}

/**
 * Await `run` and fail on a synchronous throw or a rejection. Returns what it resolved to.
 * A pending promise on an otherwise idle loop would end the test run early, so the loop is held open.
 */
async function settle<T>(run: () => Promise<T>): Promise<T> {
  const keepAlive = setTimeout(() => {}, 30_000);
  try {
    let promise: Promise<T> | undefined;
    assert.doesNotThrow(() => {
      promise = run();
    }, "must not throw synchronously");
    assert.ok(promise instanceof Promise, "must return a promise");
    let value: T | undefined;
    await assert.doesNotReject(async () => {
      value = await promise;
    }, "must not reject");
    return value as T;
  } finally {
    clearTimeout(keepAlive);
  }
}

const HARMLESS_KINDS = new Set(["allow", "skip"]);

function assertHarmless(result: ToolEvaluation, label: string): void {
  assert.ok(
    result !== null && typeof result === "object" && HARMLESS_KINDS.has(result.kind),
    `${label}: an error must be an allow or a skip, got ${JSON.stringify(result)}`,
  );
}

// --- Skips -------------------------------------------------------------------------------------

test("a call with no command and no file path is skipped as nothing-evaluable, with no check and no audit entry", async () => {
  const cases: ToolCallInput[] = [
    shellCall({ toolName: "mcp_custom_tool", command: "", toolInput: { query: "x" } }),
    shellCall({ command: "   \n\t", toolInput: { command: "   \n\t" } }),
    // A path-required file tool given no path has nothing to evaluate either.
    fileCall("read", {}),
  ];
  for (const call of cases) {
    const h = harness();
    const result = await settle(() => evaluateToolCall(call, h.deps));
    assert.deepEqual(result, { kind: "skip", why: "nothing-evaluable" });
    assert.equal(h.checker.calls.length, 0, "the checker is never called");
    assert.equal(h.decisions.length, 0, "onDecision is not called");
  }
});

test("a file tool absent from a confirmed, fresh tool list is skipped as cached and audited as skipped", async () => {
  const h = harness({ state: confirmedState(["write"]) });
  const result = await settle(() => evaluateToolCall(fileCall("read", { path: "/x/y", content: "secret" }), h.deps));

  assert.deepEqual(result, { kind: "skip", why: "cached" });
  assert.equal(h.checker.calls.length, 0, "the checker is never called");
  assert.deepEqual(h.decisions, [
    { tool_name: "read", tool_use_id: "toolu_1", decision: "skipped", tool_input: { path: "/x/y", _dropped: true } },
  ]);
});

test("the cached skip needs a server-confirmed list: a hydrated list is checked, with pull_policies", async () => {
  const state = createPolicyState();
  state.hydrate({ tools_to_check: [], tools_synced_at: NOW, fetched_at: NOW });
  const h = harness({ state });

  const result = await settle(() => evaluateToolCall(fileCall("read", { path: "/x/y" }), h.deps));

  assert.deepEqual(result, { kind: "allow" });
  assert.equal(h.checker.calls.length, 1);
  assert.equal(h.checker.calls[0]?.payload.pull_policies, true);
});

test("the cached skip covers only the profile's file tools and only tools the list does not name", async () => {
  // A listed file tool is checked; the list is confirmed and fresh, so nothing is pulled.
  const listed = harness({ state: confirmedState(["read"]) });
  await settle(() => evaluateToolCall(fileCall("read", { path: "/x/y" }), listed.deps));
  assert.equal(listed.checker.calls.length, 1);
  assert.equal("pull_policies" in (listed.checker.calls[0]?.payload ?? {}), false);

  // A shell command is never answered by a cached list.
  const shell = harness({ state: confirmedState([]) });
  const result = await settle(() => evaluateToolCall(shellCall(), shell.deps));
  assert.deepEqual(result, { kind: "allow" });
  assert.equal(shell.checker.calls.length, 1);
});

test("a stale tool list is not a skip: the call is checked and the list is pulled again", async () => {
  const h = harness({ state: confirmedState([]), now: () => NOW + TTL_MS + 1 });
  const result = await settle(() => evaluateToolCall(fileCall("read", { path: "/x/y" }), h.deps));

  assert.deepEqual(result, { kind: "allow" });
  assert.equal(h.checker.calls.length, 1);
  assert.equal(h.checker.calls[0]?.payload.pull_policies, true);
});

// --- The checked path ----------------------------------------------------------------------------

test("a checked call builds the payload from the profile, calls the checker once and audits the outcome", async () => {
  const outcomes: PolicyOutcome[] = [
    { kind: "allow" },
    { kind: "deny", reason: "rm -rf is not allowed" },
    { kind: "deny" },
    { kind: "confirm", reason: "force push needs approval" },
    { kind: "unavailable" },
    { kind: "unavailable", reason: KEY_REJECTED_BLOCK_REASON },
  ];
  for (const outcome of outcomes) {
    const hooks: CheckHooks = { notify: () => {} };
    const h = harness({ hooks, accountIdentity: { user_email: "dev@example.com" } }, outcome);
    const result = await settle(() => evaluateToolCall(shellCall(), h.deps));

    assert.deepEqual(result, outcome, "the result is the checker's outcome");
    assert.equal(h.checker.calls.length, 1, "the checker is called exactly once");
    const seen = h.checker.calls[0] as Recorded;
    assert.equal(seen.toolName, "bash");
    assert.equal(typeof seen.hooks?.notify, "function", "the notice channel reaches the checker");
    assert.equal(seen.payload.unbound_app_label, TEST_PROFILE.appLabel);
    assert.equal(seen.payload.client_entrypoint, "agent/1.2.3");
    assert.equal(seen.payload.conversation_id, "session-1");
    assert.equal(seen.payload.model, "model-x");
    assert.equal(seen.payload.pre_tool_use_data.command, "git push --force");
    assert.equal(seen.payload.pre_tool_use_data.tool_use_id, "toolu_1");
    assert.equal(seen.payload.pull_policies, true, "an unconfirmed tool list is pulled");
    assert.deepEqual(seen.payload.account_identity, { user_email: "dev@example.com" });
    assert.deepEqual(h.decisions, [
      { tool_name: "bash", tool_use_id: "toolu_1", decision: outcome.kind, tool_input: { command: "git push --force" } },
    ]);
  }
});

test("the profile decides the app label and which argument is a file path", async () => {
  const profile: Pick<AgentProfile, "appLabel" | "fileTools"> = {
    appLabel: "other-agent",
    fileTools: {
      defaulting: new Set(["glob"]),
      required: new Set(["view"]),
      pathOf: (_toolName, input) => input.filePath,
    },
  };
  const h = harness({ profile });
  await settle(() => evaluateToolCall(fileCall("view", { filePath: "/etc/hosts" }), h.deps));
  await settle(() => evaluateToolCall(fileCall("glob", {}), h.deps));
  // `read` is not a file tool of this profile, so with no command there is nothing to evaluate.
  const foreign = await settle(() => evaluateToolCall(fileCall("read", { path: "/x" }), h.deps));

  assert.deepEqual(foreign, { kind: "skip", why: "nothing-evaluable" });
  assert.equal(h.checker.calls.length, 2);
  assert.equal(h.checker.calls[0]?.payload.unbound_app_label, "other-agent");
  assert.equal(h.checker.calls[0]?.payload.pre_tool_use_data.metadata.file_path, "/etc/hosts");
  assert.equal(h.checker.calls[1]?.payload.pre_tool_use_data.metadata.file_path, "/work/project");
});

test("session id and model are read only when a payload is built", async () => {
  let reads = 0;
  const call = {
    ...fileCall("read", { path: "/x/y" }),
    get sessionId(): string {
      reads += 1;
      return "lazy-session";
    },
  };
  const skipped = harness({ state: confirmedState([]) });
  await settle(() => evaluateToolCall(call, skipped.deps));
  assert.equal(reads, 0, "a skipped call never reads the session id");

  const checked = harness();
  await settle(() => evaluateToolCall(call, checked.deps));
  assert.equal(reads, 1);
  assert.equal(checked.checker.calls[0]?.payload.conversation_id, "lazy-session");
});

// --- The nothrow matrix --------------------------------------------------------------------------

test("nothrow: a call that is null, undefined, a number or a string resolves harmlessly", async () => {
  for (const call of [null, undefined, 42, "bash", true, []]) {
    const h = harness({}, { kind: "deny", reason: "must not be reached or must not be invented" });
    const result = await settle(() => evaluateToolCall(call as unknown as ToolCallInput, h.deps));
    assertHarmless(result, `call=${JSON.stringify(call)}`);
    assert.equal(h.checker.calls.length, 0, "there is nothing to check");
  }
});

test("nothrow: fields of the wrong type are coerced, not trusted", async () => {
  const h = harness();
  const call = {
    toolName: "bash",
    toolCallId: { not: "a string" },
    command: "echo ok",
    toolInput: "not an object",
    cwd: 7,
    sessionId: null,
    model: 12,
  } as unknown as ToolCallInput;
  const result = await settle(() => evaluateToolCall(call, h.deps));

  assert.deepEqual(result, { kind: "allow" });
  const payload = h.checker.calls[0]?.payload as PretoolRequestBody;
  assert.equal(payload.conversation_id, "");
  assert.equal(payload.model, "auto");
  assert.equal(payload.pre_tool_use_data.metadata.cwd, "");
  assert.deepEqual(payload.pre_tool_use_data.metadata.tool_input, {});
  assert.equal("tool_use_id" in payload.pre_tool_use_data, false);

  // A non-string tool name or command is nothing evaluable.
  for (const bad of [{ toolName: 5, command: 9 }, { toolName: null, command: { a: 1 } }]) {
    const other = harness();
    const skipped = await settle(() => evaluateToolCall({ ...shellCall(), ...bad } as unknown as ToolCallInput, other.deps));
    assert.deepEqual(skipped, { kind: "skip", why: "nothing-evaluable" });
  }
});

test("nothrow: a call whose every property read throws resolves harmlessly", async () => {
  const h = harness({}, { kind: "deny" });
  const result = await settle(() => evaluateToolCall(throwingProxy<ToolCallInput>(), h.deps));
  assertHarmless(result, "throwing proxy call");

  // The same for a tool input whose reads throw, on a call that is otherwise checkable.
  const inner = harness();
  const withHostileInput = await settle(() =>
    evaluateToolCall(shellCall({ toolInput: throwingProxy<Record<string, unknown>>() }), inner.deps),
  );
  assertHarmless(withHostileInput, "throwing proxy tool input");
});

test("nothrow: a session id getter that throws allows without calling the checker", async () => {
  const h = harness({}, { kind: "deny" });
  const call = {
    ...shellCall(),
    get sessionId(): string {
      throw new Error("no session");
    },
  };
  const result = await settle(() => evaluateToolCall(call, h.deps));
  assert.deepEqual(result, { kind: "allow" });
  assert.equal(h.checker.calls.length, 0);
});

test("nothrow: a checker that throws synchronously, rejects, or answers garbage is an allow", async () => {
  const checkers: Record<string, PolicyChecker> = {
    "throws synchronously": {
      checkTool() {
        throw new Error("checker exploded synchronously");
      },
    },
    rejects: {
      checkTool: async () => {
        await Promise.resolve();
        throw new Error("checker rejected");
      },
    },
    "resolves undefined": { checkTool: async () => undefined as unknown as PolicyOutcome },
    "resolves null": { checkTool: async () => null as unknown as PolicyOutcome },
    "resolves a string": { checkTool: async () => "deny" as unknown as PolicyOutcome },
    "resolves an unknown kind": { checkTool: async () => ({ kind: "weird" }) as unknown as PolicyOutcome },
    "resolves a non-string kind": { checkTool: async () => ({ kind: 7 }) as unknown as PolicyOutcome },
    "returns a non-promise": { checkTool: (() => 5) as unknown as PolicyChecker["checkTool"] },
    "is not callable": { checkTool: "nope" as unknown as PolicyChecker["checkTool"] },
    "resolves an object whose reads throw": { checkTool: async () => throwingProxy<PolicyOutcome>() },
  };
  for (const [label, checker] of Object.entries(checkers)) {
    const h = harness({ checker });
    const result = await settle(() => evaluateToolCall(shellCall(), h.deps));
    assert.deepEqual(result, { kind: "allow" }, label);
  }

  const missing = harness({ checker: undefined as unknown as PolicyChecker });
  assert.deepEqual(await settle(() => evaluateToolCall(shellCall(), missing.deps)), { kind: "allow" });
});

test("nothrow: a reason that is not a string is dropped, never rendered", async () => {
  const h = harness({}, { kind: "deny", reason: { toString: () => "injected" } });
  const result = await settle(() => evaluateToolCall(shellCall(), h.deps));
  assert.deepEqual(result, { kind: "deny" });
  assert.equal(verdictMessage(result), GENERIC_DENY_REASON);
});

test("nothrow: a notify hook that throws cannot change the verdict", async () => {
  const checker: PolicyChecker = {
    async checkTool(_payload, _toolName, hooks) {
      // No guard here on purpose: the channel handed to a checker must already be safe.
      hooks?.notify?.("engine unreachable", "warning");
      return { kind: "deny", reason: "blocked" };
    },
  };
  const h = harness({
    checker,
    hooks: {
      notify() {
        throw new Error("notify exploded");
      },
    },
  });
  const result = await settle(() => evaluateToolCall(shellCall(), h.deps));
  assert.deepEqual(result, { kind: "deny", reason: "blocked" }, "the deny still stands");

  const hostileHooks = harness({ hooks: throwingProxy<CheckHooks>() }, { kind: "deny", reason: "blocked" });
  assertHarmlessOrDeny(await settle(() => evaluateToolCall(shellCall(), hostileHooks.deps)));
});

/** A hooks object that cannot be read may cost the notice, but the verdict is the checker's or an allow. */
function assertHarmlessOrDeny(result: ToolEvaluation): void {
  assert.ok(
    result.kind === "allow" || (result.kind === "deny" && result.reason === "blocked"),
    `got ${JSON.stringify(result)}`,
  );
}

test("nothrow: an onDecision that throws cannot change the verdict, on the checked and the skipped path", async () => {
  const onDecision = (): void => {
    throw new Error("audit sink exploded");
  };
  const denied = harness({ onDecision }, { kind: "deny", reason: "blocked" });
  assert.deepEqual(await settle(() => evaluateToolCall(shellCall(), denied.deps)), { kind: "deny", reason: "blocked" });

  const skipped = harness({ onDecision, state: confirmedState([]) });
  assert.deepEqual(await settle(() => evaluateToolCall(fileCall("read", { path: "/x" }), skipped.deps)), {
    kind: "skip",
    why: "cached",
  });
});

test("nothrow: a profile whose pathOf throws, or that cannot be read at all, resolves harmlessly", async () => {
  const pathOfThrows: Pick<AgentProfile, "appLabel" | "fileTools"> = {
    appLabel: "agent",
    fileTools: {
      defaulting: new Set(["ls"]),
      required: new Set(["read"]),
      pathOf() {
        throw new Error("pathOf exploded");
      },
    },
  };
  // A defaulting tool still gets cwd and is checked; a required tool has no path, so nothing to check.
  const h = harness({ profile: pathOfThrows });
  assert.deepEqual(await settle(() => evaluateToolCall(fileCall("ls", {}), h.deps)), { kind: "allow" });
  assert.equal(h.checker.calls[0]?.payload.pre_tool_use_data.metadata.file_path, "/work/project");
  assert.deepEqual(await settle(() => evaluateToolCall(fileCall("read", { path: "/x" }), h.deps)), {
    kind: "skip",
    why: "nothing-evaluable",
  });

  for (const profile of [null, undefined, 3, throwingProxy<AgentProfile>(), { appLabel: "a", fileTools: throwingProxy() }]) {
    const hostile = harness({ profile: profile as unknown as AgentProfile }, { kind: "deny" });
    assertHarmless(await settle(() => evaluateToolCall(fileCall("read", { path: "/x" }), hostile.deps)), "hostile profile");
  }
});

test("nothrow: state methods, the clock, or deps themselves throwing resolve harmlessly", async () => {
  const throwingState = throwingProxy<PolicyState>();
  const stateCase = harness({ state: throwingState }, { kind: "deny" });
  assertHarmless(await settle(() => evaluateToolCall(shellCall(), stateCase.deps)), "throwing state");

  const clockCase = harness({
    now: () => {
      throw new Error("clock exploded");
    },
  }, { kind: "deny" });
  assertHarmless(await settle(() => evaluateToolCall(shellCall(), clockCase.deps)), "throwing clock");

  for (const deps of [null, undefined, 9, throwingProxy<EvaluateDeps>()]) {
    assertHarmless(
      await settle(() => evaluateToolCall(shellCall(), deps as unknown as EvaluateDeps)),
      `deps=${typeof deps}`,
    );
  }
});

// --- The deadline --------------------------------------------------------------------------------

/** A checker whose promise never settles. */
function hangingChecker(): StubChecker {
  const calls: Recorded[] = [];
  return {
    calls,
    checkTool(payload, toolName, hooks) {
      calls.push({ payload, toolName, hooks });
      return new Promise<PolicyOutcome>(() => {});
    },
  };
}

test("deadline: a checker that never settles resolves to allow when nothing says fail-closed", async () => {
  for (const state of [createPolicyState(), confirmedState(["bash"], "allow")]) {
    const checker = hangingChecker();
    const h = harness({ checker, state, deadlineMs: 25 });
    const started = Date.now();
    const result = await settle(() => evaluateToolCall(shellCall(), h.deps));

    assert.deepEqual(result, { kind: "allow" });
    assert.equal(checker.calls.length, 1);
    assert.ok(Date.now() - started < 1_500, "bounded by the injected deadline, not by the default");
    assert.deepEqual(h.decisions.map((d) => d.decision), ["allow"], "the applied decision is audited");
  }
});

test("deadline: a checker that never settles resolves to unavailable for a fail-closed org", async () => {
  const checker = hangingChecker();
  const h = harness({ checker, state: confirmedState(["bash"], "block"), deadlineMs: 25 });
  const result = await settle(() => evaluateToolCall(shellCall(), h.deps));

  assert.deepEqual(result, { kind: "unavailable" });
  assert.equal(verdictMessage(result), ENGINE_UNAVAILABLE_REASON);
  assert.deepEqual(h.decisions.map((d) => d.decision), ["unavailable"]);
});

test("deadline: an answer that arrives in time wins, and a late one is ignored", async () => {
  const inTime: PolicyChecker = {
    checkTool: () => new Promise((done) => setTimeout(() => done({ kind: "deny", reason: "in time" }), 5)),
  };
  const fast = harness({ checker: inTime, deadlineMs: 1_000 });
  assert.deepEqual(await settle(() => evaluateToolCall(shellCall(), fast.deps)), { kind: "deny", reason: "in time" });

  const late: PolicyChecker = {
    checkTool: () => new Promise((done) => setTimeout(() => done({ kind: "deny", reason: "too late" }), 80)),
  };
  const slow = harness({ checker: late, deadlineMs: 15 });
  assert.deepEqual(await settle(() => evaluateToolCall(shellCall(), slow.deps)), { kind: "allow" });
  await new Promise((done) => setTimeout(done, 100));
  assert.deepEqual(slow.decisions.map((d) => d.decision), ["allow"], "the late answer records nothing");
});

test("deadline: the default sits just past the client's own timeout, and a bad value falls back to it", async () => {
  assert.equal(EVALUATE_DEADLINE_SLACK_MS, 2_000);
  assert.ok(PRETOOL_TIMEOUT_MS + EVALUATE_DEADLINE_SLACK_MS > PRETOOL_TIMEOUT_MS);

  // A nonsense deadline must not become "no deadline" or "fire at once": a prompt answer still wins.
  for (const deadlineMs of [0, -5, Number.NaN, Number.POSITIVE_INFINITY, "10" as unknown as number]) {
    const h = harness({ deadlineMs }, { kind: "deny", reason: "blocked" });
    assert.deepEqual(await settle(() => evaluateToolCall(shellCall(), h.deps)), { kind: "deny", reason: "blocked" });
  }
});

// --- evaluatePrompt ------------------------------------------------------------------------------

test("prompt: host-generated and blank prompts are skipped without a check", async () => {
  const cases: PromptInput[] = [
    promptInput({ source: "extension" }),
    promptInput({ text: "" }),
    promptInput({ text: "  \n " }),
    promptInput({ text: 42 as unknown as string }),
  ];
  for (const input of cases) {
    const h = harness({}, { kind: "deny" });
    const result = await settle(() => evaluatePrompt(input, h.deps));
    assert.deepEqual(result, { kind: "skip", why: "nothing-evaluable" });
    assert.equal(h.checker.calls.length, 0);
  }
});

test("prompt: a real prompt is checked once as user_prompt and the outcome is returned", async () => {
  const outcomes: PolicyOutcome[] = [
    { kind: "allow" },
    { kind: "deny", reason: "secrets in prompt" },
    { kind: "confirm", reason: "are you sure" },
    { kind: "unavailable" },
  ];
  for (const source of ["interactive", "rpc", undefined]) {
    for (const outcome of outcomes) {
      const h = harness({ accountIdentity: { org_id: "org_1" } }, outcome);
      const result = await settle(() => evaluatePrompt(promptInput({ source, hasUI: false }), h.deps));

      assert.deepEqual(result, outcome);
      assert.equal(h.checker.calls.length, 1);
      const seen = h.checker.calls[0] as Recorded;
      assert.equal(seen.toolName, "user_prompt");
      assert.equal(seen.payload.event_name, "user_prompt");
      assert.deepEqual(seen.payload.messages, [{ role: "user", content: "delete the production database" }]);
      assert.equal(seen.payload.unbound_app_label, TEST_PROFILE.appLabel);
      assert.equal(seen.payload.client_entrypoint, "agent/1.2.3");
      assert.equal(seen.payload.conversation_id, "session-1");
      assert.equal(seen.payload.pre_tool_use_data.metadata.has_ui, false);
      assert.deepEqual(seen.payload.account_identity, { org_id: "org_1" });
      assert.equal(h.decisions.length, 0, "a prompt is not a tool call: no decision entry");
    }
  }
});

test("prompt nothrow: hostile inputs, a failing checker and hostile deps all resolve harmlessly", async () => {
  for (const input of [null, undefined, 3, "text", throwingProxy<PromptInput>()]) {
    const h = harness({}, { kind: "deny" });
    assertHarmless(await settle(() => evaluatePrompt(input as unknown as PromptInput, h.deps)), `input=${typeof input}`);
  }

  const failing: PolicyChecker[] = [
    {
      checkTool() {
        throw new Error("sync");
      },
    },
    { checkTool: async () => Promise.reject(new Error("async")) },
    { checkTool: async () => undefined as unknown as PolicyOutcome },
    { checkTool: async () => ({ kind: "weird" }) as unknown as PolicyOutcome },
  ];
  for (const checker of failing) {
    const h = harness({ checker });
    assert.deepEqual(await settle(() => evaluatePrompt(promptInput(), h.deps)), { kind: "allow" });
  }

  for (const deps of [null, undefined, throwingProxy<EvaluateDeps>()]) {
    assertHarmless(await settle(() => evaluatePrompt(promptInput(), deps as unknown as EvaluateDeps)), "hostile deps");
  }

  const throwingSession = {
    ...promptInput(),
    get sessionId(): string {
      throw new Error("no session");
    },
  };
  const h = harness({}, { kind: "deny" });
  assert.deepEqual(await settle(() => evaluatePrompt(throwingSession, h.deps)), { kind: "allow" });
  assert.equal(h.checker.calls.length, 0);
});

test("prompt deadline: a checker that never settles is bounded and honours the failure action", async () => {
  const open = harness({ checker: hangingChecker(), deadlineMs: 25 });
  assert.deepEqual(await settle(() => evaluatePrompt(promptInput(), open.deps)), { kind: "allow" });

  const closed = harness({ checker: hangingChecker(), state: confirmedState([], "block"), deadlineMs: 25 });
  assert.deepEqual(await settle(() => evaluatePrompt(promptInput(), closed.deps)), { kind: "unavailable" });
});

// --- verdictMessage ------------------------------------------------------------------------------

test("verdictMessage: the one string an adapter may throw, per verdict", () => {
  const table: [ToolEvaluation, string][] = [
    [{ kind: "deny", reason: "rm -rf is not allowed" }, DENY_PREFIX + "rm -rf is not allowed"],
    [{ kind: "deny" }, GENERIC_DENY_REASON],
    [{ kind: "deny", reason: undefined }, GENERIC_DENY_REASON],
    [{ kind: "unavailable" }, ENGINE_UNAVAILABLE_REASON],
    [{ kind: "unavailable", reason: KEY_REJECTED_BLOCK_REASON }, KEY_REJECTED_BLOCK_REASON],
    [{ kind: "confirm", reason: "force push needs approval" }, "force push needs approval"],
    [{ kind: "confirm" }, GENERIC_DENY_REASON],
    [{ kind: "allow" }, ""],
    [{ kind: "skip", why: "cached" }, ""],
    [{ kind: "skip", why: "nothing-evaluable" }, ""],
  ];
  for (const [verdict, expected] of table) {
    assert.equal(verdictMessage(verdict), expected, JSON.stringify(verdict));
  }
  assert.equal(DENY_PREFIX + "x", "Blocked by Unbound policy: x");
});

test("verdictMessage: a reason is rendered only if it is a string, with control characters removed", () => {
  // The gateway's attribution footer survives byte for byte.
  const footer = "No force pushes.\n\nEnforced by Unbound · Trace ID abc123";
  assert.equal(verdictMessage({ kind: "deny", reason: footer }), DENY_PREFIX + footer);

  // A reason that skipped core's sanitiser (an injected checker) is still defanged here.
  assert.equal(verdictMessage({ kind: "deny", reason: "a\u001b[31mb‮c" }), DENY_PREFIX + "a[31mbc");
  assert.equal(
    verdictMessage({ kind: "deny", reason: 5 as unknown as string }),
    GENERIC_DENY_REASON,
  );
});

test("verdictMessage: garbage in is the generic deny text, never a throw", () => {
  const garbage: unknown[] = [null, undefined, 0, "deny", [], {}, { kind: "weird" }, { kind: 7 }, throwingProxy<object>()];
  for (const value of garbage) {
    let message: string | undefined;
    assert.doesNotThrow(() => {
      message = verdictMessage(value as ToolEvaluation);
    });
    assert.equal(message, GENERIC_DENY_REASON);
  }
});

// --- The source gate -----------------------------------------------------------------------------

test("evaluate.ts contains no throw statement", () => {
  const source = readFileSync(resolve(import.meta.dirname, "..", "src", "evaluate.ts"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(?<!:)\/\/[^\n]*/g, "");
  assert.ok(code.includes("evaluateToolCall"), "the stripped source still holds the code");
  assert.equal(/\bthrow\b/.test(code), false, "an adapter's only throw site is its own");
});
