// A standalone process whose only pending work is one evaluation against a checker that never
// settles (WR-01). Nothing else holds the event loop open: no test runner, no keep-alive timer, no
// socket. If the evaluation deadline did not keep the process alive, Node would exit 0 here having
// printed nothing, and a headless host would stop mid tool call with no verdict.
//
// Usage: node --experimental-strip-types hangingCheckerChild.ts <tool|prompt> <allow|block> [answers]
// Prints one JSON line, `{"verdict":…}`, when the evaluation resolves.
//
// With `answers`, the checker answers `deny` at once and the deadline is 60 s: the process must
// then exit promptly, which proves the deadline timer is cleared when the check settles and never
// extends a process's lifetime on the normal path.

import { evaluatePrompt, evaluateToolCall } from "../../src/evaluate.ts";
import type { PolicyChecker } from "../../src/policy.ts";
import { createPolicyState } from "../../src/policyState.ts";
import { TEST_PROFILE } from "./testProfile.ts";

const [path = "tool", failureAction = "allow", mode = "hangs"] = process.argv.slice(2);
const answers = mode === "answers";

const state = createPolicyState();
if (failureAction === "block") {
  state.recordSuccess({ decision: "allow", policy_check_failure_action: "block", tools_to_check: ["bash"] }, Date.now());
}

// A promise chain stuck on a lost resolver: it holds no handle of its own.
const checker: PolicyChecker = answers
  ? { checkTool: async () => ({ kind: "deny", reason: "answered" }) }
  : { checkTool: () => new Promise(() => {}) };
const deps = {
  checker,
  profile: TEST_PROFILE,
  entrypoint: "agent/1.2.3",
  state,
  deadlineMs: answers ? 60_000 : 200,
};

const pending =
  path === "prompt"
    ? evaluatePrompt(
        { text: "hello", source: "interactive", cwd: "/work", sessionId: "s", model: "m", hasUI: false },
        deps,
      )
    : evaluateToolCall(
        {
          toolName: "bash",
          toolCallId: "toolu_1",
          command: "echo hi",
          toolInput: { command: "echo hi" },
          cwd: "/work",
          sessionId: "s",
          model: "m",
        },
        deps,
      );

void pending.then((verdict) => {
  process.stdout.write(`${JSON.stringify({ verdict })}\n`);
});
