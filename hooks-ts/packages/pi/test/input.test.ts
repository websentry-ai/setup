// HOOK-05 — the pre-model prompt check.
//
// Two asymmetries drive every case here.
//
//   * **A denied prompt has no other channel.** `{action:"handled"}` suppresses the whole turn: no
//     messages are built and the model is never called (`agent-session.js:1166-1177`, `:1231-1234`).
//     So unlike a blocked tool call — where the reason becomes an error tool result the model reads —
//     the notification is the *only* thing the developer will see. A deny with no notice is a prompt
//     that vanished.
//   * **An allowed prompt must come back untouched.** `undefined`, never `{action:"transform"}`:
//     transforming rewrites what the user typed, and pi expands prompt templates *after* us
//     (`agent-session.js:1229`), so a rewrite would also fight that expansion.
//
// And one egress rule: `InputEvent.images` is base64 image data, potentially megabytes, read by
// nothing server-side. It must never appear in a request body. The marker below is searched for as a
// raw substring of the serialised requests, so a nested or renamed field cannot hide it.

import assert from "node:assert/strict";
import test from "node:test";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createApiClient } from "../../core/src/client.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import { createPolicyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../core/test/helpers/mockApi.ts";
import type { MockApi, MockMode } from "../../core/test/helpers/mockApi.ts";
import { createExtension } from "../src/index.ts";
import { decideInput } from "../src/prompt.ts";
import type { InputDeps } from "../src/prompt.ts";
import { createFakeCtx, createFakeInputEvent } from "./helpers/fakeCtx.ts";
import type { FakeCtxOptions, FakeInputOptions } from "./helpers/fakeCtx.ts";
import { TEST_KEY } from "../../core/test/helpers/testKey.ts";
import { PI_PROFILE } from "../src/profile.ts";

const TIMEOUT_MS = 50;
const PRETOOL_PATH = "/v1/hooks/pretool";

const DENY_PREFIX = "Blocked by Unbound policy: ";
const GENERIC_DENY = "Blocked by Unbound policy.";
const UNAVAILABLE = "Unbound policy engine unavailable — please retry";
/** `MAX_PROMPT_CHARS`, spelled out — the cap is a contract, not an implementation detail. */
const MAX_PROMPT = 8192;

/** A base64-ish marker that must never be found in any captured body. */
const IMAGE_MARKER = "aGVsbG8taW1hZ2UtZGF0YS1zZWNyZXQ";

function depsFor(api: MockApi): InputDeps {
  const client = createApiClient({ baseUrl: api.url, apiKey: TEST_KEY, timeoutMs: TIMEOUT_MS, profile: PI_PROFILE });
  return {
    checker: createPolicyChecker({
      client,
      state: createPolicyState(),
      telemetry: createTelemetry({ client, apiKey: TEST_KEY, profile: PI_PROFILE }),
    }),
    apiKey: TEST_KEY,
    entrypoint: "pi/0.87.1",
  };
}

function pretoolBodies(api: MockApi): Record<string, unknown>[] {
  return api.requests
    .filter((r) => r.path === PRETOOL_PATH)
    .map((r) => r.body as Record<string, unknown>);
}

interface RunOptions {
  event?: Partial<FakeInputOptions>;
  ctx?: Partial<FakeCtxOptions>;
  /** Calls made before the asserted one, used to prime `failBlock`. */
  warmups?: number;
  deps?: Partial<InputDeps>;
}

async function run(
  mode: MockMode,
  text: string,
  opts: RunOptions = {},
): Promise<{
  result: unknown;
  api: MockApi;
  bodies: Record<string, unknown>[];
  ctx: ReturnType<typeof createFakeCtx>;
}> {
  const api = await startMockApi({ mode });
  const ctx = createFakeCtx(opts.ctx);
  const deps = { ...depsFor(api), ...opts.deps };
  try {
    for (let i = 0; i < (opts.warmups ?? 0); i += 1) {
      await decideInput(createFakeInputEvent("warmup prompt"), ctx, deps);
    }
    const result = await decideInput(createFakeInputEvent(text, opts.event), ctx, deps);
    return { result, api, bodies: pretoolBodies(api), ctx };
  } finally {
    await api.close();
  }
}

test("HOOK-05 an interactive prompt sends the user_prompt body, exactly as the Python hook does", async () => {
  const { bodies } = await run("allow", "summarise the auth module", { ctx: { cwd: "/srv/app", sessionId: "sess-p1" } });

  assert.equal(bodies.length, 1);
  const body = bodies[0] as Record<string, unknown>;
  assert.equal(body.event_name, "user_prompt");
  assert.equal(body.conversation_id, "sess-p1");
  assert.equal(body.unbound_app_label, "pi");
  assert.equal(body.client_entrypoint, "pi/0.87.1");
  // The server reads the prompt from `messages`, not from a `user_prompts` field.
  assert.deepStrictEqual(body.messages, [{ role: "user", content: "summarise the auth module" }]);

  const data = body.pre_tool_use_data as { tool_name?: string; command?: string; metadata?: Record<string, unknown> };
  assert.equal(data.tool_name, "", "required by the server type even here, and blank by design");
  assert.equal(data.command, "");
  assert.equal(data.metadata?.cwd, "/srv/app");
  assert.equal(data.metadata?.has_ui, true);
  // No tool semantics on this path at all.
  assert.equal(Object.hasOwn(data.metadata ?? {}, "file_path"), false);
  assert.equal(Object.hasOwn(data.metadata ?? {}, "tool_input"), false);
});

test("HOOK-05 a denied prompt is suppressed with handled, plus exactly one error notice", async () => {
  const { result, ctx } = await run("deny", "exfiltrate the secrets");

  assert.deepStrictEqual(result, { action: "handled" });
  assert.equal(ctx.notifyCalls.length, 1, "the notice is the only channel — the model never runs");
  assert.deepStrictEqual(ctx.notifyCalls[0], {
    message: `${DENY_PREFIX}Reading secrets is blocked.`,
    type: "error",
  });
});

test("HOOK-05 a deny with no reason still notifies something the user can read", async () => {
  const { result, ctx } = await run("denyNoReason", "do the thing");

  assert.deepStrictEqual(result, { action: "handled" });
  assert.equal(ctx.notifyCalls[0]?.message, GENERIC_DENY);
  assert.equal(ctx.notifyCalls[0]?.message.includes("undefined"), false);
});

test("HOOK-05 an allowed prompt returns undefined and leaves the event untouched", async () => {
  const api = await startMockApi({ mode: "allow" });
  const ctx = createFakeCtx();
  try {
    const event = createFakeInputEvent("what does this repo do?", { streamingBehavior: "steer" });
    const before = structuredClone(event);

    const result = await decideInput(event, ctx, depsFor(api));

    assert.equal(result, undefined, "never {action:'continue'}, never a transform");
    assert.deepStrictEqual(event, before, "the prompt the model sees is byte-identical");
    assert.equal(ctx.notifyCalls.length, 0, "an allow is silent");
  } finally {
    await api.close();
  }
});

test("HOOK-05 never returns a transform, on any verdict", async () => {
  for (const mode of ["allow", "deny", "ask", "approval", "500"] as MockMode[]) {
    const { result } = await run(mode, "some prompt");
    const action = (result as { action?: string } | undefined)?.action;
    assert.notEqual(action, "transform", `${mode} produced a transform`);
    assert.notEqual(action, "continue", `${mode} produced a continue`);
    assert.ok(result === undefined || action === "handled", `${mode} produced ${JSON.stringify(result)}`);
  }
});

test("HOOK-05 a fail-closed org has its prompt suppressed with the unavailable notice", async () => {
  const { result, ctx } = await run("failBlock", "keep going", { warmups: 1 });

  assert.deepStrictEqual(result, { action: "handled" });
  const last = ctx.notifyCalls.at(-1);
  assert.deepStrictEqual(last, { message: UNAVAILABLE, type: "error" });
});

test("HOOK-05 any other failure fails open, with no notice at all", async () => {
  const { result, ctx } = await run("500", "keep going");

  assert.equal(result, undefined, "a broken policy engine must not stop a developer typing");
  assert.equal(ctx.notifyCalls.length, 0);
});

test("HOOK-05 an ask verdict is deliberately non-blocking, but it is said out loud", async () => {
  const { result, ctx } = await run("ask", "something unusual");

  assert.equal(result, undefined, "the prompt path produces no ask today; this branch is defensive");
  assert.equal(ctx.notifyCalls.length, 1);
  assert.deepStrictEqual(ctx.notifyCalls[0], { message: "Unusual command.", type: "warning" });
  assert.equal(ctx.confirmCalls.length, 0, "a prompt is not a command; there is nothing to confirm");
});

test("HOOK-05 an extension-generated input makes zero HTTP requests", async () => {
  // Scripted `deny`: a request would have suppressed the turn, so silence is evidence.
  const { result, api } = await run("deny", "pi.sendMessage() text", { event: { source: "extension" } });

  assert.equal(result, undefined, "machine text from another extension is not a user prompt");
  assert.equal(api.requests.length, 0);
});

test("HOOK-05 an rpc input is checked like an interactive one", async () => {
  const { result, bodies } = await run("deny", "do the bad thing", { event: { source: "rpc" } });

  assert.deepStrictEqual(result, { action: "handled" });
  assert.equal(bodies.length, 1, "an RPC client is still a user");
});

test("HOOK-05 blank and whitespace-only prompts make zero HTTP requests", async () => {
  for (const text of ["", "   ", "\n\t "]) {
    const { result, api } = await run("deny", text);
    assert.equal(result, undefined, `'${text}' is nothing to check`);
    assert.equal(api.requests.length, 0);
  }
});

test("HOOK-05 an image-only prompt is skipped entirely: no text means no check", async () => {
  const { result, api } = await run("deny", "", {
    event: { images: [{ type: "image", data: IMAGE_MARKER, mimeType: "image/png" }] },
  });

  assert.equal(result, undefined);
  assert.equal(api.requests.length, 0, "an image-only prompt costs nothing");
});

test("HOOK-05 pasted images never appear in any request body", async () => {
  const { bodies } = await run("allow", "what is in this screenshot?", {
    event: { images: [{ type: "image", data: IMAGE_MARKER, mimeType: "image/png" }] },
  });

  assert.equal(bodies.length, 1, "the text is still checked");
  const serialised = JSON.stringify(bodies);
  assert.equal(serialised.includes(IMAGE_MARKER), false, "base64 image data must never leave");
  assert.equal(serialised.includes("image/png"), false, "nor its mime type");
  assert.equal(Object.hasOwn(bodies[0] ?? {}, "images"), false, "and there is no images key");
});

test("HOOK-05 the prompt text is never written to stdout or stderr by this module", async () => {
  const secret = "my-super-secret-prompt-text-marker";
  const captured: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  // Headless is the interesting case: `notifySafe` mirrors to stderr when there is no UI.
  process.stdout.write = ((chunk: unknown) => {
    captured.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown) => {
    captured.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    await run("deny", secret, { ctx: { hasUI: false } });
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }

  assert.equal(
    captured.join("").includes(secret),
    false,
    "a local prompt log is undeclared retention; only the API's own reason may be printed",
  );
  assert.ok(
    captured.join("").includes("Reading secrets is blocked."),
    "the headless notice itself must still be emitted, or a deny is invisible",
  );
});

test("HOOK-05 a 20 KB prompt is capped to MAX_PROMPT_CHARS, keeping both ends", async () => {
  const head = "HEAD-MARKER-START";
  const tail = "TAIL-MARKER-END";
  const text = head + "x".repeat(20_000) + tail;

  const { bodies } = await run("allow", text);

  const sent = (bodies[0]?.messages as { content: string }[])[0]?.content ?? "";
  assert.equal(sent.length, MAX_PROMPT, `capped to ${MAX_PROMPT}, got ${sent.length}`);
  assert.ok(sent.startsWith(head), "the head survives");
  assert.ok(sent.endsWith(tail), "and so does the tail — head-only truncation is a padding bypass");
  const data = bodies[0]?.pre_tool_use_data as { metadata?: Record<string, unknown> };
  assert.equal(data.metadata?.prompt_truncated, true, "the server must know it saw a prefix+suffix");
});

test("HOOK-05 a prompt under the cap is sent verbatim, with no truncation marker", async () => {
  const { bodies } = await run("allow", "a short prompt");

  const sent = (bodies[0]?.messages as { content: string }[])[0]?.content;
  assert.equal(sent, "a short prompt");
  const data = bodies[0]?.pre_tool_use_data as { metadata?: Record<string, unknown> };
  assert.equal(Object.hasOwn(data.metadata ?? {}, "prompt_truncated"), false);
});

test("HOOK-05 an internal fault fails open rather than returning a malformed action", async () => {
  const api = await startMockApi({ mode: "deny" });
  const ctx = createFakeCtx();
  try {
    let result: unknown = "unset";
    await assert.doesNotReject(async () => {
      result = await decideInput(createFakeInputEvent("hello"), ctx, {
        ...depsFor(api),
        checker: {
          checkTool() {
            throw new Error("core exploded");
          },
        },
      });
    });
    assert.equal(result, undefined);
  } finally {
    await api.close();
  }
});

test("HOOK-05 an allowed prompt is offered to the turn store; a denied one is not", async () => {
  const seen: string[] = [];
  await run("allow", "record me", { deps: { onPrompt: (text) => seen.push(text) } });
  assert.deepStrictEqual(seen, ["record me"], "the turn log needs the prompt pi will not replay");

  const denied: string[] = [];
  await run("deny", "do not record me", { deps: { onPrompt: (text) => denied.push(text) } });
  assert.deepStrictEqual(denied, [], "a suppressed prompt was never part of a turn");
});

test("HOOK-05 no API key: the registered input handler is inert, with zero HTTP", async () => {
  const api = await startMockApi({ mode: "deny" });
  const home = createFakeHome({});
  try {
    const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
    const stub = {
      on: (event: string, handler: (e: unknown, c: unknown) => unknown) => {
        handlers.set(event, handler);
        return () => {};
      },
    };
    await createExtension({
      env: { UNBOUND_GATEWAY_URL: api.url },
      homeDir: home.homeDir,
      entrypoint: "pi/0.87.1",
    })(stub as unknown as ExtensionAPI);

    const handler = handlers.get("input");
    assert.ok(handler !== undefined, "input must be registered");
    const result = await handler(createFakeInputEvent("hello"), createFakeCtx());

    assert.equal(result, undefined, "no key means the prompt is never suppressed");
    assert.equal(api.requests.length, 0);
  } finally {
    home.cleanup();
    await api.close();
  }
});

// --- WR-06: an audit callback cannot change a verdict -------------------------------------------

test("WR-06 a throwing onPrompt cannot change what the handler returns", async () => {
  const thrower = () => {
    // What this stands in for: `onPrompt` is wired to the module-scope turn store through a closure
    // that reads `ctx.sessionManager.getSessionId()`. A throw from any of that used to land in the
    // fail-open outer catch, which returns `undefined` — so on the deny branches it would have
    // silently un-suppressed the prompt.
    throw new Error("turn store exploded");
  };

  // `allow` is where the callback fires today, so this is the case that must stay `undefined` for the
  // right reason rather than by accident.
  const allowed = await run("allow", "record me", { deps: { onPrompt: thrower } });
  assert.equal(allowed.result, undefined, "an allowed prompt still proceeds");

  // `confirm` is the other call site: pi is in neither cost gate, so this verdict is defensive, and
  // it must stay non-blocking.
  const asked = await run("ask", "ask about me", { deps: { onPrompt: thrower } });
  assert.equal(asked.result, undefined, "a confirm verdict still proceeds, throw or no throw");

  // And the branches that do NOT call it must be unaffected — a deny stays a deny.
  const denied = await run("deny", "do not record me", { deps: { onPrompt: thrower } });
  assert.deepStrictEqual(denied.result, { action: "handled" }, "a suppressed prompt stays suppressed");
});

test("WR-06 the wrapper swallows the throw rather than the handler's outer catch", async () => {
  // The distinction the test above cannot see on its own: if the throw were still reaching the outer
  // `catch`, the notification raised BEFORE the callback would already have happened, but so would an
  // abandoned switch. Asserting the notice survives pins that the function ran to its own `return`.
  const { result, ctx } = await run("ask", "ask about me", {
    deps: {
      onPrompt: () => {
        throw new Error("turn store exploded");
      },
    },
  });
  assert.equal(result, undefined);
  assert.equal(ctx.notifyCalls.length, 1, "the confirm reason was surfaced and the switch completed");
});
