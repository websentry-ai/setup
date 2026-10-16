// The signal reporter (13-02): non-enforcement observations an adapter files on `/v1/hooks/errors`
// (a duplicate load, an attribution miss, a tamper, an inactive API family). Rate-limited per
// category, redacted, fire-and-forget and total — and never one of the bypass/blocked categories,
// which stay exclusive to `telemetry.ts`.

import assert from "node:assert/strict";
import test from "node:test";

import type { HookErrorsBody } from "../src/client.ts";
import { ERROR_REPORT_INTERVAL_MS } from "../src/constants.ts";
import { createSignalReporter } from "../src/signals.ts";
import type { SignalReporter } from "../src/signals.ts";
import { TEST_KEY } from "./helpers/testKey.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

const START_MS = 1_700_000_000_000;

interface Harness {
  reporter: SignalReporter;
  sent: HookErrorsBody[];
  setClock(ms: number): void;
}

function harness(
  opts: {
    apiKey?: string | undefined;
    isInactive?: () => boolean;
    post?: (body: HookErrorsBody) => Promise<boolean>;
    now?: () => number;
  } = {},
): Harness {
  const sent: HookErrorsBody[] = [];
  let clockMs = START_MS;
  const apiKey = "apiKey" in opts ? opts.apiKey : TEST_KEY;
  const reporter = createSignalReporter({
    client: {
      postHookErrors:
        opts.post ??
        (async (body) => {
          sent.push(body);
          return true;
        }),
    },
    profile: TEST_PROFILE,
    apiKey,
    ...(opts.isInactive === undefined ? {} : { isInactive: opts.isInactive }),
    now: opts.now ?? (() => clockMs),
  });
  return {
    reporter,
    sent,
    setClock(ms) {
      clockMs = ms;
    },
  };
}

/** Let fire-and-forget promise chains settle. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
  await new Promise((resolve) => setImmediate(resolve));
}

test("report posts one /v1/hooks/errors body with the category and a fixed-shape message", async () => {
  const h = harness();
  h.reporter.report("duplicate_load", { toolName: "server", detail: "second_copy" });
  await flush();
  assert.equal(h.sent.length, 1);
  const body = h.sent[0]!;
  assert.equal(body.hook_source, TEST_PROFILE.hookSource);
  assert.equal(body.errors.length, 1);
  assert.equal(body.errors[0]!.category, "duplicate_load");
  assert.equal(body.errors[0]!.message, `${TEST_PROFILE.hookSource} hook duplicate_load: second_copy for tool=server`);
  assert.equal(body.errors[0]!.timestamp, new Date(START_MS).toISOString());
});

test("the window is per category: a repeat is suppressed, another category is not, and it reopens", async () => {
  const h = harness();
  h.reporter.report("duplicate_load", { toolName: "server", detail: "a" });
  await flush();
  h.reporter.report("duplicate_load", { toolName: "server", detail: "b" });
  await flush();
  assert.equal(h.sent.length, 1);

  h.reporter.report("tamper", { toolName: "bash", detail: "args_changed" });
  await flush();
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[1]!.errors[0]!.category, "tamper");

  h.setClock(START_MS + ERROR_REPORT_INTERVAL_MS - 1);
  h.reporter.report("duplicate_load", { toolName: "server", detail: "c" });
  await flush();
  assert.equal(h.sent.length, 2);

  h.setClock(START_MS + ERROR_REPORT_INTERVAL_MS);
  h.reporter.report("duplicate_load", { toolName: "server", detail: "d" });
  await flush();
  assert.equal(h.sent.length, 3);
  assert.match(h.sent[2]!.errors[0]!.message, /: d for tool=server$/);
});

test("no api key, an empty key, or an inactive key sends nothing", async () => {
  for (const h of [harness({ apiKey: undefined }), harness({ apiKey: "" }), harness({ isInactive: () => true })]) {
    h.reporter.report("duplicate_load", { toolName: "server", detail: "x" });
    await flush();
    assert.equal(h.sent.length, 0);
  }
});

test("an invalid category is dropped; detail is reduced and capped; the api key is redacted", async () => {
  const h = harness();
  for (const category of ["", "Upper", "1abc", "has space", "a".repeat(65), "bad-dash"]) {
    h.reporter.report(category, { toolName: "server", detail: "x" });
  }
  await flush();
  assert.equal(h.sent.length, 0);

  h.reporter.report("attribution_miss", { toolName: "bash", detail: `a b<c>"d'e${"z".repeat(200)}` });
  await flush();
  assert.equal(h.sent.length, 1);
  const message = h.sent[0]!.errors[0]!.message;
  const detail = message.slice(message.indexOf(": ") + 2, message.lastIndexOf(" for tool="));
  assert.match(detail, /^[A-Za-z0-9_.:/-]*$/);
  assert.ok(detail.length <= 100, `detail length ${detail.length}`);
  assert.ok(detail.startsWith("abcde"));

  h.reporter.report("tamper", { toolName: `x${TEST_KEY}`, detail: `key=${TEST_KEY}` });
  await flush();
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[1]!.errors[0]!.message.includes(TEST_KEY), false);
  assert.ok(h.sent[1]!.errors[0]!.message.includes("REDACTED"));
});

test("the category map is bounded: past 32 categories new ones are dropped", async () => {
  const h = harness();
  for (let i = 0; i < 40; i += 1) h.reporter.report(`cat_${i}`, { toolName: "t" });
  await flush();
  assert.equal(h.sent.length, 32);
});

test("total: a throwing or rejecting client, a throwing clock and hostile ctx never escape", async () => {
  const sync = harness({
    post: () => {
      throw new Error("sync boom");
    },
  });
  assert.doesNotThrow(() => sync.reporter.report("duplicate_load", { toolName: "server" }));

  const rejecting = harness({ post: async () => Promise.reject(new Error("rejected")) });
  assert.doesNotThrow(() => rejecting.reporter.report("duplicate_load", { toolName: "server" }));
  await flush();

  const clock = harness({
    now: () => {
      throw new Error("clock");
    },
  });
  assert.doesNotThrow(() => clock.reporter.report("duplicate_load", { toolName: "server" }));

  const h = harness();
  const hostile = new Proxy({}, {
    get() {
      throw new Error("hostile getter");
    },
  });
  for (const ctx of [null, undefined, 5, hostile] as unknown[]) {
    assert.doesNotThrow(() => h.reporter.report("odd_ctx", ctx as { toolName: string }));
  }
  assert.doesNotThrow(() => h.reporter.report(5 as unknown as string, { toolName: "t" }));
  await flush();

  // Later reports still work after every fault above.
  h.reporter.report("after_faults", { toolName: "server", detail: "ok" });
  await flush();
  assert.ok(h.sent.some((body) => body.errors[0]!.category === "after_faults"));
  rejecting.setClock(START_MS + ERROR_REPORT_INTERVAL_MS);
  assert.doesNotThrow(() => rejecting.reporter.report("duplicate_load", { toolName: "server" }));
});
