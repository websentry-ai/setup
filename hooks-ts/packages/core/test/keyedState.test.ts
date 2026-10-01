// CORE-04 — the keyed registry every per-session / per-directory / per-gateway container is built on.
//
// Two properties carry the weight. It is BOUNDED: a host process that is never restarted cannot grow
// it past `max`, and what goes is the least-recently-used key. And it is TOTAL: an adapter reaches it
// from handlers where an exception changes a verdict, so a bad key, a faulting factory and a faulting
// eviction callback all have to come back as a usable value rather than an exception.

import assert from "node:assert/strict";
import test from "node:test";

import { createKeyedState } from "../src/keyedState.ts";

interface Box {
  key: string;
  serial: number;
}

/** A registry of boxes that records every creation and every eviction. */
function boxes(max: number, extra: { normalizeKey?: (key: unknown) => string | undefined } = {}) {
  let serial = 0;
  const created: string[] = [];
  const evicted: Array<[string, Box]> = [];
  const registry = createKeyedState<Box>({
    max,
    create: (key) => {
      created.push(key);
      return { key, serial: ++serial };
    },
    fallback: () => ({ key: "<fallback>", serial: ++serial }),
    onEvict: (key, value) => evicted.push([key, value]),
    ...extra,
  });
  return { registry, created, evicted };
}

test("get creates a value on first use and returns the same object afterwards", () => {
  const { registry, created } = boxes(4);

  const first = registry.get("a");
  assert.equal(first.key, "a");
  assert.equal(registry.get("a"), first);
  assert.equal(registry.get("a"), first);
  assert.deepEqual(created, ["a"]);
  assert.equal(registry.size(), 1);

  assert.notEqual(registry.get("b"), first);
  assert.equal(registry.size(), 2);
});

test("an invalid key gets a fresh fallback value that is never stored", () => {
  const { registry, created } = boxes(4);
  registry.get("a");

  for (const bad of ["", undefined, null, 7, {}, [], Symbol("s"), () => "a"]) {
    const one = registry.get(bad);
    const two = registry.get(bad);
    assert.equal(one.key, "<fallback>");
    assert.notEqual(one, two, "an invalid key must not resolve to a shared value");
    assert.equal(registry.peek(bad), undefined);
  }
  assert.equal(registry.size(), 1);
  assert.deepEqual(registry.keys(), ["a"]);
  assert.deepEqual(created, ["a"], "create is never called for an invalid key");
});

test("normalizeKey decides which keys are valid and which spellings are the same key", () => {
  const { registry } = boxes(4, {
    normalizeKey: (key) => (typeof key === "string" && key.startsWith("/") ? key.toLowerCase() : undefined),
  });

  const lower = registry.get("/a");
  assert.equal(registry.get("/A"), lower);
  assert.equal(registry.size(), 1);
  assert.deepEqual(registry.keys(), ["/a"]);

  assert.equal(registry.get("relative").key, "<fallback>");
  assert.equal(registry.size(), 1);

  registry.release("/A");
  assert.equal(registry.size(), 0);
});

test("a normalizeKey that faults, or answers a non-string or empty key, makes the key invalid", () => {
  for (const normalizeKey of [
    () => {
      throw new Error("normalize fault");
    },
    () => "",
    () => 42 as unknown as string,
  ]) {
    const { registry } = boxes(4, { normalizeKey });
    assert.equal(registry.get("a").key, "<fallback>");
    assert.equal(registry.peek("a"), undefined);
    registry.release("a");
    assert.equal(registry.size(), 0);
  }
});

test("inserting past max evicts the least-recently-used key, and get refreshes recency", () => {
  const { registry, evicted } = boxes(3);
  const a = registry.get("a");
  registry.get("b");
  registry.get("c");

  // Touch `a`: `b` is now the oldest.
  assert.equal(registry.get("a"), a);
  assert.deepEqual(registry.keys(), ["b", "c", "a"]);

  registry.get("d");
  assert.equal(registry.size(), 3);
  assert.deepEqual(registry.keys(), ["c", "a", "d"]);
  assert.equal(evicted.length, 1);
  assert.equal(evicted[0]![0], "b");
  assert.equal(evicted[0]![1].key, "b");
  assert.equal(registry.peek("a"), a, "the refreshed key survived");

  // The evicted key comes back as a NEW value, and pushes out the next-oldest.
  const b2 = registry.get("b");
  assert.notEqual(b2, evicted[0]![1]);
  assert.deepEqual(registry.keys(), ["a", "d", "b"]);
  assert.deepEqual(evicted.map(([key]) => key), ["b", "c"]);
});

test("size never exceeds max however many keys are inserted", () => {
  const { registry, evicted } = boxes(8);
  for (let i = 0; i < 1000; i += 1) {
    registry.get(`k${i}`);
    assert.ok(registry.size() <= 8);
  }
  assert.equal(registry.size(), 8);
  assert.equal(evicted.length, 992);
  assert.deepEqual(registry.keys(), ["k992", "k993", "k994", "k995", "k996", "k997", "k998", "k999"]);
});

test("peek reads without creating and without refreshing recency", () => {
  const { registry, created } = boxes(2);
  const a = registry.get("a");
  registry.get("b");

  assert.equal(registry.peek("a"), a);
  assert.equal(registry.peek("missing"), undefined);
  assert.deepEqual(created, ["a", "b"]);

  // Had peek refreshed `a`, this insert would have evicted `b`.
  registry.get("c");
  assert.deepEqual(registry.keys(), ["b", "c"]);
  assert.equal(registry.peek("a"), undefined);
});

test("release removes the entry and reports it; an unknown or invalid key is a no-op", () => {
  const { registry, evicted } = boxes(4);
  const a = registry.get("a");
  registry.get("b");

  registry.release("a");
  assert.equal(registry.size(), 1);
  assert.equal(registry.peek("a"), undefined);
  assert.deepEqual(evicted, [["a", a]]);

  registry.release("a");
  registry.release("never-seen");
  registry.release("");
  registry.release(undefined);
  registry.release({});
  assert.equal(registry.size(), 1);
  assert.equal(evicted.length, 1);

  assert.notEqual(registry.get("a"), a, "a released key starts fresh");
});

test("clear empties the registry and reports every entry", () => {
  const { registry, evicted } = boxes(4);
  registry.get("a");
  registry.get("b");
  registry.get("c");

  registry.clear();
  assert.equal(registry.size(), 0);
  assert.deepEqual(registry.keys(), []);
  assert.deepEqual(evicted.map(([key]) => key), ["a", "b", "c"]);

  registry.clear();
  assert.equal(evicted.length, 3);
});

test("a faulting create is contained: get answers the fallback and stores nothing", () => {
  let fallbacks = 0;
  const registry = createKeyedState<Box>({
    max: 4,
    create: (key) => {
      if (key === "bad") throw new Error("create fault");
      return { key, serial: 0 };
    },
    fallback: () => ({ key: "<fallback>", serial: ++fallbacks }),
  });

  const one = registry.get("bad");
  const two = registry.get("bad");
  assert.equal(one.key, "<fallback>");
  assert.notEqual(one, two);
  assert.equal(registry.size(), 0);
  assert.equal(registry.peek("bad"), undefined);

  // The registry still works for everything else.
  assert.equal(registry.get("good").key, "good");
  assert.equal(registry.size(), 1);
});

test("a faulting onEvict is swallowed and the eviction still completes", () => {
  let calls = 0;
  const registry = createKeyedState<Box>({
    max: 2,
    create: (key) => ({ key, serial: 0 }),
    fallback: () => ({ key: "<fallback>", serial: 0 }),
    onEvict: () => {
      calls += 1;
      throw new Error("evict fault");
    },
  });

  registry.get("a");
  registry.get("b");
  const c = registry.get("c"); // evicts a
  assert.equal(c.key, "c");
  assert.deepEqual(registry.keys(), ["b", "c"]);

  registry.release("b");
  assert.deepEqual(registry.keys(), ["c"]);

  registry.get("d");
  registry.clear();
  assert.equal(registry.size(), 0);
  assert.equal(calls, 4, "one call per evicted, released and cleared entry");
});

test("an onEvict that re-enters the registry cannot corrupt it", () => {
  const registry = createKeyedState<Box>({
    max: 2,
    create: (key) => ({ key, serial: 0 }),
    fallback: () => ({ key: "<fallback>", serial: 0 }),
    onEvict: (key) => {
      // A callback that looks its own key up again must not resurrect the entry past the bound.
      registry.get(key);
      registry.release("zzz");
    },
  });

  for (const key of ["a", "b", "c", "d", "e"]) registry.get(key);
  assert.ok(registry.size() <= 2, `size ${registry.size()}`);
  registry.clear();
  assert.ok(registry.size() <= 2, `size ${registry.size()}`);
});

test("even a faulting fallback does not escape get", () => {
  const registry = createKeyedState<Box>({
    max: 2,
    create: () => {
      throw new Error("create fault");
    },
    fallback: () => {
      throw new Error("fallback fault");
    },
  });

  assert.doesNotThrow(() => registry.get("a"));
  assert.doesNotThrow(() => registry.get(""));
  assert.equal(registry.size(), 0);
});

test("max below 1, fractional or non-finite is clamped", () => {
  for (const max of [0, -5, Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY, undefined as unknown as number, "9" as unknown as number]) {
    const { registry } = boxes(max);
    registry.get("a");
    registry.get("b");
    assert.equal(registry.size(), 1, `max ${String(max)}`);
    assert.deepEqual(registry.keys(), ["b"]);
  }

  const { registry } = boxes(2.9);
  registry.get("a");
  registry.get("b");
  registry.get("c");
  assert.equal(registry.size(), 2, "a fractional max rounds down");
});

test("no method ever throws, whatever it is handed", () => {
  const registry = createKeyedState<Box>(undefined as never);
  assert.doesNotThrow(() => registry.get("a"));
  assert.doesNotThrow(() => registry.peek("a"));
  assert.doesNotThrow(() => registry.release("a"));
  assert.doesNotThrow(() => registry.clear());
  assert.equal(registry.size(), 0);
  assert.deepEqual(registry.keys(), []);
});
