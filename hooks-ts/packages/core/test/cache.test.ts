// RES-03 — the on-disk policy cache.
//
// This file is where a local file starts influencing whether an enforcement check happens at all, so
// most of it is about what the cache must REFUSE:
//
//   * T-09-14 — the API key must never reach disk. Only a sha256 prefix is stored, and one test
//     writes a literal key and greps the file for it.
//   * T-09-01 / T-09-02 — a planted cache must not be able to brick pi or silently disable every
//     file-tool check: 0600 in a 0700 dir, and a record is only accepted when BOTH `gateway_url`
//     and `key_fingerprint` match the resolved pair.
//   * T-09-15 — a torn read between two concurrent pi sessions is a MISS, never a throw. Every
//     malformed shape below is asserted through `doesNotThrow`, not merely by its return value.
//
// Every path here is a temp dir from `createFakeHome`, so nothing touches the real `~/.pi`.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, sep } from "node:path";
import test from "node:test";

import {
  CACHE_TTL_MS,
  ENV_PI_AGENT_DIR,
  KEY_FINGERPRINT_PREFIX,
  MAX_CACHE_BYTES,
} from "../src/constants.ts";
import {
  getFailureActionFromCache,
  isToolsFresh,
  keyFingerprint,
  readCache,
  resolveCachePath,
  shouldSkipFileTool,
  writeCache,
} from "../src/cache.ts";
import type { CachedPolicy, CacheIdentity } from "../src/cache.ts";
import { NATIVE_FILE_TOOLS } from "../src/payload.ts";
import { createPolicyState } from "../src/policyState.ts";
import { createFakeHome } from "./helpers/fakeHome.ts";

const GATEWAY = "https://api.getunbound.ai";
const OTHER_GATEWAY = "https://api.getunbound.ai/tenant-a";
const KEY = "unb_test_key_1234567890";
const NOW = 1_700_000_000_000;

function identityFor(gatewayUrl = GATEWAY, apiKey = KEY): CacheIdentity {
  return { gatewayUrl, fingerprint: keyFingerprint(apiKey) };
}

function record(extra: Partial<CachedPolicy> = {}): CachedPolicy {
  return {
    gateway_url: GATEWAY,
    key_fingerprint: keyFingerprint(KEY),
    fetched_at: NOW,
    tools_synced_at: NOW,
    tools_to_check: [...NATIVE_FILE_TOOLS].slice(0, 1),
    policy_check_failure_action: "allow",
    ...extra,
  };
}

/** A temp HOME plus the cache path under it. Callers must `cleanup()`. */
function fixture() {
  const home = createFakeHome();
  const path = resolveCachePath({}, home.homeDir);
  assert.ok(path !== undefined, "a temp HOME resolves a cache path");
  return { home, path, dir: dirname(path) };
}

/** The six names come from payload.ts; this file must never retype them. */
const SOME_FILE_TOOL = [...NATIVE_FILE_TOOLS][0] as string;
const OTHER_FILE_TOOL = [...NATIVE_FILE_TOOLS][1] as string;
const SHELL_TOOL = "bash";

// --- resolveCachePath -------------------------------------------------------------------------

test("resolveCachePath: PI_CODING_AGENT_DIR wins over the home default", () => {
  const custom = join(sep, "custom", "agent");
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: custom }, join(sep, "home", "u")),
    join(custom, ".unbound", "policy_cache.json"),
  );
});

test("resolveCachePath: falls back to <home>/.pi/agent when the env var is absent", () => {
  const home = join(sep, "home", "u");
  const path = resolveCachePath({}, home);
  assert.equal(path, join(home, ".pi", "agent", ".unbound", "policy_cache.json"));
});

test("resolveCachePath: a leading tilde expands against the passed home dir", () => {
  const home = join(sep, "home", "u");
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: "~/relocated" }, home),
    join(home, "relocated", ".unbound", "policy_cache.json"),
  );
  assert.equal(
    resolveCachePath({ [ENV_PI_AGENT_DIR]: "~" }, home),
    join(home, ".unbound", "policy_cache.json"),
  );
});

test("resolveCachePath: a relative or blank env value falls back instead of resolving against cwd", () => {
  const home = join(sep, "home", "u");
  const fallback = join(home, ".pi", "agent", ".unbound", "policy_cache.json");
  // A repo-relative value must never be honoured: `join(cwd, ...)` would put the cache inside
  // whatever repository pi was started in, where the repo itself could plant one.
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "agent" }, home), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "./agent" }, home), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "   " }, home), fallback);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "" }, home), fallback);
});

test("resolveCachePath: a non-absolute resolved base is refused outright — no read, no write", () => {
  // `os.homedir()` can fail and the caller's fallback is "", exactly the config.ts hazard.
  assert.equal(resolveCachePath({}, ""), undefined);
  assert.equal(resolveCachePath({}, "relative/home"), undefined);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "agent" }, ""), undefined);
  assert.equal(resolveCachePath({ [ENV_PI_AGENT_DIR]: "~/x" }, ""), undefined);
  assert.equal(resolveCachePath({}, undefined as unknown as string), undefined);
});

test("resolveCachePath: never throws, whatever the env holds", () => {
  assert.doesNotThrow(() => resolveCachePath(undefined as unknown as NodeJS.ProcessEnv, "/home/u"));
  assert.doesNotThrow(() => resolveCachePath({ [ENV_PI_AGENT_DIR]: 42 as unknown as string }, "/home/u"));
  const path = resolveCachePath({}, "/home/u");
  assert.ok(path !== undefined && isAbsolute(path));
});

// --- keyFingerprint --------------------------------------------------------------------------

test("keyFingerprint: prefix + 16 hex chars, stable, and not the key", () => {
  const fp = keyFingerprint(KEY);
  assert.equal(fp, keyFingerprint(KEY), "stable across calls");
  assert.ok(fp.startsWith(KEY_FINGERPRINT_PREFIX), fp);
  const hex = fp.slice(KEY_FINGERPRINT_PREFIX.length);
  assert.equal(hex.length, 16, "16 hex chars = 64 bits, enough to separate tenants");
  assert.match(hex, /^[0-9a-f]{16}$/);
  assert.ok(!fp.includes(KEY), "the fingerprint is not the key");

  // A known vector, so a future refactor cannot quietly change the digest.
  assert.equal(keyFingerprint(""), `${KEY_FINGERPRINT_PREFIX}e3b0c44298fc1c14`);
});

test("keyFingerprint: different keys fingerprint differently, and a non-string does not throw", () => {
  assert.notEqual(keyFingerprint(KEY), keyFingerprint(`${KEY}x`));
  assert.doesNotThrow(() => keyFingerprint(undefined as unknown as string));
});

// --- writeCache ------------------------------------------------------------------------------

test("writeCache: 0600 file inside a 0700 dir, written by temp+rename with no leftovers", () => {
  const f = fixture();
  try {
    assert.equal(writeCache(f.path, record()), true);

    assert.equal(statSync(f.path).mode & 0o777, 0o600, "the cache file is owner-only");
    assert.equal(statSync(f.dir).mode & 0o777, 0o700, "so is its directory");

    // temp+rename, not a truncating write: the temp name must not survive.
    assert.deepEqual(readdirSync(f.dir), ["policy_cache.json"]);

    // A second write replaces it in place and still leaves exactly one file.
    assert.equal(writeCache(f.path, record({ fetched_at: NOW + 1 })), true);
    assert.deepEqual(readdirSync(f.dir), ["policy_cache.json"]);
    assert.equal(statSync(f.path).mode & 0o777, 0o600);
    assert.equal(readCache(f.path, identityFor())?.fetched_at, NOW + 1);
  } finally {
    f.home.cleanup();
  }
});

test("writeCache: an unwritable path returns false rather than throwing", () => {
  const home = createFakeHome();
  try {
    // A file where a directory must be: mkdir -p fails with ENOTDIR.
    const blocker = join(home.homeDir, "blocker");
    writeFileSync(blocker, "not a directory");
    const path = join(blocker, ".unbound", "policy_cache.json");

    let result: boolean | undefined;
    assert.doesNotThrow(() => {
      result = writeCache(path, record());
    }, "a failed cache write is a no-op, never an error");
    assert.equal(result, false);
  } finally {
    home.cleanup();
  }
});

test("writeCache: the raw API key never appears on disk (T-09-14)", () => {
  const f = fixture();
  const secret = "super-secret-api-key-value";
  try {
    assert.equal(
      writeCache(f.path, record({ key_fingerprint: keyFingerprint(secret) })),
      true,
    );
    const onDisk = readFileSync(f.path, "utf8");
    assert.equal(onDisk.includes(secret), false, "the key is not in the file");
    // Nor any long substring of it — a partial leak is still a leak.
    for (let i = 0; i + 12 <= secret.length; i += 1) {
      assert.equal(onDisk.includes(secret.slice(i, i + 12)), false, `substring at ${i}`);
    }
    assert.ok(onDisk.includes(KEY_FINGERPRINT_PREFIX), "only the digest prefix is stored");
  } finally {
    f.home.cleanup();
  }
});

test("writeCache: the persisted key set is exactly the documented six", () => {
  const f = fixture();
  try {
    writeCache(f.path, record());
    const parsed: unknown = JSON.parse(readFileSync(f.path, "utf8"));
    assert.deepEqual(Object.keys(parsed as object).sort(), [
      "fetched_at",
      "gateway_url",
      "key_fingerprint",
      "policy_check_failure_action",
      "tools_synced_at",
      "tools_to_check",
    ]);
    // Deliberately NOT persisted: repo_policies / unbound_attribution_enabled. Nothing in this
    // extension reads them, and an unread field on disk is only a liability.
    const text = readFileSync(f.path, "utf8");
    assert.equal(text.includes("repo_policies"), false);
    assert.equal(text.includes("unbound_attribution_enabled"), false);
  } finally {
    f.home.cleanup();
  }
});

// --- readCache -------------------------------------------------------------------------------

test("readCache: a round trip returns the record", () => {
  const f = fixture();
  try {
    writeCache(f.path, record());
    const got = readCache(f.path, identityFor());
    assert.ok(got !== undefined);
    assert.equal(got.gateway_url, GATEWAY);
    assert.equal(got.tools_synced_at, NOW);
    assert.equal(got.policy_check_failure_action, "allow");
  } finally {
    f.home.cleanup();
  }
});

test("readCache: a missing, empty or truncated file is a miss and never throws", () => {
  const f = fixture();
  try {
    // Missing.
    let got: CachedPolicy | undefined;
    assert.doesNotThrow(() => {
      got = readCache(f.path, identityFor());
    });
    assert.equal(got, undefined, "no file yet");

    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    for (const body of ["", "   ", '{"gateway_url": "https://api.getun', "{", "]}"]) {
      writeFileSync(f.path, body);
      assert.doesNotThrow(() => {
        got = readCache(f.path, identityFor());
      }, `readCache(${JSON.stringify(body)})`);
      assert.equal(got, undefined, `miss for ${JSON.stringify(body)}`);
    }

    // A directory where the file should be — an EISDIR, still a miss.
    const dirPath = join(f.dir, "subdir");
    mkdirSync(dirPath, { recursive: true });
    assert.doesNotThrow(() => {
      got = readCache(dirPath, identityFor());
    });
    assert.equal(got, undefined);
  } finally {
    f.home.cleanup();
  }
});

test("readCache: valid JSON that is not an object is a miss", () => {
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    for (const body of ["[]", '["a"]', "42", '"a string"', "null", "true"]) {
      writeFileSync(f.path, body);
      let got: CachedPolicy | undefined;
      assert.doesNotThrow(() => {
        got = readCache(f.path, identityFor());
      }, body);
      assert.equal(got, undefined, `miss for ${body}`);
    }
  } finally {
    f.home.cleanup();
  }
});

test("readCache: the record is only accepted when BOTH identity keys match (T-09-02)", () => {
  const f = fixture();
  try {
    writeCache(f.path, record());

    assert.ok(readCache(f.path, identityFor()) !== undefined, "the matching pair hits");

    // A different gateway: another tenant's policy set must not govern this one.
    assert.equal(readCache(f.path, identityFor(OTHER_GATEWAY)), undefined);
    // A different key: a second account on the same machine.
    assert.equal(readCache(f.path, identityFor(GATEWAY, "a-different-key")), undefined);
    // Both different.
    assert.equal(readCache(f.path, identityFor(OTHER_GATEWAY, "a-different-key")), undefined);
    // No identity at all.
    assert.equal(readCache(f.path, undefined as unknown as CacheIdentity), undefined);
  } finally {
    f.home.cleanup();
  }
});

test("readCache: wrong-typed identity fields on disk are a miss", () => {
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    const bodies: Record<string, unknown>[] = [
      { key_fingerprint: keyFingerprint(KEY) }, // gateway_url absent
      { gateway_url: GATEWAY }, // key_fingerprint absent
      { gateway_url: 42, key_fingerprint: keyFingerprint(KEY) },
      { gateway_url: GATEWAY, key_fingerprint: ["x"] },
      { gateway_url: null, key_fingerprint: null },
    ];
    for (const body of bodies) {
      writeFileSync(f.path, JSON.stringify(body));
      let got: CachedPolicy | undefined;
      assert.doesNotThrow(() => {
        got = readCache(f.path, identityFor());
      }, JSON.stringify(body));
      assert.equal(got, undefined, `miss for ${JSON.stringify(body)}`);
    }
  } finally {
    f.home.cleanup();
  }
});

test("readCache: an empty tools_to_check survives the round trip", () => {
  const f = fixture();
  try {
    writeCache(f.path, record({ tools_to_check: [], tools_synced_at: NOW }));
    const got = readCache(f.path, identityFor());
    assert.ok(got !== undefined);
    assert.deepEqual(got.tools_to_check, [], "not undefined — the org has no file policies");
    assert.equal(got.tools_synced_at, NOW);
  } finally {
    f.home.cleanup();
  }
});

test("readCache: a bad tools_to_check drops just that field and its timestamp", () => {
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    const base = {
      gateway_url: GATEWAY,
      key_fingerprint: keyFingerprint(KEY),
      fetched_at: NOW,
      policy_check_failure_action: "block",
    };

    for (const bad of [{ tools_to_check: SOME_FILE_TOOL }, { tools_to_check: {} }, { tools_to_check: 5 }]) {
      writeFileSync(f.path, JSON.stringify({ ...base, ...bad, tools_synced_at: NOW }));
      const got = readCache(f.path, identityFor());
      assert.ok(got !== undefined, "the rest of the record is still usable");
      assert.equal(got.tools_to_check, undefined);
      assert.equal(got.tools_synced_at, undefined, "no list means no tools freshness");
      assert.equal(got.policy_check_failure_action, "block", "the failure action survived");
      assert.equal(got.fetched_at, NOW);
    }

    // A list with no timestamp cannot be aged, so it is not usable freshness either.
    writeFileSync(f.path, JSON.stringify({ ...base, tools_to_check: [SOME_FILE_TOOL] }));
    const unstamped = readCache(f.path, identityFor());
    assert.ok(unstamped !== undefined);
    assert.equal(unstamped.tools_synced_at, undefined);
    assert.equal(unstamped.tools_to_check, undefined);

    // Junk timestamps and a junk failure action are dropped, not fatal.
    writeFileSync(
      f.path,
      JSON.stringify({
        ...base,
        fetched_at: "yesterday",
        policy_check_failure_action: "BLOCK",
        tools_synced_at: Number.NaN,
        tools_to_check: [SOME_FILE_TOOL, 7, null],
      }),
    );
    const junk = readCache(f.path, identityFor());
    assert.ok(junk !== undefined);
    assert.equal(junk.fetched_at, undefined);
    assert.equal(junk.policy_check_failure_action, undefined);
    assert.equal(junk.tools_synced_at, undefined);
    assert.equal(junk.tools_to_check, undefined);
  } finally {
    f.home.cleanup();
  }
});

// --- freshness -------------------------------------------------------------------------------

test("isToolsFresh: bounded by tools_synced_at, not by fetched_at", () => {
  assert.equal(isToolsFresh({ tools_synced_at: NOW - 299_999 }, NOW, CACHE_TTL_MS), true);
  assert.equal(isToolsFresh({ tools_synced_at: NOW - 300_000 }, NOW, CACHE_TTL_MS), true, "exactly at the TTL");
  assert.equal(isToolsFresh({ tools_synced_at: NOW - 300_001 }, NOW, CACHE_TTL_MS), false);

  // Never synced: the whole point of the second timestamp.
  assert.equal(isToolsFresh({ tools_synced_at: undefined }, NOW, CACHE_TTL_MS), false);
  assert.equal(isToolsFresh({}, NOW, CACHE_TTL_MS), false);
  assert.equal(isToolsFresh(undefined, NOW, CACHE_TTL_MS), false);

  // A `fetched_at` cannot stand in for it — the upstream bug in one assertion.
  assert.equal(isToolsFresh({ fetched_at: NOW } as CachedPolicy, NOW, CACHE_TTL_MS), false);

  // The TTL defaults to CACHE_TTL_MS.
  assert.equal(isToolsFresh({ tools_synced_at: NOW - 299_999 }, NOW), true);
  assert.equal(isToolsFresh({ tools_synced_at: NOW - 300_001 }, NOW), false);

  // A future-stamped file is a clock skew, not infinite freshness.
  assert.equal(isToolsFresh({ tools_synced_at: NOW + 60_000 }, NOW), false);
  assert.equal(isToolsFresh({ tools_synced_at: Number.NaN }, NOW), false);
});

test("getFailureActionFromCache ignores the TTL entirely (unbound.py:225)", () => {
  const ancient = { policy_check_failure_action: "block" as const, tools_synced_at: NOW - 86_400_000 };
  assert.equal(getFailureActionFromCache(ancient), "block", "an opt-out from fail-open does not lapse");
  assert.equal(isToolsFresh(ancient, NOW), false, "while its tools freshness has long expired");

  assert.equal(getFailureActionFromCache({ policy_check_failure_action: "allow" }), "allow");
  assert.equal(getFailureActionFromCache({}), undefined, "cold means unknown, not 'allow'");
  assert.equal(getFailureActionFromCache(undefined), undefined);
  assert.equal(
    getFailureActionFromCache({ policy_check_failure_action: "BLOCK" as unknown as "block" }),
    undefined,
    "out of enum is unknown",
  );
});

test("shouldSkipFileTool: only a native file tool, only when fresh, only when unlisted", () => {
  const fresh: CachedPolicy = record({ tools_to_check: [SOME_FILE_TOOL], tools_synced_at: NOW });

  // The skippable case: a native file tool the org has no policy for.
  assert.equal(shouldSkipFileTool(OTHER_FILE_TOOL, fresh, NOW), true);
  // Listed ⇒ it must be checked.
  assert.equal(shouldSkipFileTool(SOME_FILE_TOOL, fresh, NOW), false);

  // Stale ⇒ round-trip (which itself re-syncs the cache).
  assert.equal(shouldSkipFileTool(OTHER_FILE_TOOL, fresh, NOW + CACHE_TTL_MS + 1), false);
  // Never synced ⇒ round-trip, even though the record exists.
  const neverSynced: CachedPolicy = record({ tools_to_check: undefined, tools_synced_at: undefined });
  assert.equal(shouldSkipFileTool(OTHER_FILE_TOOL, neverSynced, NOW), false);
  assert.equal(shouldSkipFileTool(OTHER_FILE_TOOL, undefined, NOW), false);

  // An empty list is an answer: every file tool is skippable.
  const noPolicies: CachedPolicy = record({ tools_to_check: [], tools_synced_at: NOW });
  for (const tool of NATIVE_FILE_TOOLS) {
    assert.equal(shouldSkipFileTool(tool, noPolicies, NOW), true, tool);
  }

  // Shell and unknown tools are evaluated on `command` and are NEVER skippable, whatever the cache.
  for (const tool of [SHELL_TOOL, "powershell", "some_mcp_tool", "", "READ"]) {
    assert.equal(shouldSkipFileTool(tool, noPolicies, NOW), false, tool);
    assert.equal(shouldSkipFileTool(tool, fresh, NOW), false, tool);
  }
});

// --- the full seam: PolicyState -> snapshot -> writeCache -> readCache -> hydrate ---------------

test("a policy snapshot survives the whole round trip, including the empty-list case", () => {
  for (const tools of [[SOME_FILE_TOOL], [] as string[]]) {
    const f = fixture();
    try {
      // What `policy.ts` does on a successful response, via the onSync seam.
      const live = createPolicyState();
      live.recordSuccess(
        { decision: "allow", tools_to_check: tools, policy_check_failure_action: "block" },
        NOW,
      );
      const identity = identityFor();
      assert.equal(
        writeCache(f.path, {
          ...live.snapshot(),
          gateway_url: identity.gatewayUrl,
          key_fingerprint: identity.fingerprint,
        }),
        true,
      );

      // What the next session does at startup.
      const onDisk = readCache(f.path, identity);
      assert.ok(onDisk !== undefined, "the record came back");
      const cold = createPolicyState();
      cold.hydrate(onDisk);

      assert.deepEqual(cold.getToolsToCheck(), tools, `tools survived for ${JSON.stringify(tools)}`);
      assert.equal(cold.getToolsSyncedAt(), NOW, "and so did its timestamp");
      assert.equal(cold.getFailureAction(), "block", "the fail-open opt-out survived too");
      assert.equal(cold.getFetchedAt(), NOW);
      assert.deepEqual(cold.snapshot(), live.snapshot(), "byte-for-byte the same snapshot");

      // And the point of it all: the skip decision is the same on both sides.
      assert.equal(
        shouldSkipFileTool(OTHER_FILE_TOOL, onDisk, NOW),
        !tools.includes(OTHER_FILE_TOOL),
      );
    } finally {
      f.home.cleanup();
    }
  }
});

test("a snapshot written under one gateway URL does not govern a prefixed sibling (WR-09)", () => {
  const f = fixture();
  try {
    const live = createPolicyState();
    live.recordSuccess({ decision: "allow", tools_to_check: [] }, NOW);
    const identity = identityFor(GATEWAY);
    writeCache(f.path, {
      ...live.snapshot(),
      gateway_url: identity.gatewayUrl,
      key_fingerprint: identity.fingerprint,
    });

    // The prefixed deployment is a different tenant. Before WR-09 both normalised to the same
    // origin, so this record would have been handed to it — and `tools_to_check: []` would have
    // disabled every file-tool check for an org that never said so.
    assert.equal(readCache(f.path, identityFor(OTHER_GATEWAY)), undefined);
  } finally {
    f.home.cleanup();
  }
});

test("NATIVE_FILE_TOOLS is the single source of the six names", () => {
  assert.equal(NATIVE_FILE_TOOLS.size, 6);
  assert.equal(NATIVE_FILE_TOOLS.has(SHELL_TOOL), false, "bash is evaluated on its command");
});

// --- CR-01: only a small regular file is ever opened ------------------------------------------
//
// A try/catch cannot intercept a blocking syscall, so these three cases are about what `readCache`
// must refuse to *open*, not about what it does with the bytes. The FIFO case is the blocker: before
// the `lstat` guard, `readFileSync` on a writerless pipe never returned and never threw, inside
// `init()`, inside handlers pi awaits — a permanently wedged agent from a planted file.

/**
 * Run `readCache` in a child process under a hard timeout, so a regression HANGS THE CHILD rather
 * than the test runner. An in-process watchdog cannot work here: `readFileSync` blocks the only
 * thread, so no timer would ever fire to observe it.
 *
 * @returns `"miss"` or `"hit"`; throws (ETIMEDOUT) if the read blocked past `timeoutMs`.
 */
function readCacheInChild(path: string, identity: CacheIdentity, timeoutMs: number): string {
  const moduleUrl = new URL("../src/cache.ts", import.meta.url).href;
  const script = [
    `const { readCache } = await import(${JSON.stringify(moduleUrl)});`,
    `const out = readCache(${JSON.stringify(path)}, ${JSON.stringify(identity)});`,
    `process.stdout.write(out === undefined ? "miss" : "hit");`,
  ].join("\n");
  return execFileSync(
    process.execPath,
    ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
    { timeout: timeoutMs, killSignal: "SIGKILL", encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
}

test("readCache: a FIFO at the cache path is a prompt miss, not a permanent hang (CR-01)", (t) => {
  if (process.platform === "win32") {
    t.skip("mkfifo is POSIX-only");
    return;
  }
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    // A real named pipe with no writer — the exact shape `PI_CODING_AGENT_DIR` or a hostile `$HOME`
    // can plant, and the one `readFileSync` cannot survive.
    execFileSync("mkfifo", [f.path], { stdio: "ignore" });
    assert.equal(statSync(f.path).isFIFO(), true, "the fixture really is a pipe");

    const started = Date.now();
    // 2 s is orders of magnitude above the ~50 ms an lstat-and-refuse costs, and finite — which is
    // the entire property under test.
    const out = readCacheInChild(f.path, identityFor(), 2000);
    assert.equal(out, "miss", "a pipe is a cache miss");
    assert.ok(Date.now() - started < 2000, "and it returned promptly");
  } finally {
    f.home.cleanup();
  }
});

test("readCache: a cache file above MAX_CACHE_BYTES is refused unread (CR-01/WR-01)", () => {
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    // A record that is valid in every other way, padded past the cap with a field the reader would
    // otherwise simply drop. Without the size guard this parses and returns a usable record.
    const padded = { ...record(), pad: "x".repeat(MAX_CACHE_BYTES) };
    writeFileSync(f.path, JSON.stringify(padded), { encoding: "utf8", mode: 0o600 });
    assert.ok(statSync(f.path).size > MAX_CACHE_BYTES, "the fixture really is oversize");

    assert.equal(readCache(f.path, identityFor()), undefined);
    // The same record under the cap is still accepted, so the guard is a cap and not a refusal.
    writeFileSync(f.path, JSON.stringify(record()), { encoding: "utf8", mode: 0o600 });
    assert.ok(readCache(f.path, identityFor()) !== undefined);
  } finally {
    f.home.cleanup();
  }
});

test("readCache: a symlinked cache path is a miss even when the target is valid (CR-01)", (t) => {
  if (process.platform === "win32") {
    t.skip("symlink creation needs a privilege on Windows");
    return;
  }
  const f = fixture();
  try {
    mkdirSync(f.dir, { recursive: true, mode: 0o700 });
    const target = join(f.dir, "real_cache.json");
    writeFileSync(target, JSON.stringify(record()), { encoding: "utf8", mode: 0o600 });
    symlinkSync(target, f.path);

    // `lstat`, not `stat`: the link is refused rather than followed, because following it is what
    // lets a symlink-to-FIFO block. Nothing legitimately links this path — `writeCache` renames a
    // real file into place.
    assert.equal(readCache(f.path, identityFor()), undefined);
  } finally {
    f.home.cleanup();
  }
});
