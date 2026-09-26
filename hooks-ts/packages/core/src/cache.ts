// The on-disk policy cache (RES-03) — the first file this extension writes.
//
// What it buys: a native file tool the org has no policy for costs zero HTTP, because the last
// `tools_to_check` is still on disk from the previous session. What it costs: a local file now has a
// say in whether an enforcement check happens at all. Everything below is shaped by that trade.
//
// **Every function is total.** There is no `throw` statement in this file and every `fs` call sits
// in a try/catch, because the eventual caller is a pi `tool_call` handler and an exception out of
// one is a *block* with the exception text handed to the model (RESEARCH §F1). A cache that cannot
// be read must cost one round trip, never a broken tool call.
//
// The refusals, and the threats they answer:
//
//   * **The key never reaches disk** (T-09-14). Only `keyFingerprint` — a sha256 prefix — is stored.
//   * **A record is accepted only when BOTH `gateway_url` and `key_fingerprint` match** the resolved
//     pair (T-09-02). Another tenant's policy set, or a second account's, is a miss. This is also
//     why WR-09 belongs in the same wave: the gateway URL is half the cache key, so silently
//     truncating a path prefix would silently re-key the cache.
//   * **0600 file in a 0700 directory, written temp+rename** (T-09-01/T-09-15). Concurrent pi
//     sessions share this file; a torn read is a miss, and the in-memory copy stays authoritative
//     for the session (`policyState.hydrate` never downgrades a network-learned value).
//   * **A non-absolute base directory is refused outright**, the same guard `config.ts` carries: a
//     relative path resolves against the process cwd, i.e. whatever repository pi was started in,
//     which could then plant its own cache.
//
// Deliberate deviation from the Python hook's cache (`unbound.py:270-276`): `repo_policies` and
// `unbound_attribution_enabled` are **not** persisted. Nothing in this extension reads them, and an
// unread field on disk is only a liability — it widens what a planted file can say without widening
// what we can act on. The two timestamps replace its single `last_synced`; see `policyState.ts` for
// why (`handleGuardrails` omits `tools_to_check`, so one timestamp disables file checks for 300 s).

import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute, join } from "node:path";

import {
  CACHE_DIR_NAME,
  CACHE_FILE_NAME,
  CACHE_TTL_MS,
  ENV_PI_AGENT_DIR,
  KEY_FINGERPRINT_PREFIX,
  PI_AGENT_DIR_SEGMENTS,
} from "./constants.ts";
import { parseFailureAction, parseTimestamp, parseToolsToCheck } from "./policyState.ts";
import type { FailureAction, PolicySnapshot } from "./policyState.ts";
import { NATIVE_FILE_TOOLS } from "./payload.ts";

/**
 * The on-disk record, snake_case so the file is diffable by eye against the Python hook's cache.
 * These six keys are the whole schema; a reader drops anything else.
 */
export interface CachedPolicy extends PolicySnapshot {
  /** Half the cache key: the fully resolved base URL, path prefix included (WR-09). */
  gateway_url: string;
  /** The other half: `"sha256:" + 16 hex chars`, never the key itself. */
  key_fingerprint: string;
}

/** The resolved pair a record must match to be usable. */
export interface CacheIdentity {
  gatewayUrl: string;
  fingerprint: string;
}

/** Just the two fields a freshness question needs, so a caller can ask with a partial record. */
type ToolsFreshness = Pick<PolicySnapshot, "tools_synced_at" | "tools_to_check">;

/** Tilde expansion against an explicit home dir — never `process.env.HOME`. */
function expandTilde(raw: unknown, homeDir: string): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed === "~") return homeDir;
  if (trimmed.startsWith("~/")) return join(homeDir, trimmed.slice(2));
  return trimmed;
}

/**
 * `<PI_CODING_AGENT_DIR | ~/.pi/agent>/.unbound/policy_cache.json`, or `undefined` when no safe
 * absolute base exists — in which case the cache is simply not used, for reading or writing.
 *
 * A **relative** `PI_CODING_AGENT_DIR` falls back to the home default rather than resolving against
 * the process cwd. `os.homedir()` can also fail, and the caller's fallback for that is `""`; joining
 * from `""` would put the cache inside the repository pi was started in, where a hostile repo could
 * plant one. Same reasoning, same guard, as `readUnboundConfig` (PR #348 finding 3).
 */
export function resolveCachePath(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  let base = expandTilde(env?.[ENV_PI_AGENT_DIR], typeof homeDir === "string" ? homeDir : "");
  if (base === undefined || !isAbsolute(base)) {
    if (typeof homeDir !== "string" || homeDir.length === 0 || !isAbsolute(homeDir)) return undefined;
    base = join(homeDir, ...PI_AGENT_DIR_SEGMENTS);
  }
  if (!isAbsolute(base)) return undefined;
  return join(base, CACHE_DIR_NAME, CACHE_FILE_NAME);
}

/**
 * A stable, non-reversible tenant/account discriminator: `"sha256:"` + the first 16 hex characters
 * of the sha256 of the key. 64 bits is ample to separate the handful of accounts on one machine, and
 * the truncation means even the full digest is not on disk to grind offline.
 *
 * Computed with `node:crypto` — never a hand-rolled digest, and never the key.
 */
export function keyFingerprint(apiKey: string): string {
  const material = typeof apiKey === "string" ? apiKey : "";
  return KEY_FINGERPRINT_PREFIX + createHash("sha256").update(material, "utf8").digest("hex").slice(0, 16);
}

/**
 * Read and validate the cache. **Any** surprise is a miss: a missing file, an EACCES, an EISDIR, an
 * empty or half-written file, JSON that is not an object, or an identity that does not match.
 *
 * Field-level damage is narrower than record-level damage, deliberately: a malformed
 * `tools_to_check` drops that field **and its timestamp** (so no file tool is skipped) while leaving
 * the failure action usable, because losing a remembered fail-closed setting is the worse outcome.
 */
export function readCache(path: string, identity: CacheIdentity): CachedPolicy | undefined {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const body = parsed as Record<string, unknown>;

  // Identity first: nothing else in the file matters if it belongs to another gateway or account.
  const gatewayUrl = body.gateway_url;
  const fingerprint = body.key_fingerprint;
  if (typeof gatewayUrl !== "string" || gatewayUrl !== identity?.gatewayUrl) return undefined;
  if (typeof fingerprint !== "string" || fingerprint !== identity?.fingerprint) return undefined;

  const out: CachedPolicy = { gateway_url: gatewayUrl, key_fingerprint: fingerprint };

  const fetchedAt = parseTimestamp(body.fetched_at);
  if (fetchedAt !== undefined) out.fetched_at = fetchedAt;

  const action = parseFailureAction(body.policy_check_failure_action);
  if (action !== undefined) out.policy_check_failure_action = action;

  // Both or neither. An unstamped list cannot be aged, and a stamp with no list means nothing —
  // either half alone would be a file-tool skip with no basis.
  const tools = parseToolsToCheck(body.tools_to_check);
  const syncedAt = parseTimestamp(body.tools_synced_at);
  if (tools !== undefined && syncedAt !== undefined) {
    out.tools_to_check = tools;
    out.tools_synced_at = syncedAt;
  }

  return out;
}

/**
 * Persist the record. Returns `false` on any failure — a cache that could not be written is a cache
 * miss next session, which is a round trip, not an error.
 *
 * Atomicity: write `<file>.tmp-<pid>-<rand>` in the same directory, then `rename`. That is atomic on
 * the same filesystem on POSIX, so a concurrent pi session never reads a half-written file. On
 * Windows `renameSync` over an existing file throws `EPERM`/`EEXIST`, so fall back to
 * `unlink`+`rename` (§F6). The temp name carries the pid so two sessions writing at once cannot
 * collide on it.
 *
 * Posture: directory `0700`, file `0600`. Both modes are masked by umask at creation, so both are
 * `chmod`ed explicitly — a 0644 cache is a file any local process could rewrite to claim `[]`.
 */
export function writeCache(path: string, value: CachedPolicy): boolean {
  let tmp: string | undefined;
  try {
    const dir = dirname(path);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      chmodSync(dir, 0o700);
    } catch {
      // A pre-existing directory we do not own is not ours to tighten; the file mode still holds.
    }

    tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
    writeFileSync(tmp, JSON.stringify(value), { encoding: "utf8", mode: 0o600 });
    try {
      chmodSync(tmp, 0o600);
    } catch {
      // Best effort; the create mode already applied.
    }

    try {
      renameSync(tmp, path);
    } catch {
      // Windows: rename onto an existing file fails. Remove the target, then retry once.
      try {
        unlinkSync(path);
      } catch {
        // The target may not exist at all, in which case the first rename failed for another
        // reason and the retry below will fail too.
      }
      renameSync(tmp, path);
    }
    return true;
  } catch {
    // Never leave a temp file behind on a failed write.
    if (tmp !== undefined) {
      try {
        unlinkSync(tmp);
      } catch {
        // Nothing further to do; the caller only needs to know the cache was not written.
      }
    }
    return false;
  }
}

/**
 * Is the remembered `tools_to_check` recent enough to skip a round trip?
 *
 * Bounded by `tools_synced_at` **only**. A `fetched_at` from a heartbeat or a prompt check says
 * nothing about the tool list — treating it as if it did is the upstream bug this design exists to
 * avoid. A future-dated stamp is a clock skew, not infinite freshness.
 */
export function isToolsFresh(
  cache: ToolsFreshness | undefined,
  now: number,
  ttlMs: number = CACHE_TTL_MS,
): boolean {
  const syncedAt = parseTimestamp(cache?.tools_synced_at);
  if (syncedAt === undefined) return false;
  const age = now - syncedAt;
  if (age < 0) return false;
  return age <= ttlMs;
}

/**
 * The remembered fail-open opt-out, **ignoring the TTL** — matching `unbound.py:225`. An org that
 * turned off fail-open must not drift back into it just because the last good response is old.
 *
 * Unlike the Python hook this returns `undefined` rather than defaulting to allow: `undefined` means
 * "nothing known", which `policy.ts` already treats as fail-open, and keeping the two distinct is
 * what lets a cold start be recognisable as one.
 */
export function getFailureActionFromCache(
  cache: Pick<PolicySnapshot, "policy_check_failure_action"> | undefined,
): FailureAction | undefined {
  return parseFailureAction(cache?.policy_check_failure_action);
}

/**
 * May this tool call skip the API entirely? Three conditions, all required:
 *
 *   1. the tool is one of the six native file tools — everything else (shell tools, MCP tools, an
 *      unknown name) is evaluated on `command` and is never skippable;
 *   2. the tool list is **tools-fresh**, not merely cached;
 *   3. the list does not contain this tool.
 *
 * Mirrors `unbound.py:3818-3826`, with condition 2 tightened to the tools-specific timestamp. Note
 * the comparison is exact: an unknown casing is an unknown tool, and Phase 7 registered pi's
 * lowercase names.
 */
export function shouldSkipFileTool(
  toolName: string,
  cache: ToolsFreshness | undefined,
  now: number,
): boolean {
  if (typeof toolName !== "string" || !NATIVE_FILE_TOOLS.has(toolName)) return false;
  if (!isToolsFresh(cache, now)) return false;
  const tools = cache?.tools_to_check;
  if (!Array.isArray(tools)) return false;
  return !tools.includes(toolName);
}
