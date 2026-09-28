// Identity resolution (RES-06): where the API key and the gateway URL come from.
//
// Both sources are user-controlled trust boundaries (a process environment and a 0600 file), so:
//   * the key is returned as a value and never logged — `redactSecrets` exists for every consumer
//     that does log (T-08-03);
//   * the URL is normalised and https-only for non-loopback hosts, so a hostile value cannot
//     receive the Bearer header in cleartext (T-08-04 / ASVS V9);
//   * the whole file read sits in one try/catch, and goes through `safeRead.ts` so it cannot BLOCK
//     rather than throw (CR-01). An exception thrown out of a pi `tool_call` handler is a BLOCK
//     (RESEARCH §F1), so an EACCES on a config file must never stop a developer's tool call
//     (T-08-07) — and a config file that is a FIFO must not stop it either.
//
// Read-only by design: Phase 8 adds no writer, so the file's 0600-in-0700 posture — created by
// `unbound login` — cannot be widened here (T-08-09 / ASVS V12).

import { isAbsolute, join } from "node:path";

import {
  CONFIG_DIR_NAME,
  CONFIG_FILE_NAME,
  DEFAULT_GATEWAY_URL,
  ENV_API_KEY_GENERIC,
  ENV_API_KEY_PI,
  ENV_GATEWAY_URL,
  MAX_CONFIG_BYTES,
} from "./constants.ts";
import { readSmallRegularFile } from "./safeRead.ts";

/** Hosts for which plain `http:` is allowed — the documented mock-API-smoke exemption (§E4a). */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Read `<homeDir>/.unbound/config.json`. One of only two file reads in Phase 8 (ASVS V12).
 *
 * Returns `{}` on any failure — ENOENT, EACCES, malformed JSON, or a JSON body that is not an
 * object. Never throws and never echoes the file contents anywhere.
 *
 * "Never throws" was not the same as "always returns" (CR-01). The read goes through
 * `readSmallRegularFile`, which `lstat`s first: a `config.json` that is a FIFO — or a `$HOME` on a
 * hung network mount — made `readFileSync` block forever here, on the `init()` path every handler
 * awaits. Only a regular file of at most `MAX_CONFIG_BYTES` is opened.
 *
 * A **non-absolute** `homeDir` is refused outright. `os.homedir()` can fail, and the caller's
 * fallback is `""`; `join("", ".unbound/config.json")` resolves relative to the process cwd — i.e.
 * the repository pi was started in. A repo-planted `.unbound/config.json` could then supply both
 * `api_key` and `gateway_url`, sending the Bearer token to an attacker's https host (which passes
 * the https-only check) and silently replacing the policy engine. The config file is a
 * user-profile artifact; anything that is not an absolute path is not it.
 */
export function readUnboundConfig(homeDir: string): Record<string, unknown> {
  if (typeof homeDir !== "string" || homeDir === "" || !isAbsolute(homeDir)) return {};
  const raw = readSmallRegularFile(join(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), MAX_CONFIG_BYTES);
  if (raw === undefined) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed as Record<string, unknown>;
  } catch {
    return {};
  }
}

/**
 * A candidate is usable only when it is a non-blank string, and it is returned **trimmed**.
 *
 * Returning the raw value would be a silent enforcement hole: `UNBOUND_API_KEY=$(cat keyfile)`
 * keeps the trailing newline, and `Bearer <key>\n` is either rejected by undici as an invalid
 * header value or 401s at the gateway — both of which fail open, so every tool runs unchecked
 * while the developer believes a policy is active.
 */
function usableString(candidate: unknown): string | undefined {
  if (typeof candidate !== "string") return undefined;
  const trimmed = candidate.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * The four locked key tiers: the pi-specific env var, the generic env var (6 other tools honour
 * it), then `api_key` from the config file, then `undefined` — which means "extension inactive",
 * never "block" (RES-06).
 */
export function resolveApiKey(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  const fromEnv = usableString(env[ENV_API_KEY_PI]) ?? usableString(env[ENV_API_KEY_GENERIC]);
  if (fromEnv !== undefined) return fromEnv;
  return usableString(readUnboundConfig(homeDir).api_key);
}

/**
 * Validate and canonicalise a gateway URL, or return `undefined` when the value is not a usable,
 * safe base URL — in which case resolution falls through to the next tier.
 *
 * `https:` is required for every real host; plain `http:` is accepted only on loopback.
 *
 * **A non-root path prefix is preserved (WR-09).** This previously returned bare `url.origin`, which
 * was framed as hardening: drop anything an attacker or a copy-paste appended. That framing was
 * wrong. In the scenario it defends against the attacker already controls the entire host, so a
 * preserved prefix adds no attack surface — while dropping it broke a real deployment shape. A
 * prefixed tenant (`https://host/unbound` behind an ingress path route or an API-gateway stage) had
 * every request rewritten to `https://host/v1/hooks/pretool`, which 404s, which fails open —
 * permanently, silently, with no local signal. The prefix is also half the on-disk cache key
 * (`cache.ts`), so truncating it would silently re-key the cache as well.
 *
 * Still dropped or refused, because none of these have a legitimate base-URL meaning:
 *   * a **root** path (`/`, `///`) — normalised away so the base never ends in a slash and
 *     `${base}${PRETOOL_PATH}` cannot produce a double slash;
 *   * **query and fragment** — a base URL carrying either would corrupt every request target;
 *   * **userinfo** (`https://user:pass@host`) — credentials must not ride the base URL beside the
 *     Bearer header, and there is no prefixed-tenant case that needs them.
 */
export function normalizeGatewayUrl(raw: unknown): string | undefined {
  const candidate = usableString(raw);
  if (candidate === undefined) return undefined;
  try {
    // `usableString` already trimmed it.
    const url = new URL(candidate);
    const isLoopbackHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !isLoopbackHttp) return undefined;
    if (url.username !== "" || url.password !== "") return undefined;
    // `url.pathname` is already percent-normalised by the URL parser; `url.origin` carries no path,
    // query or fragment, so concatenating the two drops both by construction.
    const path = url.pathname.replace(/\/+$/, "");
    return path === "" ? url.origin : url.origin + path;
  } catch {
    return undefined;
  }
}

/**
 * The three URL tiers, mirroring unbound-cli `src/config.js:95-97` exactly. The middle tier is
 * load-bearing: without it a tenant on a custom host (the real `zendesk-api.getunbound.ai` case)
 * would have its calls sent to the wrong host, which fails open — i.e. zero enforcement, silently.
 */
export function resolveGatewayUrl(env: NodeJS.ProcessEnv, homeDir: string): string {
  const fromEnv = normalizeGatewayUrl(env[ENV_GATEWAY_URL]);
  if (fromEnv !== undefined) return fromEnv;
  // Read the file at most once per call.
  const fromFile = normalizeGatewayUrl(readUnboundConfig(homeDir).gateway_url);
  return fromFile ?? DEFAULT_GATEWAY_URL;
}

/**
 * Port of `unbound.py:137-141` `redact_secrets`. Apply to everything sent to /v1/hooks/errors and
 * to every line written to stderr (T-08-03). Keys shorter than 8 characters are left alone —
 * they are too generic to substitute without mangling unrelated text.
 */
export function redactSecrets(text: string, apiKey?: string): string {
  let out = text.replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]");
  if (apiKey !== undefined && apiKey.length >= 8) {
    // split/join is a literal replacement — no regex escaping hazard with key characters.
    out = out.split(apiKey).join("[REDACTED]");
  }
  return out;
}
