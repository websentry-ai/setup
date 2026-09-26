// Identity resolution (RES-06): where the API key and the gateway URL come from.
//
// Both sources are user-controlled trust boundaries (a process environment and a 0600 file), so:
//   * the key is returned as a value and never logged — `redactSecrets` exists for every consumer
//     that does log (T-08-03);
//   * the URL is normalised and https-only for non-loopback hosts, so a hostile value cannot
//     receive the Bearer header in cleartext (T-08-04 / ASVS V9);
//   * the whole file read sits in one try/catch. An exception thrown out of a pi `tool_call`
//     handler is a BLOCK (RESEARCH §F1), so an EACCES on a config file must never stop a
//     developer's tool call (T-08-07).
//
// Read-only by design: Phase 8 adds no writer, so the file's 0600-in-0700 posture — created by
// `unbound login` — cannot be widened here (T-08-09 / ASVS V12).

import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";

import {
  CONFIG_DIR_NAME,
  CONFIG_FILE_NAME,
  DEFAULT_GATEWAY_URL,
  ENV_API_KEY_GENERIC,
  ENV_API_KEY_PI,
  ENV_GATEWAY_URL,
} from "./constants.ts";

/** Hosts for which plain `http:` is allowed — the documented mock-API-smoke exemption (§E4a). */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Read `<homeDir>/.unbound/config.json`. One of only two file reads in Phase 8 (ASVS V12).
 *
 * Returns `{}` on any failure — ENOENT, EACCES, malformed JSON, or a JSON body that is not an
 * object. Never throws and never echoes the file contents anywhere.
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
  try {
    const raw = readFileSync(join(homeDir, CONFIG_DIR_NAME, CONFIG_FILE_NAME), "utf8");
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
 * Validate and canonicalise a gateway URL. Returns the `origin` — which drops any path, query and
 * trailing slash an attacker (or a copy-paste) appended — or `undefined` when the value is not a
 * usable, safe base URL, so resolution falls through to the next tier.
 *
 * `https:` is required for every real host; plain `http:` is accepted only on loopback.
 */
export function normalizeGatewayUrl(raw: unknown): string | undefined {
  const candidate = usableString(raw);
  if (candidate === undefined) return undefined;
  try {
    // `usableString` already trimmed it.
    const url = new URL(candidate);
    const isLoopbackHttp = url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol !== "https:" && !isLoopbackHttp) return undefined;
    return url.origin;
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
