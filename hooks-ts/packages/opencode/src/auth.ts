// opencode's credential store — `<data dir>/auth.json`, or `OPENCODE_AUTH_CONTENT` — reduced to what
// the account identity needs: which provider, whether it has a credential, and whether that
// credential is a subscription (OAuth) sign-in. Handed to core as `AgentProfile.readAuth`.
//
// **Nothing but `type` is read from an entry** (HOOK-17). opencode stores `{type:"api", key}`,
// `{type:"oauth", refresh, access, expires, accountId?}` and `{type:"wellknown", key, token}`
// (`oc:opencode/src/auth/index.ts:15-35`). None of those values is copied out of the parsed JSON,
// so no key, token or refresh value can reach a return value, a log line or the wire.
//
// **Why `anthropicOAuth` is true for any `oauth` entry.** Core's field means "this seat is a
// subscription sign-in", which `buildAccountIdentity` turns into `auth_mode: "subscription"`. The
// profile request core would make for an Anthropic OAuth seat needs `accessToken`, which this reader
// never returns, so core never makes that request and no credential value is used. opencode 1.x has
// no built-in Anthropic OAuth, so most seats report `api_key`, or `subscription` for an
// OpenAI-Codex OAuth sign-in.
//
// **Where it reads.** `OPENCODE_AUTH_CONTENT`, when it parses to an object, replaces the file
// wholesale, as opencode itself does (`:59-61`); otherwise `<dataDir>/auth.json` through
// `readSmallRegularFile`. The file is read, never written.
//
// Total: no throw statement here; any failure is "no credential store", i.e. `undefined`.

import { join } from "node:path";

import { identityLabel } from "../../core/src/accountIdentity.ts";
import { MAX_AUTH_FILE_BYTES } from "../../core/src/constants.ts";
import type { AgentAuthSummary } from "../../core/src/profile.ts";
import { readSmallRegularFile } from "../../core/src/safeRead.ts";
import { AUTH_FILE_NAME, ENV_OPENCODE_AUTH_CONTENT } from "./constants.ts";

/** opencode's credential `type` for a subscription sign-in. */
const AUTH_TYPE_OAUTH = "oauth";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseStore(raw: string | undefined): Record<string, unknown> | undefined {
  if (raw === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function envContent(env: unknown): string | undefined {
  try {
    if (env === null || typeof env !== "object") return undefined;
    const raw: unknown = (env as Record<string, unknown>)[ENV_OPENCODE_AUTH_CONTENT];
    if (typeof raw !== "string" || raw === "" || raw.length > MAX_AUTH_FILE_BYTES) return undefined;
    return raw;
  } catch {
    return undefined;
  }
}

/** The credential `type` per provider; nothing else from an entry. */
function readTypes(dataDir: unknown, env: unknown): Map<string, string> | undefined {
  let store = parseStore(envContent(env));
  if (store === undefined) {
    if (typeof dataDir !== "string" || dataDir === "") return undefined;
    store = parseStore(readSmallRegularFile(join(dataDir, AUTH_FILE_NAME), MAX_AUTH_FILE_BYTES));
  }
  if (store === undefined) return undefined;
  const types = new Map<string, string>();
  for (const name of Object.keys(store)) {
    const entry = store[name];
    if (!isRecord(entry)) continue;
    const type = entry.type;
    if (typeof type === "string" && type !== "") types.set(name, type);
  }
  return types;
}

/**
 * opencode's `readAuth`: the store reduced to `{provider, hasCredential, anthropicOAuth}`, or
 * `undefined` when there is no readable store. The provider is the session's own when named, else the
 * only one in the store, else none (an ambiguous store names no account). Lookup is by own key, so a
 * provider named `constructor` or `__proto__` reports no credential.
 */
export function readOpencodeAuthSummary(
  dataDir: string | undefined,
  modelProvider: string | undefined,
  env: NodeJS.ProcessEnv,
): AgentAuthSummary | undefined {
  try {
    const types = readTypes(dataDir, env);
    if (types === undefined) return undefined;
    const named = identityLabel(modelProvider);
    const provider = named ?? (types.size === 1 ? [...types.keys()][0] : undefined);
    const type = provider === undefined ? undefined : types.get(provider);
    return {
      provider,
      hasCredential: type !== undefined,
      anthropicOAuth: type === AUTH_TYPE_OAUTH,
    };
  } catch {
    return undefined;
  }
}
