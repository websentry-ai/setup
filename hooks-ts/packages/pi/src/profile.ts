// The pi profile: every pi-specific fact core needs, in one frozen object.
//
// Core takes an `AgentProfile` and never names an agent itself (`core/src/profile.ts`). The scalar
// values below are exactly what pi has always put on the wire — they are pinned literally by
// `test/profile.test.ts` and, end to end, by the frozen wire golden.
//
// The file-tool taxonomy is defined here. `resolveAgentDir` and `readAuth` still delegate to readers
// that live in core today (`resolvePiAgentDir`, `readPiAuth`, `chooseProvider`); a later slice of the
// same refactor moves those into this package, and the profile's surface and values do not change
// when it does.
//
// **Every function here is total.** A throw out of a pi handler is a BLOCK whose message reaches the
// model, so each member answers a safe default for any input — `null`, a Proxy whose getters throw,
// a non-string environment value — instead of raising.

import { chooseProvider, readPiAuth } from "../../core/src/accountIdentity.ts";
import { resolvePiAgentDir } from "../../core/src/cache.ts";
import { ANTHROPIC_PROVIDER_ID, PI_AUTH_TYPE_OAUTH } from "../../core/src/constants.ts";
import { nativeFileTools } from "../../core/src/payload.ts";
import type { AgentAuthSummary, AgentFileTools, AgentProfile } from "../../core/src/profile.ts";
import { resolveClientEntrypoint } from "./version.ts";

/** What `resolveClientEntrypoint` answers when even the total reader could not be reached. */
const UNKNOWN_ENTRYPOINT = "pi/unknown";

/** Native search tools whose `path` is optional in pi — `file_path` falls back to cwd. */
export const PI_PATH_DEFAULTING_TOOLS = ["grep", "find", "ls"] as const;
/** Native file tools whose `path` is required by pi's schema. */
export const PI_PATH_REQUIRED_TOOLS = ["read", "write", "edit"] as const;

export const PI_FILE_TOOLS: AgentFileTools = Object.freeze({
  defaulting: new Set<string>(PI_PATH_DEFAULTING_TOOLS) as ReadonlySet<string>,
  required: new Set<string>(PI_PATH_REQUIRED_TOOLS) as ReadonlySet<string>,
  /** Every pi file tool names its target `path`. The value is returned raw; the caller validates. */
  pathOf(_toolName: string, input: Record<string, unknown>): unknown {
    try {
      return input?.path;
    } catch {
      return undefined;
    }
  },
});

/**
 * The six tools the API evaluates on `metadata.file_path` rather than on a command —
 * `PI_NATIVE_FILE_TOOLS` in the API's `taxonomy.ts:137-144`, and the exact set `computeToolsToCheck`
 * intersects against. The two lists are a drift pair: a name here that the API does not know is a
 * round trip that evaluates nothing, and a name the API knows that is missing here is a file tool
 * sent with no `file_path`.
 *
 * Built by core's `nativeFileTools` from `PI_FILE_TOOLS`, which is also what core's cache skip
 * calls — so this is the same set object core uses, not a second copy of the names.
 */
export const PI_NATIVE_FILE_TOOLS: ReadonlySet<string> = nativeFileTools(PI_FILE_TOOLS);

/**
 * pi's `auth.json`, reduced to what the account identity needs.
 *
 * `undefined` means "no credential store": nothing to describe, so nothing is probed. Otherwise the
 * provider is the session's own when pi knows it, else the only one in the store, else none.
 */
function readAuth(agentDir: string | undefined, modelProvider: string | undefined): AgentAuthSummary | undefined {
  try {
    const auth = readPiAuth(agentDir);
    if (auth === undefined) return undefined;
    const provider = chooseProvider(auth, modelProvider);
    const entry = provider !== undefined && Object.hasOwn(auth, provider) ? auth[provider] : undefined;
    const summary: AgentAuthSummary = {
      provider,
      hasCredential: entry !== undefined,
      // The one provider whose subscription sign-in can be turned into an account.
      anthropicOAuth: provider === ANTHROPIC_PROVIDER_ID && entry?.type === PI_AUTH_TYPE_OAUTH,
    };
    if (entry?.access !== undefined) summary.accessToken = entry.access;
    if (entry?.expires !== undefined) summary.expiresAt = entry.expires;
    return summary;
  } catch {
    return undefined;
  }
}

export const PI_PROFILE: AgentProfile = Object.freeze({
  appLabel: "pi",
  hookSource: "pi",
  turnLogPath: "/v1/hooks/pi",
  envApiKey: "UNBOUND_PI_API_KEY",
  versionMetadataKey: "pi_version",
  resolveClientEntrypoint(env: NodeJS.ProcessEnv, argv1?: string): string {
    try {
      return resolveClientEntrypoint(env, argv1);
    } catch {
      return UNKNOWN_ENTRYPOINT;
    }
  },
  resolveAgentDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
    try {
      return resolvePiAgentDir(env, homeDir);
    } catch {
      return undefined;
    }
  },
  fileTools: PI_FILE_TOOLS,
  readAuth,
});
