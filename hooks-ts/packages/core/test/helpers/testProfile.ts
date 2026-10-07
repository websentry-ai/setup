// The `AgentProfile` core's own tests inject.
//
// Why it carries pi's values: the existing core assertions were written when core held pi's literals
// (`hook_source: "pi"`, `/v1/hooks/pi`, `UNBOUND_PI_API_KEY`, `pi_version`). Giving the test profile
// the same wire values keeps every one of those assertions true, unchanged, without core's tests
// importing `packages/pi` — core may not depend on an adapter package, in tests either.
// `packages/pi/test/profile.test.ts` asserts the five scalar fields here equal `PI_PROFILE`'s, so the
// two cannot drift apart silently.
//
// The function members are implemented here, not borrowed from an adapter, and are total like any
// real profile's: every failure is a safe default, never a throw.

import { isAbsolute, join } from "node:path";

import { readSmallRegularFile } from "../../src/safeRead.ts";
import type { AgentAuthSummary, AgentProfile } from "../../src/profile.ts";

const AGENT_DIR_ENV = "PI_CODING_AGENT_DIR";
const AGENT_DIR_SEGMENTS = [".pi", "agent"] as const;
const AUTH_FILE_NAME = "auth.json";
const MAX_AUTH_BYTES = 65_536;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function resolveAgentDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined {
  try {
    const home = typeof homeDir === "string" ? homeDir : "";
    const raw = env?.[AGENT_DIR_ENV];
    let base: string | undefined;
    if (typeof raw === "string" && raw.trim().length > 0) {
      const trimmed = raw.trim();
      base = trimmed === "~" ? home : trimmed.startsWith("~/") ? join(home, trimmed.slice(2)) : trimmed;
    }
    if (base === undefined || !isAbsolute(base)) {
      if (home.length === 0 || !isAbsolute(home)) return undefined;
      base = join(home, ...AGENT_DIR_SEGMENTS);
    }
    return isAbsolute(base) ? base : undefined;
  } catch {
    return undefined;
  }
}

function readAuth(agentDir: string | undefined, modelProvider: string | undefined): AgentAuthSummary | undefined {
  try {
    if (typeof agentDir !== "string" || agentDir === "") return undefined;
    const raw = readSmallRegularFile(join(agentDir, AUTH_FILE_NAME), MAX_AUTH_BYTES);
    if (raw === undefined) return undefined;
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return undefined;
    const entries = new Map<string, Record<string, unknown>>();
    for (const [name, value] of Object.entries(parsed)) {
      if (isRecord(value) && typeof value.type === "string") entries.set(name, value);
    }
    const named = typeof modelProvider === "string" ? modelProvider.trim() : "";
    const provider = named.length > 0 ? named : entries.size === 1 ? [...entries.keys()][0] : undefined;
    const entry = provider === undefined ? undefined : entries.get(provider);
    const summary: AgentAuthSummary = {
      provider,
      hasCredential: entry !== undefined,
      anthropicOAuth: provider === "anthropic" && entry?.type === "oauth",
    };
    if (typeof entry?.access === "string" && entry.access.length > 0) summary.accessToken = entry.access;
    if (typeof entry?.expires === "number" && Number.isFinite(entry.expires)) summary.expiresAt = entry.expires;
    return summary;
  } catch {
    return undefined;
  }
}

export const TEST_PROFILE: AgentProfile = Object.freeze({
  appLabel: "pi",
  hookSource: "pi",
  turnLogPath: "/v1/hooks/pi",
  envApiKey: "UNBOUND_PI_API_KEY",
  versionMetadataKey: "pi_version",
  resolveClientEntrypoint: (): string => "pi/test",
  resolveAgentDir,
  fileTools: Object.freeze({
    defaulting: new Set(["grep", "find", "ls"]) as ReadonlySet<string>,
    required: new Set(["read", "write", "edit"]) as ReadonlySet<string>,
    pathOf(_toolName: string, input: Record<string, unknown>): unknown {
      try {
        return input?.path;
      } catch {
        return undefined;
      }
    },
  }),
  readAuth,
});
