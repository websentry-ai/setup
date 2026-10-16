// pi's credential store — `<agent dir>/auth.json` — and what it says about the current sign-in.
//
// Core builds the account identity (`core/src/accountIdentity.ts`) but does not know how any agent
// stores a sign-in. This file is pi's answer, handed to core as `AgentProfile.readAuth`: it reads
// `auth.json`, picks the session's provider, and reduces the entry to an `AgentAuthSummary`.
//
// **What is read into memory.** Per provider: `type`, and for the one profile request an OAuth
// `access` token and its `expires`. The refresh token and any API key are never copied out of the
// parsed file. The file is read, never written.
//
// **Total by construction.** No `throw` in this file; a missing or corrupt `auth.json` is "no
// credential store", which core turns into no identity at all.

import { join } from "node:path";

import { identityLabel } from "../../core/src/accountIdentity.ts";
import { ANTHROPIC_PROVIDER_ID, MAX_AUTH_FILE_BYTES } from "../../core/src/constants.ts";
import type { AgentAuthSummary } from "../../core/src/profile.ts";
import { readSmallRegularFile } from "../../core/src/safeRead.ts";

/** pi's credential store, beside its own install: `<agent dir>/auth.json`. Read, never written. */
export const PI_AUTH_FILE_NAME = "auth.json";
/** pi's credential `type` for a subscription sign-in. */
export const PI_AUTH_TYPE_OAUTH = "oauth";

/**
 * One `auth.json` entry, narrowed to what the identity needs. `access` is held in memory only for
 * the one profile request; the refresh token and any API key are never read into this shape.
 */
export interface PiAuthEntry {
  type: string;
  access?: string;
  expires?: number;
}

export type PiAuth = Record<string, PiAuthEntry>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * pi's credential store, narrowed to `{type, access?, expires?}` per provider — or `undefined` when
 * it is missing, unreadable, not a small regular file, not JSON, or not an object. Entries that are
 * not objects with a string `type` are skipped.
 */
export function readPiAuth(agentDir: string | undefined): PiAuth | undefined {
  try {
    if (typeof agentDir !== "string" || agentDir === "") return undefined;
    const raw = readSmallRegularFile(join(agentDir, PI_AUTH_FILE_NAME), MAX_AUTH_FILE_BYTES);
    if (raw === undefined) return undefined;
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return undefined;
    const out: PiAuth = {};
    for (const [provider, value] of Object.entries(parsed)) {
      if (!isRecord(value) || typeof value.type !== "string") continue;
      const entry: PiAuthEntry = { type: value.type };
      if (typeof value.access === "string" && value.access.length > 0) entry.access = value.access;
      if (typeof value.expires === "number" && Number.isFinite(value.expires)) entry.expires = value.expires;
      out[provider] = entry;
    }
    return out;
  } catch {
    return undefined;
  }
}

/**
 * The session's provider when pi knows it (`ctx.model.provider`), else the only provider in
 * `auth.json`, else none — an ambiguous store names no account rather than a guessed one.
 */
export function chooseProvider(
  auth: Record<string, unknown> | undefined,
  modelProvider: string | undefined,
): string | undefined {
  try {
    const fromModel = identityLabel(modelProvider);
    if (fromModel !== undefined) return fromModel;
    if (!isRecord(auth)) return undefined;
    const providers = Object.keys(auth);
    return providers.length === 1 ? providers[0] : undefined;
  } catch {
    return undefined;
  }
}

/** The one provider whose subscription sign-in can be turned into an account. */
function isAnthropicOAuth(provider: string | undefined, entry: PiAuthEntry | undefined): boolean {
  return provider === ANTHROPIC_PROVIDER_ID && entry?.type === PI_AUTH_TYPE_OAUTH;
}

/**
 * pi's `AgentProfile.readAuth`: `auth.json` reduced to what the account identity needs.
 *
 * `undefined` means "no credential store": nothing to describe, so core probes nothing. Otherwise the
 * provider is the session's own when pi knows it, else the only one in the store, else none.
 *
 * The provider's entry is looked up as an own property, so a provider named after an inherited
 * object member (`constructor`, `toString`) reports no credential rather than a phantom one.
 */
export function readPiAuthSummary(
  agentDir: string | undefined,
  modelProvider: string | undefined,
): AgentAuthSummary | undefined {
  try {
    const auth = readPiAuth(agentDir);
    if (auth === undefined) return undefined;
    const provider = chooseProvider(auth, modelProvider);
    const entry = provider !== undefined && Object.hasOwn(auth, provider) ? auth[provider] : undefined;
    const summary: AgentAuthSummary = {
      provider,
      hasCredential: entry !== undefined,
      anthropicOAuth: isAnthropicOAuth(provider, entry),
    };
    if (entry?.access !== undefined) summary.accessToken = entry.access;
    if (entry?.expires !== undefined) summary.expiresAt = entry.expires;
    return summary;
  } catch {
    return undefined;
  }
}
