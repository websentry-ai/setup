// Account identity — which provider account the agent is signed in with, for the console's Account
// Usage page. Parity with the Claude Code hook (`unbound.py` `read_account_identity` / `_device_serial`):
// the same `account_identity` wire object, the same `plan` / `auth_mode` vocabulary.
//
// Where it comes from:
//
//   * The agent's own credential store, read by the adapter and handed over as an
//     `AgentAuthSummary` (`AgentProfile.readAuth`). Core never opens that store and does not know
//     its layout; the agent dir is resolved exactly like the policy cache
//     (`AgentProfile.resolveAgentDir`).
//   * For an Anthropic **OAuth** sign-in with a live token: the same profile endpoint Claude Code
//     uses, which names the account email, the organisation and its plan.
//   * Everything else — an API-key provider, or an OAuth provider we cannot resolve — is
//     `auth_mode: "api_key"` and nothing more. No email is knowable, so none is invented.
//   * `device_serial` — the hardware serial, probed the way the Python hook probes it.
//
// **The token.** It is an opaque bearer string and it goes to exactly one place: its own issuer,
// `api.anthropic.com`, on a request that refuses redirects. It is never logged, never written, never
// placed in anything this module returns, and never sent to Unbound.
//
// **Total by construction.** No `throw` in this file; every failure is an absence. No credential
// store (or a reader that throws) is no identity at all; a failed profile call is an identity without email/plan;
// a failed probe is an identity without a serial. Every wait has a deadline.

import { execFile as nodeExecFile } from "node:child_process";
import { tmpdir } from "node:os";

import {
  ACCOUNT_IDENTITY_TIMEOUT_MS,
  ANTHROPIC_OAUTH_BETA_HEADER,
  ANTHROPIC_OAUTH_BETA_VALUE,
  ANTHROPIC_PROFILE_URL,
  AUTH_MODE_API_KEY,
  AUTH_MODE_SUBSCRIPTION,
  LINUX_MACHINE_ID_PATHS,
  MAX_IDENTITY_FIELD_CHARS,
  MAX_PROFILE_BYTES,
  MAX_SERIAL_PROBE_BYTES,
  PLACEHOLDER_SERIALS,
} from "./constants.ts";
import type { AgentAuthSummary } from "./profile.ts";
import { readSmallRegularFile } from "./safeRead.ts";

/** The wire object, field for field what `preToolUseHandler.ts` declares. All optional strings. */
export interface AccountIdentity {
  user_email?: string;
  org_id?: string;
  plan?: string;
  auth_mode?: string;
  email_domain?: string;
  device_serial?: string;
}

/** What the profile endpoint says, already validated. */
export interface AnthropicProfile {
  email?: string;
  orgId?: string;
  plan?: string;
}

/** `execFile` reduced to "stdout or nothing". Injectable so no test runs a real probe. */
export type ExecFileLike = (
  file: string,
  args: readonly string[],
  opts: { timeoutMs: number; maxBytes: number },
) => Promise<string | undefined>;

const PLACEHOLDERS: ReadonlySet<string> = new Set(PLACEHOLDER_SERIALS);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A trimmed, non-empty, short string — or `undefined`. Long values are dropped, not truncated. */
function label(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_IDENTITY_FIELD_CHARS) return undefined;
  return trimmed;
}

/** `label`, for an adapter's credential-store reader: a provider name is held to the same rule. */
export { label as identityLabel };

/**
 * Resolve `promise`, or `fallback` once `ms` elapses — whichever is first. The timer is unref'd so a
 * pending identity never holds a `pi -p` process open, and a rejection is the fallback too.
 */
function withDeadline<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      timer = setTimeout(() => resolve(fallback), ms);
      timer.unref?.();
    } catch {
      resolve(fallback);
      return;
    }
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(fallback);
      },
    );
  });
}

/** Call `fn` and turn a synchronous throw into a rejected promise. */
function attempt<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return fn();
  } catch (error) {
    return Promise.reject(error);
  }
}

// --- profile ---------------------------------------------------------------------------------------

export interface ProfileFetchOptions {
  /** Resolved at call time by default: pi swaps `globalThis.fetch` before extensions load. */
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Tests point this at a local server; production is always `ANTHROPIC_PROFILE_URL`. */
  url?: string;
}

/**
 * `GET /api/oauth/profile` with the OAuth token, mapped to `{email, orgId, plan}`. `undefined` on
 * any failure: non-2xx, redirect, timeout, oversized or unparseable body.
 */
export async function fetchAnthropicProfile(
  token: string,
  opts: ProfileFetchOptions = {},
): Promise<AnthropicProfile | undefined> {
  try {
    if (typeof token !== "string" || token.length === 0) return undefined;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const fetchImpl = opts.fetch ?? globalThis.fetch;
    const request = attempt(async () => {
      const res = await fetchImpl(opts.url ?? ANTHROPIC_PROFILE_URL, {
        method: "GET",
        headers: {
          authorization: `Bearer ${token}`,
          [ANTHROPIC_OAUTH_BETA_HEADER]: ANTHROPIC_OAUTH_BETA_VALUE,
          accept: "application/json",
        },
        // The token must not follow a redirect anywhere, even same-origin.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) return undefined;
      const declared = Number(res.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_PROFILE_BYTES) return undefined;
      const text = await res.text();
      if (text.length > MAX_PROFILE_BYTES) return undefined;
      return parseProfile(JSON.parse(text));
    });
    // The signal bounds undici; the race bounds anything that ignores it.
    return await withDeadline<AnthropicProfile | undefined>(request, timeoutMs, undefined);
  } catch {
    return undefined;
  }
}

function parseProfile(body: unknown): AnthropicProfile | undefined {
  if (!isRecord(body)) return undefined;
  const profile: AnthropicProfile = {};
  const account = isRecord(body.account) ? body.account : {};
  const organization = isRecord(body.organization) ? body.organization : {};
  const email = label(account.email);
  if (email !== undefined && email.includes("@")) profile.email = email;
  const orgId = label(organization.uuid);
  if (orgId !== undefined) profile.orgId = orgId;
  const plan = label(organization.organization_type);
  if (plan !== undefined) profile.plan = plan;
  return profile;
}

// --- building -------------------------------------------------------------------------------------

function emailDomain(email: string | undefined): string | undefined {
  if (email === undefined) return undefined;
  const at = email.lastIndexOf("@");
  if (at === -1) return undefined;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domain.length > 0 ? domain : undefined;
}

export interface BuildIdentityInput {
  /** What the agent's credential store says (`AgentProfile.readAuth`); `undefined` = no store. */
  auth: AgentAuthSummary | undefined;
  profile?: AnthropicProfile;
  deviceSerial?: string;
}

/**
 * The wire object, or `undefined` when there is nothing to say. No credential store means no
 * identity at all (not even a serial): there is no sign-in to describe.
 *
 * A store with a credential for the session's provider is `subscription` when that credential is an
 * Anthropic OAuth sign-in (the profile fields ride along when known) and `api_key` otherwise. A store
 * with no credential for the provider says nothing about the mode.
 */
export function buildAccountIdentity(input: BuildIdentityInput): AccountIdentity | undefined {
  try {
    if (!isRecord(input?.auth)) return undefined;
    const identity: AccountIdentity = {};
    const auth = input.auth;
    if (auth.hasCredential === true) {
      if (auth.anthropicOAuth === true) {
        identity.auth_mode = AUTH_MODE_SUBSCRIPTION;
        const profile = input.profile;
        const email = label(profile?.email);
        if (email !== undefined) {
          identity.user_email = email;
          const domain = emailDomain(email);
          if (domain !== undefined) identity.email_domain = domain;
        }
        const orgId = label(profile?.orgId);
        if (orgId !== undefined) identity.org_id = orgId;
        const plan = label(profile?.plan);
        if (plan !== undefined) identity.plan = plan;
      } else {
        identity.auth_mode = AUTH_MODE_API_KEY;
      }
    } else {
      // No credential was read: a host-reported label is all there is to say about the mode.
      const mode = label(auth.authMode);
      if (mode !== undefined) identity.auth_mode = mode;
    }
    const serial = label(input.deviceSerial);
    if (serial !== undefined && isValidSerial(serial)) identity.device_serial = serial;
    return Object.keys(identity).length > 0 ? identity : undefined;
  } catch {
    return undefined;
  }
}

// --- device serial ----------------------------------------------------------------------------------

/** Not blank and not a DMI/BIOS placeholder that would collapse many machines onto one serial. */
export function isValidSerial(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "" && !PLACEHOLDERS.has(value.trim().toLowerCase());
}

/**
 * Absolute paths for the serial probes. Bare names would be resolved through PATH — and on Windows
 * libuv searches the current directory first, which under pi is the developer's project checkout,
 * so a repo shipping `powershell.exe` would run on every session start. Same binaries and arguments
 * as `unbound.py`'s `_get_device_serial`, so the value is byte-identical across hooks.
 */
export function probeToolPath(tool: "system_profiler" | "dmidecode" | "powershell", env: NodeJS.ProcessEnv = process.env): string {
  switch (tool) {
    case "system_profiler":
      return "/usr/sbin/system_profiler";
    case "dmidecode":
      return "/usr/sbin/dmidecode";
    case "powershell": {
      const root = typeof env.SystemRoot === "string" && env.SystemRoot.trim() !== "" ? env.SystemRoot : "C:\\Windows";
      return `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    }
  }
}

/**
 * The production probe: `child_process.execFile`, killed at the deadline, stdout or nothing. `cwd` is
 * the OS temp dir so the child never inherits the project checkout as its working directory.
 */
export const defaultExecFile: ExecFileLike = (file, args, opts) =>
  new Promise<string | undefined>((resolve) => {
    try {
      nodeExecFile(
        file,
        [...args],
        { timeout: opts.timeoutMs, maxBuffer: opts.maxBytes, windowsHide: true, encoding: "utf8", cwd: tmpdir() },
        (error, stdout) => resolve(error === null && typeof stdout === "string" ? stdout : undefined),
      );
    } catch {
      resolve(undefined);
    }
  });

export interface SerialProbeOptions {
  execFile?: ExecFileLike;
  /** `process.platform` by default. */
  platform?: string;
  /** Reads a machine-id file; defaults to the non-blocking small-file reader. */
  readFile?: (path: string) => string | undefined;
  timeoutMs?: number;
}

function firstValid(stdout: string | undefined): string | undefined {
  return stdout !== undefined && isValidSerial(stdout) ? stdout.trim() : undefined;
}

async function probeSerial(opts: SerialProbeOptions, timeoutMs: number): Promise<string | undefined> {
  const run = opts.execFile ?? defaultExecFile;
  const exec = (file: string, args: readonly string[]): Promise<string | undefined> =>
    attempt(() => run(file, args, { timeoutMs, maxBytes: MAX_SERIAL_PROBE_BYTES })).catch(() => undefined);
  const platform = opts.platform ?? process.platform;

  if (platform === "darwin") {
    const out = await exec(probeToolPath("system_profiler"), ["SPHardwareDataType"]);
    for (const line of (out ?? "").split("\n")) {
      if (!line.includes("Serial Number")) continue;
      const sep = line.indexOf(": ");
      if (sep === -1) continue;
      const value = line.slice(sep + 2);
      if (isValidSerial(value)) return value.trim();
    }
    return undefined;
  }
  if (platform === "linux") {
    const dmi = firstValid(await exec(probeToolPath("dmidecode"), ["-s", "system-serial-number"]));
    if (dmi !== undefined) return dmi;
    const read = opts.readFile ?? ((path: string) => readSmallRegularFile(path, 4_096));
    for (const path of LINUX_MACHINE_ID_PATHS) {
      try {
        const value = firstValid(read(path));
        if (value !== undefined) return value;
      } catch {
        // Next candidate.
      }
    }
    return undefined;
  }
  if (platform === "win32") {
    const bios = firstValid(
      await exec(probeToolPath("powershell"), ["-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"]),
    );
    if (bios !== undefined) return bios;
    return firstValid(
      await exec(probeToolPath("powershell"), [
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid",
      ]),
    );
  }
  return undefined;
}

/** The hardware serial, or `undefined` — bounded by one deadline across every probe. */
export async function readDeviceSerial(opts: SerialProbeOptions = {}): Promise<string | undefined> {
  try {
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    return await withDeadline(attempt(() => probeSerial(opts, timeoutMs)), timeoutMs, undefined);
  } catch {
    return undefined;
  }
}

// --- the loader ---------------------------------------------------------------------------------------

export interface AccountIdentityLoaderOptions extends SerialProbeOptions {
  agentDir: string | undefined;
  /**
   * The adapter's credential-store reader (`AgentProfile.readAuth`). `undefined` from it means "no
   * store", and a throw is treated the same way.
   */
  readAuth: (agentDir: string | undefined, modelProvider: string | undefined) => AgentAuthSummary | undefined;
  fetch?: typeof fetch;
  profileUrl?: string;
  now?: () => number;
}

export interface AccountIdentityLoader {
  /**
   * Start the computation (first call only) and return its promise, which never rejects and settles
   * within the deadline. Later calls return the same promise whatever provider they name.
   */
  start(modelProvider: string | undefined): Promise<AccountIdentity | undefined>;
  /** The settled identity, or `undefined` while pending, before `start`, or when there is none. */
  current(): AccountIdentity | undefined;
}

/** One computation per loader — the extension holds one loader, so one per process. */
export function createAccountIdentityLoader(opts: AccountIdentityLoaderOptions): AccountIdentityLoader {
  let pending: Promise<AccountIdentity | undefined> | undefined;
  let settled: AccountIdentity | undefined;

  async function compute(modelProvider: string | undefined): Promise<AccountIdentity | undefined> {
    let auth: AgentAuthSummary | undefined;
    try {
      auth = opts.readAuth(opts.agentDir, modelProvider);
    } catch {
      auth = undefined;
    }
    // No credential store, no sign-in to describe: nothing is probed and nothing leaves the machine.
    if (!isRecord(auth)) return undefined;
    const now = (opts.now ?? Date.now)();
    // The token is spent only when it is an Anthropic OAuth token that has not expired. It goes to
    // `fetchAnthropicProfile` and nowhere else.
    const token =
      auth.hasCredential === true &&
      auth.anthropicOAuth === true &&
      typeof auth.accessToken === "string" &&
      auth.accessToken.length > 0 &&
      typeof auth.expiresAt === "number" &&
      auth.expiresAt > now
        ? auth.accessToken
        : undefined;
    const timeoutMs = opts.timeoutMs ?? ACCOUNT_IDENTITY_TIMEOUT_MS;
    const [profile, deviceSerial] = await Promise.all([
      token !== undefined
        ? fetchAnthropicProfile(token, {
            timeoutMs,
            ...(opts.fetch === undefined ? {} : { fetch: opts.fetch }),
            ...(opts.profileUrl === undefined ? {} : { url: opts.profileUrl }),
          })
        : Promise.resolve(undefined),
      readDeviceSerial({ ...opts, timeoutMs }),
    ]);
    return buildAccountIdentity({
      auth,
      ...(profile === undefined ? {} : { profile }),
      ...(deviceSerial === undefined ? {} : { deviceSerial }),
    });
  }

  return {
    start(modelProvider) {
      if (pending === undefined) {
        pending = attempt(() => compute(modelProvider))
          .catch(() => undefined)
          .then((identity) => {
            settled = identity;
            return identity;
          });
      }
      return pending;
    },
    current() {
      return settled;
    },
  };
}
