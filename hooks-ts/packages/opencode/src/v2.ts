// The v2 `setup` entry: ACTIVE on `@opencode/cli` 2.x (Phase 14, every 14-SPIKES.md verdict GO).
//
// Two hosts call it (13-SPIKES.md V1-2b, 14-SPIKES.md V2-1):
//
//   * opencode 1.18.x embeds the v2 core plugin host and calls `setup(ctx)` once per process, in the
//     SAME process where the v1 `server` entry is the one enforcing. Its ctx has no `tool`,
//     `permission` or `session` key. On that host this function is a pure no-op: no report, no I/O,
//     no interaction with the `server` sentinel (Phase 13 rule, unchanged).
//   * `@opencode/cli` 2.x calls `setup(ctx)` once per directory and never calls `server`. There it
//     registers the decision handlers (v2Enforce.ts: tool calls through `permission.evaluate`, native
//     approval, MCP and user shell raises, prompt replacement) and the recording handlers
//     (v2Record.ts: heartbeat with the host version, tool audit, turn log, provider-level identity),
//     and reports ONE `v2_status` per process listing what each capability does (14-CONTEXT: it
//     replaces the Phase 13 `api_family_inactive` report), plus `v2_not_enforcing` when tool calls
//     are audit-only. It returns the cleanup the host runs on location shutdown.
//
// One runtime per PROCESS (14-SPIKES V2-12): the host re-evaluates the module for every directory
// but shares `globalThis`, so the runtime lives in a `globalThis` slot keyed by the build token,
// with the server sentinel's tamper rule (13-REVIEW WR-04): only a genuine holder of THIS build is
// shared; anything else in the slot is reported as `sentinel_tampered` and this copy keeps enforcing
// on its own runtime. A directory that already has handlers registered gets nothing more (a second
// copy of the plugin, or a repeated call), reported as `duplicate_load`.
//
// Never raises, never rejects, never awaits I/O: every report is sent from a later macrotask.

import { directoryKey } from "../../core/src/sessionState.ts";
import {
  SENTINEL_KEY,
  SIGNAL_DUPLICATE_LOAD,
  SIGNAL_INIT_DEGRADED,
  SIGNAL_SENTINEL_TAMPERED,
  SIGNAL_V2_NOT_ENFORCING,
  SIGNAL_V2_STATUS,
  V2_CAPABILITIES,
} from "./constants.ts";
import type { V2Capabilities } from "./constants.ts";
import type { V2Cleanup, V2ContextLike } from "./hostTypesV2.ts";
import { BUILD_TOKEN, createRuntime } from "./plugin.ts";
import type { Deps, DirectoryRecord, RuntimeHandle } from "./plugin.ts";
import { registerV2Enforcement, v2HostClient } from "./v2Enforce.ts";
import { registerV2Recording, V2_RECORDING_GAPS, v2ProviderIdentity } from "./v2Record.ts";

/** The `globalThis` slot key of the process-wide v2 state. */
const SETUP_SENTINEL_KEY = `${SENTINEL_KEY}.v2-setup`;
/** Signal label. */
const SETUP_TOOL_LABEL = "setup";

/** The seam: the runtime's `Deps` plus the capability set (tests pick the audit-only branches). */
export type SetupDeps = Deps & {
  /** The process slot. Default `Symbol.for("unbound.opencode.v2-setup")`. */
  sentinelKey: symbol;
  /** What each capability does. Default `V2_CAPABILITIES` (the 14-SPIKES verdicts). */
  capabilities: V2Capabilities;
};

export type SetupEntry = (ctx: unknown) => Promise<V2Cleanup | undefined>;

/** The process-wide v2 state every module evaluation of this build shares. */
interface SharedV2 {
  handle: RuntimeHandle;
  capabilities: V2Capabilities;
  /** Directories whose handlers are registered (until their cleanup runs). */
  directories: Set<string>;
  statusReported: boolean;
}

/**
 * `v2_status` detail: every capability, e.g. `tools:enforce/ask:native/…/shell:enforce` (core's
 * signal tokens allow only `[A-Za-z0-9_.:/-]`, at most 100 characters; the widest set is 99).
 */
export function v2StatusDetail(capabilities: V2Capabilities): string {
  const gaps = V2_RECORDING_GAPS.length > 0 ? "." + V2_RECORDING_GAPS.join(".") : "";
  return [
    `tools:${capabilities.tools}`,
    `ask:${capabilities.ask}`,
    `mcp:${capabilities.mcp}`,
    `prompt:${capabilities.prompt}`,
    `recording:${capabilities.recording}${gaps}`,
    `identity:${capabilities.identity}`,
    `shell:${capabilities.userShell}`,
  ].join("/");
}

/** Does this ctx come from a real v2 host (not 1.18's embedded core host)? Total. */
function isV2Context(ctx: unknown): boolean {
  try {
    if (ctx === null || typeof ctx !== "object") return false;
    return ("tool" in ctx && "permission" in ctx) || "session" in ctx;
  } catch {
    return false;
  }
}

function readField(value: unknown, key: string): unknown {
  try {
    if (value === null || typeof value !== "object") return undefined;
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/** Run `fn` on a later macrotask, unref'd, with every fault swallowed. */
function later(fn: () => void): void {
  try {
    const timer = setTimeout(() => {
      try {
        fn();
      } catch {
        // A deferred report is never worth an uncaught exception.
      }
    }, 0);
    timer.unref?.();
  } catch {
    // No timer, no report.
  }
}

export function createSetupV2(overrides: Partial<SetupDeps> = {}): SetupEntry {
  const source: Partial<SetupDeps> = overrides ?? {};
  const slotKey = typeof source.sentinelKey === "symbol" ? source.sentinelKey : Symbol.for(SETUP_SENTINEL_KEY);
  const buildToken = typeof source.buildToken === "string" && source.buildToken !== "" ? source.buildToken : BUILD_TOKEN;
  const capabilities = source.capabilities ?? V2_CAPABILITIES;
  /** This copy's own state, used only when the slot holds something that is not ours to share. */
  let local: SharedV2 | undefined;

  function freshShared(): SharedV2 {
    const { capabilities: _capabilities, sentinelKey: _sentinelKey, ...deps } = source;
    // HV2-07 PROVIDER-LEVEL: the identity reader reads nothing; the provider id is the label.
    const handle = createRuntime({ ...deps, readAuth: (_dataDir, provider) => v2ProviderIdentity(provider) });
    return { handle, capabilities, directories: new Set<string>(), statusReported: false };
  }

  /** Put a frozen holder of `shared` in the slot: non-writable, non-configurable, non-enumerable. */
  function claim(shared: SharedV2): void {
    try {
      Object.defineProperty(globalThis, slotKey, {
        value: Object.freeze({ module: SETUP_SENTINEL_KEY, build: buildToken, shared }),
        writable: false,
        configurable: false,
        enumerable: false,
      });
    } catch {
      // The slot could not be taken: this copy runs on its own state.
    }
  }

  /** The process state to use, and why the slot was not shared when it was not. Getters never run. */
  function acquire(): { shared: SharedV2; tampered?: string } {
    let foreign: string;
    let configurable = false;
    try {
      const desc = Object.getOwnPropertyDescriptor(globalThis, slotKey);
      if (desc === undefined) {
        const shared = freshShared();
        claim(shared);
        return { shared };
      }
      configurable = desc.configurable === true;
      if (!("value" in desc)) {
        foreign = "accessor";
      } else {
        const holder: unknown = desc.value;
        const own = (key: string): unknown => {
          const d = holder !== null && typeof holder === "object" ? Object.getOwnPropertyDescriptor(holder, key) : undefined;
          return d !== undefined && "value" in d ? d.value : undefined;
        };
        const shared = own("shared") as SharedV2 | undefined;
        if (holder === null || typeof holder !== "object" || own("module") !== SETUP_SENTINEL_KEY) {
          foreign = "foreign_value";
        } else if (own("build") !== buildToken) {
          foreign = "other_build";
        } else if (desc.writable !== false || desc.configurable !== false || !Object.isFrozen(holder)) {
          foreign = "forged_holder";
        } else if (shared === undefined || shared === null || typeof shared !== "object" || !(shared.directories instanceof Set)) {
          foreign = "forged_holder";
        } else {
          return { shared };
        }
      }
    } catch {
      foreign = "unreadable";
    }
    if (local === undefined) local = freshShared();
    if (configurable) claim(local);
    return { shared: local, tampered: foreign };
  }

  /** One `v2_status` (and `v2_not_enforcing` when tool calls are audit-only) per process. */
  function reportStatus(shared: SharedV2): void {
    if (shared.statusReported) return;
    shared.statusReported = true;
    const runtime = shared.handle.runtime;
    const detail = v2StatusDetail(shared.capabilities);
    later(() => {
      runtime.reportOnce(SIGNAL_V2_STATUS, SETUP_TOOL_LABEL, detail);
      if (shared.capabilities.tools === "audit") runtime.reportOnce(SIGNAL_V2_NOT_ENFORCING, SETUP_TOOL_LABEL, "tools");
    });
  }

  return (ctx: unknown): Promise<V2Cleanup | undefined> => {
    try {
      if (!isV2Context(ctx)) return Promise.resolve(undefined);
      const { shared, tampered } = acquire();
      const handle = shared.handle;
      const runtime = handle.runtime;
      if (tampered !== undefined) later(() => runtime.reportOnce(SIGNAL_SENTINEL_TAMPERED, SETUP_TOOL_LABEL, tampered));

      const v2 = ctx as V2ContextLike;
      const rawDirectory = readField(readField(v2, "location"), "directory");
      const directory = typeof rawDirectory === "string" ? rawDirectory : "";
      const key = directoryKey(directory) ?? "";
      if (shared.directories.has(key)) {
        later(() => runtime.reportOnce(SIGNAL_DUPLICATE_LOAD, SETUP_TOOL_LABEL, "second_copy"));
        return Promise.resolve(undefined);
      }
      shared.directories.add(key);
      reportStatus(shared);

      let stopRecording: (() => void) | undefined;
      try {
        const client = v2HostClient(v2, directory);
        // MCP server names are not known at setup (`ctx.mcp.list()` is empty before servers
        // connect, 14-SPIKES V2-3): the decision side reads the live list when it needs it.
        handle.recordFor(directory, client, []);
        const recordFor = (dir: string): DirectoryRecord => handle.recordFor(dir, client);
        const registered = registerV2Enforcement(v2, runtime, recordFor, shared.capabilities);
        stopRecording = registered ? registerV2Recording(v2, runtime, recordFor) : undefined;
        if (stopRecording === undefined) {
          later(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, SETUP_TOOL_LABEL, "registration_fault"));
        }
      } catch {
        later(() => runtime.reportOnce(SIGNAL_INIT_DEGRADED, SETUP_TOOL_LABEL, "registration_fault"));
      }

      // Location shutdown: stop recording and free the directory; a pending turn is never posted
      // from here.
      const cleanup = async (): Promise<void> => {
        try {
          stopRecording?.();
          shared.directories.delete(key);
          runtime.instances.release(directory);
          handle.releaseRecord(directory);
        } catch {
          // Nothing to release.
        }
      };
      return Promise.resolve(cleanup);
    } catch {
      return Promise.resolve(undefined);
    }
  };
}

/** The production entry. */
export const setupV2: SetupEntry = createSetupV2();
