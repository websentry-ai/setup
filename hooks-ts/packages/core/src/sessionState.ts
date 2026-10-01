// Per-session and per-directory state for a host that runs many of each in one process (CORE-04).
//
// pi is one session in one process, so its turn record, heartbeat gate and notice latch are
// module-scope singletons, and they stay that way: nothing in this file is used by pi. A host that
// keeps many sessions and many project directories alive in ONE long-lived process needs the same
// three things looked up by key, or they bleed:
//
//   * the turn record, by SESSION id — otherwise one session's prompt and commands ride another
//     session's turn-log row, and whichever session finishes first takes the other's record;
//   * the heartbeat gate and the no-key notice latch, by DIRECTORY — otherwise the first project to
//     announce itself silences every other project's heartbeat and "no key" notice.
//
// Both registries are built on `createKeyedState`, so both are LRU-bounded and total, and an id or
// directory that cannot be used gets a private throwaway state rather than a shared one.
//
// **Dropped state is never posted.** `release` (the host says the session ended), eviction by the
// bound, and `clear` all discard the pending turn record without sending it. This is the same rule
// `turn.ts` applies on a session change: a turn that nothing reported as finished is not posted,
// because posting it would attribute a half-recorded turn. A finished turn is posted by the adapter
// from `turn.take()` BEFORE it releases the session.
//
// There is no module-scope instance here, deliberately. Each adapter creates its registries and
// owns them; a shared one at module scope would be the very bleed this file removes.

import { isAbsolute, resolve } from "node:path";

import { CACHE_TTL_MS, MAX_TRACKED_INSTANCES, MAX_TRACKED_SESSIONS } from "./constants.ts";
import { createHeartbeatGate, type HeartbeatGate } from "./heartbeat.ts";
import { createKeyedState } from "./keyedState.ts";
import { createTurnStore, type TurnStore } from "./turn.ts";

// --- sessions ----------------------------------------------------------------------------------

export interface SessionState {
  /** The session this state belongs to; `""` for the throwaway state of an unusable id. */
  readonly sessionId: string;
  /** This session's own turn record. */
  readonly turn: TurnStore;
}

export interface SessionStates {
  /** The state for a session id, created on first use. An unusable id gets an unstored state. */
  forSession(id: unknown): SessionState;
  /** Drop a session's state when the host reports it ended. Its pending turn is NOT posted. */
  release(id: unknown): void;
  clear(): void;
  size(): number;
}

export function createSessionStates(opts: { max?: number } = {}): SessionStates {
  const states = createKeyedState<SessionState>({
    max: opts?.max ?? MAX_TRACKED_SESSIONS,
    create: (id) => ({ sessionId: id, turn: createTurnStore() }),
    fallback: () => ({ sessionId: "", turn: createTurnStore() }),
  });

  return {
    forSession: (id) => states.get(id),
    release: (id) => states.release(id),
    clear: () => states.clear(),
    size: () => states.size(),
  };
}

// --- instances (project directories) -----------------------------------------------------------

/**
 * The canonical key for a project directory, or `undefined` when it cannot be one.
 *
 * Only an absolute path is a key. A relative path means different directories depending on the
 * process's working directory, so two projects could collapse onto one entry; it is refused rather
 * than resolved. `resolve` removes `.`/`..` segments, repeated separators and any trailing separator
 * (the root keeps its own), so `/a`, `/a/` and `/a/b/..` are one key. No filesystem access: a
 * symlink and its target are two keys, which costs at most one extra heartbeat.
 */
export function directoryKey(dir: unknown): string | undefined {
  try {
    if (typeof dir !== "string" || dir === "" || !isAbsolute(dir)) return undefined;
    const key = resolve(dir);
    return key === "" ? undefined : key;
  } catch {
    return undefined;
  }
}

export interface InstanceState {
  /** The canonical directory; `""` for the throwaway state of an unusable directory. */
  readonly directory: string;
  /** One heartbeat per TTL window for THIS directory. */
  readonly heartbeatGate: HeartbeatGate;
  /** Set by the adapter once the "no API key" notice has been shown for this directory. */
  noKeyNoticeShown: boolean;
}

export interface InstanceStates {
  /**
   * The state for a directory, created on first use. An unusable directory gets an unstored state,
   * whose gate and latch therefore never remember anything — a caller that needs "once" must hand
   * in an absolute directory.
   */
  forDirectory(dir: unknown): InstanceState;
  release(dir: unknown): void;
  clear(): void;
  size(): number;
}

export function createInstanceStates(
  opts: { max?: number; now?: () => number; ttlMs?: number } = {},
): InstanceStates {
  const now = typeof opts?.now === "function" ? opts.now : Date.now;
  const ttlMs = typeof opts?.ttlMs === "number" && opts.ttlMs > 0 ? opts.ttlMs : CACHE_TTL_MS;

  const fresh = (directory: string): InstanceState => ({
    directory,
    heartbeatGate: createHeartbeatGate({ now, ttlMs }),
    noKeyNoticeShown: false,
  });

  const states = createKeyedState<InstanceState>({
    max: opts?.max ?? MAX_TRACKED_INSTANCES,
    normalizeKey: directoryKey,
    create: fresh,
    fallback: () => fresh(""),
  });

  return {
    forDirectory: (dir) => states.get(dir),
    release: (dir) => states.release(dir),
    clear: () => states.clear(),
    size: () => states.size(),
  };
}
