// A keyed, bounded, total registry — the building block for per-session, per-directory and
// per-gateway state (CORE-04).
//
// Why it exists: pi runs one session in one process, so its state can be a module-scope singleton.
// A host that runs many sessions and many project directories in ONE long-lived process cannot do
// that — one session's turn record would ride another session's log row, and one project's heartbeat
// gate would silence another's. State for such a host has to be looked up by key. This module is the
// lookup; `sessionState.ts` and `breakerRegistry.ts` decide what the keys and values are.
//
// Three properties are load-bearing:
//
//   1. **Bounded.** At most `max` entries. Inserting one more evicts the least-recently-USED key (a
//      `get` counts as use, a `peek` does not). A desktop process that stays up for a week and opens
//      thousands of sessions therefore holds a fixed amount of state, with or without `release`.
//   2. **Invalid keys are never stored.** A key the registry cannot normalise — empty, not a string,
//      or refused by `normalizeKey` — gets a fresh `fallback()` value on every call. It is usable, so
//      the caller's code path is the same, but it is private to that one call: two callers that both
//      failed to produce a key must not end up sharing state through a common "unknown" entry.
//   3. **Total.** Every method catches everything. The registry is reached from handlers where an
//      exception changes a verdict, and the functions it is given (`create`, `normalizeKey`,
//      `onEvict`) are the caller's, so none of them is trusted not to fault. A faulting `create`
//      yields the fallback (unstored); a faulting `onEvict` is swallowed and the entry is still gone.
//
// `fallback` is the one function that has to be dependable: it is what `get` answers with when
// nothing else worked. If it faults as well there is no value of type V left to give, and `get`
// answers `undefined` rather than raising — so keep `fallback` to a plain constructor call.
//
// No I/O, no timers, no module-scope state: each caller owns the registries it creates. A registry
// at module scope would be exactly the cross-session bleed this file exists to remove.

export interface KeyedState<V> {
  /** The value for `key`, created on first use. An invalid key gets an unstored fallback value. */
  get(key: unknown): V;
  /** The stored value, or `undefined`. Creates nothing and does not count as use. */
  peek(key: unknown): V | undefined;
  /** Drop `key` (and report it to `onEvict`). Unknown and invalid keys are a no-op. */
  release(key: unknown): void;
  /** Drop everything, reporting each entry to `onEvict`. */
  clear(): void;
  size(): number;
  /** The stored keys, least-recently-used first. */
  keys(): string[];
}

export interface KeyedStateOptions<V> {
  /** Capacity. Anything that is not a finite number of at least 1 is treated as 1. */
  max: number;
  /** Builds the value for a key seen for the first time. Handed the NORMALISED key. */
  create(key: string): V;
  /** Builds the unstored value answered for an invalid key or a faulting `create`. */
  fallback(): V;
  /**
   * Maps a raw key to its canonical string, or `undefined` to refuse it. Two raw keys that map to
   * the same string are the same entry. Default: a non-empty string, as it is.
   */
  normalizeKey?(key: unknown): string | undefined;
  /** Called once for every entry that leaves: evicted by the bound, released, or cleared. */
  onEvict?(key: string, value: V): void;
}

function clampMax(max: unknown): number {
  if (typeof max !== "number" || !Number.isFinite(max) || max < 1) return 1;
  return Math.floor(max);
}

export function createKeyedState<V>(opts: KeyedStateOptions<V>): KeyedState<V> {
  // A Map iterates in insertion order, so "delete then set" on every use keeps the first key the
  // least recently used one.
  const entries = new Map<string, V>();
  const max = clampMax(opts?.max);
  /**
   * Non-zero while an `onEvict` callback is running. A callback that looks a key up again would
   * otherwise re-insert it, evict the next entry, and recurse through the whole registry.
   */
  let evicting = 0;

  function keyOf(raw: unknown): string | undefined {
    try {
      const normalize = opts?.normalizeKey;
      const key = typeof normalize === "function" ? normalize(raw) : raw;
      return typeof key === "string" && key !== "" ? key : undefined;
    } catch {
      return undefined;
    }
  }

  function fallbackValue(): V {
    try {
      return opts.fallback();
    } catch {
      // See the header: there is no V left to give.
      return undefined as V;
    }
  }

  function report(key: string, value: V): void {
    evicting += 1;
    try {
      opts?.onEvict?.(key, value);
    } catch {
      // The entry is already gone; a faulting observer must not undo that or reach the caller.
    } finally {
      evicting -= 1;
    }
  }

  function enforceBound(): void {
    while (entries.size > max) {
      const oldest = entries.keys().next();
      if (oldest.done === true) return;
      const value = entries.get(oldest.value) as V;
      entries.delete(oldest.value);
      report(oldest.value, value);
    }
  }

  return {
    get(raw: unknown): V {
      try {
        const key = keyOf(raw);
        if (key === undefined) return fallbackValue();

        if (entries.has(key)) {
          const existing = entries.get(key) as V;
          entries.delete(key);
          entries.set(key, existing);
          return existing;
        }
        // Inside an eviction callback nothing new is stored (see `evicting`).
        if (evicting > 0) return fallbackValue();

        let created: V;
        try {
          created = opts.create(key);
        } catch {
          return fallbackValue();
        }
        entries.set(key, created);
        enforceBound();
        return created;
      } catch {
        return fallbackValue();
      }
    },

    peek(raw: unknown): V | undefined {
      try {
        const key = keyOf(raw);
        return key === undefined ? undefined : entries.get(key);
      } catch {
        return undefined;
      }
    },

    release(raw: unknown): void {
      try {
        const key = keyOf(raw);
        if (key === undefined || !entries.has(key)) return;
        const value = entries.get(key) as V;
        entries.delete(key);
        report(key, value);
      } catch {
        // Total by contract — see the header.
      }
    },

    clear(): void {
      try {
        const leaving = [...entries];
        entries.clear();
        for (const [key, value] of leaving) report(key, value);
      } catch {
        // Total by contract — see the header.
      }
    },

    size(): number {
      return entries.size;
    },

    keys(): string[] {
      try {
        return [...entries.keys()];
      } catch {
        return [];
      }
    },
  };
}
