// The one way this extension is allowed to read a file (CR-01).
//
// `readFileSync` inside a try/catch is not total. A try/catch intercepts *errors*; it cannot
// intercept a **blocking** syscall, and two ordinary things on a developer's machine block one
// forever:
//
//   * a **named pipe** with no writer — `open`/`read` block indefinitely, never return, never throw.
//     Both of this extension's reads sit on paths an attacker can choose: `resolveCachePath` honours
//     the agent's own relocation variable and both readers resolve `$HOME` (`keyState.ts` names a hostile repo's
//     `.envrc` under direnv as a realistic way to set either). Point one at a directory holding a
//     FIFO named `policy_cache.json` and pi wedges on the first statement of its first handler —
//     `init()` runs there, and pi awaits both `session_start` and `prepareToolCall`. Quieter and
//     harder to diagnose than unsetting the key.
//   * a `$HOME` on a **hung or stale NFS/SMB mount** — no attacker at all, just an enterprise
//     networked-home outage, blocking every session start for minutes.
//
// So: `lstat` first, and open only a small regular file.
//
//   * `lstat`, not `stat`, on purpose. `lstat` reports the **link**, so a symlink is refused rather
//     than followed — otherwise a symlink to a FIFO passes an `isFile()` check on the target and
//     blocks anyway. Neither file is ever legitimately a link: `unbound login` writes a real
//     `config.json` and `writeCache` writes a real file via temp+rename.
//   * `lstat` does not block on a FIFO; it reads the inode, not the pipe.
//   * a size cap, so the read is bounded as well as non-blocking (WR-01).
//
// The residual TOCTOU — a regular file swapped for a FIFO between the `lstat` and the `read` — is
// accepted. Closing it needs `open(O_NONBLOCK)` + `fstat` + a streaming read off a raw fd, which is
// materially more code on the path pi awaits, and the race requires an attacker who already has write
// access to the directory and can hit a microsecond window. The `lstat` removes the durable,
// plant-once-and-wait version of the attack, which is the one that is actually reachable.
//
// Total by construction: one try/catch, `undefined` for every failure, no `throw` anywhere. A file
// that cannot be read is a cache miss (one round trip) or an absent config (an inert extension) —
// never a broken tool call.

import { lstatSync, readFileSync } from "node:fs";

/**
 * The contents of `path`, or `undefined` when it is not a regular file of at most `maxBytes`.
 *
 * `undefined` deliberately conflates "refused" with "absent" and "unreadable": every caller's answer
 * to all three is the same, and a distinction no caller acts on is a distinction that only invites a
 * future reader to act on it.
 */
export function readSmallRegularFile(path: string, maxBytes: number): string | undefined {
  try {
    if (typeof path !== "string" || path === "") return undefined;
    const stats = lstatSync(path);
    // A FIFO, socket, device, directory or symlink is not a config file or a cache file.
    if (!stats.isFile()) return undefined;
    const size = stats.size;
    if (typeof size !== "number" || !Number.isFinite(size) || size > maxBytes) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}
