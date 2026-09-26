// Temp HOME fixture mirroring the production posture of `~/.unbound`: the directory is 0700 and
// `config.json` is 0600 (what `unbound login` writes). Core's config module takes `homeDir` as an
// explicit parameter, so no test ever mutates `process.env.HOME`.

import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface FakeHome {
  /** Pass this to core's config resolver; nothing global is touched. */
  homeDir: string;
  cleanup(): void;
}

/**
 * @param config an object (JSON-stringified) or a raw string written verbatim, so a test can
 *               install a deliberately malformed `config.json`. Omit it for a HOME with a
 *               `.unbound` directory but no config file.
 */
export function createFakeHome(config?: Record<string, unknown> | string): FakeHome {
  const homeDir = mkdtempSync(join(tmpdir(), "unbound-home-"));
  const unboundDir = join(homeDir, ".unbound");
  mkdirSync(unboundDir, { mode: 0o700 });
  // mkdir/writeFile modes are masked by umask; chmod pins the exact bits the assertions check.
  chmodSync(unboundDir, 0o700);

  if (config !== undefined) {
    const contents = typeof config === "string" ? config : JSON.stringify(config, null, 2);
    const configFile = join(unboundDir, "config.json");
    writeFileSync(configFile, contents, { mode: 0o600 });
    chmodSync(configFile, 0o600);
  }

  return {
    homeDir,
    cleanup() {
      rmSync(homeDir, { recursive: true, force: true });
    },
  };
}
