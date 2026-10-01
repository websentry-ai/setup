// CORE-02's oracle, second golden (review WR-05): the paths the first scenario table cannot see.
//
//   * the agent-dir relocation variable (`PI_CODING_AGENT_DIR`, absolute and `~/` forms) — the cache
//     and `auth.json` follow it;
//   * a policy cache already on disk: a matching, fresh `[]` list is still pulled (WR-02), a hydrated
//     `block` applies from the first call, a foreign-identity cache is ignored;
//   * stderr: the headless mirror of every notice.
//
// `fixtures/pi-wire-golden-extra.json` was captured from the PRE-refactor ARTIFACT — the `pi/index.js`
// committed at `EXTRA_GOLDEN_BASE`, the same commit the first golden names — run through this same
// harness. It is then asserted against the current source entry and the current committed artifact,
// exactly like the first golden. The first golden (`pi-wire-golden.json`) is not read or written here.
//
// **Frozen like the first.** Written only under `UNBOUND_WRITE_EXTRA_GOLDEN=1`, and always from the
// old artifact (extracted with `git show`), never from the code under test — so re-capturing cannot
// make a current regression pass.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";

import {
  ARTIFACT_ENTRY,
  EXTRA_GOLDEN_BASE,
  EXTRA_GOLDEN_PATH,
  EXTRA_SCENARIOS,
  EXTRA_SCENARIO_NAMES,
  SCENARIO_NAMES,
  SOURCE_ENTRY,
  WORKSPACE_ROOT,
  runScenario,
} from "./helpers/wireScenario.ts";
import type { Transcript } from "./helpers/wireScenario.ts";

interface ExtraGolden {
  /** `<sha>:pi/index.js` — the artifact the transcripts were captured from. */
  captured_from: string;
  /** sha256 of that artifact's bytes, so the capture source is pinned by content too. */
  artifact_sha256: string;
  scenarios: Record<string, Transcript>;
}

const CAPTURE_COMMAND =
  "UNBOUND_WRITE_EXTRA_GOLDEN=1 node --test --experimental-strip-types packages/pi/test/equivalenceExtra.test.ts";
const WRITE_EXTRA_GOLDEN = process.env.UNBOUND_WRITE_EXTRA_GOLDEN === "1";
const CONCURRENCY = 8;

let cachedGolden: ExtraGolden | undefined;

function loadGolden(): ExtraGolden {
  if (cachedGolden === undefined) {
    assert.ok(
      existsSync(EXTRA_GOLDEN_PATH),
      `missing golden ${EXTRA_GOLDEN_PATH} — it is captured once, from the ${EXTRA_GOLDEN_BASE} artifact, with: ${CAPTURE_COMMAND}`,
    );
    cachedGolden = JSON.parse(readFileSync(EXTRA_GOLDEN_PATH, "utf8")) as ExtraGolden;
  }
  return cachedGolden;
}

function expectedFor(name: string): Transcript {
  const expected = loadGolden().scenarios[name];
  assert.ok(expected !== undefined, `the extra golden has no scenario "${name}"`);
  return expected;
}

if (WRITE_EXTRA_GOLDEN) {
  test(`capture the extra pi wire golden from the ${EXTRA_GOLDEN_BASE} artifact (UNBOUND_WRITE_EXTRA_GOLDEN=1)`, async () => {
    const bytes = execFileSync("git", ["show", `${EXTRA_GOLDEN_BASE}:pi/index.js`], { cwd: WORKSPACE_ROOT });
    const dir = mkdtempSync(join(tmpdir(), "pi-old-artifact-"));
    try {
      const oldEntry = join(dir, "index.mjs");
      writeFileSync(oldEntry, bytes);
      const scenarios: Record<string, Transcript> = {};
      for (const name of EXTRA_SCENARIO_NAMES) {
        // Twice, so a field that differs between two runs of the SAME code is caught here, at capture
        // time, rather than frozen into the golden as a value no later run can reproduce.
        const [first, second] = await Promise.all([runScenario(oldEntry, name), runScenario(oldEntry, name)]);
        assert.deepStrictEqual(second, first, `${name}: two captures of the old artifact differ`);
        scenarios[name] = first;
      }
      const { createHash } = await import("node:crypto");
      const golden: ExtraGolden = {
        captured_from: `${EXTRA_GOLDEN_BASE}:pi/index.js`,
        artifact_sha256: createHash("sha256").update(bytes).digest("hex"),
        scenarios,
      };
      mkdirSync(dirname(EXTRA_GOLDEN_PATH), { recursive: true });
      writeFileSync(EXTRA_GOLDEN_PATH, `${JSON.stringify(golden, null, 2)}\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
} else {
  describe("pi wire equivalence against the extra golden (captured from the pre-refactor artifact)", { concurrency: CONCURRENCY }, () => {
    test("the extra golden covers exactly the extra scenario table, and names its source", () => {
      const golden = loadGolden();
      assert.deepStrictEqual(Object.keys(golden.scenarios).sort(), [...EXTRA_SCENARIO_NAMES].sort());
      assert.equal(golden.captured_from, `${EXTRA_GOLDEN_BASE}:pi/index.js`);
      assert.match(golden.artifact_sha256, /^[0-9a-f]{64}$/);
    });

    test("the two scenario tables share no name", () => {
      for (const name of EXTRA_SCENARIO_NAMES) {
        assert.equal((SCENARIO_NAMES as readonly string[]).includes(name), false, name);
      }
    });

    test("the extra scenarios actually exercise what they are for", () => {
      const golden = loadGolden();
      // A golden whose scenarios silently stopped reaching their path would pass forever.
      const absolute = JSON.stringify(golden.scenarios["agent-dir-env-absolute"]?.files_written);
      assert.match(absolute, /<ROOT>\/home\/alt-agent\/\.unbound\/policy_cache\.json/);
      const tilde = JSON.stringify(golden.scenarios["agent-dir-env-tilde"]?.files_written);
      assert.match(tilde, /<ROOT>\/home\/tilde-agent\/\.unbound\/policy_cache\.json/);
      const pulled = golden.scenarios["hydrated-cache-pulls"]?.steps[0]?.requests[0]?.body as { pull_policies?: unknown };
      assert.equal(pulled?.pull_policies, true, "a hydrated-only list is pulled, never trusted");
      const stderr = golden.scenarios["headless-stderr"]?.steps.flatMap((step) => step.stderr ?? []) ?? [];
      assert.ok(stderr.length > 0, "the headless scenario recorded stderr");
      assert.ok(Object.keys(EXTRA_SCENARIOS).length === EXTRA_SCENARIO_NAMES.length);
    });

    for (const name of EXTRA_SCENARIO_NAMES) {
      test(`${name}: source entry matches the extra golden`, async () => {
        assert.deepStrictEqual(await runScenario(SOURCE_ENTRY, name), expectedFor(name));
      });

      test(`${name}: committed artifact pi/index.js matches the extra golden`, async () => {
        assert.deepStrictEqual(await runScenario(ARTIFACT_ENTRY, name), expectedFor(name));
      });
    }
  });
}
