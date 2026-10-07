// The third pi wire oracle: origin/staging's own shipped pi.
//
// The two frozen goldens describe pi BEFORE the core was generalised. While the refactor was in
// flight, staging changed pi's wire output on purpose (the turn prompt on tool calls and the
// standalone !cmd turn log, be6fa19; tool output in the turn log, c3cf7da). When the branch was
// merged with staging, "pi unchanged" therefore came to mean "pi equals staging's pi" — so this
// golden is captured from staging's COMMITTED `pi/index.js`, not from the branch, and every scenario
// (both tables) is replayed against it from the source entry and the committed artifact.
//
// The frozen goldens are not regenerated. The scenarios staging changed skip their frozen comparison
// (`SUPERSEDED_BY_STAGING`), and the test below proves that list is EXACTLY the set of scenarios
// where a frozen golden and this one disagree — so a name cannot be added to hide a regression.
//
// Written only under `UNBOUND_WRITE_STAGING_GOLDEN=1`, from `git show <STAGING_GOLDEN_BASE>:pi/index.js`.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { describe, test } from "node:test";

import {
  ARTIFACT_ENTRY,
  EXTRA_GOLDEN_PATH,
  EXTRA_SCENARIO_NAMES,
  GOLDEN_PATH,
  SCENARIO_NAMES,
  SOURCE_ENTRY,
  STAGING_GOLDEN_BASE,
  STAGING_GOLDEN_PATH,
  SUPERSEDED_BY_STAGING,
  WORKSPACE_ROOT,
  runScenario,
} from "./helpers/wireScenario.ts";
import type { Transcript } from "./helpers/wireScenario.ts";

interface StagingGolden {
  /** `<sha>:pi/index.js` — the staging artifact the transcripts were captured from. */
  captured_from: string;
  artifact_sha256: string;
  scenarios: Record<string, Transcript>;
}

const CAPTURE_COMMAND =
  "UNBOUND_WRITE_STAGING_GOLDEN=1 node --test --experimental-strip-types packages/pi/test/equivalenceStaging.test.ts";
const WRITE_STAGING_GOLDEN = process.env.UNBOUND_WRITE_STAGING_GOLDEN === "1";
const CONCURRENCY = 8;
const ALL_NAMES: readonly string[] = [...SCENARIO_NAMES, ...EXTRA_SCENARIO_NAMES];

let cachedGolden: StagingGolden | undefined;

function loadGolden(): StagingGolden {
  if (cachedGolden === undefined) {
    assert.ok(
      existsSync(STAGING_GOLDEN_PATH),
      `missing golden ${STAGING_GOLDEN_PATH} — it is captured once, from ${STAGING_GOLDEN_BASE}:pi/index.js, with: ${CAPTURE_COMMAND}`,
    );
    cachedGolden = JSON.parse(readFileSync(STAGING_GOLDEN_PATH, "utf8")) as StagingGolden;
  }
  return cachedGolden;
}

function expectedFor(name: string): Transcript {
  const expected = loadGolden().scenarios[name];
  assert.ok(expected !== undefined, `the staging golden has no scenario "${name}"`);
  return expected;
}

if (WRITE_STAGING_GOLDEN) {
  test(`capture the staging pi wire golden from ${STAGING_GOLDEN_BASE}:pi/index.js (UNBOUND_WRITE_STAGING_GOLDEN=1)`, async () => {
    const bytes = execFileSync("git", ["show", `${STAGING_GOLDEN_BASE}:pi/index.js`], { cwd: WORKSPACE_ROOT });
    const dir = mkdtempSync(join(tmpdir(), "pi-staging-artifact-"));
    try {
      const entry = join(dir, "index.mjs");
      writeFileSync(entry, bytes);
      const scenarios: Record<string, Transcript> = {};
      for (const name of ALL_NAMES) {
        // Twice, so a field that differs between two runs of the SAME code is caught at capture time.
        const first = await runScenario(entry, name as never);
        const second = await runScenario(entry, name as never);
        assert.deepStrictEqual(second, first, `${name}: two captures of the staging artifact differ`);
        scenarios[name] = first;
      }
      const golden: StagingGolden = {
        captured_from: `${STAGING_GOLDEN_BASE}:pi/index.js`,
        artifact_sha256: createHash("sha256").update(bytes).digest("hex"),
        scenarios,
      };
      mkdirSync(dirname(STAGING_GOLDEN_PATH), { recursive: true });
      writeFileSync(STAGING_GOLDEN_PATH, `${JSON.stringify(golden, null, 2)}\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
} else {
  describe("pi wire equivalence against origin/staging's shipped pi", { concurrency: CONCURRENCY }, () => {
    test("the staging golden covers both scenario tables and names its source", () => {
      const golden = loadGolden();
      assert.deepStrictEqual(Object.keys(golden.scenarios).sort(), [...ALL_NAMES].sort());
      assert.equal(golden.captured_from, `${STAGING_GOLDEN_BASE}:pi/index.js`);
      assert.match(golden.artifact_sha256, /^[0-9a-f]{64}$/);
    });

    test("SUPERSEDED_BY_STAGING is exactly the set where a frozen golden and the staging golden differ", () => {
      const staging = loadGolden().scenarios;
      const base = (JSON.parse(readFileSync(GOLDEN_PATH, "utf8")) as { scenarios: Record<string, Transcript> }).scenarios;
      const extra = (JSON.parse(readFileSync(EXTRA_GOLDEN_PATH, "utf8")) as { scenarios: Record<string, Transcript> })
        .scenarios;
      const differing = ALL_NAMES.filter((name) => !isDeepStrictEqual(base[name] ?? extra[name], staging[name]));
      assert.deepStrictEqual([...differing].sort(), Object.keys(SUPERSEDED_BY_STAGING).sort());
    });

    for (const name of ALL_NAMES) {
      test(`${name}: source entry matches the staging golden`, async () => {
        assert.deepStrictEqual(await runScenario(SOURCE_ENTRY, name as never), expectedFor(name));
      });

      test(`${name}: committed artifact pi/index.js matches the staging golden`, async () => {
        assert.deepStrictEqual(await runScenario(ARTIFACT_ENTRY, name as never), expectedFor(name));
      });
    }
  });
}
