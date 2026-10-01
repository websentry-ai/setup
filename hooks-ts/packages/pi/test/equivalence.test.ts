// CORE-02's oracle: "pi unchanged" as a wire-level fact rather than a claim.
//
// `fixtures/pi-wire-golden.json` records, for a fixed set of scenarios, every HTTP request the pi
// extension sends (method, path, auth header, JSON body), every handler return value, every notice
// and confirm, and every file it writes — captured from the code as it stood BEFORE the core was
// generalised (`captured_from` names that commit). This file replays the same scenarios against
//
//   * the SOURCE entry (`packages/pi/src/index.ts`), and
//   * the COMMITTED artifact (`pi/index.js`, the file users actually install),
//
// and fails on any difference. A refactor that moves a literal, drops a field, reorders two POSTs or
// relocates the cache shows up here as a diff against a file nobody is allowed to regenerate.
//
// **The golden is frozen.** It is written only when `UNBOUND_WRITE_GOLDEN=1` is set, which was done
// exactly once. Re-capturing it to make a failing comparison pass is the one thing this test exists
// to prevent: if a wire change is intended, it is a product decision and belongs in its own commit
// with its own justification — not in a refactor.
//
// Each scenario runs in its own child process (see `helpers/wireScenario.ts` for why), so this file
// neither depends on nor disturbs the module-scope state the rest of the suite shares.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { describe, test } from "node:test";

import {
  ARTIFACT_ENTRY,
  GOLDEN_PATH,
  SCENARIO_NAMES,
  SOURCE_ENTRY,
  WORKSPACE_ROOT,
  runScenario,
} from "./helpers/wireScenario.ts";
import type { Transcript } from "./helpers/wireScenario.ts";

interface Golden {
  /** The git sha the transcripts were captured from — the pre-refactor code. */
  captured_from: string;
  scenarios: Record<string, Transcript>;
}

const CAPTURE_COMMAND =
  "UNBOUND_WRITE_GOLDEN=1 node --test --experimental-strip-types packages/pi/test/equivalence.test.ts";
const WRITE_GOLDEN = process.env.UNBOUND_WRITE_GOLDEN === "1";
/** Each scenario is its own process, so they are safe to overlap; this only bounds the fan-out. */
const CONCURRENCY = 8;

let cachedGolden: Golden | undefined;

function loadGolden(): Golden {
  if (cachedGolden === undefined) {
    assert.ok(
      existsSync(GOLDEN_PATH),
      `missing golden ${GOLDEN_PATH} — it is captured once, from pre-refactor code, with: ${CAPTURE_COMMAND}`,
    );
    cachedGolden = JSON.parse(readFileSync(GOLDEN_PATH, "utf8")) as Golden;
  }
  return cachedGolden;
}

function expectedFor(name: string): Transcript {
  const expected = loadGolden().scenarios[name];
  assert.ok(expected !== undefined, `the golden has no scenario "${name}" — the scenario table and the golden disagree`);
  return expected;
}

if (WRITE_GOLDEN) {
  test("capture the pi wire golden (UNBOUND_WRITE_GOLDEN=1)", async () => {
    const captured_from = execFileSync("git", ["rev-parse", "HEAD"], { cwd: WORKSPACE_ROOT, encoding: "utf8" }).trim();
    const scenarios: Record<string, Transcript> = {};
    for (const name of SCENARIO_NAMES) {
      const [fromSource, fromArtifact] = await Promise.all([
        runScenario(SOURCE_ENTRY, name),
        runScenario(ARTIFACT_ENTRY, name),
      ]);
      // A golden the committed artifact does not also produce would freeze a difference that already
      // exists, and every later comparison would be measuring against the wrong thing.
      assert.deepStrictEqual(fromArtifact, fromSource, `${name}: source and committed artifact already differ`);
      scenarios[name] = fromSource;
    }
    const golden: Golden = { captured_from, scenarios };
    mkdirSync(dirname(GOLDEN_PATH), { recursive: true });
    writeFileSync(GOLDEN_PATH, `${JSON.stringify(golden, null, 2)}\n`);
  });
} else {
  describe("pi wire equivalence against the frozen golden", { concurrency: CONCURRENCY }, () => {
    test("the golden covers exactly the scenario table", () => {
      assert.deepStrictEqual(Object.keys(loadGolden().scenarios).sort(), [...SCENARIO_NAMES].sort());
    });

    for (const name of SCENARIO_NAMES) {
      test(`${name}: source entry matches the golden`, async () => {
        const expected = expectedFor(name);
        assert.deepStrictEqual(await runScenario(SOURCE_ENTRY, name), expected);
      });

      test(`${name}: committed artifact pi/index.js matches the golden`, async () => {
        const expected = expectedFor(name);
        assert.deepStrictEqual(await runScenario(ARTIFACT_ENTRY, name), expected);
      });
    }
  });
}
