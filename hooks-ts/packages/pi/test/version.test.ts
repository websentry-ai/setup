// The pi version reader: `client_entrypoint: "pi/<version>"` without importing pi.
//
// These cases moved here verbatim from `core/test/payload.test.ts` together with the reader itself
// (`core/src/piVersion.ts` -> `pi/src/version.ts`): how pi's version is found is a pi fact, so it is
// owned and tested by the pi package.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { resolveClientEntrypoint } from "../src/version.ts";

const PI_PACKAGE_NAME = "@earendil-works/pi-coding-agent";

test("resolveClientEntrypoint: reads the managed install's current-version file", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-install-"));
  try {
    writeFileSync(join(root, "current-version"), "0.87.1\n");
    assert.equal(resolveClientEntrypoint({ PI_MANAGED_INSTALL_ROOT: root }), "pi/0.87.1");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("resolveClientEntrypoint: walks up from argv[1] to the pi package.json", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-global-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: PI_PACKAGE_NAME, version: "9.9.9" }));
    const bundleDir = join(root, "dist", "bundle");
    mkdirSync(bundleDir, { recursive: true });
    assert.equal(resolveClientEntrypoint({}, join(bundleDir, "cli.js")), "pi/9.9.9");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("resolveClientEntrypoint: unresolvable version -> pi/unknown, never throws", () => {
  assert.doesNotThrow(() => resolveClientEntrypoint({ PI_MANAGED_INSTALL_ROOT: "/nope/does/not/exist" }));
  assert.equal(
    resolveClientEntrypoint({ PI_MANAGED_INSTALL_ROOT: "/nope/does/not/exist" }, "/nope/also/cli.js"),
    "pi/unknown",
  );
  assert.equal(resolveClientEntrypoint({}), "pi/unknown");
  assert.doesNotThrow(() => resolveClientEntrypoint({}, ""));
});

test("resolveClientEntrypoint: a hostile version string is sanitised and capped", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-hostile-"));
  try {
    writeFileSync(join(root, "current-version"), "0.87.1; rm -rf / #" + "z".repeat(80));
    const entrypoint = resolveClientEntrypoint({ PI_MANAGED_INSTALL_ROOT: root });
    assert.ok(entrypoint.startsWith("pi/"), entrypoint);
    assert.ok(!/[;\s#\/]/.test(entrypoint.slice(3)), entrypoint);
    assert.ok(entrypoint.length <= 3 + 32, entrypoint);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
