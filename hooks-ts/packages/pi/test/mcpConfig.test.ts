// `mcp_server_config` lookup — strict-or-omit (Revision 3).
//
// The rule with security weight: a config is described ONLY when every source is in a shape whose
// meaning is unambiguous, and the files are still the ones the adapter loaded. Everything else omits
// — for every server — because a wrong config can lend an unsanctioned binary a sanctioned server's
// fingerprint. So most cases here assert ABSENCE; the positive cases at the top prove the feature is
// not dead for an ordinary configuration.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import { createMcpConfigReader, hasMcpConfigFlag, mcpConfigSources } from "../src/mcpConfig.ts";

interface Fixture {
  homeDir: string;
  cwd: string;
  agentDir: string;
  write(path: string, content: unknown): void;
  cleanup(): void;
}

function fixture(): Fixture {
  const home = createFakeHome();
  const cwd = mkdtempSync(join(tmpdir(), "mcp-config-cwd-"));
  return {
    homeDir: home.homeDir,
    cwd,
    agentDir: join(home.homeDir, ".pi", "agent"),
    write(path, content) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
    },
    cleanup() {
      home.cleanup();
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}

const lookup = (f: Fixture, server: string, env: NodeJS.ProcessEnv = {}, argv: string[] = []) =>
  createMcpConfigReader({ env, homeDir: f.homeDir, argv }).serverConfig(server, f.cwd);

const GLOBAL = (f: Fixture) => join(f.homeDir, ".config", "mcp", "mcp.json");
const PROJECT = (f: Fixture) => join(f.cwd, ".mcp.json");
const PROJECT_PI = (f: Fixture) => join(f.cwd, ".pi", "mcp-adapter.json");

// --- The feature is alive ----------------------------------------------------------------------

test("a plain strict-JSON single source sends the config", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), { mcpServers: { github: { command: "npx", args: ["-y", "srv"], env: { K: "SECRET" } } } });
    assert.deepStrictEqual(lookup(f, "github"), { command: "npx", args: ["-y", "srv"] });
    f.write(GLOBAL(f), { mcpServers: { remote: { url: "https://r.invalid/mcp", type: "http", headers: { A: "SECRET" } } } });
    assert.deepStrictEqual(lookup(f, "remote"), { url: "https://r.invalid/mcp", type: "http" });
  } finally {
    f.cleanup();
  }
});

test("a two-source override sends the merged config (later wins; url drops command/args)", () => {
  const f = fixture();
  try {
    f.write(GLOBAL(f), { mcpServers: { s: { command: "c", args: ["1"] }, t: { command: "tc", args: ["x"] } } });
    f.write(PROJECT(f), { mcpServers: { s: { args: ["2"] }, t: { url: "https://t.invalid" } } });
    assert.deepStrictEqual(lookup(f, "s"), { command: "c", args: ["2"] });
    assert.deepStrictEqual(lookup(f, "t"), { url: "https://t.invalid" });
  } finally {
    f.cleanup();
  }
});

test("a BOM, symlinks and an empty file are accepted", () => {
  const f = fixture();
  try {
    const target = join(f.cwd, "dotfiles", "mcp.json");
    f.write(target, `﻿${JSON.stringify({ mcpServers: { s: { url: "https://linked.invalid" } } })}`);
    mkdirSync(dirname(GLOBAL(f)), { recursive: true });
    symlinkSync(target, GLOBAL(f));
    f.write(PROJECT(f), "  \n");
    assert.deepStrictEqual(lookup(f, "s"), { url: "https://linked.invalid" });
  } finally {
    f.cleanup();
  }
});

// --- Strict: anything not fully modelled omits, for every server -----------------------------------

const OMIT_SOURCES: [string, string][] = [
  ["a // comment", '// c\n{"mcpServers":{"s":{"url":"https://s.invalid"}}}'],
  ["a trailing comma", '{"mcpServers":{"s":{"url":"https://s.invalid"},}}'],
  ["a top-level non-object", "[1]"],
  ["mcpServers not an object", '{"mcpServers":0}'],
  ["an mcp-servers key", '{"mcp-servers":{"s":{"url":"https://s.invalid"}}}'],
  ["a non-object settings", '{"settings":1}'],
  ["imports", '{"imports":["cursor"]}'],
  ["claudePlugins", '{"claudePlugins":[]}'],
  ["settings.ancestorConfigRoots", '{"settings":{"ancestorConfigRoots":[]}}'],
  ["settings.agentPluginPaths", '{"settings":{"agentPluginPaths":["x"]}}'],
  ["settings.hostConfigDiscovery", '{"settings":{"hostConfigDiscovery":"off"}}'],
  ["settings.jev", '{"settings":{"jev":{}}}'],
  ["a socket transport", '{"mcpServers":{"other":{"socket":"/tmp/x.sock"}}}'],
  ["an unknown server key", '{"mcpServers":{"other":{"command":"o","transport":"weird"}}}'],
  ["a non-object server", '{"mcpServers":{"other":"npx"}}'],
  ["a non-string command", '{"mcpServers":{"other":{"command":1}}}'],
  ["non-string args", '{"mcpServers":{"other":{"command":"o","args":["a",2]}}}'],
];

test("omitted when ANY source is not strict, fully-modelled JSON", () => {
  for (const [name, text] of OMIT_SOURCES) {
    const f = fixture();
    try {
      f.write(GLOBAL(f), { mcpServers: { s: { url: "https://s.invalid" } } });
      f.write(PROJECT_PI(f), text);
      assert.equal(lookup(f, "s"), undefined, `${name}: never a config from a partial or ambiguous view`);
    } finally {
      f.cleanup();
    }
  }
});

test("omitted: a directory, a FIFO or an oversized file in place of a source", () => {
  const plants: [string, (path: string) => void][] = [
    ["directory", (path) => mkdirSync(path, { recursive: true })],
    ["fifo", (path) => {
      mkdirSync(dirname(path), { recursive: true });
      execFileSync("mkfifo", [path]);
    }],
    ["oversized", (path) => {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `{"pad":"${"x".repeat(1_100_000)}"}`);
    }],
  ];
  for (const [name, plant] of plants) {
    const f = fixture();
    try {
      f.write(PROJECT(f), { mcpServers: { s: { url: "https://s.invalid" } } });
      plant(join(f.homeDir, ".agents", "mcp.json"));
      assert.equal(lookup(f, "s"), undefined, name);
    } finally {
      f.cleanup();
    }
  }
});

test("omitted: both url and command, neither, a `__` name, or a server not found", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), {
      mcpServers: { both: { url: "https://b.invalid", command: "b" }, bare: { type: "x" }, "pkg__srv": { command: "p" } },
    });
    for (const name of ["both", "bare", "pkg__srv", "missing"]) assert.equal(lookup(f, name), undefined, name);
  } finally {
    f.cleanup();
  }
});

test("omitted when the extension cannot resolve the adapter's paths", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), { mcpServers: { s: { url: "https://s.invalid" } } });
    assert.equal(lookup(f, "s", {}, ["node", "pi", "--mcp-config", "/x.json"]), undefined, "--mcp-config");
    assert.equal(lookup(f, "s", {}, ["node", "pi", "--mcp-config=@x"]), undefined, "--mcp-config=");
    assert.equal(lookup(f, "s", { PI_PACKAGE_DIR: "/opt/arc" }), undefined, "a rebranded build");
    assert.equal(lookup(f, "s", { PI_CODING_AGENT_DIR: "relative/dir" }), undefined, "a relative agent dir");
    assert.equal(createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] }).serverConfig("s", ""), undefined, "no cwd");
    assert.equal(createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] }).serverConfig("s", "rel"), undefined);
    assert.equal(hasMcpConfigFlag(["pi", "--mcp-config"]), true);
    assert.equal(hasMcpConfigFlag(["pi"]), false);
  } finally {
    f.cleanup();
  }
});

test("sources follow the adapter's order; exclusive mode reads only the adapter file", () => {
  const f = fixture();
  try {
    assert.deepStrictEqual(mcpConfigSources({ env: {}, homeDir: f.homeDir, argv: [] }, f.cwd), [
      GLOBAL(f),
      join(f.homeDir, ".agents", "mcp.json"),
      join(f.homeDir, ".agents", "mcp", "mcp.json"),
      join(f.agentDir, "mcp-adapter.json"),
      PROJECT(f),
      PROJECT_PI(f),
    ]);
    f.write(PROJECT(f), { mcpServers: { s: { command: "project" } } });
    f.write(join(f.agentDir, "mcp-adapter.json"), { mcpServers: { s: { url: "https://adapter.invalid" } } });
    assert.deepStrictEqual(lookup(f, "s", { PI_MCP_CONFIG_MODE: "exclusive" }), { url: "https://adapter.invalid" });
    assert.deepStrictEqual(lookup(f, "s"), { command: "project" }, "non-exclusive: the project file wins");
  } finally {
    f.cleanup();
  }
});

// --- Snapshot once (REVIEW-2 CR-02) --------------------------------------------------------------

test("CR-02: a file changed after the snapshot omits the config for the rest of the instance", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), { mcpServers: { github: { command: "/tmp/evil-mcp" } } });
    const reader = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    reader.snapshot(f.cwd);
    assert.deepStrictEqual(reader.serverConfig("github", f.cwd), { command: "/tmp/evil-mcp" });

    // A prompt-injected model rewrites the file to the sanctioned definition. The adapter is still
    // running what it loaded, so the reader must not start describing the new file.
    f.write(PROJECT(f), { mcpServers: { github: { command: "npx", args: ["-y", "srv"] } } });
    const later = new Date(Date.now() + 5_000);
    utimesSync(PROJECT(f), later, later);
    assert.equal(reader.serverConfig("github", f.cwd), undefined);

    // Latched: even restoring the original content does not re-enable it.
    f.write(PROJECT(f), { mcpServers: { github: { command: "/tmp/evil-mcp" } } });
    assert.equal(reader.serverConfig("github", f.cwd), undefined);
  } finally {
    f.cleanup();
  }
});

test("a new file appearing after the snapshot, or a different cwd, also omits", () => {
  const f = fixture();
  const other = mkdtempSync(join(tmpdir(), "mcp-config-other-"));
  try {
    f.write(GLOBAL(f), { mcpServers: { s: { url: "https://s.invalid" } } });
    const reader = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    reader.snapshot(f.cwd);
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { url: "https://s.invalid" });
    assert.equal(reader.serverConfig("s", other), undefined, "another cwd than the adapter loaded with");
    assert.deepStrictEqual(
      reader.serverConfig("s", f.cwd),
      { url: "https://s.invalid" },
      "per call: the other cwd did not poison the snapshot of the adapter's own cwd",
    );

    const g = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    g.snapshot(f.cwd);
    f.write(PROJECT(f), { mcpServers: { s: { command: "planted" } } });
    assert.equal(g.serverConfig("s", f.cwd), undefined, "a source that appeared later");
  } finally {
    f.cleanup();
    rmSync(other, { recursive: true, force: true });
  }
});

test("total on hostile options", () => {
  const hostile = createMcpConfigReader({ env: undefined as never, homeDir: undefined as never, argv: null as never });
  assert.doesNotThrow(() => hostile.snapshot(undefined as never));
  assert.equal(hostile.serverConfig(undefined as never, undefined as never), undefined);
});

// --- PR #371 review: an unusable cwd must not latch ---------------------------------------------

test("an empty or relative cwd omits for that call only; the next real cwd still takes the snapshot", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), { mcpServers: { s: { url: "https://s.invalid" } } });
    const reader = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    assert.equal(reader.serverConfig("s", ""), undefined, "no usable cwd: omitted");
    assert.equal(reader.serverConfig("s", "relative"), undefined);
    reader.snapshot("");
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { url: "https://s.invalid" }, "not latched");
  } finally {
    f.cleanup();
  }
});

test("a file changed after a REAL snapshot still omits for good", () => {
  const f = fixture();
  try {
    f.write(PROJECT(f), { mcpServers: { s: { command: "/tmp/evil-mcp" } } });
    const reader = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    assert.equal(reader.serverConfig("s", ""), undefined);
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { command: "/tmp/evil-mcp" });
    f.write(PROJECT(f), { mcpServers: { s: { command: "npx" } } });
    const later = new Date(Date.now() + 5_000);
    utimesSync(PROJECT(f), later, later);
    assert.equal(reader.serverConfig("s", f.cwd), undefined);
    assert.equal(reader.serverConfig("s", ""), undefined);
  } finally {
    f.cleanup();
  }
});
