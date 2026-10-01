// `mcp_server_config` lookup by the broker's exact server name (Revision 2).
//
// The rule with security weight: when this reader cannot be sure it sees what the adapter sees, it
// answers `undefined` (config omitted) — never a possibly wrong config, which could lend an
// unsanctioned server a sanctioned fingerprint (review CR-02). So the JSONC parser is pinned against
// the edge cases `strip-json-comments` handles, and every "cannot be sure" case is asserted to omit.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import {
  createMcpConfigReader,
  mcpConfigOverride,
  mcpConfigSources,
  parseJsonc,
  stripJsonComments,
} from "../src/mcpConfig.ts";

interface Fixture {
  homeDir: string;
  cwd: string;
  agentDir: string;
  write(path: string, content: string): void;
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
      writeFileSync(path, content);
    },
    cleanup() {
      home.cleanup();
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}

const lookup = (f: Fixture, server: string, env: NodeJS.ProcessEnv = {}, argv: string[] = []) =>
  createMcpConfigReader({ env, homeDir: f.homeDir, argv }).serverConfig(server, f.cwd);

// --- JSONC -------------------------------------------------------------------------------------

test("stripJsonComments: comments and trailing commas outside strings only", () => {
  const text = `{
    // line comment with "quotes", and a comma,
    "url": "https://x.invalid/a//b?c=/*not*/", /* block, */
    "s": "a \\"quoted, // still string\\" b",
    "list": [1, 2, /* c */ ],
    "o": { "k": 1, },
  }`;
  assert.deepStrictEqual(JSON.parse(stripJsonComments(text)), {
    url: "https://x.invalid/a//b?c=/*not*/",
    s: 'a "quoted, // still string" b',
    list: [1, 2],
    o: { k: 1 },
  });
});

test("parseJsonc: a BOM is accepted, and invalid JSON still throws", () => {
  assert.deepStrictEqual(parseJsonc('﻿{"a": 1}'), { a: 1 });
  assert.throws(() => parseJsonc("{ nope"));
  assert.throws(() => parseJsonc('{"a": 1,, }'));
});

// --- Sources -----------------------------------------------------------------------------------

test("sources: the adapter's order; --mcp-config replaces the adapter file; exclusive reads only it", () => {
  const f = fixture();
  try {
    const base = mcpConfigSources({ env: {}, homeDir: f.homeDir, argv: [] }, f.cwd);
    assert.deepStrictEqual(base, [
      join(f.homeDir, ".config", "mcp", "mcp.json"),
      join(f.homeDir, ".agents", "mcp.json"),
      join(f.homeDir, ".agents", "mcp", "mcp.json"),
      join(f.agentDir, "mcp-adapter.json"),
      join(f.cwd, ".mcp.json"),
      join(f.cwd, ".pi", "mcp-adapter.json"),
    ]);
    const override = join(f.cwd, "custom.json");
    assert.equal(mcpConfigOverride(["pi", "--mcp-config", override]), override);
    assert.equal(mcpConfigOverride(["pi", `--mcp-config=${override}`]), override);
    assert.equal(mcpConfigOverride(["pi"]), undefined);
    const withOverride = mcpConfigSources({ env: {}, homeDir: f.homeDir, argv: ["--mcp-config", override] }, f.cwd);
    assert.equal(withOverride[3], override);
    assert.equal(withOverride.includes(join(f.agentDir, "mcp-adapter.json")), false);
    assert.deepStrictEqual(
      mcpConfigSources({ env: { PI_MCP_CONFIG_MODE: "exclusive" }, homeDir: f.homeDir, argv: [] }, f.cwd),
      [join(f.agentDir, "mcp-adapter.json")],
    );
    // A global path that IS the adapter file is read once, at the adapter-file position.
    const generic = join(f.homeDir, ".config", "mcp", "mcp.json");
    const same = mcpConfigSources({ env: {}, homeDir: f.homeDir, argv: ["--mcp-config", generic] }, f.cwd);
    assert.equal(same.filter((p) => p === generic).length, 1);
    assert.equal(same.indexOf(generic), 2);
  } finally {
    f.cleanup();
  }
});

test("later sources win per field; a later url drops command/args and vice versa", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), '{"mcpServers": {"s": {"command": "c", "args": ["1"]}, "t": {"url": "https://t.invalid"}}}');
    f.write(join(f.homeDir, ".agents", "mcp.json"), '{"mcpServers": {"s": {"args": ["2"], "type": "stdio"}}}');
    f.write(join(f.cwd, ".mcp.json"), '{"mcpServers": {"t": {"command": "tc"}}}');
    assert.deepStrictEqual(lookup(f, "s"), { command: "c", args: ["2"], type: "stdio" });
    assert.deepStrictEqual(lookup(f, "t"), { command: "tc" });
  } finally {
    f.cleanup();
  }
});

// --- Unknown ⇒ omitted --------------------------------------------------------------------------

test("omitted: server not found, or a server with neither url nor command", () => {
  const f = fixture();
  try {
    f.write(join(f.cwd, ".mcp.json"), '{"mcpServers": {"bare": {"type": "x"}}}');
    assert.equal(lookup(f, "missing"), undefined);
    assert.equal(lookup(f, "bare"), undefined);
  } finally {
    f.cleanup();
  }
});

test("omitted: any existing source that is unparseable, a directory, over-unreadable, or a FIFO", () => {
  const variants: [string, (f: Fixture, path: string) => void][] = [
    ["unparseable", (f, path) => f.write(path, "{ nope")],
    ["directory", (_f, path) => mkdirSync(path, { recursive: true })],
    ["fifo", (_f, path) => {
      mkdirSync(dirname(path), { recursive: true });
      execFileSync("mkfifo", [path]);
    }],
  ];
  for (const [name, plant] of variants) {
    const f = fixture();
    try {
      f.write(join(f.cwd, ".mcp.json"), '{"mcpServers": {"s": {"url": "https://s.invalid"}}}');
      plant(f, join(f.homeDir, ".agents", "mcp.json"));
      assert.equal(lookup(f, "s"), undefined, `${name}: never a config from a partial view`);
    } finally {
      f.cleanup();
    }
  }
});

test("omitted: a source pulling in servers this reader does not model (imports, ancestor roots)", () => {
  for (const extra of ['"imports": ["cursor"]', '"settings": {"ancestorConfigRoots": ["~/work"]}']) {
    const f = fixture();
    try {
      f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), `{${extra}, "mcpServers": {"s": {"url": "https://s.invalid"}}}`);
      assert.equal(lookup(f, "s"), undefined, extra);
    } finally {
      f.cleanup();
    }
  }
});

test("not omitted: an empty or comment-only file is skipped like the adapter skips it", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), "  // nothing yet\n");
    f.write(join(f.cwd, ".mcp.json"), '{"mcpServers": {"s": {"url": "https://s.invalid"}}}');
    assert.deepStrictEqual(lookup(f, "s"), { url: "https://s.invalid" });
  } finally {
    f.cleanup();
  }
});

test("symlinked sources are followed (dotfile managers)", () => {
  const f = fixture();
  try {
    const target = join(f.cwd, "dotfiles", "mcp.json");
    f.write(target, '{"mcpServers": {"s": {"url": "https://linked.invalid"}}}');
    mkdirSync(join(f.homeDir, ".config", "mcp"), { recursive: true });
    symlinkSync(target, join(f.homeDir, ".config", "mcp", "mcp.json"));
    assert.deepStrictEqual(lookup(f, "s"), { url: "https://linked.invalid" });
  } finally {
    f.cleanup();
  }
});

test("only url / command / args / type are ever read into the config", () => {
  const f = fixture();
  try {
    f.write(
      join(f.cwd, ".mcp.json"),
      '{"mcpServers": {"s": {"url": "https://s.invalid?api_key=k", "headers": {"A": "SECRET"}, "bearerToken": "SECRET", "oauth": {"x": "SECRET"}, "env": {"E": "SECRET"}}}}',
    );
    const config = lookup(f, "s");
    // The URL is sent as written — a credential in a query string is parity egress with the Python
    // hook, documented, not claimed away.
    assert.deepStrictEqual(config, { url: "https://s.invalid?api_key=k" });
    assert.equal(JSON.stringify(config).includes("SECRET"), false);
  } finally {
    f.cleanup();
  }
});

test("memoised on the sources' stat signature; a touched file is re-read; total on hostile input", () => {
  const f = fixture();
  try {
    const path = join(f.cwd, ".mcp.json");
    f.write(path, '{"mcpServers": {"s": {"command": "c"}}}');
    const reader = createMcpConfigReader({ env: {}, homeDir: f.homeDir, argv: [] });
    const pinned = new Date(Date.now() - 60_000);
    utimesSync(path, pinned, pinned);
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { command: "c" });
    f.write(path, '{"mcpServers": {"s": {"command": "d"}}}');
    utimesSync(path, pinned, pinned);
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { command: "c" }, "served from the memo");
    const later = new Date();
    utimesSync(path, later, later);
    assert.deepStrictEqual(reader.serverConfig("s", f.cwd), { command: "d" });

    const hostile = createMcpConfigReader({ env: undefined as never, homeDir: undefined as never, argv: null as never });
    assert.equal(hostile.serverConfig(undefined as never, undefined as never), undefined);
  } finally {
    f.cleanup();
  }
});
