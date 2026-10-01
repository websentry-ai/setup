// pi-mcp-adapter call resolution — every call shape the adapter accepts, the ones it refuses, and the
// collisions forward-mapping exists to catch.
//
// Fixtures are synthetic: config files and an `mcp-cache.json` written under a temp HOME and a temp
// cwd. The two contracts with security weight are asserted explicitly rather than inferred:
//
//   * `serverConfig` carries `url` or `command`+`args` (+`type`) and NOTHING else — `env`, `headers`,
//     `bearerToken` and `oauth` are present in the fixture files precisely so their absence means
//     something;
//   * ambiguity is `undefined`, never a guess — a mis-resolved call would be checked against the
//     wrong server's policy.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { MAX_CONFIG_BYTES } from "../../core/src/constants.ts";
import { createFakeHome } from "../../core/test/helpers/fakeHome.ts";
import {
  createMcpResolver,
  formatServerNamespace,
  readMcpAdapterConfig,
  readMcpCache,
  resolveMcpCall,
} from "../src/mcpResolve.ts";
import type { McpAdapterConfig, McpCache } from "../src/mcpResolve.ts";

interface Fixture {
  homeDir: string;
  cwd: string;
  agentDir: string;
  env: Record<string, string>;
  write(path: string, value: unknown): void;
  cleanup(): void;
}

function fixture(env: Record<string, string> = {}): Fixture {
  const home = createFakeHome();
  const cwd = mkdtempSync(join(tmpdir(), "mcp-cwd-"));
  const agentDir = env.PI_CODING_AGENT_DIR ?? join(home.homeDir, ".pi", "agent");
  return {
    homeDir: home.homeDir,
    cwd,
    agentDir,
    env,
    write(path, value) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
    },
    cleanup() {
      home.cleanup();
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}

/** A cache file in the adapter's shape: `servers.<name>.tools[].name`, plus noise we must ignore. */
function cacheFile(servers: Record<string, string[]>, resources: Record<string, string[]> = {}): unknown {
  return {
    version: 1,
    servers: Object.fromEntries(
      Object.entries(servers).map(([name, tools]) => [
        name,
        {
          configHash: "h",
          tools: tools.map((tool) => ({ name: tool, description: "d", inputSchema: { type: "object" } })),
          resources: (resources[name] ?? []).map((r) => ({ name: r, uri: `file:///${r}` })),
          cachedAt: 1,
        },
      ]),
    ),
  };
}

/** Build the in-memory pair directly, for pure `resolveMcpCall` cases. */
function universe(
  servers: Record<string, Record<string, unknown>>,
  tools: Record<string, string[]>,
  settings: McpAdapterConfig["settings"] = {},
): { config: McpAdapterConfig; cache: McpCache } {
  const config: McpAdapterConfig = { servers: new Map(), settings };
  for (const [name, def] of Object.entries(servers)) config.servers.set(name, def as never);
  return { config, cache: new Map(Object.entries(tools)) };
}

const BASE = universe(
  {
    github: { url: "https://mcp.example.invalid/github", type: "http" },
    "my-srv": { command: "node", args: ["srv.js", "--stdio"] },
  },
  { github: ["create_issue", "list_repos"], "my-srv": ["do.thing", "ping"] },
);

const resolve = (name: string, input: unknown, u = BASE) => resolveMcpCall(name, input, u.config, u.cache);

// --- Proxy `mcp` --------------------------------------------------------------------------------

test("proxy with server: args as an object and as a JSON string both resolve", () => {
  const asObject = resolve("mcp", { tool: "create_issue", server: "github", args: { title: "t" } });
  const asString = resolve("mcp", { tool: "create_issue", server: "github", args: '{"title":"t"}' });
  const expected = {
    server: "github",
    tool: "create_issue",
    args: { title: "t" },
    serverConfig: { url: "https://mcp.example.invalid/github", type: "http" },
  };
  assert.deepStrictEqual(asObject, expected);
  assert.deepStrictEqual(asString, expected);
});

test("proxy: unparseable or non-object string args are the adapter's own refusal → undefined", () => {
  for (const args of ["{not json", "[1,2]", "42", '"str"', "null", [1], null]) {
    assert.equal(resolve("mcp", { tool: "create_issue", server: "github", args }), undefined, String(args));
  }
});

test("proxy: absent or '' args become {}", () => {
  assert.deepStrictEqual(resolve("mcp", { tool: "ping", server: "my-srv" })?.args, {});
  assert.deepStrictEqual(resolve("mcp", { tool: "ping", server: "my-srv", args: "" })?.args, {});
});

test("proxy: a server not in config ∪ cache → undefined", () => {
  assert.equal(resolve("mcp", { tool: "create_issue", server: "nope" }), undefined);
});

test("proxy with server: a prefixed tool name maps back to the original", () => {
  assert.equal(resolve("mcp", { tool: "github_create_issue", server: "github" })?.tool, "create_issue");
  assert.equal(resolve("mcp", { tool: "my-srv_do_thing", server: "my-srv" })?.tool, "do.thing");
});

test("proxy without server: (a) a unique prefixed-name match", () => {
  const call = resolve("mcp", { tool: "github_list_repos" });
  assert.equal(call?.server, "github");
  assert.equal(call?.tool, "list_repos");
});

test("proxy without server: (b) a unique original name", () => {
  const call = resolve("mcp", { tool: "ping" });
  assert.deepStrictEqual([call?.server, call?.tool], ["my-srv", "ping"]);
});

test("proxy without server: (c) the longest configured prefix works with a cold cache", () => {
  const cold = universe(
    { github: { url: "https://mcp.example.invalid/github" }, "github-enterprise": { url: "https://ghe.example.invalid" } },
    {},
  );
  const call = resolve("mcp", { tool: "github-enterprise_search_code" }, cold);
  assert.deepStrictEqual([call?.server, call?.tool], ["github-enterprise", "search_code"]);
  assert.deepStrictEqual(call?.serverConfig, { url: "https://ghe.example.invalid" });
});

test("proxy without server: (d) a unique candidate match across servers", () => {
  // `fetch_page` is neither a prefixed name nor an original one, and there is no prefix to scope by;
  // it is only the dash-folded legacy candidate of `fetch-page`, which is rule (d).
  const u = universe({ alpha: { command: "a" } }, { alpha: ["fetch-page"] }, { toolPrefix: "none" });
  const call = resolve("mcp", { tool: "fetch_page" }, u);
  assert.deepStrictEqual([call?.server, call?.tool], ["alpha", "fetch-page"]);
});

test("proxy without server: two matches at any step → undefined", () => {
  const twoOriginal = universe({ a: { command: "a" }, b: { command: "b" } }, { a: ["search"], b: ["search"] });
  assert.equal(resolve("mcp", { tool: "search" }, twoOriginal), undefined, "two servers publish `search`");

  const twoPrefixes = universe({ foo: { command: "f" }, "foo-mcp": { command: "g" } }, {}, { toolPrefix: "short" });
  assert.equal(resolve("mcp", { tool: "foo_bar" }, twoPrefixes), undefined, "short mode folds foo and foo-mcp");
});

test("proxy: no tool, a non-call action, or a search/describe/connect call → undefined", () => {
  assert.equal(resolve("mcp", {}), undefined);
  assert.equal(resolve("mcp", { tool: "" }), undefined);
  for (const action of ["install", "ui-messages", "auth-start", "auth-complete"]) {
    assert.equal(resolve("mcp", { tool: "ping", server: "my-srv", action }), undefined, action);
  }
  assert.equal(resolve("mcp", { search: "issues" }), undefined);
  assert.equal(resolve("mcp", { describe: "github_create_issue" }), undefined);
  assert.equal(resolve("mcp", { connect: "github" }), undefined);
  assert.equal(resolve("mcp", "not an object"), undefined);
});

// --- Namespace wrappers -------------------------------------------------------------------------

test("namespace wrapper resolves, including a dashed server name", () => {
  assert.equal(formatServerNamespace("my-srv"), "my_srv");
  const call = resolve("mcp__my_srv", { tool: "ping", args: { n: 1 } });
  assert.deepStrictEqual(call, {
    server: "my-srv",
    tool: "ping",
    args: { n: 1 },
    serverConfig: { command: "node", args: ["srv.js", "--stdio"] },
  });
  assert.equal(resolve("mcp__github", { tool: "list_repos" })?.server, "github");
});

test("namespace wrapper without `tool` is the adapter's missing_tool → undefined", () => {
  assert.equal(resolve("mcp__github", {}), undefined);
  assert.equal(resolve("mcp__github", { args: {} }), undefined);
});

test("namespaceProxyTools: false → namespace names are not resolved", () => {
  const off = universe(
    { github: { url: "https://mcp.example.invalid/github" } },
    { github: ["list_repos"] },
    { namespaceProxyTools: false },
  );
  assert.equal(resolve("mcp__github", { tool: "list_repos" }, off), undefined);
});

test("an unsafe server name uses the _mcpns_ encoding, and a long one is hashed", () => {
  assert.equal(formatServerNamespace("a.b"), "_mcpns_a_2e_b");
  const long = formatServerNamespace("s".repeat(80));
  assert.ok(long.length <= 59 && long.startsWith("_mcpns__h_"), long);
  const u = universe({ "a.b": { url: "https://x.invalid" } }, { "a.b": ["t"] });
  assert.equal(resolve("mcp___mcpns_a_2e_b", { tool: "t" }, u)?.server, "a.b");
});

// --- Direct tools -------------------------------------------------------------------------------

test("direct tools under every prefix mode, with `.` folded and per-server override", () => {
  const modes = universe(
    {
      srv: { command: "s" },
      shorty: { command: "s", toolPrefix: "short" },
      "files-mcp": { command: "s", toolPrefix: "short" },
      mcpd: { command: "s", toolPrefix: "mcp" },
      bare: { command: "s", toolPrefix: "none" },
    },
    {
      srv: ["a.b"],
      shorty: ["one"],
      "files-mcp": ["two"],
      mcpd: ["three"],
      bare: ["four"],
    },
  );
  const at = (name: string) => {
    const call = resolve(name, { k: "v" }, modes);
    return call === undefined ? undefined : [call.server, call.tool];
  };
  assert.deepStrictEqual(at("srv_a_b"), ["srv", "a.b"], "server mode, `.` → `_`");
  assert.deepStrictEqual(at("shorty_one"), ["shorty", "one"]);
  assert.deepStrictEqual(at("files_two"), ["files-mcp", "two"], "short mode strips -mcp");
  assert.deepStrictEqual(at("mcp__mcpd_three"), ["mcpd", "three"], "mcp mode is ONE underscore");
  assert.deepStrictEqual(at("four"), ["bare", "four"]);
  assert.deepStrictEqual(resolve("srv_a_b", { k: "v" }, modes)?.args, { k: "v" }, "direct input IS the args");
});

test("settings.toolPrefix applies unless the server overrides it", () => {
  const u = universe(
    { g: { command: "g" }, h: { command: "h", toolPrefix: "server" } },
    { g: ["x"], h: ["y"] },
    { toolPrefix: "mcp" },
  );
  assert.equal(resolve("mcp__g_x", {}, u)?.server, "g");
  assert.equal(resolve("h_y", {}, u)?.server, "h");
  assert.equal(resolve("g_x", {}, u), undefined, "the global prefix moved g's names");
});

// --- Collisions ---------------------------------------------------------------------------------

test("a name that is both a namespace wrapper and an mcp-prefix direct tool → undefined", () => {
  // Server `x_y`'s wrapper is `mcp__x_y`; server `x`'s tool `y` under toolPrefix "mcp" is ALSO
  // `mcp__x_y`. Parsing would pick one; forward-mapping sees both and refuses.
  const u = universe(
    { x_y: { url: "https://xy.invalid" }, x: { command: "x", toolPrefix: "mcp" } },
    { x_y: ["t"], x: ["y"] },
  );
  assert.equal(resolve("mcp__x_y", { tool: "t" }, u), undefined);
});

test("a direct name claimed by two servers → undefined", () => {
  const u = universe(
    { a: { command: "a" }, b: { command: "b" } },
    { a: ["shared"], b: ["shared"] },
    { toolPrefix: "none" },
  );
  assert.equal(resolve("shared", {}, u), undefined);
});

test("native names, resource tools and unknown custom tools → undefined", () => {
  for (const name of ["bash", "read", "write", "edit", "grep", "find", "ls", "powershell"]) {
    assert.equal(resolve(name, { command: "ls", path: "/" }), undefined, name);
  }
  const withResources = universe({ docs: { command: "d" } }, { docs: ["search"] });
  assert.equal(resolve("docs_read_readme", {}, withResources), undefined, "a resource read is not a tool call");
  assert.equal(resolve("my_custom_tool", {}), undefined);
  assert.equal(resolve("mcpScript", { script: "..." }), undefined);
});

test("a disabled server is never resolved", () => {
  const u = universe({ off: { command: "o", disabled: true } }, { off: ["t"] });
  assert.equal(resolve("off_t", {}, u), undefined);
  assert.equal(resolve("mcp", { tool: "t", server: "off" }, u), undefined);
});

// --- Config sources -----------------------------------------------------------------------------

test("config precedence: later sources win per field per server, in the adapter's order", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), {
      mcpServers: { s: { command: "first", args: ["1"] }, keep: { url: "https://keep.invalid" } },
    });
    f.write(join(f.homeDir, ".agents", "mcp.json"), { mcpServers: { s: { args: ["2"] } } });
    f.write(join(f.homeDir, ".agents", "mcp", "mcp.json"), { mcpServers: { s: { type: "stdio" } } });
    f.write(join(f.agentDir, "mcp-adapter.json"), {
      mcpServers: { s: { command: "fourth" } },
      settings: { toolPrefix: "short" },
    });
    f.write(join(f.cwd, ".mcp.json"), { mcpServers: { s: { args: ["5"] } } });
    f.write(join(f.cwd, ".pi", "mcp-adapter.json"), { mcpServers: { s: { toolPrefix: "none" } } });

    const config = readMcpAdapterConfig(f.env, f.homeDir, f.cwd);
    assert.deepStrictEqual(config.servers.get("s"), {
      command: "fourth",
      args: ["5"],
      type: "stdio",
      toolPrefix: "none",
    });
    assert.deepStrictEqual(config.servers.get("keep"), { url: "https://keep.invalid" });
    assert.equal(config.settings.toolPrefix, "short");
  } finally {
    f.cleanup();
  }
});

test("a later url drops an inherited command/args, and vice versa", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), { mcpServers: { s: { command: "c", args: ["a"] } } });
    f.write(join(f.cwd, ".mcp.json"), { mcpServers: { s: { url: "https://later.invalid" } } });
    assert.deepStrictEqual(readMcpAdapterConfig(f.env, f.homeDir, f.cwd).servers.get("s"), {
      url: "https://later.invalid",
    });
  } finally {
    f.cleanup();
  }
});

test("PI_MCP_CONFIG_MODE=exclusive reads only <agentDir>/mcp-adapter.json", () => {
  const f = fixture({ PI_MCP_CONFIG_MODE: "Exclusive" });
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), { mcpServers: { global: { command: "g" } } });
    f.write(join(f.cwd, ".mcp.json"), { mcpServers: { project: { command: "p" } } });
    f.write(join(f.agentDir, "mcp-adapter.json"), { mcpServers: { only: { command: "o" } } });
    assert.deepStrictEqual([...readMcpAdapterConfig(f.env, f.homeDir, f.cwd).servers.keys()], ["only"]);
  } finally {
    f.cleanup();
  }
});

test("PI_CODING_AGENT_DIR moves the agent dir for both the config and the cache", () => {
  const moved = mkdtempSync(join(tmpdir(), "mcp-agentdir-"));
  const f = fixture({ PI_CODING_AGENT_DIR: moved });
  try {
    f.write(join(moved, "mcp-adapter.json"), { mcpServers: { here: { command: "h" } } });
    f.write(join(moved, "mcp-cache.json"), cacheFile({ here: ["t"] }));
    f.write(join(f.homeDir, ".pi", "agent", "mcp-adapter.json"), { mcpServers: { stale: { command: "s" } } });
    const config = readMcpAdapterConfig(f.env, f.homeDir, f.cwd);
    assert.deepStrictEqual([...config.servers.keys()], ["here"]);
    assert.deepStrictEqual(readMcpCache(moved).get("here"), ["t"]);
  } finally {
    f.cleanup();
    rmSync(moved, { recursive: true, force: true });
  }
});

test("~/.mcp.json is not a source unless cwd is $HOME", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".mcp.json"), { mcpServers: { homefile: { command: "h" } } });
    assert.equal(readMcpAdapterConfig(f.env, f.homeDir, f.cwd).servers.has("homefile"), false);
    assert.equal(readMcpAdapterConfig(f.env, f.homeDir, f.homeDir).servers.has("homefile"), true);
  } finally {
    f.cleanup();
  }
});

test("mcp-cache.json: tool names per server, resources ignored", () => {
  const f = fixture();
  try {
    f.write(join(f.agentDir, "mcp-cache.json"), cacheFile({ docs: ["search", "fetch"] }, { docs: ["readme"] }));
    assert.deepStrictEqual(readMcpCache(f.agentDir), new Map([["docs", ["search", "fetch"]]]));
  } finally {
    f.cleanup();
  }
});

// --- Projection (T-kdp-01) ----------------------------------------------------------------------

test("serverConfig is {url,type?} or {command,args?,type?} — never env, headers or tokens", () => {
  const f = fixture();
  try {
    f.write(join(f.agentDir, "mcp-adapter.json"), {
      mcpServers: {
        remote: {
          url: "https://remote.invalid/mcp",
          type: "streamable-http",
          headers: { Authorization: "Bearer sk-SECRET-HEADER" },
          bearerToken: "sk-SECRET-BEARER",
          bearerTokenEnv: "TOKEN_VAR",
          oauth: { clientSecret: "sk-SECRET-OAUTH" },
          env: { API_KEY: "sk-SECRET-ENV" },
        },
        local: {
          command: "npx",
          args: ["-y", "some-server"],
          env: { API_KEY: "sk-SECRET-ENV2" },
          cwd: "/secret/dir",
        },
        badargs: { command: "npx", args: ["ok", 7] },
      },
    });
    f.write(join(f.agentDir, "mcp-cache.json"), cacheFile({ remote: ["q"], local: ["r"], badargs: ["s"] }));
    const resolver = createMcpResolver({ env: f.env, homeDir: f.homeDir });

    const remote = resolver.resolve("remote_q", {}, f.cwd);
    assert.deepStrictEqual(remote?.serverConfig, { url: "https://remote.invalid/mcp", type: "streamable-http" });
    const local = resolver.resolve("local_r", {}, f.cwd);
    assert.deepStrictEqual(local?.serverConfig, { command: "npx", args: ["-y", "some-server"] });
    const bad = resolver.resolve("badargs_s", {}, f.cwd);
    assert.deepStrictEqual(bad?.serverConfig, { command: "npx" }, "non-string args entries → args omitted");

    const wire = JSON.stringify([remote, local, bad]);
    assert.equal(wire.includes("SECRET"), false, `a credential leaked: ${wire}`);
    for (const key of ["env", "headers", "bearerToken", "bearerTokenEnv", "oauth", "cwd"]) {
      assert.equal(wire.includes(`"${key}"`), false, key);
    }
  } finally {
    f.cleanup();
  }
});

test("a server known only from the cache resolves without a serverConfig", () => {
  const u = universe({}, { imported: ["t"] });
  const call = resolve("imported_t", {}, u);
  assert.deepStrictEqual(call, { server: "imported", tool: "t", args: {} });
});

// --- Totality and memoisation -------------------------------------------------------------------

test("malformed, oversize, directory and symlink sources are empty, never a throw", () => {
  const f = fixture();
  try {
    f.write(join(f.homeDir, ".config", "mcp", "mcp.json"), "{not json");
    f.write(join(f.homeDir, ".agents", "mcp.json"), " ".repeat(MAX_CONFIG_BYTES + 1));
    mkdirSync(join(f.homeDir, ".agents", "mcp", "mcp.json"), { recursive: true });
    const real = join(f.cwd, "real.json");
    f.write(real, { mcpServers: { linked: { command: "l" } } });
    symlinkSync(real, join(f.cwd, ".mcp.json"));
    f.write(join(f.agentDir, "mcp-cache.json"), "[]");

    const config = readMcpAdapterConfig(f.env, f.homeDir, f.cwd);
    assert.equal(config.servers.size, 0, "a symlink is refused, not followed");
    assert.equal(readMcpCache(f.agentDir).size, 0);
    const resolver = createMcpResolver({ env: f.env, homeDir: f.homeDir });
    assert.equal(resolver.resolve("linked_x", {}, f.cwd), undefined);
  } finally {
    f.cleanup();
  }
});

test("hostile inputs never throw", () => {
  const hostile = new Proxy(
    {},
    {
      get() {
        throw new Error("getter exploded");
      },
      has() {
        throw new Error("has exploded");
      },
    },
  );
  assert.doesNotThrow(() => resolve("mcp", hostile));
  assert.equal(resolve("mcp", hostile), undefined);
  assert.equal(resolve("mcp__github", hostile), undefined);
  const resolver = createMcpResolver({ env: undefined as never, homeDir: undefined as never });
  assert.equal(resolver.resolve("anything", hostile, undefined as never), undefined);
  assert.equal(readMcpCache(undefined).size, 0);
});

test("native names return before any filesystem access", () => {
  // A homeDir whose every lookup would throw if touched: the native branch must never reach it.
  const resolver = createMcpResolver({
    env: new Proxy({}, { get: () => assert.fail("env read for a native tool") }) as never,
    homeDir: "/nonexistent",
  });
  for (const name of ["bash", "read", "write", "edit", "grep", "find", "ls", "powershell"]) {
    assert.equal(resolver.resolve(name, { command: "ls" }, "/tmp"), undefined);
  }
});

test("memoised: unchanged files are not re-read, a touched file is", () => {
  const f = fixture();
  try {
    const configPath = join(f.agentDir, "mcp-adapter.json");
    f.write(configPath, { mcpServers: { aaaa: { command: "c" } } });
    f.write(join(f.agentDir, "mcp-cache.json"), cacheFile({ aaaa: ["t"], bbbb: ["t"] }));
    const resolver = createMcpResolver({ env: f.env, homeDir: f.homeDir });
    assert.deepStrictEqual(resolver.resolve("aaaa_t", {}, f.cwd)?.serverConfig, { command: "c" });

    // Same size, same mtime: rewritten in place, so only a re-READ could see the new content.
    const pinned = new Date(Date.now() - 60_000);
    utimesSync(configPath, pinned, pinned);
    assert.ok(resolver.resolve("aaaa_t", {}, f.cwd), "re-signed at the pinned mtime");
    f.write(configPath, { mcpServers: { aaaa: { command: "d" } } });
    utimesSync(configPath, pinned, pinned);
    assert.deepStrictEqual(
      resolver.resolve("aaaa_t", {}, f.cwd)?.serverConfig,
      { command: "c" },
      "served from the memo — no re-read",
    );

    // Touched: the signature moves and the new content is read.
    const later = new Date(Date.now());
    utimesSync(configPath, later, later);
    assert.deepStrictEqual(resolver.resolve("aaaa_t", {}, f.cwd)?.serverConfig, { command: "d" });
  } finally {
    f.cleanup();
  }
});

test("the memo keeps only the most recent cwd", () => {
  const f = fixture();
  const other = mkdtempSync(join(tmpdir(), "mcp-cwd2-"));
  try {
    f.write(join(f.agentDir, "mcp-cache.json"), cacheFile({ p: ["t"] }));
    f.write(join(f.cwd, ".mcp.json"), { mcpServers: { p: { url: "https://one.invalid" } } });
    f.write(join(other, ".mcp.json"), { mcpServers: { p: { url: "https://two.invalid" } } });
    const resolver = createMcpResolver({ env: f.env, homeDir: f.homeDir });
    assert.deepStrictEqual(resolver.resolve("p_t", {}, f.cwd)?.serverConfig, { url: "https://one.invalid" });
    assert.deepStrictEqual(resolver.resolve("p_t", {}, other)?.serverConfig, { url: "https://two.invalid" });
    assert.deepStrictEqual(resolver.resolve("p_t", {}, f.cwd)?.serverConfig, { url: "https://one.invalid" });
  } finally {
    f.cleanup();
    rmSync(other, { recursive: true, force: true });
  }
});
