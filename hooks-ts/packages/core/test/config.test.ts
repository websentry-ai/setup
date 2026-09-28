// RES-06 — identity resolution.
//
// Four key tiers (UNBOUND_PI_API_KEY -> UNBOUND_API_KEY -> ~/.unbound/config.json api_key -> none)
// and three URL tiers (UNBOUND_GATEWAY_URL -> config.gateway_url -> https://api.getunbound.ai),
// mirroring unbound-cli `src/config.js:95-97`. Every malformed / unreadable input must resolve to
// `undefined` rather than throw: an exception escaping a pi `tool_call` handler is a BLOCK
// (RESEARCH §F1), so a filesystem permission problem must never stop a developer's tool call.

import { chmodSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { createFakeHome } from "./helpers/fakeHome.ts";
import { DEFAULT_GATEWAY_URL, MAX_CONFIG_BYTES } from "../src/constants.ts";
import {
  normalizeGatewayUrl,
  readUnboundConfig,
  redactSecrets,
  resolveApiKey,
  resolveGatewayUrl,
} from "../src/config.ts";

const NO_ENV: NodeJS.ProcessEnv = {};

test("resolveApiKey: UNBOUND_PI_API_KEY beats the config file", () => {
  const home = createFakeHome({ api_key: "from-file" });
  try {
    assert.equal(
      resolveApiKey({ UNBOUND_PI_API_KEY: "from-pi-env", UNBOUND_API_KEY: "from-generic-env" }, home.homeDir),
      "from-pi-env",
    );
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: the generic UNBOUND_API_KEY is the second tier", () => {
  const home = createFakeHome({ api_key: "from-file" });
  try {
    assert.equal(resolveApiKey({ UNBOUND_API_KEY: "from-generic-env" }, home.homeDir), "from-generic-env");
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: falls back to config.json api_key when no env var is set", () => {
  const home = createFakeHome({ api_key: "from-file" });
  try {
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), "from-file");
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: no env and no config file -> undefined", () => {
  const home = createFakeHome();
  try {
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), undefined);
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: malformed JSON -> undefined, never throws", () => {
  const home = createFakeHome("{ not json");
  try {
    assert.doesNotThrow(() => resolveApiKey(NO_ENV, home.homeDir));
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), undefined);
    assert.deepEqual(readUnboundConfig(home.homeDir), {});
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: an unreadable config file -> undefined, never throws", { skip: process.getuid?.() === 0 ? "root can read 0000 files" : false }, () => {
  const home = createFakeHome({ api_key: "from-file" });
  const configFile = join(home.homeDir, ".unbound", "config.json");
  chmodSync(configFile, 0o000);
  try {
    assert.doesNotThrow(() => resolveApiKey(NO_ENV, home.homeDir));
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), undefined);
  } finally {
    chmodSync(configFile, 0o600);
    home.cleanup();
  }
});

test("resolveApiKey: a non-string or blank api_key is rejected", () => {
  const numeric = createFakeHome({ api_key: 12345 });
  const blank = createFakeHome({ api_key: "   " });
  const empty = createFakeHome({ api_key: "" });
  const usable = createFakeHome({ api_key: "from-file" });
  try {
    assert.equal(resolveApiKey(NO_ENV, numeric.homeDir), undefined);
    assert.equal(resolveApiKey(NO_ENV, blank.homeDir), undefined);
    assert.equal(resolveApiKey(NO_ENV, empty.homeDir), undefined);
    // …and a blank env var must not shadow a usable config value.
    assert.equal(resolveApiKey({ UNBOUND_PI_API_KEY: "  " }, usable.homeDir), "from-file");
  } finally {
    numeric.cleanup();
    blank.cleanup();
    empty.cleanup();
    usable.cleanup();
  }
});

test("readUnboundConfig: a blank or relative home is refused, never resolved against cwd", () => {
  // os.homedir() can throw and the pi adapter's fallback is "". join("", ".unbound/config.json")
  // would read the *repository* pi was started in, letting a planted file supply api_key and
  // gateway_url — i.e. ship the Bearer token to an attacker's https host and replace the policy
  // engine. Every non-absolute home must therefore read as "no config at all".
  const home = createFakeHome({ api_key: "from-file", gateway_url: "https://evil.example.com" });
  try {
    for (const bogus of ["", ".", "./x", "relative/path"]) {
      assert.deepEqual(readUnboundConfig(bogus), {});
      assert.equal(resolveApiKey(NO_ENV, bogus), undefined);
      assert.equal(resolveGatewayUrl(NO_ENV, bogus), "https://api.getunbound.ai");
    }
    // …and the absolute case still works, so this is a guard and not a regression.
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), "from-file");
  } finally {
    home.cleanup();
  }
});

test("resolveApiKey: surrounding whitespace is stripped from every tier", () => {
  // A padded key would be sent as `Bearer <key>\n`, which undici rejects as an invalid header
  // value (and the gateway would 401 anyway) — and both outcomes fail OPEN, i.e. silently no
  // enforcement at all. Every tier must therefore hand back a trimmed token.
  const home = createFakeHome({ api_key: "  from-file\n" });
  try {
    assert.equal(resolveApiKey({ UNBOUND_PI_API_KEY: "pi-key\n" }, home.homeDir), "pi-key");
    assert.equal(resolveApiKey({ UNBOUND_API_KEY: " generic-key " }, home.homeDir), "generic-key");
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), "from-file");
  } finally {
    home.cleanup();
  }
});

test("resolveGatewayUrl: a padded URL is still accepted", () => {
  const home = createFakeHome({ gateway_url: "\thttps://from-file.example.com\n" });
  try {
    assert.equal(
      resolveGatewayUrl({ UNBOUND_GATEWAY_URL: "  https://from-env.example.com  " }, home.homeDir),
      "https://from-env.example.com",
    );
    assert.equal(resolveGatewayUrl(NO_ENV, home.homeDir), "https://from-file.example.com");
  } finally {
    home.cleanup();
  }
});

test("resolveGatewayUrl: UNBOUND_GATEWAY_URL beats the config file", () => {
  const home = createFakeHome({ gateway_url: "https://zendesk-api.getunbound.ai" });
  try {
    assert.equal(
      resolveGatewayUrl({ UNBOUND_GATEWAY_URL: "https://api-gateway-staging.unboundsecurity.ai" }, home.homeDir),
      "https://api-gateway-staging.unboundsecurity.ai",
    );
  } finally {
    home.cleanup();
  }
});

test("resolveGatewayUrl: the config gateway_url is the second tier (custom-host tenant)", () => {
  const home = createFakeHome({ gateway_url: "https://zendesk-api.getunbound.ai" });
  try {
    assert.equal(resolveGatewayUrl(NO_ENV, home.homeDir), "https://zendesk-api.getunbound.ai");
  } finally {
    home.cleanup();
  }
});

test("resolveGatewayUrl: neither tier -> the default host", () => {
  const home = createFakeHome();
  try {
    assert.equal(resolveGatewayUrl(NO_ENV, home.homeDir), DEFAULT_GATEWAY_URL);
    assert.equal(resolveGatewayUrl(NO_ENV, home.homeDir), "https://api.getunbound.ai");
  } finally {
    home.cleanup();
  }
});

test("resolveGatewayUrl: a rejected env URL falls through to the next tier, it does not win", () => {
  const home = createFakeHome({ gateway_url: "https://zendesk-api.getunbound.ai" });
  try {
    assert.equal(
      resolveGatewayUrl({ UNBOUND_GATEWAY_URL: "http://example.com" }, home.homeDir),
      "https://zendesk-api.getunbound.ai",
    );
    // …and a rejected value in BOTH tiers reaches the default.
    const bad = createFakeHome({ gateway_url: "ftp://h" });
    try {
      assert.equal(resolveGatewayUrl({ UNBOUND_GATEWAY_URL: "not a url" }, bad.homeDir), DEFAULT_GATEWAY_URL);
    } finally {
      bad.cleanup();
    }
  } finally {
    home.cleanup();
  }
});

test("normalizeGatewayUrl: WR-09 — a non-root path prefix is PRESERVED, not truncated", () => {
  // The bug: a prefixed-tenant deployment (`https://host/unbound` behind an ingress path route or
  // an API-gateway stage) had its prefix dropped, so every request went to `https://host/v1/hooks/
  // pretool`, 404'd, and fell through to fail-open — forever, with no local signal. Framing the
  // truncation as hardening was wrong: in the scenario it defends against, the attacker already
  // controls the whole host.
  assert.equal(normalizeGatewayUrl("https://host/unbound"), "https://host/unbound");
  assert.equal(normalizeGatewayUrl("https://host/unbound/"), "https://host/unbound");
  assert.equal(normalizeGatewayUrl("https://host/a/b/c///"), "https://host/a/b/c");
  assert.equal(normalizeGatewayUrl("https://h:8443/x"), "https://h:8443/x");

  // A root path is still normalised away, so the base URL never ends in a slash and the
  // `${base}${PRETOOL_PATH}` concatenation cannot produce a double slash.
  assert.equal(normalizeGatewayUrl("https://host/"), "https://host");
  assert.equal(normalizeGatewayUrl("https://host"), "https://host");
  assert.equal(normalizeGatewayUrl("https://host///"), "https://host");
});

test("normalizeGatewayUrl: query and fragment are still dropped", () => {
  assert.equal(normalizeGatewayUrl("https://host/unbound?x=1#y"), "https://host/unbound");
  assert.equal(normalizeGatewayUrl("https://h/v1/hooks/pretool?a=b"), "https://h/v1/hooks/pretool");
  assert.equal(normalizeGatewayUrl("https://host/?a=b"), "https://host");
  assert.equal(normalizeGatewayUrl("https://host#frag"), "https://host");
});

test("normalizeGatewayUrl: a URL carrying userinfo is rejected outright", () => {
  // Credentials in the base URL would be concatenated into every request target and would ride
  // along beside the Bearer header. There is no legitimate prefixed-tenant case for this.
  assert.equal(normalizeGatewayUrl("https://user:pass@host/x"), undefined);
  assert.equal(normalizeGatewayUrl("https://user@host/x"), undefined);
  assert.equal(normalizeGatewayUrl("https://:pass@host"), undefined);
  assert.equal(normalizeGatewayUrl("http://user:pass@127.0.0.1:8799"), undefined);
});

test("normalizeGatewayUrl: the path prefix is part of the cache key, so it must be stable", () => {
  // `cache.ts` keys a record on this exact string. Two spellings of one deployment must collapse to
  // one key, or a tenant silently never gets a cache hit.
  const spellings = ["https://host/unbound", "https://host/unbound/", "https://host/unbound/?a=1"];
  const normalised = spellings.map((s) => normalizeGatewayUrl(s));
  assert.deepEqual(new Set(normalised), new Set(["https://host/unbound"]), JSON.stringify(normalised));
});

test("normalizeGatewayUrl: rejects empty, unparseable, non-http(s) and non-string input", () => {
  assert.equal(normalizeGatewayUrl(""), undefined);
  assert.equal(normalizeGatewayUrl("   "), undefined);
  assert.equal(normalizeGatewayUrl("not a url"), undefined);
  assert.equal(normalizeGatewayUrl("ftp://h"), undefined);
  assert.equal(normalizeGatewayUrl(undefined), undefined);
  assert.equal(normalizeGatewayUrl(12345), undefined);
  assert.doesNotThrow(() => normalizeGatewayUrl({ nested: true }));
});

test("normalizeGatewayUrl: V9 — plain http is rejected for a real host but exempted on loopback", () => {
  // A hostile UNBOUND_GATEWAY_URL must not receive the Bearer header in cleartext.
  assert.equal(normalizeGatewayUrl("http://example.com"), undefined);
  assert.equal(normalizeGatewayUrl("http://evil.internal:8799"), undefined);
  // WR-09 changed nothing here: a prefix on a hostile http host is still refused.
  assert.equal(normalizeGatewayUrl("http://evil.com/unbound"), undefined);
  // The documented exemption: the mock-API smoke (RESEARCH §E4a) runs over loopback http.
  assert.equal(normalizeGatewayUrl("http://127.0.0.1:8799"), "http://127.0.0.1:8799");
  assert.equal(normalizeGatewayUrl("http://localhost:8799"), "http://localhost:8799");
  assert.equal(normalizeGatewayUrl("http://[::1]:8799"), "http://[::1]:8799");
});

test("redactSecrets: strips Bearer values and the literal key", () => {
  const out = redactSecrets("failed with Bearer abc123 and key sk-liveKEY", "sk-liveKEY");
  assert.ok(!out.includes("abc123"), out);
  assert.ok(!out.includes("sk-liveKEY"), out);
  assert.ok(out.includes("Bearer [REDACTED]"), out);
});

test("redactSecrets: case-insensitive Bearer, no key, and short keys left alone", () => {
  assert.ok(!redactSecrets("bearer abc123").includes("abc123"));
  assert.equal(redactSecrets("plain text"), "plain text");
  // A key shorter than 8 chars is too generic to substitute safely (port of unbound.py:137-141).
  assert.equal(redactSecrets("value short", "short"), "value short");
  assert.doesNotThrow(() => redactSecrets("a+b(c)", "a+b(c)d?"));
  assert.ok(!redactSecrets("token a+b(c)d? here", "a+b(c)d?").includes("a+b(c)d?"));
});

// --- CR-01: the config read is bounded and non-blocking too ------------------------------------

test("readUnboundConfig: a FIFO config.json is an empty config, not a permanent hang (CR-01)", (t) => {
  if (process.platform === "win32") {
    t.skip("mkfifo is POSIX-only");
    return;
  }
  const home = createFakeHome();
  try {
    const configPath = join(home.homeDir, ".unbound", "config.json");
    execFileSync("mkfifo", [configPath], { stdio: "ignore" });

    // Run it in a child under a hard timeout: `readFileSync` on a writerless pipe blocks the only
    // thread, so no in-process timer could ever observe the hang it used to cause on `init()`.
    const moduleUrl = new URL("../src/config.ts", import.meta.url).href;
    const script = [
      `const { readUnboundConfig } = await import(${JSON.stringify(moduleUrl)});`,
      `const out = readUnboundConfig(${JSON.stringify(home.homeDir)});`,
      `process.stdout.write(JSON.stringify(out));`,
    ].join("\n");
    const out = execFileSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
      { timeout: 2000, killSignal: "SIGKILL", encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    assert.equal(out, "{}");
  } finally {
    home.cleanup();
  }
});

test("readUnboundConfig: a config above MAX_CONFIG_BYTES is refused, and identity falls through", () => {
  // Padded past the cap with a key nothing reads, so the only thing under test is the size guard.
  const home = createFakeHome({ api_key: "from-file", pad: "x".repeat(MAX_CONFIG_BYTES) });
  try {
    assert.deepEqual(readUnboundConfig(home.homeDir), {});
    // An unreadable config is an INERT extension, never a block: no key, default URL.
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), undefined);
    assert.equal(resolveGatewayUrl(NO_ENV, home.homeDir), DEFAULT_GATEWAY_URL);
  } finally {
    home.cleanup();
  }
});

test("readUnboundConfig: a symlinked config.json is refused even when the target is valid (CR-01)", (t) => {
  if (process.platform === "win32") {
    t.skip("symlink creation needs a privilege on Windows");
    return;
  }
  const home = createFakeHome();
  try {
    const target = join(home.homeDir, "real_config.json");
    writeFileSync(target, JSON.stringify({ api_key: "from-link" }), { encoding: "utf8", mode: 0o600 });
    symlinkSync(target, join(home.homeDir, ".unbound", "config.json"));

    // Following the link is what would let a symlink-to-FIFO block; `unbound login` writes a real
    // file, so nothing legitimate is lost by refusing one.
    assert.deepEqual(readUnboundConfig(home.homeDir), {});
    assert.equal(resolveApiKey(NO_ENV, home.homeDir), undefined);
  } finally {
    home.cleanup();
  }
});
