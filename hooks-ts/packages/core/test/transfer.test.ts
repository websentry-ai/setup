// Transfer resolution — the Pi port of the Python hooks' transfer block. The shared corpus in
// tests/fixtures/transfer_cases.json is checked here and by tests/test_transfer_destination.py, so the same command
// sends the same `transfer` field from every hook.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

import { defaultExecFile, type ExecFileLike } from "../src/accountIdentity.ts";
import {
  ipv4Mapped, platform, resolveTransfers, transferCommand, type LookupLike, type ResolveOptions, type Transfer,
} from "../src/transfer.ts";

interface Fixture {
  addresses: Record<string, string[]>;
  ssh_hosts: Record<string, string>;
  hook_env: Record<string, string>;
  /** env is what the agent's shell passes on, such as a proxy. */
  cases: { command: string; transfer: Transfer | null; env?: Record<string, string> }[];
}

const FIXTURE = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "..", "..", "..", "..", "tests", "fixtures", "transfer_cases.json"), "utf8"),
) as Fixture;
// Not a real credential; it only has to sit where a login goes.
const FAKE_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"; // gitleaks:allow
const EMPTY_HOME = mkdtempSync(join(tmpdir(), "transfer-home-"));

const lookup: LookupLike = async (host) => {
  const found = FIXTURE.addresses[host];
  if (found === undefined) throw new Error("ENOTFOUND");
  return found;
};

/** A config's lines with each Include read in place, its Host blocks ending with it, as ssh does. */
function configLines(path: string, depth = 0): string[] {
  if (depth > 8 || !existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").flatMap((line) => {
    const [key, ...targets] = line.trim().split(/\s+/);
    if (key?.toLowerCase() !== "include") return [line];
    return targets.flatMap((target) => [...configLines(target.replace(/^"|"$/g, ""), depth + 1), "Host \0end"]);
  });
}

/** ssh -G answered from the fixture's hosts, -o HostName and a `-F` file's `Host`/`HostName` lines; each call logged. */
function fakeSsh(calls: string[][] = []): ExecFileLike {
  return async (file, args) => {
    calls.push([file, ...args]);
    if (file !== "ssh" || args[0] !== "-G") return undefined;
    let destination = "";
    let hostname: string | undefined;
    let config: string | undefined;
    for (let i = 1; i < args.length; i += 2) {
      if (args[i] === "--") destination = args[i + 1] as string;
      else if (args[i] === "-o" && /^hostname=/i.test(args[i + 1] as string)) hostname = (args[i + 1] as string).split("=")[1];
      else if (args[i] === "-F") config = args[i + 1];
    }
    const host = destination.split("@").pop() as string;
    let jump: string | undefined;
    if (config !== undefined && config !== "none") {
      let current: string[] = [];
      for (const line of configLines(config)) {
        const [key, ...values] = line.trim().split(/\s+/);
        if (key?.toLowerCase() === "host") current = values;
        else if (key?.toLowerCase() === "hostname" && current.includes(host)) hostname ??= values[0];
        else if (key?.toLowerCase() === "proxyjump" && current.includes(host)) jump ??= values.join(" ");
      }
    }
    // As some ssh versions print it for a host with neither.
    return `hostname ${(hostname ?? FIXTURE.ssh_hosts[host] ?? host).toLowerCase()}\nport 22\nproxyjump ${jump ?? "none"}\nproxycommand none\n`;
  };
}

function options(extra: ResolveOptions = {}): ResolveOptions {
  return { execFile: fakeSsh(), lookup, home: EMPTY_HOME, env: {}, ...extra };
}

async function transfer(command: string, cwd?: string, extra: ResolveOptions = {}): Promise<Transfer | undefined> {
  const found = await resolveTransfers([{ tool_name: "bash", tool_use_id: "c1", tool_input: { command } }], cwd, options(extra));
  return found.get("c1");
}

async function hosts(command: string, cwd?: string): Promise<[string, string][]> {
  return ((await transfer(command, cwd))?.endpoints ?? []).map((e): [string, string] => [e.direction ?? "", e.host]);
}

/** A repo whose `cfg` maps prod to a public address and whose frontend/cfg maps it to a private one. */
function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "transfer-repo-"));
  mkdirSync(join(dir, "frontend"));
  writeFileSync(join(dir, "cfg"), "Host prod\n  HostName 203.0.113.9\n");
  writeFileSync(join(dir, "frontend", "cfg"), "Host prod\n  HostName 10.0.4.12\n");
  return dir;
}

test("every command in the shared corpus sends the same transfer as the Python hooks", async () => {
  // hook_env is the hook's own environment: none of its values may reach a host, a lookup or ssh -G.
  const seen: string[] = [];
  const calls: string[][] = [];
  const recording: LookupLike = async (host) => {
    seen.push(host);
    return lookup(host);
  };
  for (const { command, transfer: expected, env } of FIXTURE.cases) {
    const found = await transfer(command, "/", { env: { ...FIXTURE.hook_env, ...env }, lookup: recording, execFile: fakeSsh(calls) });
    assert.deepEqual(found ?? null, expected, command);
  }
  for (const value of Object.values(FIXTURE.hook_env)) assert.ok(!JSON.stringify([seen, calls]).includes(value), value);
});

test("the hook's own remote shell never reaches ssh -G", async () => {
  // Only text the command wrote may reach a lookup; an RSYNC_RSH the hook inherited stays unknown.
  const calls: string[][] = [];
  const env = { RSYNC_RSH: "ssh -o HostName=leak.example" };
  for (const command of ["rsync -a src prod:/dest", "export RSYNC_RSH; rsync -a src prod:/dest"]) {
    const found = await transfer(command, "/", { env, execFile: fakeSsh(calls) });
    assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }], command);
  }
  const set = await transfer('RSYNC_RSH="ssh -o HostName=10.9.9.9" rsync -a src prod:/dest', "/", { env, execFile: fakeSsh(calls) });
  assert.equal(set?.endpoints[0]?.resolved_host, "10.9.9.9");
  assert.ok(!JSON.stringify(calls).includes("leak.example"));
});

test("a command nested too deep sends no transfer, and the turn's later calls still do", async () => {
  const deep = "{ ".repeat(101) + "curl https://example.com/a" + "; }".repeat(101);
  const found = await resolveTransfers([
    { tool_name: "bash", tool_use_id: "c1", tool_input: { command: deep } },
    { tool_name: "bash", tool_use_id: "c2", tool_input: { command: "curl https://example.com/b" } },
  ], "/", options());
  assert.equal(found.get("c1"), undefined);
  assert.equal(found.get("c2")?.endpoints[0]?.host, "example.com");
});

test("an IPv4-mapped address is read as its IPv4 address in every form, as Python's ipaddress does", () => {
  // Converted first, so the kind never depends on how a Node version's BlockList treats a mapped address.
  for (const mapped of ["::ffff:10.0.0.1", "::ffff:a00:1", "0:0:0:0:0:ffff:a00:1", "::FFFF:A00:1"]) {
    assert.equal(ipv4Mapped(mapped), "10.0.0.1", mapped);
  }
  assert.equal(ipv4Mapped("::ffff:0:1"), "0.0.0.1");
  for (const other of ["fe80::1", "::1", "2001:db8::ffff:a00:1", "10.0.0.1", "example.com"]) {
    assert.equal(ipv4Mapped(other), other, other);
  }
});

test("a one-letter host is a drive only on Windows", async () => {
  // Windows OpenSSH reads C:file as a local path; elsewhere scp dials host a.
  assert.deepEqual(await hosts("scp build.zip a:/srv", "/"), [["out", "a"]]);
  const before = platform.windows;
  platform.windows = true;
  try {
    for (const command of ["scp C:file prod:/srv", "scp c:/dir/file prod:/srv"]) {
      assert.deepEqual(await hosts(command, "/"), [["out", "prod"]], command);
    }
    assert.equal(await transfer("scp build.zip a:/srv", "/"), undefined);
  } finally {
    platform.windows = before;
  }
});

test("transfer_command is read in place of the capped command, and its length cap still applies", async () => {
  const found = await resolveTransfers([
    { tool_name: "bash", tool_use_id: "c1", tool_input: { command: "echo cut" }, transfer_command: "curl https://example.com/a" },
    { tool_name: "bash", tool_use_id: "c2", tool_input: { command: "echo" }, transfer_command: transferCommand(": " + "x".repeat(30_000) + "; curl https://example.com/b") },
  ], "/", options());
  assert.equal(found.get("c1")?.endpoints[0]?.host, "example.com");
  assert.equal(found.get("c2"), undefined);
  assert.equal(transferCommand("x".repeat(30_000)).length, 20_001);
  assert.equal(transferCommand("curl https://example.com/a"), "curl https://example.com/a");
});

// The ssh on PATH; ssh -G runs a Match exec command, which these lookups never must.
const REAL_SSH = (process.env.PATH ?? "").split(delimiter).filter(Boolean).map((dir) => join(dir, "ssh")).find(existsSync);

test("a Match exec never runs however the config reaches ssh", { skip: REAL_SSH === undefined }, async () => {
  // Each config is shown to run its command when handed to ssh -G directly, then never runs through the lookup.
  const folder = repo();
  const home = mkdtempSync(join(tmpdir(), "transfer-sentinel-home-"));
  mkdirSync(join(home, ".ssh"));
  const sentinel = join(mkdtempSync(join(tmpdir(), "transfer-sentinel-")), "ran");
  const evil = `Match exec "touch ${sentinel}"\n  HostName 10.6.6.6\n`;
  const safe = "Host prod\n  HostName 10.0.4.12\n";
  writeFileSync(join(folder, "evil.conf"), evil);
  mkdirSync(join(folder, "conf.d"));
  writeFileSync(join(folder, "conf.d", "b.conf"), evil);
  writeFileSync(join(home, "evil.conf"), evil);
  writeFileSync(join(home, ".ssh", "rel.conf"), evil);
  const forms: Record<string, string> = {
    direct: evil, include: `Include ${folder}/evil.conf\n${safe}`, glob: `Include ${folder}/conf.d/*.conf\n${safe}`,
    tilde: `Include ~/evil.conf\n${safe}`, relative: `Include rel.conf\n${safe}`, nested: `Include ${folder}/include\n${safe}`,
  };
  const real = { execFile: undefined, home, env: { HOME: home, PATH: process.env.PATH } };
  const unresolved = [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }];
  for (const [name, text] of Object.entries(forms)) {
    writeFileSync(join(folder, name), text);
    if (name !== "tilde" && name !== "relative") {
      // ssh puts those two under the account's own home.
      spawnSync(REAL_SSH as string, ["-G", "-F", join(folder, name), "--", "prod"], { cwd: folder, timeout: 10_000 });
      assert.ok(existsSync(sentinel), name);
      rmSync(sentinel);
    }
    assert.deepEqual((await transfer(`scp -F ${name} f prod:/tmp`, folder, real))?.endpoints, unresolved, name);
    assert.ok(!existsSync(sentinel), name);
  }
  // The account's own config, read when no -F is given.
  writeFileSync(join(home, ".ssh", "config"), evil);
  assert.deepEqual((await transfer("scp f prod:/tmp", folder, real))?.endpoints, unresolved);
  assert.ok(!existsSync(sentinel));
});

test("a Match exec split by a trailing backslash never runs", { skip: REAL_SSH === undefined }, async () => {
  // ssh joins no lines, so the split line is a bad option to it; the check refuses any line ending in a backslash.
  const folder = repo();
  const sentinel = join(mkdtempSync(join(tmpdir(), "transfer-sentinel-")), "ran");
  const split = `Match host prod \\\n  exec "touch ${sentinel}"\n  HostName 10.6.6.6\n`;
  writeFileSync(join(folder, "split"), split);
  writeFileSync(join(folder, "split.conf"), split);
  writeFileSync(join(folder, "includes"), `Include ${folder}/split.conf\nHost prod\n  HostName 10.0.4.12\n`);
  writeFileSync(join(folder, "canon"), "CanonicalizeHostname \\\nyes\nHost prod\n  HostName 10.0.4.12\n");
  for (const name of ["split", "includes", "canon"]) {
    const ran: string[][] = [];
    const counting: ExecFileLike = (file, args, opts) => {
      ran.push([file, ...args]);
      return defaultExecFile(file, args, opts);
    };
    const found = await transfer(`scp -F ${name} f prod:/tmp`, folder, { execFile: counting, env: { PATH: process.env.PATH } });
    assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }], name);
    assert.deepEqual(ran, [], name); // refused before ssh -G ever starts
    assert.ok(!existsSync(sentinel), name);
  }
});

test("a host reached through a jump host or proxy command is never looked up", async () => {
  // The jump host or proxy resolves it, so neither ssh -G nor DNS runs here; an address as written still counts.
  const dir = repo();
  const calls: string[][] = [];
  const seen: string[] = [];
  const recording: LookupLike = async (host) => {
    seen.push(host);
    return lookup(host);
  };
  const extra = { execFile: fakeSsh(calls), lookup: recording };
  for (const command of [
    "scp -J jump f prod:/tmp", "scp -o ProxyJump=jump f prod:/tmp", "scp -o 'ProxyCommand nc %h %p' f prod:/tmp",
    "ssh -J jump prod cat < f", 'rsync -a -e "ssh -J jump" f prod:/tmp',
  ]) {
    assert.deepEqual((await transfer(command, dir, extra))?.endpoints,
      [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }], command);
  }
  assert.equal((await transfer("scp -J jump f 10.0.4.12:/tmp", dir, extra))?.endpoints[0]?.address, "private");
  assert.deepEqual([calls, seen], [[], []]);
  // A jump host the config names, as ssh -G reports it, carries the bytes where it sends them, so neither the config's
  // HostName nor its address is reported.
  writeFileSync(join(dir, "jump_cfg"), "Host prod\n  HostName files.acme-infra.net\n  ProxyJump bastion\n");
  assert.deepEqual((await transfer("scp -F jump_cfg f prod:/tmp", dir, extra))?.endpoints,
    [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }]);
  writeFileSync(join(dir, "jump_cfg"), "Host prod\n  HostName files.acme-infra.net\n");
  assert.deepEqual((await transfer("scp -F jump_cfg f prod:/tmp", dir, extra))?.endpoints,
    [{ direction: "out", host: "prod", resolved_host: "files.acme-infra.net", address: "private" }]);
});

test("ssh reads the copy that was checked, not the file as it is later", { skip: REAL_SSH === undefined }, async () => {
  // The config turns into one that runs a command after the check and before ssh starts; ssh never sees it.
  const folder = repo();
  const sentinel = join(mkdtempSync(join(tmpdir(), "transfer-sentinel-")), "ran");
  writeFileSync(join(folder, "swap"), "Host prod\n  HostName 10.0.4.12\n");
  const swapThenRun: ExecFileLike = (file, args, opts) => {
    writeFileSync(join(folder, "swap"), `Match exec "touch ${sentinel}"\n  HostName 10.6.6.6\n`);
    return defaultExecFile(file, args, opts);
  };
  const found = await transfer("scp -F swap f prod:/tmp", folder, { execFile: swapThenRun, env: { PATH: process.env.PATH } });
  assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "10.0.4.12", address: "private" }]);
  assert.ok(!existsSync(sentinel));
});

test("ssh -G runs through a fake ssh on PATH, with the options that change the host", async () => {
  const bin = mkdtempSync(join(tmpdir(), "transfer-bin-"));
  const log = join(bin, "calls.log");
  writeFileSync(
    join(bin, "ssh"),
    `#!/usr/bin/env node\nrequire("node:fs").appendFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)) + "\\n");\n` +
      `const a = process.argv.slice(2); const o = a.indexOf("-o");\n` +
      `console.log("hostname " + (o >= 0 ? a[o + 1].split("=")[1] : "10.0.4.12"));\n`,
  );
  chmodSync(join(bin, "ssh"), 0o755);
  const path = process.env.PATH;
  process.env.PATH = `${bin}${delimiter}${path ?? ""}`;
  try {
    const found = await resolveTransfers(
      [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command: "scp -P 2222 -o HostName=10.9.9.9 -o ProxyJump=none f prod:/tmp" } }],
      "/", { lookup, home: EMPTY_HOME, env: {} },
    );
    assert.deepEqual(found.get("c1"), {
      tool: "scp",
      endpoints: [{ direction: "out", host: "prod", resolved_host: "10.9.9.9", address: "private" }],
    });
    const argv = (JSON.parse(readFileSync(log, "utf8").trim()) as string[]).map((arg) => (arg.includes("unbound-ssh-") ? "<vetted>" : arg));
    assert.deepEqual(argv, ["-G", "-F", "<vetted>", "-p", "2222", "-o", "HostName=10.9.9.9", "-o", "ProxyJump=none", "--", "prod"]);
  } finally {
    process.env.PATH = path;
  }
});

test("every tool's out and in", async () => {
  const cases: [string, [string, string][]][] = [
    ["curl -F file=@a.zip https://example.com/u", [["out", "example.com"]]],
    ["curl --request put https://example.com/u", [["out", "example.com"]]],
    ["curl -X DELETE https://example.com/u", [["in", "example.com"]]],
    ["wget --body-data x --method PUT https://example.com/u", [["out", "example.com"]]],
    ["wget -O a.zip https://example.com/a.zip", [["in", "example.com"]]],
    ["scp a b", []],
    ["rsync -a src prod::module", [["out", "prod"]]],
    ["rsync -a prod:/a example.com:/b", [["in", "prod"], ["out", "example.com"]]],
    ["sftp -b batch.txt sftp://deploy@prod:2222/srv", [["in", "prod"]]],
    ["ssh prod 'tar c /srv' | tar x", [["in", "prod"]]],
    ["ssh prod uptime > /dev/null", []],
    ["nc -w 3 example.com 80 < req.txt", [["out", "example.com"]]],
    ["netcat example.com 80", [["", "example.com"]]],
    ["nc -U /tmp/sock", []],
    ["socat - PROXY:proxy.corp:example.com:443,proxyport=3128", [["", "example.com"]]],
    ["socat - UNIX-CONNECT:/tmp/sock", []],
    ["http example.com/api config:=@cfg.json", [["out", "example.com"]]],
    ["http PUT example.com/api < body.json", [["out", "example.com"]]],
    ["http --ignore-stdin example.com/api < body.json", [["in", "example.com"]]],
    ["http --offline POST example.com/api a=1", []],
    ["Get-Content a.json | Invoke-RestMethod https://example.com/api", [["out", "example.com"]]],
    ["invoke-webrequest -uri https://example.com/up -form $form", [["out", "example.com"]]],
    ["irm https://example.com/api -Method:Put", [["out", "example.com"]]],
    ["iwr https://example.com/a.zip -UseBasicParsing", [["in", "example.com"]]],
    ["pwsh -c 'irm https://example.com/api'", [["in", "example.com"]]],
  ];
  for (const [command, expected] of cases) assert.deepEqual(await hosts(command), expected, command);
});

test("no login, password, token, path or URL reaches the field", async () => {
  for (const command of [
    `curl https://jdoe:${FAKE_TOKEN}@example.com/x`,
    `curl -u jdoe:${FAKE_TOKEN} https://example.com/x`, // gitleaks:allow
    `wget https://jdoe:${FAKE_TOKEN}@example.com/x`,
    `scp f scp://jdoe:${FAKE_TOKEN}@example.com/tmp`,
    "rsync -a f jdoe@example.com:/tmp",
    `ssh jdoe:${FAKE_TOKEN}@example.com 'cat > f' < f`,
    `http -a jdoe:${FAKE_TOKEN} example.com/x`,
    `iwr -Uri https://jdoe:${FAKE_TOKEN}@example.com/x?token=abc -OutFile x`,
  ]) {
    const found = await transfer(command);
    assert.equal(found?.endpoints[0]?.host, "example.com", command);
    const text = JSON.stringify(found);
    for (const secret of [FAKE_TOKEN, "jdoe", "token", "/x", "/tmp"]) assert.ok(!text.includes(secret), `${secret} in ${text}`);
    assert.deepEqual(Object.keys(found ?? {}), ["tool", "endpoints"]);
  }
});

test("the address kinds", async () => {
  const cases: Record<string, string> = {
    "https://files.acme-infra.net/x": "private",
    "https://vpn.acme.internal/x": "private",
    "http://192.168.1.10/x": "private",
    "http://172.20.0.5/x": "private",
    "https://example.com/x": "public",
    "http://8.8.8.8/x": "public",
    "https://split.example/x": "public",
    "https://cgnat.example/x": "cgnat",
    "http://100.100.1.1/x": "cgnat",
    "https://metadata.example/x": "link_local",
    "http://localhost:8080/x": "loopback",
    "http://[::ffff:10.1.2.3]/x": "private",
    "https://nowhere.invalid/x": "unresolved",
  };
  for (const [url, kind] of Object.entries(cases)) assert.equal((await transfer(`curl ${url}`))?.endpoints[0]?.address, kind, url);
});

test("an ssh config that could run commands is never handed to ssh, and sudo or a dash-led destination never is", async () => {
  const home = mkdtempSync(join(tmpdir(), "transfer-unsafe-"));
  mkdirSync(join(home, ".ssh"));
  writeFileSync(join(home, ".ssh", "config"), 'Match host * exec "touch /tmp/never"\n');
  const calls: string[][] = [];
  const found = await transfer("scp f prod:/tmp", "/", { home, execFile: fakeSsh(calls) });
  assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }]);
  const dir = repo();
  writeFileSync(join(dir, "canon"), "CanonicalizeHostname yes\n");
  await transfer("scp -F canon f prod:/tmp", dir, { execFile: fakeSsh(calls) });
  await transfer("sudo -u deploy scp f prod:/tmp", "/", { execFile: fakeSsh(calls) });
  await transfer("ssh -- -Fevil:x < f", "/", { execFile: fakeSsh(calls) });
  assert.deepEqual(calls, []);
});

test("Match criteria are read as ssh reads them", async () => {
  // Only an exec criterion runs a command; a host pattern that starts with exec does not.
  const dir = repo();
  const calls: string[][] = [];
  writeFileSync(join(dir, "host"), "Match host exec-prod\n  HostName 10.1.1.1\n");
  await transfer("scp -F host f prod:/tmp", dir, { execFile: fakeSsh(calls) });
  assert.equal(calls.length, 1);
  for (const config of ["Match exec=true\n", 'Match !exec "true"\n', 'Match canonical exec "true"\n']) {
    writeFileSync(join(dir, "run"), config);
    await transfer("scp -F run f prod:/tmp", dir, { execFile: fakeSsh(calls) });
  }
  assert.equal(calls.length, 1);
});

test("a failed or refused ssh -G never falls back to looking up the host as written", async () => {
  // Looking up the alias itself would classify a host the config may send elsewhere.
  const dir = repo();
  writeFileSync(join(dir, "exec.cfg"), 'Match exec "true"\n');
  const lookups: string[] = [];
  const recording: LookupLike = async (host) => (lookups.push(host), lookup(host));
  const failing: ExecFileLike = async () => undefined;
  const expected = [{ direction: "out", host: "example.com", resolved_host: "example.com", address: "unresolved" }];
  assert.deepEqual((await transfer("scp f example.com:/tmp", dir, { execFile: failing, lookup: recording }))?.endpoints, expected);
  for (const command of ["scp -F exec.cfg f example.com:/tmp", "scp -F '~/cfg' f example.com:/tmp"]) {
    assert.deepEqual((await transfer(command, dir, { lookup: recording }))?.endpoints, expected, command);
  }
  assert.deepEqual(lookups, []);
});

test("a hanging lookup is cut off, the turn ends on time, and a spent budget runs nothing", async () => {
  let release: () => void = () => {};
  const hung = new Promise<void>((done) => (release = done));
  const hang: LookupLike = async () => {
    await hung;
    return ["93.184.216.34"];
  };
  const started = Date.now();
  const command = Array.from({ length: 6 }, (_, n) => `curl https://slow${n}.example/x`).join("; ");
  const found = await transfer(command, "/", { lookup: hang, budgetMs: 2_500 });
  assert.ok(Date.now() - started < 2_000, `took ${Date.now() - started} ms`);
  assert.deepEqual(new Set(found?.endpoints.map((e) => e.address)), new Set(["unresolved"]));
  assert.equal(found?.endpoints.length, 6);
  release();
  await sleep(10);

  const slowSsh: ExecFileLike = (_file, _args, opts) => new Promise((done) => setTimeout(() => done(undefined), opts.timeoutMs));
  const cut = Date.now();
  const viaSsh = await transfer("scp f prod:/tmp", "/", { execFile: slowSsh, budgetMs: 300 });
  assert.ok(Date.now() - cut < 1_000);
  assert.deepEqual(viaSsh?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }]);

  const calls: string[][] = [];
  let lookups = 0;
  const spent = await transfer("scp f prod:/tmp; curl https://example.com", "/", {
    execFile: fakeSsh(calls), lookup: async () => (lookups++, []), budgetMs: 0,
  });
  assert.deepEqual(new Set(spent?.endpoints.map((e) => e.address)), new Set(["unresolved"]));
  assert.deepEqual([calls.length, lookups], [0, 0]);
});

test("only ssh -G is ever run, a call that never ran is not resolved, and errors return what resolved", async () => {
  const calls: string[][] = [];
  const found = await resolveTransfers(
    [
      { tool_name: "bash", tool_use_id: "a", decision: "allow", tool_input: { command: "scp f prod:/x; curl -T f https://example.com; rsync -a f prod:/y" } },
      { tool_name: "bash", tool_use_id: "b", decision: "deny", tool_input: { command: "curl https://example.com" } },
      { tool_name: "bash", tool_use_id: "c", decision: "confirm", ran: false, tool_input: { command: "curl https://example.com" } },
      { tool_name: "read", tool_use_id: "d", tool_input: { command: "curl https://example.com" } },
    ],
    "/", options({ execFile: fakeSsh(calls) }),
  );
  assert.deepEqual([...found.keys()], ["a"]);
  assert.ok(calls.length > 0 && calls.every((c) => c[0] === "ssh" && c[1] === "-G"), JSON.stringify(calls));
  const throwing = await resolveTransfers([{ tool_name: "bash", tool_use_id: "x", tool_input: { command: "curl https://example.com" } }], "/",
    options({ lookup: () => { throw new Error("boom"); } }));
  assert.equal(throwing.get("x")?.endpoints[0]?.address, "unresolved");
});

test("curl reads an attached or expanded value as curl does", async () => {
  for (const command of [
    "curl --data=hello https://example.com/up",
    "curl --upload-file=build.zip https://example.com/up",
    "curl --json=@payload.json https://example.com/up",
    "curl --form=file=@a.zip https://example.com/up",
    "curl --request=PUT https://example.com/up",
    "curl --url=https://example.com/up --data-binary=@build.zip",
    "curl --expand-data '{{body}}' https://example.com/up",
  ]) assert.deepEqual(await hosts(command), [["out", "example.com"]], command);
  assert.deepEqual(await hosts("curl --output=page.html --proxy=http://proxy.corp:3128 https://example.com/x"), [["in", "example.com"]]);
});

test("each curl --next starts a request with its own options", async () => {
  assert.deepEqual(await hosts("curl -T build.zip https://files.acme-infra.net/up --next https://example.com/file"),
    [["out", "files.acme-infra.net"], ["in", "example.com"]]);
  assert.deepEqual(await hosts("curl https://example.com/a -: -d x https://files.acme-infra.net/up"),
    [["in", "example.com"], ["out", "files.acme-infra.net"]]);
  // A --next or -: that is another option's value is that value, not a new request.
  assert.deepEqual(await hosts("curl --data --next https://example.com/a"), [["out", "example.com"]]);
  assert.deepEqual(await hosts("curl -d -: https://example.com/a"), [["out", "example.com"]]);
});

test("a negated command still obeys the && or || before it", async () => {
  for (const command of [
    "false && ! curl -T x https://never.example/a; curl https://actual.example/b",
    "false && ! echo $(curl https://never.example/a); curl https://actual.example/b",
    "true || ! echo $(curl https://never.example/a); curl https://actual.example/b",
  ]) assert.deepEqual(await hosts(command), [["in", "actual.example"]], command);
  assert.deepEqual(await hosts("true && ! curl https://ran.example/a"), [["in", "ran.example"]]);
  // A skipped `!` must not flip the status of the next command.
  const cases: [string, [string, string][]][] = [
    ["false && ! true; false && curl https://never.example/a", []],
    ["false && ! true; true && curl https://ran.example/a", [["in", "ran.example"]]],
    ["true || ! false; true && curl https://ran.example/a", [["in", "ran.example"]]],
    ["if false; then ! true; fi; false && curl https://never.example/a", []],
  ];
  for (const [command, expected] of cases) assert.deepEqual(await hosts(command), expected, command);
});

test("a function written name () is only defined, not run", async () => {
  for (const command of [
    "f () { curl -T x https://never.example/a; }; curl https://actual.example/b",
    "function f () { curl -T x https://never.example/a; }; curl https://actual.example/b",
    "if true; then f () { curl https://never.example/a; }; fi; curl https://actual.example/b",
    "{ f() { curl https://never.example/a; }; }; curl https://actual.example/b",
    "while true; do g () { curl https://never.example/a; }; break; done; curl https://actual.example/b",
  ]) assert.deepEqual(await hosts(command), [["in", "actual.example"]], command);
});

test("a compound's pipes and redirections reach the commands inside it", async () => {
  const cases: [string, [string, string][]][] = [
    ["tar c . | (ssh prod 'tar x -C /srv')", [["out", "prod"]]],
    ["(ssh prod 'tar c /srv') > backup.tar", [["in", "prod"]]],
    ["{ ssh prod 'tar c /srv'; } > backup.tar", [["in", "prod"]]],
    ["tar c . | { cd /tmp && ssh prod 'tar x'; }", [["out", "prod"]]],
    ["if true; then nc example.com 80; fi < request.txt", [["out", "example.com"]]],
    ["case x in *) ssh prod 'tar c /srv';; esac | tar x", [["in", "prod"]]],
    ["echo $(ssh prod 'cat f') > out.txt", []],
  ];
  for (const [command, expected] of cases) assert.deepEqual(await hosts(command), expected, command);
  const dir = repo();
  for (const command of ["{ cd frontend; } & scp -F cfg f prod:/tmp", "if true; then cd frontend; fi & scp -F cfg f prod:/tmp"]) {
    assert.equal((await transfer(command, dir))?.endpoints[0]?.resolved_host, "203.0.113.9", command);
  }
});

test("a followed command string shares its wrapper's pipes and redirections", async () => {
  const cases: [string, [string, string][]][] = [
    [`tar c . | sh -c "ssh prod 'tar x -C /srv'"`, [["out", "prod"]]],
    [`sh -c "ssh prod 'tar c /srv'" > backup.tar`, [["in", "prod"]]],
    [`bash -c "nc example.com 80" < request.txt`, [["out", "example.com"]]],
    [`Get-Content a.json | powershell -Command "Invoke-RestMethod https://example.com/api"`, [["out", "example.com"]]],
  ];
  for (const [command, expected] of cases) assert.deepEqual(await hosts(command), expected, command);
});

test("Includes are checked under $HOME as well as the account's home", async () => {
  // ssh reads ~/.ssh/config from the account's home but expands an Include with $HOME.
  const elsewhere = mkdtempSync(join(tmpdir(), "transfer-env-home-"));
  mkdirSync(join(elsewhere, ".ssh", "config.d"), { recursive: true });
  writeFileSync(join(elsewhere, ".ssh", "config.d", "x.conf"), 'Match exec "touch /tmp/never"\n');
  writeFileSync(join(elsewhere, ".ssh", "other.conf"), 'Match exec "touch /tmp/never"\n');
  const dir = repo();
  writeFileSync(join(dir, "relative_cfg"), "Include config.d/*.conf\nHost prod\n  HostName 10.0.4.12\n");
  writeFileSync(join(dir, "tilde_cfg"), "Include ~/.ssh/other.conf\nHost prod\n  HostName 10.0.4.12\n");
  const calls: string[][] = [];
  for (const config of ["relative_cfg", "tilde_cfg"]) {
    const found = await transfer(`scp -F ${config} f prod:/tmp`, dir, { execFile: fakeSsh(calls), env: { HOME: elsewhere } });
    assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }], config);
  }
  assert.deepEqual(calls, []);
});

test("sudo around a command string still skips ssh -G", async () => {
  const calls: string[][] = [];
  for (const command of ["sudo -u deploy sh -c 'scp f prod:/tmp'", `sudo bash -c "tar c . | ssh prod 'tar x'"`]) {
    const found = await transfer(command, "/", { execFile: fakeSsh(calls) });
    assert.deepEqual(found?.endpoints, [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }], command);
  }
  assert.deepEqual(calls, []);
});

test("a substitution under an untaken branch or a function body does not run", async () => {
  for (const command of [
    "if false; then echo $(curl -T x https://never.example/a); fi; curl https://actual.example/b",
    'if true; then :; else echo "$(curl https://never.example/a)"; fi; curl https://actual.example/b',
    'f() { echo "$(curl -T x https://never.example/a)"; }; curl https://actual.example/b',
    "function f { echo `curl https://never.example/a`; }; curl https://actual.example/b",
    "while false; do echo $(curl https://never.example/a); done; curl https://actual.example/b",
  ]) assert.deepEqual(await hosts(command), [["in", "actual.example"]], command);
  assert.deepEqual(await hosts("if [ -f x ]; then echo $(curl https://maybe.example/a); fi"), [["in", "maybe.example"]]);
});

test("the five parser findings", async () => {
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  // A short-circuited group is skipped whole.
  for (const command of [
    "false && (echo skipped; curl -T f https://never.example/x); curl https://actual.example/y",
    "true || (echo skipped; curl -T f https://never.example/x); curl https://actual.example/y",
    "false && { echo skipped; curl -T f https://never.example/x; }; curl https://actual.example/y",
  ]) assert.deepEqual(await hosts(command, dir), [["in", "actual.example"]], command);
  // A ) in a case pattern does not end the subshell.
  assert.equal(await at("(cd frontend; case x in y) true;; esac; scp -F cfg f prod:/tmp)"), "10.0.4.12");
  // A substitution inside double quotes runs.
  assert.equal(await at('echo "$(cd frontend && scp -F cfg f prod:/tmp)"'), "10.0.4.12");
  // Untaken branches and function bodies do not run.
  assert.deepEqual(await hosts("if false; then curl https://never.example/a; else curl https://actual.example/b; fi"), [["in", "actual.example"]]);
  assert.deepEqual(await hosts("function f { curl -T x https://never.example/a; }; curl https://actual.example/b"), [["in", "actual.example"]]);
  for (const command of [
    "if false; then cd frontend; fi; scp -F cfg f prod:/tmp",
    "f() { cd frontend; }; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "203.0.113.9", command);
  // A backgrounded cd does not move the next command.
  assert.equal(await at("cd frontend & scp -F cfg f prod:/tmp"), "203.0.113.9");
  assert.equal(await at("cd frontend | true; scp -F cfg f prod:/tmp"), "203.0.113.9");
  assert.equal(await at("cd frontend && scp -F cfg f prod:/tmp &"), "10.0.4.12");
  // A backgrounded list inside a compound starts where the compound's body does, after the cd before it.
  for (const command of [
    "cd frontend && { true & scp -F cfg f prod:/tmp; }",
    "cd frontend && { for x in a; do true; done & scp -F cfg f prod:/tmp; }",
    "cd frontend && if true; then true & scp -F cfg f prod:/tmp; fi",
  ]) assert.equal(await at(command), "10.0.4.12", command);
});

test("a piped compound keeps its cd to itself, and a called function runs its body in the caller's shell", async () => {
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  for (const command of [
    "{ cd frontend; } | cat; scp -F cfg f prod:/tmp",
    "if true; then cd frontend; fi | cat; scp -F cfg f prod:/tmp",
    "cat x | ( cd frontend ); scp -F cfg f prod:/tmp",
    "cd frontend && { true; } & scp -F cfg f prod:/tmp",
    "f() { cd frontend; }; f | cat; scp -F cfg f prod:/tmp",
    "f() ( cd frontend ); f; scp -F cfg f prod:/tmp",
    ": $(f() { cd frontend; }); f; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "203.0.113.9", command);
  for (const command of [
    "cat x | { cd frontend; scp -F cfg f prod:/tmp; }",
    "f() { cd frontend; }; f; scp -F cfg f prod:/tmp",
    "f() { scp -F cfg f prod:/tmp; }; cd frontend; f",
  ]) assert.equal(await at(command), "10.0.4.12", command);
  // zsh runs a pipeline's last command in this shell and bash in a subshell, so what it changes is unknown.
  for (const command of [
    "cat x | { true; cd frontend; }; scp -F cfg f prod:/tmp",
    "cat x | cd frontend; scp -F cfg f prod:/tmp",
    "f() { cd frontend; }; cat x | f; scp -F cfg f prod:/tmp",
    "cat x | if true; then cd frontend; fi; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "prod", command);
  // A recursive function is followed a bounded number of times, and the command after it is still read.
  const started = Date.now();
  assert.deepEqual(await hosts("f() { f; f; f; f; }; f; curl https://actual.example/b"), [["in", "actual.example"]]);
  assert.ok(Date.now() - started < 5_000);
});

test("a cd that may not have run leaves the folder unknown, and one that surely ran still applies", async () => {
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  // Where a cd hangs on an unknown status, a later relative -F config is not read from a guessed folder.
  for (const command of [
    "test -f marker && cd frontend; scp -F cfg f prod:/tmp",
    "mkdir x && cd frontend && scp -F cfg f prod:/tmp",
    "if [ -d frontend ]; then cd frontend; fi; scp -F cfg f prod:/tmp",
    "case x in y) cd frontend;; esac; scp -F cfg f prod:/tmp",
    "[ -d x ] && { cd frontend; }; scp -F cfg f prod:/tmp",
    "f() { cd frontend; }; [ -d x ] && f; scp -F cfg f prod:/tmp",
    "for x in a; do [ -f y ] && break; cd frontend; done; scp -F cfg f prod:/tmp",
    "[ -d x ] && cd frontend; cd ..; scp -F cfg f prod:/tmp",
    "f() { [ -f y ] && return; cd frontend; }; f; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "prod", command);
  // A call inside a branch that may not run is never looked up.
  for (const command of [
    "if [ -d frontend ]; then cd frontend; scp -F cfg f prod:/tmp; fi",
    "[ -d x ] && { cd frontend; scp -F cfg f prod:/tmp; }",
  ]) assert.equal(await at(command), "prod", command);
  for (const command of [
    "cd frontend && scp -F cfg f prod:/tmp",
    `[ -d x ] && cd /tmp; cd ${dir}/frontend; scp -F cfg f prod:/tmp`,
    "f() { cd frontend; return; cd ..; }; f; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "10.0.4.12", command);
  for (const command of [
    "f() { return; cd frontend; }; f; scp -F cfg f prod:/tmp",
    "for x in a; do break; cd frontend; done; scp -F cfg f prod:/tmp",
    "for x in; do cd frontend; done; scp -F cfg f prod:/tmp",
    "(cd frontend; exit; cd ..); scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "203.0.113.9", command);
});

test("a loop that may repeat, or a cd into a missing folder, leaves the folder unknown", async () => {
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  // A body that runs again repeats its cd; a folder another command names may have been made or removed by it, since
  // the folder is read after the command ran. Neither is guessed.
  for (const command of [
    "cd frontend; for x in a b; do cd ..; done; scp -F cfg f prod:/tmp",
    "cd frontend; for x in a b; do cd ..; continue; done; scp -F cfg f prod:/tmp",
    "cd frontend; while [ -f y ]; do cd ..; done; scp -F cfg f prod:/tmp",
    "cd frontend; for x in *.txt; do cd ..; done; scp -F cfg f prod:/tmp",
    "mkdir nowhere; cd nowhere; cd frontend; scp -F cfg f prod:/tmp",
    "cd nowhere; cd frontend; scp -F cfg f prod:/tmp",
    "if [ -f y ]; then f() { cd frontend; }; fi; f; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "prod", command);
  for (const command of ["cd -P frontend; scp -F cfg f prod:/tmp", "cd -- frontend; scp -F cfg f prod:/tmp", "cd -L frontend; scp -F cfg f prod:/tmp"]) {
    assert.equal(await at(command), "10.0.4.12", command);
  }
  for (const command of [
    "cd frontend; for x in a; do cd ..; done; scp -F cfg f prod:/tmp",
    "cd frontend; for x in a b; do cd ..; break; done; scp -F cfg f prod:/tmp",
    "cd frontend; while true; do cd ..; break; done; scp -F cfg f prod:/tmp",
    "for x in a b; do scp -F cfg f prod:/tmp; done",
  ]) assert.equal(await at(command), "203.0.113.9", command);
});

test("pushd lands as cd does, and any other stack move leaves the folder unknown", async () => {
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  for (const command of [
    "pushd frontend; scp -F cfg build.zip prod:/srv", "pushd frontend && scp -F cfg f prod:/tmp",
    "pushd -- frontend; scp -F cfg f prod:/tmp", "cd -- frontend; scp -F cfg f prod:/tmp",
  ]) {
    assert.equal(await at(command), "10.0.4.12", command);
  }
  for (const command of [
    "pushd frontend; popd; scp -F cfg f prod:/tmp", "pushd frontend; pushd; scp -F cfg f prod:/tmp",
    "pushd frontend; pushd +1; scp -F cfg f prod:/tmp", "pushd -n frontend; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "prod", command);
});

test("a turn that names an ssh config makes no ssh lookup", async () => {
  // ssh -G reads the configs at the end of the turn, so a later call that may rewrite one leaves the turn's ssh
  // destinations unresolved; a turn that names none still resolves.
  for (const [second, expected] of [
    ["sed -i 's/HostName 203.0.113.9/HostName 10.0.4.12/' ~/.ssh/config", "unresolved"],
    ["echo done", "private"],
  ] as const) {
    const calls: string[][] = [];
    const found = await resolveTransfers([
      { tool_name: "bash", tool_use_id: "c1", tool_input: { command: "scp build.zip prod:/srv" } },
      { tool_name: "bash", tool_use_id: "c2", tool_input: { command: second } },
    ], "/", options({ execFile: fakeSsh(calls) }));
    assert.equal(found.get("c1")?.endpoints[0]?.address, expected, second);
    assert.equal(calls.length, expected === "private" ? 1 : 0, second);
  }
});

test("a proxied or unsure call is unresolved whatever an earlier call found", async () => {
  // The turn caches each lookup, but a call that must not look up never reads it.
  const found = await resolveTransfers([
    { tool_name: "bash", tool_use_id: "c1", tool_input: { command: "curl https://files.acme-infra.net/a" } },
    { tool_name: "bash", tool_use_id: "c2", tool_input: { command: "curl --socks5-hostname proxy.example:1080 -T secret https://files.acme-infra.net/up" } },
    { tool_name: "bash", tool_use_id: "c3", tool_input: { command: "[ -f /nope ] && curl -T secret https://files.acme-infra.net/up" } },
  ], "/", options());
  assert.deepEqual(["c1", "c2", "c3"].map((id) => found.get(id)?.endpoints[0]?.address), ["private", "unresolved", "unresolved"]);
});

test("a call that may not have run is never looked up", async () => {
  // Neither DNS nor ssh -G runs for it; an address as written is still classified, and a sure call looks up.
  const seen: string[] = [];
  const calls: string[][] = [];
  const recording: LookupLike = async (host) => {
    seen.push(host);
    return lookup(host);
  };
  const extra = { lookup: recording, execFile: fakeSsh(calls) };
  assert.deepEqual((await transfer("if [ -f /nope ]; then curl https://example.com/up; fi", "/", extra))?.endpoints,
    [{ direction: "in", host: "example.com", resolved_host: "example.com", address: "unresolved" }]);
  assert.deepEqual((await transfer("[ -f /nope ] && scp f prod:/srv", "/", extra))?.endpoints,
    [{ direction: "out", host: "prod", resolved_host: "prod", address: "unresolved" }]);
  assert.deepEqual((await transfer("[ -f /nope ] || curl https://10.0.0.5/up", "/", extra))?.endpoints,
    [{ direction: "in", host: "10.0.0.5", resolved_host: "10.0.0.5", address: "private" }]);
  assert.deepEqual([seen, calls], [[], []]);
  assert.equal((await transfer("curl https://example.com/up", "/", extra))?.endpoints[0]?.address, "public");
  assert.deepEqual(seen, ["example.com"]);
});

test("a builtin behind a wrapper that is a program changes nothing here", async () => {
  // env, sudo, nohup and the like run it as a program of its own, or fail; command and builtin run it here.
  const dir = repo();
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  for (const command of [
    "env cd frontend; scp -F cfg f prod:/tmp", "sudo cd frontend; scp -F cfg f prod:/tmp",
    "nohup pushd frontend; scp -F cfg f prod:/tmp", "nice -n 5 cd frontend; scp -F cfg f prod:/tmp",
    "timeout 5 cd frontend; scp -F cfg f prod:/tmp", "env exit; scp -F cfg f prod:/tmp",
    "nohup source f; scp -F cfg f prod:/tmp", "env eval x; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "203.0.113.9", command);
  assert.equal(await at("builtin export H=1; cd frontend; scp -F cfg f prod:/tmp"), "10.0.4.12");
});

test("eval and source leave every function unknown", async () => {
  // Their text may redefine a function, so a call after them may no longer run the body seen before.
  const dir = repo();
  const front = join(dir, "frontend");
  for (const command of [
    `f() { cd ${front}; }; eval 'f() { cd ${dir}; }'; f; scp -F cfg f prod:/tmp`,
    `f() { cd ${front}; }; source x.sh; cd ${dir}; f; scp -F cfg f prod:/tmp`,
  ]) assert.equal((await transfer(command, dir))?.endpoints[0]?.resolved_host, "prod", command);
});

test("a cd lands where bash and zsh both do, or leaves the folder unknown", async () => {
  const dir = repo();
  mkdirSync(join(dir, "frontend", "inner"));
  symlinkSync(join(dir, "frontend", "inner"), join(dir, "link"));
  writeFileSync(join(dir, "notes"), "a file, not a folder");
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  // -P resolves links (bash takes the last of -L and -P, zsh any -P); a cd every shell rejects stays put, and one the
  // shells land differently on (a second folder, -e, -q) is not guessed.
  for (const [command, expected] of [
    ["cd link; cd ..; scp -F cfg f prod:/tmp", "203.0.113.9"],
    ["cd -P link; cd ..; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["cd link; cd -P ..; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["cd -L -P link; cd ..; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["cd -P -L link; cd ..; scp -F cfg f prod:/tmp", "prod"],
    ["env -C link/.. scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["cd -Z frontend; scp -F cfg f prod:/tmp", "203.0.113.9"],
    ["cd --physical frontend; scp -F cfg f prod:/tmp", "203.0.113.9"],
    ["cd frontend extra; scp -F cfg f prod:/tmp", "prod"],
    ["cd frontend -P; scp -F cfg f prod:/tmp", "prod"],
    ["cd -Pe frontend; scp -F cfg f prod:/tmp", "prod"],
    ["cd -q frontend; scp -F cfg f prod:/tmp", "prod"],
    ["cd missing/../frontend; scp -F cfg f prod:/tmp", "prod"],
    // A cd into a folder that is there succeeds, and one into a file fails and stays; a missing folder may have been
    // there when it ran.
    ["cd frontend || cd ..; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["cd nowhere || cd frontend; scp -F cfg f prod:/tmp", "prod"],
    ["cd nowhere && cd frontend; scp -F cfg f prod:/tmp", "prod"],
    ["cd notes; scp -F cfg f prod:/tmp", "203.0.113.9"],
    // In double quotes a backslash stays unless it escapes $ ` " \ or a newline.
    ['cd "\\frontend"; scp -F cfg f prod:/tmp', "prod"],
    ['cd "\\~/frontend"; scp -F cfg f prod:/tmp', "prod"],
    ['cd "front\\\nend"; scp -F cfg f prod:/tmp', "10.0.4.12"],
    // Naming the -F file anywhere else in the turn means no lookup, as it may be rewritten.
    ["cd cfg; scp -F cfg f prod:/tmp", "prod"],
    // A command that only reads inside the folder, such as wc, does not name it.
    ["wc -c frontend/notes; cd frontend; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // Every shell fails that cd, so the || after it surely runs.
    ["cd -Z frontend || cd frontend; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // An arithmetic for that stops after one pass keeps its cd, unless its body touches the counter.
    ["for ((i=0;i<1;i++)); do cd frontend; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["for ((i=0;i<1;i++)); do cd frontend; [ -f m ] && i=-1; done; scp -F cfg f prod:/tmp", "prod"],
    ["for ((i=0;i<1;i++)); do cd frontend; i=0; break; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["for ((i=0;i<1;i++)); do echo $i; cd frontend; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // A bare cd and a leading ~ go to the shell's HOME. A HOME= in front of cd applies to a bare cd, but ~ is expanded
    // before it; a VAR= in front of cd leaves it a cd.
    [`HOME=${dir}/frontend; cd; scp -F cfg f prod:/tmp`, "10.0.4.12"],
    [`HOME=${dir}/frontend; cd ~; scp -F cfg f prod:/tmp`, "10.0.4.12"],
    [`HOME=${dir}; HOME=${dir}/frontend cd; scp -F cfg f prod:/tmp`, "10.0.4.12"],
    [`HOME=${dir}; HOME=${dir}/frontend cd ~; scp -F cfg f prod:/tmp`, "203.0.113.9"],
    [`HOME=${dir}; HOME=${dir}/frontend scp -F ~/cfg f prod:/tmp`, "203.0.113.9"],
    // A quoted or escaped ~ is a folder named ~, which is not there, so where the cd went is not known.
    [`HOME=${dir}; cd '~/frontend'; scp -F cfg f prod:/tmp`, "prod"],
    [`HOME=${dir}; cd \\~/frontend; scp -F cfg f prod:/tmp`, "prod"],
    [`HOME=${dir}; cd ~/frontend; scp -F cfg f prod:/tmp`, "10.0.4.12"],
    [`HOME=${dir}; cd '~root'; scp -F cfg f prod:/tmp`, "prod"],
    // After empty quotes bash leaves a ~ and zsh expands it.
    [`HOME=${dir}; cd ''~/frontend; scp -F cfg f prod:/tmp`, "prod"],
    // An assignment expands the ~ its value starts with.
    [`HOME=${dir}/frontend; cd; HOME=~/..; cd; scp -F cfg f prod:/tmp`, "203.0.113.9"],
    ["FOO=1 cd frontend; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // exec replaces the shell even when what it runs is a builtin, so the scp never runs.
    ["exec cd frontend; scp -F cfg f prod:/tmp", undefined],
  ] as const) assert.equal(await at(command), expected, command);
  // An -F path's ~ is the shell's HOME, which the agent's environment exports.
  const tilde = await transfer(`HOME=${dir}/frontend; scp -F ~/cfg f prod:/tmp`, dir, { env: { HOME: EMPTY_HOME } });
  assert.equal(tilde?.endpoints[0]?.resolved_host, "10.0.4.12");
});

test("a powershell tool call keeps a hashtable whole", async () => {
  // A ; inside @{ } separates the hashtable's entries, so the cmdlet keeps its -Uri.
  const command = "Invoke-WebRequest -Method Post -Body @{a=1; b=2} -Uri https://example.com/up";
  const found = await resolveTransfers([{ tool_name: "powershell", tool_use_id: "p1", tool_input: { command } }], "/", options());
  assert.deepEqual(found.get("p1"), {
    tool: "powershell",
    endpoints: [{ direction: "out", host: "example.com", resolved_host: "example.com", address: "public" }],
  });
});

test("URL globs reach every host they name", async () => {
  // curl expands {a,b} sets and [1-3] ranges itself unless --globoff is given, and stops at a glob it rejects.
  const cases: [string, [string, string][]][] = [
    ["curl -T x 'https://{files.acme-infra.net,example.com}/up'", [["out", "files.acme-infra.net"], ["out", "example.com"]]],
    ["curl 'https://h[1-3].example/x'", [["in", "h1.example"], ["in", "h2.example"], ["in", "h3.example"]]],
    ["curl 'https://h[01-10:9].example/x'", [["in", "h01.example"], ["in", "h10.example"]]],
    ["curl 'https://{a,b\\,c}.example/x'", [["in", "a.example"]]],
    ["curl 'https://[::1]:8080/x'", [["in", "::1"]]],
    ["curl --url 'https://{a,b}.example/x'", [["in", "a.example"], ["in", "b.example"]]],
    ["curl -g 'https://{a,b}.example/x'", []],
    ["curl 'https://a.example/x' 'https://{{b}}.example/y' https://c.example/z", [["in", "a.example"]]],
    ["curl 'https://h[3-1].example/x'", []],
    ["curl 'https://a.example/x}'", []],
    // With globbing off, brackets or a backslash in the host are a name curl rejects.
    ["curl -g 'https://h[1-2].example/x'", []],
    ["curl -g 'https://a.example\\b/x'", []],
    // Unquoted, bash expands the braces before curl runs; quoted, curl reads {1..2} as one name.
    ["curl -g https://{a,b}.example/x", [["in", "a.example"], ["in", "b.example"]]],
    ["curl https://h{1..2}.example/x", [["in", "h1.example"], ["in", "h2.example"]]],
    ["curl 'https://h{1..2}.example/x'", [["in", "h1..2.example"]]],
  ];
  for (const [command, expected] of cases) assert.deepEqual(await hosts(command), expected, command);
});

test("--connect-to and --resolve set where a URL connects", async () => {
  // As curl applies them: the first matching --connect-to, then the last pin for that host and port, a named host
  // before *; pins carry on past --next and a --connect-to does not.
  const cases: [string, [string, string, string][]][] = [
    ["curl --resolve example.com:443:10.0.0.5 https://example.com/x", [["example.com", "10.0.0.5", "private"]]],
    ["curl --resolve example.com:80:10.0.0.5 https://example.com/x", [["example.com", "example.com", "public"]]],
    ["curl --resolve '*:443:10.0.0.5' https://example.com/x", [["example.com", "10.0.0.5", "private"]]],
    ["curl --resolve example.com:443:8.8.8.8 --resolve '*:443:10.0.0.5' https://example.com/x", [["example.com", "8.8.8.8", "public"]]],
    ["curl --resolve example.com:443:10.0.0.5 --resolve -example.com:443 https://example.com/x", [["example.com", "example.com", "public"]]],
    ["curl --resolve 'example.com:443:10.0.0.5,8.8.8.8' https://example.com/x", [["example.com", "10.0.0.5", "public"]]],
    ["curl --connect-to example.com:443:cgnat.example:8443 --resolve cgnat.example:8443:[fd00::1] https://example.com/x",
      [["example.com", "fd00::1", "private"]]],
    ["curl --connect-to example.com:443:cgnat.example: --resolve example.com:443:8.8.8.8 https://example.com/x",
      [["example.com", "cgnat.example", "cgnat"]]],
    ["curl --connect-to ::10.1.2.3: --connect-to ::8.8.8.8: https://example.com/x", [["example.com", "10.1.2.3", "private"]]],
    ["curl https://example.com/a --next --resolve example.com:443:10.0.0.5 https://example.com/b",
      [["example.com", "example.com", "public"], ["example.com", "10.0.0.5", "private"]]],
    ["curl --connect-to ::10.1.2.3: https://example.com/a --next https://example.com/b",
      [["example.com", "10.1.2.3", "private"], ["example.com", "example.com", "public"]]],
  ];
  for (const [command, expected] of cases) {
    const got = ((await transfer(command))?.endpoints ?? []).map((e) => [e.host, e.resolved_host, e.address]);
    assert.deepEqual(got, expected, command);
  }
});

test("folders, wrappers and exports carry to the commands after them", async () => {
  const dir = repo();
  for (const command of [
    "cd frontend && scp -F cfg f prod:/tmp",
    "if cd frontend; then scp -F cfg f prod:/tmp; fi",
    "env -C frontend scp -F cfg f prod:/tmp",
    "timeout -s KILL 30 env -C frontend scp -F cfg f prod:/tmp",
    "env -S 'scp -F frontend/cfg f prod:/tmp'",
    'export RSYNC_RSH="ssh -F frontend/cfg"; rsync -a f prod:/tmp',
    "bash -c 'cd frontend && scp -F cfg f prod:/tmp'",
  ]) assert.equal((await transfer(command, dir))?.endpoints[0]?.resolved_host, "10.0.4.12", command);
  assert.equal((await transfer("(cd frontend; true) && scp -F cfg f prod:/tmp", dir))?.endpoints[0]?.resolved_host, "203.0.113.9");
  assert.equal(await transfer("curl -T x 'https://example.com"), undefined);
  assert.equal(await transfer("echo $(curl https://example.com"), undefined);
});

function sleep(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}
