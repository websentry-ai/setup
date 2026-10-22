// Transfer resolution — the Pi port of the Python hooks' transfer block. The shared corpus in
// tests/fixtures/transfer_cases.json is checked here and by tests/test_transfer_destination.py, so the same command
// sends the same `transfer` field from every hook.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

import type { ExecFileLike } from "../src/accountIdentity.ts";
import { resolveTransfers, type LookupLike, type ResolveOptions, type Transfer } from "../src/transfer.ts";

interface Fixture {
  addresses: Record<string, string[]>;
  ssh_hosts: Record<string, string>;
  cases: { command: string; transfer: Transfer | null }[];
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
    if (config !== undefined && config !== "none") {
      let current: string[] = [];
      for (const line of readFileSync(config, "utf8").split("\n")) {
        const [key, ...values] = line.trim().split(/\s+/);
        if (key?.toLowerCase() === "host") current = values;
        else if (key?.toLowerCase() === "hostname" && current.includes(host)) hostname ??= values[0];
      }
    }
    return `hostname ${(hostname ?? FIXTURE.ssh_hosts[host] ?? host).toLowerCase()}\nport 22\n`;
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
  for (const { command, transfer: expected } of FIXTURE.cases) {
    assert.deepEqual((await transfer(command, "/")) ?? null, expected, command);
  }
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
      [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command: "scp -P 2222 -o HostName=10.9.9.9 -J jump f prod:/tmp" } }],
      "/", { lookup, home: EMPTY_HOME, env: {} },
    );
    assert.deepEqual(found.get("c1"), {
      tool: "scp",
      endpoints: [{ direction: "out", host: "prod", resolved_host: "10.9.9.9", address: "private" }],
    });
    const argv = JSON.parse(readFileSync(log, "utf8").trim()) as string[];
    assert.deepEqual(argv, ["-G", "-p", "2222", "-o", "HostName=10.9.9.9", "-J", "jump", "--", "prod"]);
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
  assert.equal(await at("(cd frontend; case x in y) cd ..;; esac; scp -F cfg f prod:/tmp)"), "10.0.4.12");
  // A substitution inside double quotes runs.
  assert.equal(await at('echo "$(cd frontend && scp -F cfg f prod:/tmp)"'), "10.0.4.12");
  // Untaken branches and function bodies do not run.
  assert.deepEqual(await hosts("if false; then curl https://never.example/a; else curl https://actual.example/b; fi"), [["in", "actual.example"]]);
  assert.deepEqual(await hosts("function f { curl -T x https://never.example/a; }; curl https://actual.example/b"), [["in", "actual.example"]]);
  for (const command of [
    "if false; then cd frontend; fi; scp -F cfg f prod:/tmp",
    "f() { cd frontend; }; scp -F cfg f prod:/tmp",
    "case x in y) cd frontend;; esac; scp -F cfg f prod:/tmp",
  ]) assert.equal(await at(command), "203.0.113.9", command);
  // A backgrounded cd does not move the next command.
  assert.equal(await at("cd frontend & scp -F cfg f prod:/tmp"), "203.0.113.9");
  assert.equal(await at("cd frontend | true; scp -F cfg f prod:/tmp"), "203.0.113.9");
  assert.equal(await at("cd frontend && scp -F cfg f prod:/tmp &"), "10.0.4.12");
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
