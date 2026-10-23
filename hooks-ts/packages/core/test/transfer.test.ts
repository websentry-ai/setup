// Transfer resolution — the Pi port of the Python hooks' transfer block. The shared corpus in
// tests/fixtures/transfer_cases.json is checked here and by tests/test_transfer_destination.py, so the same command
// sends the same `transfer` field from every hook.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
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
  for (const command of [
    "cd frontend && scp -F cfg f prod:/tmp",
    "if [ -d frontend ]; then cd frontend; scp -F cfg f prod:/tmp; fi",
    "[ -d x ] && { cd frontend; scp -F cfg f prod:/tmp; }",
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
  // A body that runs again repeats its cd, so where it ends is not known; a cd into a folder that is not there may
  // have failed. Neither is guessed.
  for (const command of [
    "cd frontend; for x in a b; do cd ..; done; scp -F cfg f prod:/tmp",
    "cd frontend; for x in a b; do cd ..; continue; done; scp -F cfg f prod:/tmp",
    "cd frontend; while [ -f y ]; do cd ..; done; scp -F cfg f prod:/tmp",
    "cd frontend; for x in *.txt; do cd ..; done; scp -F cfg f prod:/tmp",
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

test("a cd lands where bash and zsh both do, or leaves the folder unknown", async () => {
  const dir = repo();
  mkdirSync(join(dir, "frontend", "inner"));
  symlinkSync(join(dir, "frontend", "inner"), join(dir, "link"));
  const at = async (command: string): Promise<string | undefined> => (await transfer(command, dir))?.endpoints[0]?.resolved_host;
  // -P resolves links, so a later `..` leaves the real folder: bash takes the last of -L and -P, zsh any -P. A cd
  // every shell rejects stays put; bash 5 rejects a second folder that bash 3 takes the first of, and -e and -q are
  // not in every shell, so where those land is not guessed.
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
    // Every shell fails that cd, so the || after it surely runs.
    ["cd -Z frontend || cd frontend; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // An arithmetic for that stops after one pass keeps its cd, unless its body touches the counter.
    ["for ((i=0;i<1;i++)); do cd frontend; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["for ((i=0;i<1;i++)); do cd frontend; [ -f m ] && i=-1; done; scp -F cfg f prod:/tmp", "prod"],
    ["for ((i=0;i<1;i++)); do cd frontend; i=0; break; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    ["for ((i=0;i<1;i++)); do echo $i; cd frontend; done; scp -F cfg f prod:/tmp", "10.0.4.12"],
    // exec replaces the shell even when what it runs is a builtin, so the scp never runs.
    ["exec cd frontend; scp -F cfg f prod:/tmp", undefined],
  ] as const) assert.equal(await at(command), expected, command);
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
