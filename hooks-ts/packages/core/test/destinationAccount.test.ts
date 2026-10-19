// Destination account — the Pi port of the Python hooks' account resolution. Runs real git and ssh
// against throwaway repos and ssh configs, mirroring tests/test_destination_account.py.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync as run } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { resolveDestinationAccounts, type DestinationAccount } from "../src/destinationAccount.ts";

// Not a real credential; it only has to sit in a remote URL.
const FAKE_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"; // gitleaks:allow
// Lookups inherit the process environment, so no gh login leaks in from the machine running the tests.
process.env.GH_CONFIG_DIR = mkdtempSync(join(tmpdir(), "gh-"));
for (const key of ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_REPO"]) delete process.env[key];
const NO_GH: Record<string, string> = {};

function repo(remotes: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "repo-"));
  execFileSync("git", ["-C", dir, "init", "-q", "-b", "main"]);
  for (const [name, url] of Object.entries(remotes)) execFileSync("git", ["-C", dir, "remote", "add", name, url]);
  return dir;
}

const sshConfig = (() => {
  const file = join(mkdtempSync(join(tmpdir(), "ssh-")), "config");
  writeFileSync(file, "Host prod-bastion\n  HostName 10.0.4.12\n  User deploy\n  Port 2222\n");
  return file;
})();

async function resolve(command: string, cwd?: string, env: Record<string, string> = NO_GH) {
  const accounts = await resolveDestinationAccounts(
    [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command } }], cwd, { env },
  );
  return accounts.get("c1");
}

test("a push to a named remote reports its host and owner without the login", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git", personal: `https://jdoe:${FAKE_TOKEN}@github.com/jdoe-dev/app.git` });
  const account = await resolve("git push personal main", dir);
  assert.deepEqual(account, { platform: "github", host: "github.com", account: "jdoe-dev", context: "personal", source: "command" });
  assert.ok(!JSON.stringify(account).includes(FAKE_TOKEN));
});

test("newlines separate commands, push options are skipped and the default remote is origin", async () => {
  const dir = repo({ origin: "git@github.com:acme/app.git", personal: "https://github.com/jdoe-dev/app.git" });
  for (const command of ["echo ready\ngit push personal main", "git push -o ci.skip personal main"]) {
    assert.equal((await resolve(command, dir))?.account, "jdoe-dev", command);
  }
  const fallback = await resolve("git push", dir);
  assert.deepEqual([fallback?.host, fallback?.account, fallback?.context], ["github.com", "acme", "origin"]);
});

test("each segment resolves in the folder it runs in", async () => {
  const mine = repo({ origin: "https://github.com/jdoe-dev/app.git" });
  const other = repo({ origin: "https://github.com/acme/other.git" });
  assert.equal((await resolve(`git push origin main; cd ${other}`, mine))?.account, "jdoe-dev");
  assert.equal((await resolve(`cd ${mine} && git push origin main`, other))?.account, "jdoe-dev");
});

test("commands that reach no account report nothing", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  for (const command of ["git status", "ls -la", "rsync -a dir host::module", ""]) {
    assert.equal(await resolve(command, dir), undefined, command);
  }
});

test("gh reads the repo flag and inline host, and drops the login under a token", async () => {
  const flagged = await resolve("gh pr create -R acme/app --fill");
  assert.deepEqual([flagged?.platform, flagged?.host, flagged?.account], ["github", "github.com", "acme"]);
  const tokened = await resolve("GH_HOST=ghe.acme.com GH_TOKEN=x gh repo view acme/app");
  assert.equal(tokened?.host, "ghe.acme.com");
  assert.equal(tokened?.user, undefined);
});

test("ssh-family commands resolve the real host, user and port, honouring identity options", async () => {
  const cases: [string, string, string][] = [
    [`ssh -F ${sshConfig} prod-bastion uptime`, "10.0.4.12:2222", "deploy"],
    [`scp -F ${sshConfig} dump.sql prod-bastion:/tmp/`, "10.0.4.12:2222", "deploy"],
    [`ssh -F ${sshConfig} -o HostName=10.9.9.9 -o User=ops -p2200 prod-bastion`, "10.9.9.9:2200", "ops"],
    [`sftp -F ${sshConfig} deploy2@prod-bastion`, "10.0.4.12:2222", "deploy2"],
  ];
  for (const [command, host, user] of cases) {
    const account = await resolve(command);
    assert.deepEqual([account?.host, account?.user], [host, user], command);
  }
});

test("only allowlisted lookups ever run, and a spent budget leaves the call account unknown", async () => {
  const ran: string[][] = [];
  const execFile = async (file: string, args: readonly string[]) => {
    ran.push([file, ...args]);
    return undefined;
  };
  const accounts = await resolveDestinationAccounts(
    [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command: "ssh prod-bastion" } }],
    undefined, { execFile, env: NO_GH },
  );
  assert.deepEqual(accounts.get("c1"), { platform: "ssh", source: "unknown" } satisfies DestinationAccount);
  assert.ok(ran.every((argv) => argv[0] === "ssh" && argv[1] === "-G"), JSON.stringify(ran));

  let t = 0;
  const spent = await resolveDestinationAccounts(
    [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command: "ssh prod-bastion" } }],
    undefined, { execFile: async () => { throw new Error("must not run"); }, env: NO_GH, now: () => (t += 20_000) },
  );
  assert.deepEqual(spent.get("c1"), { platform: "ssh", source: "unknown" });
});

test("only shell calls are resolved", async () => {
  const accounts = await resolveDestinationAccounts(
    [{ tool_name: "read", tool_use_id: "c1", tool_input: { command: "ssh prod-bastion" } }], undefined, { env: NO_GH },
  );
  assert.equal(accounts.size, 0);
});

test("a gh repo URL never carries its login or token", async () => {
  for (const command of [
    `gh pr create -R https://jdoe:${FAKE_TOKEN}@github.com/acme/app --fill`,
    `GH_REPO=https://jdoe:${FAKE_TOKEN}@github.com/acme/app gh repo view`,
  ]) {
    const account = await resolve(command);
    assert.deepEqual([account?.host, account?.account], ["github.com", "acme"], command);
    assert.ok(!JSON.stringify(account).toLowerCase().includes(FAKE_TOKEN.toLowerCase()), command);
  }
});

test("gh names the repo the command reaches", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  const cases: [string, string | undefined][] = [
    ["GH_REPO=acme/app gh repo view other-org/other-repo", "other-org"],
    ["gh api repos/other-org/svc/pulls", "other-org"],
    ["gh api repos/{owner}/{repo}/pulls", "acme"],
    ["gh api user", undefined],
  ];
  for (const [command, owner] of cases) assert.equal((await resolve(command, dir))?.account, owner, command);
});

test("comments, line continuations and a failed earlier lookup keep the push", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git", personal: "https://github.com/jdoe-dev/app.git" });
  for (const [command, cwd] of [
    [`cd ${dir} # into the repo; git push origin\ngit push personal main`, "/"],
    ["git push \\\n  personal main", dir],
    ["git push missing main; git push personal main", dir],
  ] as const) {
    assert.equal((await resolve(command, cwd))?.account, "jdoe-dev", command);
  }
});

test("a push with no known folder is unknown rather than the hook's own", async () => {
  assert.deepEqual(await resolve("git push origin main"), { platform: "git", source: "unknown" });
});

test("scp switches and bandwidth limits are not read as values or logins, and the destination wins", async () => {
  for (const command of [
    `scp -p -F ${sshConfig} prod-bastion:/var/log/app.log .`,
    `scp -l 8192 -F ${sshConfig} dump.sql prod-bastion:/tmp/`,
    `scp -F ${sshConfig} notes:draft prod-bastion:/tmp/`,
  ]) {
    const account = await resolve(command);
    assert.deepEqual([account?.host, account?.user], ["10.0.4.12:2222", "deploy"], command);
  }
});

test("a relative ssh config is read from the folder the command ran in", async () => {
  const account = await resolve("ssh -F ./config prod-bastion", dirname(sshConfig));
  assert.deepEqual([account?.host, account?.user], ["10.0.4.12:2222", "deploy"]);
});

test("an ssh config that runs commands is never read", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-exec-"));
  const marker = join(dir, "ran");
  const config = join(dir, "config");
  writeFileSync(config, `Match host * exec "touch ${marker}"\n  HostName 10.9.9.9\n`);
  assert.deepEqual(await resolve(`ssh -F ${config} prod-bastion`), { platform: "ssh", source: "unknown" });
  assert.equal(existsSync(marker), false);
});

test("calls the policy blocked never run a lookup", async () => {
  const ran: string[][] = [];
  const execFile = async (file: string, args: readonly string[]) => {
    ran.push([file, ...args]);
    return undefined;
  };
  const accounts = await resolveDestinationAccounts(
    ["deny", "unavailable"].map((decision, i) => ({
      tool_name: "bash", tool_use_id: `c${i}`, decision, tool_input: { command: "ssh prod-bastion" },
    })),
    undefined, { execFile, env: NO_GH },
  );
  assert.equal(accounts.size, 0);
  assert.deepEqual(ran, []);
});

test("what follows an ssh destination is the remote command, and option clusters are walked", async () => {
  for (const command of [
    `ssh -F ${sshConfig} prod-bastion ls -la /var/log`,
    `ssh -F ${sshConfig} prod-bastion ps -p 123 -o user`,
    `ssh -vF ${sshConfig} prod-bastion`,
  ]) {
    const account = await resolve(command);
    assert.deepEqual([account?.host, account?.user], ["10.0.4.12:2222", "deploy"], command);
  }
});

test("rsync reads its remote shell and skips option values", async () => {
  const cases: [string, string][] = [
    [`rsync -a -e "ssh -F ${sshConfig} -p 2200" src prod-bastion:/dest`, "10.0.4.12:2200"],
    [`rsync -avze 'ssh -F ${sshConfig}' src prod-bastion:/dest --exclude foo:bar`, "10.0.4.12:2222"],
    [`rsync -a --rsh="ssh -F ${sshConfig}" src prod-bastion:/dest`, "10.0.4.12:2222"],
  ];
  for (const [command, host] of cases) assert.equal((await resolve(command))?.host, host, command);
  assert.equal(await resolve("rsync -a -e /usr/local/bin/custom-shell src prod-bastion:/dest"), undefined);
});

test("ssh configs are scanned through includes and only as regular files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-include-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "inner"), `Match host * exec "touch ${marker}"\n`);
  writeFileSync(join(dir, "outer"), `Include ${join(dir, "inner")}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
  writeFileSync(join(dir, "safe"), `Include ${sshConfig}\n`);
  run("mkfifo", [join(dir, "fifo")]);
  assert.deepEqual(await resolve(`ssh -F ${join(dir, "outer")} prod-bastion`), { platform: "ssh", source: "unknown" });
  assert.deepEqual(await resolve(`ssh -F ${join(dir, "fifo")} prod-bastion`), { platform: "ssh", source: "unknown" });
  const safe = await resolve(`ssh -F ${join(dir, "safe")} prod-bastion`);
  assert.deepEqual([safe?.host, safe?.user], ["10.0.4.12:2222", "deploy"]);
  assert.equal(existsSync(marker), false);
});

test("a push that moves the repository or rewrites its config is unknown", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  for (const command of [
    "git -c remote.origin.pushurl=https://github.com/evil/secret.git push",
    "git --git-dir=/elsewhere/.git push",
    "GIT_DIR=/elsewhere/.git git push origin main",
  ]) {
    assert.deepEqual(await resolve(command, dir), { platform: "git", source: "unknown" }, command);
  }
});

test("gh commands that reach no repo report nothing", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  for (const command of ["gh help", "gh auth status", "gh version", "gh --version"]) {
    assert.equal(await resolve(command, dir), undefined, command);
  }
});

test("a bare push before tracking uses the remote git would", async () => {
  for (const setting of [["remote.pushDefault", "personal"], ["branch.main.remote", "personal"], ["branch.main.pushRemote", "personal"]]) {
    const dir = repo({ origin: "https://github.com/acme/app.git", personal: "https://github.com/jdoe-dev/app.git" });
    execFileSync("git", ["-C", dir, "config", ...setting]);
    const account = await resolve("git push", dir);
    assert.deepEqual([account?.account, account?.context], ["jdoe-dev", "personal"], setting.join("="));
  }
});

test("quoted and wildcard includes are scanned", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-quoted-"));
  const folder = join(dir, "with space");
  run("mkdir", [folder]);
  const marker = join(dir, "ran");
  writeFileSync(join(folder, "inner.conf"), `Match host * exec "touch ${marker}"\n`);
  for (const include of [`"${folder}/inner.conf"`, `"${folder}/*.conf"`]) {
    const outer = join(dir, "outer");
    writeFileSync(outer, `Include ${include}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
    assert.deepEqual(await resolve(`ssh -F ${outer} prod-bastion`), { platform: "ssh", source: "unknown" }, include);
  }
  assert.equal(existsSync(marker), false);
});

test("an ssh config named from the home folder is read", async () => {
  const home = mkdtempSync(join(tmpdir(), "home-"));
  writeFileSync(join(home, "bastion.cfg"), "Host prod-bastion\n  HostName 10.0.4.12\n  User deploy\n");
  const previous = process.env.HOME;
  process.env.HOME = home;
  try {
    const account = await resolve("ssh -F ~/bastion.cfg prod-bastion");
    assert.deepEqual([account?.host, account?.user], ["10.0.4.12", "deploy"]);
  } finally {
    process.env.HOME = previous;
  }
});
