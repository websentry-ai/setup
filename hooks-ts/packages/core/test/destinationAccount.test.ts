// Destination account — the Pi port of the Python hooks' account resolution. Runs real git and ssh
// against throwaway repos and ssh configs, mirroring tests/test_destination_account.py.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
