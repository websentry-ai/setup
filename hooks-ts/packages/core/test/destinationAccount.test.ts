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

test("quoted ssh keywords are read as ssh reads them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-keyword-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "inner"), `"Match" host * exec "touch ${marker}"\n`);
  for (const body of [`"Match" exec "touch ${marker}"`, `"Include" "${join(dir, "inner")}"`, `Match host * "exec" "touch ${marker}"`]) {
    writeFileSync(join(dir, "config"), `${body}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
    assert.deepEqual(await resolve(`ssh -F ${join(dir, "config")} prod-bastion`), { platform: "ssh", source: "unknown" }, body);
  }
  assert.equal(existsSync(marker), false);
});

test("bracketed IPv6 copy destinations resolve", async () => {
  for (const command of ["scp -F none dump.sql deploy@[2001:db8::1]:/tmp/", "scp -F none dump.sql deploy@[2001:db8:0:0:0:0:0:1]:/tmp/"]) {
    const account = await resolve(command);
    assert.equal(account?.user, "deploy", command);
    assert.ok(["2001:db8::1", "2001:db8:0:0:0:0:0:1"].includes(account?.host ?? ""), command);
  }
});

test("a token in any remote shape never reaches the account", async () => {
  const dir = repo({ weird: `jdoe:${FAKE_TOKEN}@github.com:acme/app.git`, double: `https://x@${FAKE_TOKEN}@github.com/acme/app.git` });
  for (const command of ["git push weird main", "git push double main", `git push https://x@${FAKE_TOKEN}@github.com/acme/app.git main`]) {
    const account = await resolve(command, dir);
    assert.deepEqual([account?.host, account?.account], ["github.com", "acme"], command);
    assert.ok(!JSON.stringify(account).toLowerCase().includes(FAKE_TOKEN.toLowerCase()), command);
  }
});

test("another global git config and gh flag forms are read", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  for (const command of ["GIT_CONFIG_GLOBAL=/elsewhere/gitconfig git push", "GIT_CONFIG_SYSTEM=/elsewhere/gitconfig git push"]) {
    assert.deepEqual(await resolve(command, dir), { platform: "git", source: "unknown" }, command);
  }
  const cases: [string, string, string][] = [
    ["gh pr create --hostname=ghe.example.com -R acme/app", "ghe.example.com", "acme"],
    ["gh pr create -Rother/app", "github.com", "other"],
    ["gh pr create -R=other/app", "github.com", "other"],
  ];
  for (const [command, host, owner] of cases) {
    const account = await resolve(command, dir);
    assert.deepEqual([account?.host, account?.account], [host, owner], command);
  }
});

test("an equals before an ssh config argument is only a separator", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-equals-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "inner"), `Match exec "touch ${marker}"\n`);
  for (const body of [`Match =exec "touch ${marker}"`, `Include =${join(dir, "inner")}`]) {
    writeFileSync(join(dir, "config"), `${body}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
    assert.deepEqual(await resolve(`ssh -F ${join(dir, "config")} prod-bastion`), { platform: "ssh", source: "unknown" }, body);
  }
  assert.equal(existsSync(marker), false);
});

test("a token in any gh repo shape never reaches the account", async () => {
  for (const command of [
    `GH_REPO=x@${FAKE_TOKEN}@github.com/acme/app gh pr list`,
    `gh pr create -Rx@${FAKE_TOKEN}@github.com/acme/app`,
    `gh api repos/x@${FAKE_TOKEN}@github.com/acme/contents`,
  ]) {
    assert.ok(!JSON.stringify(await resolve(command)).toLowerCase().includes(FAKE_TOKEN.toLowerCase()), command);
  }
});

test("gh follows the repo origin fetches from", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  execFileSync("git", ["-C", dir, "remote", "set-url", "--push", "origin", "https://github.com/personal/app.git"]);
  assert.equal((await resolve("gh pr view 1", dir))?.account, "acme");
});

test("a semicolon in an included path is part of the path", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-semi-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "inner;config"), `Match exec "touch ${marker}"\n`);
  writeFileSync(join(dir, "config"), `Include ${join(dir, "inner;config")}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
  assert.deepEqual(await resolve(`ssh -F ${join(dir, "config")} prod-bastion`), { platform: "ssh", source: "unknown" });
  assert.equal(existsSync(marker), false);
});

test("ssh options right after the destination are read", async () => {
  const account = await resolve(`ssh -F ${sshConfig} prod-bastion -p 2200 -l ops uptime`);
  assert.deepEqual([account?.host, account?.user], ["10.0.4.12:2200", "ops"]);
});

test("scp URIs resolve without their password, and a login in GH_HOST is dropped", async () => {
  for (const command of [
    `scp -F ${sshConfig} dump.sql scp://deploy@prod-bastion:2200/tmp/`,
    `sftp -F ${sshConfig} sftp://deploy:${FAKE_TOKEN}@prod-bastion:2200/tmp`,
  ]) {
    const uri = await resolve(command);
    assert.deepEqual([uri?.host, uri?.user], ["10.0.4.12:2200", "deploy"], command);
    assert.ok(!JSON.stringify(uri).toLowerCase().includes(FAKE_TOKEN.toLowerCase()), command);
  }
  const account = await resolve(`GH_HOST=jdoe:${FAKE_TOKEN}@ghe.example.com gh pr create -R acme/app`);
  assert.equal(account?.host, "ghe.example.com");
  assert.ok(!JSON.stringify(account).toLowerCase().includes(FAKE_TOKEN.toLowerCase()));
});

test("a backslash escape in an included path is read as ssh reads it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-escape-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "inner_config"), `Match exec "touch ${marker}"\n`);
  writeFileSync(join(dir, "config"), `Include ${join(dir, "inner\\_config")}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
  assert.deepEqual(await resolve(`ssh -F ${join(dir, "config")} prod-bastion`), { platform: "ssh", source: "unknown" });
  assert.equal(existsSync(marker), false);
});

test("wrappers and their option values never hide the command", async () => {
  const dir = repo({ personal: "https://github.com/jdoe-dev/app.git" });
  const cases: [string, string | undefined][] = [
    [`sudo -u deploy ssh -F ${sshConfig} prod-bastion`, undefined],
    ["env -u HOME git push personal main", dir],
    ["timeout -s KILL 30 git push personal main", dir],
    ["nice -n 10 git push personal main", dir],
    [`env -C ${dir} git push personal main`, "/"],
    [`sudo -D ${dir} git push personal main`, "/"],
    ["env -S 'git push personal main'", dir],
  ];
  for (const [command, cwd] of cases) {
    const account = await resolve(command, cwd);
    assert.ok(["jdoe-dev", "deploy"].includes(account?.account ?? account?.user ?? ""), command);
  }
  assert.equal(await resolve("command -v ssh"), undefined);
});

test("exports carry to later commands and literal short circuits are followed", async () => {
  const dir = repo({ personal: "https://github.com/jdoe-dev/app.git" });
  assert.deepEqual(await resolve("export GIT_DIR=/elsewhere/.git && git push personal main", dir), { platform: "git", source: "unknown" });
  const cases: [string, string | undefined][] = [
    ["false && git push personal main", undefined],
    ["true || git push personal main", undefined],
    ["false || git push personal main", "jdoe-dev"],
    ["true && git push personal main", "jdoe-dev"],
    ["false && echo x || git push personal main", "jdoe-dev"],
  ];
  for (const [command, owner] of cases) assert.equal((await resolve(command, dir))?.account, owner, command);
});

test("gh reads urls, its default repo, and skips option values", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git", upstream: "https://github.com/base/app.git" });
  const cases: [string, string][] = [
    ["gh pr view https://github.com/other/app/pull/1", "other"],
    ["gh pr create -R acme/app --title '-Rpersonal/app' --body text", "acme"],
    ["gh pr list", "base"],
  ];
  for (const [command, owner] of cases) assert.equal((await resolve(command, dir))?.account, owner, command);
  execFileSync("git", ["-C", dir, "config", "remote.origin.gh-resolved", "base"]);
  assert.equal((await resolve("gh pr list", dir))?.account, "acme");
  const api = await resolve(`gh api repos/x@${FAKE_TOKEN}@github.com/acme/contents`);
  assert.notEqual(api?.account, "github.com");
  assert.ok(!JSON.stringify(api).toLowerCase().includes(FAKE_TOKEN.toLowerCase()));
});

test("explicit push urls follow git url rewrites, and a push default may be a url", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  execFileSync("git", ["-C", dir, "config", "url.https://github.com/acme/.pushInsteadOf", "work:"]);
  execFileSync("git", ["-C", dir, "config", "url.https://github.com/personal/.insteadOf", "https://github.com/elsewhere/"]);
  for (const [command, owner] of [["git push work:app.git main", "acme"], ["git push https://github.com/elsewhere/app.git main", "personal"]] as const) {
    const account = await resolve(command, dir);
    assert.deepEqual([account?.host, account?.account], ["github.com", owner], command);
  }
  const other = repo({ origin: "https://github.com/acme/app.git" });
  execFileSync("git", ["-C", other, "config", "remote.pushDefault", "https://github.com/jdoe-dev/app.git"]);
  assert.equal((await resolve("git push", other))?.account, "jdoe-dev");
});

test("a remote named with a slash is the one pushed to", async () => {
  const dir = repo({ "forks/mine": "https://github.com/jdoe-dev/app.git", origin: "https://github.com/acme/app.git" });
  execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "x"]);
  execFileSync("git", ["-C", dir, "update-ref", "refs/remotes/forks/mine/main", "HEAD"]);
  execFileSync("git", ["-C", dir, "config", "branch.main.remote", "forks/mine"]);
  execFileSync("git", ["-C", dir, "config", "branch.main.merge", "refs/heads/main"]);
  const account = await resolve("git push", dir);
  assert.deepEqual([account?.account, account?.context], ["jdoe-dev", "forks/mine"]);
});

test("a remote rewritten later in the turn leaves earlier pushes unknown", async () => {
  const dir = repo({ personal: "https://github.com/decoy/app.git" });
  assert.deepEqual(
    await resolve("git push personal main; git remote set-url personal https://github.com/decoy/app.git", dir),
    { platform: "git", source: "unknown" },
  );
  const accounts = await resolveDestinationAccounts(
    [
      { tool_name: "bash", tool_use_id: "push", tool_input: { command: "git push personal main" } },
      { tool_name: "bash", tool_use_id: "rewrite", tool_input: { command: "git config --global url.https://x/.insteadOf https://y/" } },
    ],
    dir, { env: NO_GH },
  );
  assert.deepEqual(accounts.get("push"), { platform: "git", source: "unknown" });
});

test("rsync reads RSYNC_RSH and option clusters that take values", async () => {
  for (const command of [
    `RSYNC_RSH="ssh -F ${sshConfig} -p 2200" rsync -a src prod-bastion:/dest`,
    `rsync -af 'foo:bar' -e 'ssh -F ${sshConfig} -p 2200' src prod-bastion:/dest`,
  ]) {
    const account = await resolve(command);
    assert.deepEqual([account?.host, account?.user], ["10.0.4.12:2200", "deploy"], command);
  }
});

test("escapes inside quoted includes are read as ssh reads them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-quoted-escape-"));
  const folder = join(dir, "sub dir");
  run("mkdir", [folder]);
  const marker = join(dir, "ran");
  writeFileSync(join(folder, "inner_config"), `Match exec "touch ${marker}"\n`);
  for (const body of [`Include '${folder}/inner\\_config'`, `Include '${dir}/sub\\ dir/inner_config'`]) {
    writeFileSync(join(dir, "config"), `${body}\nHost prod-bastion\n  HostName 10.0.4.12\n`);
    assert.deepEqual(await resolve(`ssh -F ${join(dir, "config")} prod-bastion`), { platform: "ssh", source: "unknown" }, body);
  }
  assert.equal(existsSync(marker), false);
});

test("a call known not to have run is never resolved", async () => {
  const ran: string[][] = [];
  const execFile = async (file: string, args: readonly string[]) => {
    ran.push([file, ...args]);
    return undefined;
  };
  const accounts = await resolveDestinationAccounts(
    [{ tool_name: "bash", tool_use_id: "c1", decision: "confirm", ran: false, tool_input: { command: "ssh prod-bastion" } }],
    undefined, { execFile, env: NO_GH },
  );
  assert.equal(accounts.size, 0);
  assert.deepEqual(ran, []);
});

test("redirections are not arguments and heredoc bodies are not commands", async () => {
  const dir = repo({ personal: "https://github.com/jdoe-dev/app.git" });
  for (const command of [
    "git push personal main 2>&1 | tail -5",
    "git push > /tmp/push.log personal main",
    "git push personal main &>/dev/null",
    "cat <<'EOF'\nnotes\nEOF\ngit push personal main",
  ]) {
    assert.equal((await resolve(command, dir))?.account, "jdoe-dev", command);
  }
  for (const command of [
    `cat > deploy.sh <<'EOF'\nssh -F ${sshConfig} prod-bastion uptime\ngit push personal main\nEOF`,
    `cat <<-EOF\n\tssh -F ${sshConfig} prod-bastion\n\tEOF`,
  ]) {
    assert.equal(await resolve(command, dir), undefined, command);
  }
});

test("gh commands outside the checkout and urls with a login", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  for (const command of ["gh search repos unbound", "gh gist create notes.md", "gh repo create scratch --private"]) {
    assert.equal((await resolve(command, dir))?.account, undefined, command);
  }
  assert.equal((await resolve("gh pr view https://jdoe@github.com/other/app/pull/1", dir))?.account, "other");
});

test("scp uris, drive letters and sudo are never misread", async () => {
  assert.equal(await resolve(`scp -F ${sshConfig} dump.sql scp://deploy:p@ss@prod-bastion:2200/tmp/`), undefined);
  // scp reads C:\x as a local path everywhere, and C:/x as host C except on Windows.
  const backslash = await resolve(`scp -F ${sshConfig} prod-bastion:/tmp/file C:\\\\Users\\\\me`);
  assert.deepEqual([backslash?.host, backslash?.user], ["10.0.4.12:2222", "deploy"]);
  const slash = await resolve(`scp -F ${sshConfig} prod-bastion:/tmp/file C:/Users/me/out`);
  assert.equal(slash?.host, process.platform === "win32" ? "10.0.4.12:2222" : "c");
  assert.deepEqual(await resolve("sudo -u nobody ssh prod-bastion"), { platform: "ssh", source: "unknown" });
});

test("git config set rewrites count as rewrites", async () => {
  const dir = repo({ personal: "https://github.com/decoy/app.git" });
  assert.deepEqual(
    await resolve("git push personal main; git config set remote.personal.url https://github.com/decoy/app.git", dir),
    { platform: "git", source: "unknown" },
  );
});

test("gh repo, unset variables and api urls follow the command", async () => {
  const dir = repo({ origin: "https://github.com/acme/app.git" });
  assert.equal((await resolve("GH_REPO=other/app gh search repos unbound", dir))?.account, undefined);
  const unset = await resolveDestinationAccounts(
    [{ tool_name: "bash", tool_use_id: "c1", tool_input: { command: "unset GH_HOST; gh repo view acme/app" } }],
    undefined, { env: { GH_HOST: "ghe.example.com" } },
  );
  assert.equal(unset.get("c1")?.host, "github.com");
  const full = await resolve("gh api https://ghe.example.com/api/v3/repos/acme/app", dir);
  assert.deepEqual([full?.host, full?.account], ["ghe.example.com", "acme"]);
  const user = await resolve("gh api https://ghe.example.com/api/v3/user", dir);
  assert.deepEqual([user?.host, user?.account], ["ghe.example.com", undefined]);
});

test("a destination starting with a dash never reaches ssh as an option", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ssh-dash-"));
  const marker = join(dir, "ran");
  writeFileSync(join(dir, "evil"), `Match exec "touch ${marker}"\n`);
  assert.equal(await resolve(`ssh -- -F${join(dir, "evil")} prod-bastion`), undefined);
  assert.equal(existsSync(marker), false);
});
