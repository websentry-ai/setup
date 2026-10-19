// Destination account — which account a shell call reached, identity fields only.
// Parity with the Python hooks' `_destination_account` block: the same platforms (git push, gh, the ssh
// family), the same allowlisted local lookups, the same wire object on each `tool_use` entry.
//
// Total by construction: no `throw` escapes; a failed or slow lookup is `{platform, source: "unknown"}`,
// a command that reaches no account is `undefined`. Every lookup has a deadline and the turn shares one
// budget, so the turn log is never held up for long.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, normalize, basename, dirname } from "node:path";
import { homedir } from "node:os";

import { defaultExecFile, type ExecFileLike } from "./accountIdentity.ts";

export interface DestinationAccount {
  platform: string;
  host?: string;
  account?: string;
  user?: string;
  context?: string;
  source: "command" | "file" | "unknown";
}

/** Only these lookups are ever run; anything else is refused before it starts. */
const ALLOWED_RUNS: readonly (readonly string[])[] = [
  ["git", "remote", "get-url", "--push"],
  ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name"],
  ["git", "config", "--get"],
  ["gh", "config", "get", "-h"],
  ["ssh", "-G"],
];
const RUN_TIMEOUT_MS = 5_000;
const TURN_BUDGET_MS = 10_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const WRAPPERS: ReadonlySet<string> = new Set(["sudo", "env", "command", "exec", "time", "nohup"]);
const SSH_TOOLS: ReadonlySet<string> = new Set(["ssh", "scp", "sftp", "rsync"]);
/** Options that take a value, per program; every other option is a switch. */
const SSH_VALUE_FLAGS: Record<string, string> = { ssh: "BbcDEeFIiJLlmOoPpQRSWw", scp: "cDFiJloPSX", sftp: "BbcDFiJloPRSsX" };
const GH_TOKEN_ENV = ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"];
const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell"]);
/** Of ssh's -o settings, only these change which host or user ssh -G resolves. */
const SSH_IDENTITY_OPTIONS: ReadonlySet<string> = new Set(["hostname", "user", "port", "proxyjump"]);
const SSH_CONFIG_MAX_BYTES = 256 * 1024;
const SSH_CONFIG_MAX_FILES = 32;
// One string, because a bundle-check treats `-from", "` between literals as an import.
const RSYNC_VALUE_OPTIONS: ReadonlySet<string> = new Set(
  ("--exclude --include --filter -f --exclude-from --include-from --files-from --rsync-path --log-file " +
    "--partial-dir --temp-dir -T --compare-dest --copy-dest --link-dest --backup-dir --chmod --chown --suffix " +
    "--password-file --port --bwlimit --timeout --max-size --min-size --out-format --remote-option -M").split(" "),
);
/** gh commands that reach no repository. */
const GH_NO_REPO: ReadonlySet<string> = new Set([
  "auth", "help", "version", "config", "alias", "extension", "completion", "--help", "-h", "--version",
]);
/** Settings that move the repository or rewrite its config, so the remote read here may not be the one pushed to. */
const GIT_OVERRIDE_ENV = ["GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"];
/** Policy outcomes under which the call never ran, so there is nothing to resolve. */
const NEVER_RAN: ReadonlySet<string> = new Set(["deny", "unavailable"]);

export interface ResolveOptions {
  execFile?: ExecFileLike;
  env?: Record<string, string | undefined>;
  now?: () => number;
}

interface State {
  run: ExecFileLike;
  env: Record<string, string | undefined>;
  now: () => number;
  deadline: number;
  ghUser: Map<string, string>;
}

function stripGitDir(argv: readonly string[]): readonly string[] {
  return argv.length >= 3 && argv[0] === "git" && argv[1] === "-C" ? [argv[0], ...argv.slice(3)] : argv;
}

async function run(argv: string[], state: State): Promise<string | undefined> {
  try {
    const bare = stripGitDir(argv);
    if (!ALLOWED_RUNS.some((p) => p.every((part, i) => bare[i] === part))) return undefined;
    const remaining = state.deadline - state.now();
    if (remaining <= 0) return undefined;
    const [file, ...args] = argv;
    if (file === undefined) return undefined;
    return await state.run(file, args, { timeoutMs: Math.min(RUN_TIMEOUT_MS, remaining), maxBytes: MAX_OUTPUT_BYTES });
  } catch {
    return undefined;
  }
}

/** The command split into simple commands on ; && || | and newlines, each as argv. */
export function segments(command: string): string[][] {
  const out: string[][] = [];
  let current: string[] = [];
  let word = "";
  let inWord = false;
  let quote: "'" | '"' | undefined;
  const endWord = (): void => {
    if (inWord) current.push(word);
    word = "";
    inWord = false;
  };
  const endSegment = (): void => {
    endWord();
    if (current.length > 0) out.push(current);
    current = [];
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i] as string;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else if (ch === "\\" && quote === '"' && i + 1 < command.length) word += command[++i];
      else word += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
    } else if (ch === "\\" && command[i + 1] === "\n") {
      i++; // a backslash-newline continues the line
    } else if (ch === "#" && !inWord) {
      while (i + 1 < command.length && command[i + 1] !== "\n") i++; // a comment runs to the end of its line
    } else if (ch === "\\" && i + 1 < command.length) {
      word += command[++i];
      inWord = true;
    } else if (ch === ";" || ch === "&" || ch === "|" || ch === "\n") {
      endSegment();
    } else if (ch === " " || ch === "\t" || ch === "\r") {
      endWord();
    } else {
      word += ch;
      inWord = true;
    }
  }
  endSegment();
  return out;
}

function program(argv: string[]): { name?: string; args: string[]; env: Record<string, string> } {
  const env: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i] as string;
    const eq = token.indexOf("=");
    if (eq > 0 && !token.startsWith("-") && /^[A-Za-z0-9_]+$/.test(token.slice(0, eq))) {
      env[token.slice(0, eq)] = token.slice(eq + 1);
    } else if (WRAPPERS.has(basename(token))) {
      continue;
    } else if (token.startsWith("-") && i > 0 && WRAPPERS.has(basename(argv[i - 1] as string))) {
      continue;
    } else {
      return { name: basename(token), args: argv.slice(i + 1), env };
    }
  }
  return { args: [], env };
}

function stripLogin(url: string): string {
  return url.trim().replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/@]*@/, "$1");
}

function remoteParts(raw: string): { host: string; owner: string } {
  const url = stripLogin(raw);
  const match =
    /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/:]+)(?::\d+)?\/(.*)$/.exec(url) ?? /^(?:[^@/:]+@)?([^/:]+):(?!\/\/)(.*)$/.exec(url);
  if (match === null) return { host: "", owner: "" };
  const host = (match[1] ?? "").toLowerCase();
  const parts = (match[2] ?? "").replace(/^\/+|\/+$/g, "").replace(/\.git$/, "").split("/").filter(Boolean);
  return { host, owner: parts[0] ?? "" };
}

function platformForHost(host: string): string {
  if (host === "github.com" || host.endsWith(".ghe.com")) return "github";
  if (host === "gitlab.com") return "gitlab";
  return "git";
}

function firstLine(out: string | undefined): string {
  return (out ?? "").trim().split(/\r?\n/)[0] ?? "";
}

async function ghUser(host: string, env: Record<string, string>, state: State): Promise<string> {
  if (GH_TOKEN_ENV.some((k) => env[k] || state.env[k]) || env.GH_CONFIG_DIR) return "";
  const cached = state.ghUser.get(host);
  if (cached !== undefined) return cached;
  const user = firstLine(await run(["gh", "config", "get", "-h", host, "user"], state));
  state.ghUser.set(host, user);
  return user;
}

async function gitPush(
  args: string[], env: Record<string, string>, cwd: string | undefined, state: State,
): Promise<DestinationAccount | undefined> {
  let gitDir = cwd;
  let overridden = GIT_OVERRIDE_ENV.some((k) => env[k]);
  const rest = [...args];
  while (rest.length > 0 && (rest[0] as string).startsWith("-")) {
    const flag = rest.shift() as string;
    if (flag === "-C" && rest.length > 0) {
      const path = expandHome(rest.shift() as string);
      gitDir = isAbsolute(path) ? path : gitDir === undefined ? undefined : join(gitDir, path);
    } else if (["-c", "--git-dir", "--work-tree"].includes(flag) && rest.length > 0) {
      rest.shift();
      overridden = true;
    } else if (/^(--git-dir=|--work-tree=|--config-env)/.test(flag) || (flag.startsWith("-c") && flag.length > 2)) {
      overridden = true;
    } else if (flag === "--namespace" && rest.length > 0) {
      rest.shift();
    }
  }
  if (rest[0] !== "push") return undefined;
  // Unknown is safe; the cwd repo's remote would be a confident wrong answer.
  if (overridden) return { platform: "git", source: "unknown" };
  const pushArgs = rest.slice(1);
  let target: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < pushArgs.length; i++) {
    const arg = pushArgs[i] as string;
    if (["-o", "--push-option", "--receive-pack", "--exec"].includes(arg)) {
      i++;
    } else if (arg === "--repo" && i + 1 < pushArgs.length) {
      target = pushArgs[++i];
    } else if (arg.startsWith("--repo=")) {
      target = arg.slice("--repo=".length);
    } else if (!arg.startsWith("-")) {
      positional.push(arg);
    }
  }
  target = target ?? positional[0];
  const base = ["git", "-C", gitDir ?? "."];
  let url: string | undefined;
  let remote = "";
  if (target !== undefined && /:\/\/|^[^/:]+@[^/:]+:|^[^/:]+:[^/]/.test(target)) {
    url = target;
  } else if (gitDir === undefined) {
    // Without the folder the push ran in, its remotes can't be read.
    return { platform: "git", source: "unknown" };
  } else {
    remote = target ?? "";
    if (remote === "") {
      const out = firstLine(await run([...base, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}"], state));
      remote = out.includes("/") ? (out.split("/")[0] as string) : "origin";
    }
    url = firstLine(await run([...base, "remote", "get-url", "--push", remote], state)) || undefined;
  }
  const { host, owner } = url === undefined ? { host: "", owner: "" } : remoteParts(url);
  if (host === "" || url === undefined) return { platform: "git", source: "unknown" };
  let user = "";
  if (/^https?:\/\//.test(url.trim())) {
    const helper =
      (await run([...base, "config", "--get", `credential.https://${host}.helper`], state)) ??
      (await run([...base, "config", "--get", "credential.helper"], state)) ??
      "";
    if (helper.includes("auth git-credential")) user = await ghUser(host, env, state);
  }
  return { platform: platformForHost(host), host, account: owner, user, context: remote, source: "command" };
}

async function gh(
  args: string[], env: Record<string, string>, cwd: string | undefined, state: State,
): Promise<DestinationAccount | undefined> {
  if (args[0] === undefined || GH_NO_REPO.has(args[0])) return undefined;
  let repo = "";
  let flagHost = "";
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if ((arg === "-R" || arg === "--repo") && i + 1 < args.length) repo = args[i + 1] as string;
    else if (arg.startsWith("--repo=")) repo = arg.slice("--repo=".length);
    else if (arg === "--hostname" && i + 1 < args.length) flagHost = (args[i + 1] as string).toLowerCase();
  }
  // `gh repo view|clone|fork|… OWNER/REPO` and `gh api repos/OWNER/REPO/…` name the repository themselves.
  const third = args[2];
  if (repo === "" && args[0] === "repo" && third !== undefined && !third.startsWith("-") && third.includes("/")) {
    repo = third;
  }
  let lookupDir = cwd;
  if (repo === "" && args[0] === "api") {
    const named = args.slice(1).map((a) => /^\/?repos\/([^/{}]+\/[^/{}]+)/.exec(a)).find((m) => m !== null);
    if (named) repo = named[1] as string;
    else if (!args.some((a) => a.includes("{owner}") || a.includes("{repo}"))) lookupDir = undefined;
  }
  repo = repo || env.GH_REPO || state.env.GH_REPO || "";
  const envHost = (env.GH_HOST ?? state.env.GH_HOST ?? "").toLowerCase();
  let host = "";
  let owner = "";
  if (repo !== "") {
    repo = repo.trim().replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?[^/@]*@/, "$1"); // never keep a login or token
    if (repo.includes(":")) {
      ({ host, owner } = remoteParts(repo));
    } else {
      const parts = repo.split("/").filter(Boolean);
      if (parts.length >= 3) {
        host = (parts[0] as string).toLowerCase();
        owner = parts[1] as string;
      } else {
        owner = parts[0] ?? "";
      }
    }
  } else if (lookupDir !== undefined) {
    const url = firstLine(await run(["git", "-C", lookupDir, "remote", "get-url", "--push", "origin"], state));
    if (url !== "") ({ host, owner } = remoteParts(url));
  }
  host = flagHost || host || envHost || "github.com";
  return { platform: "github", host, account: owner, user: await ghUser(host, env, state), context: "", source: "command" };
}

/** The last [user@]host: operand, which is where a copy goes; undefined for an rsync daemon or only local paths. */
function remoteOperand(operands: readonly string[]): string | undefined {
  for (const arg of [...operands].reverse()) {
    if (arg.startsWith("rsync://") || arg.includes("::")) return undefined;
    const match = /^((?:[^@/:]+@)?\[?[^/:\]]+\]?):/.exec(arg);
    if (match !== null && !/^[A-Za-z]:\\/.test(arg)) return match[1];
  }
  return undefined;
}

/** rsync's last remote operand, reached through its remote shell, with that shell's ssh identity options. */
function rsyncDestination(args: string[]): { destination?: string; passthrough: string[] } {
  let shell: string | undefined;
  const operands: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === "--rsh" && i + 1 < args.length) shell = args[++i];
    else if (arg.startsWith("--rsh=")) shell = arg.slice("--rsh=".length);
    else if (arg.startsWith("-") && !arg.startsWith("--") && arg.indexOf("e", 1) > 0) {
      const rest = arg.slice(arg.indexOf("e", 1) + 1);
      if (rest !== "") shell = rest;
      else if (i + 1 < args.length) shell = args[++i];
    } else if (RSYNC_VALUE_OPTIONS.has(arg)) i++;
    else if (!arg.startsWith("-")) operands.push(arg);
  }
  let passthrough: string[] = [];
  if (shell !== undefined) {
    const shellArgv = segments(shell)[0] ?? [];
    // A remote shell other than ssh never reads the ssh config.
    if (shellArgv[0] === undefined || basename(shellArgv[0]) !== "ssh") return { passthrough: [] };
    passthrough = sshDestination("ssh", [...shellArgv.slice(1), "-"]).passthrough;
  }
  const destination = remoteOperand(operands);
  return destination === undefined ? { passthrough: [] } : { destination, passthrough };
}

function sshDestination(name: string, args: string[]): { destination?: string; passthrough: string[] } {
  if (name === "rsync") return rsyncDestination(args);
  const passthrough: string[] = [];
  const operands: string[] = [];
  const valueFlags = SSH_VALUE_FLAGS[name] ?? "";
  // Only the options that change which host or user ssh -G resolves are passed through; scp's -l is a bandwidth limit.
  const identityFlags = name === "ssh" ? ["l", "o", "F", "J", "p"] : ["o", "F", "J", "P"];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    // Options end at the first operand: what follows an ssh destination is the remote command.
    if (operands.length > 0 || !arg.startsWith("-") || arg === "-") {
      operands.push(arg);
      continue;
    }
    if (arg === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    // Walk a cluster such as -vF: the first option that takes a value takes the rest of it, or the next word.
    for (let j = 1; j < arg.length; j++) {
      const flag = arg[j] as string;
      if (!valueFlags.includes(flag)) continue;
      let value = arg.slice(j + 1);
      if (value === "" && i + 1 < args.length) value = args[++i] as string;
      const option = (value.trim().split(/[\s=]/)[0] ?? "").toLowerCase();
      if (value !== "" && identityFlags.includes(flag) && (flag !== "o" || SSH_IDENTITY_OPTIONS.has(option))) {
        passthrough.push(flag === "P" ? "-p" : `-${flag}`, value);
      }
      break;
    }
  }
  if (name === "ssh") return operands[0] === undefined ? { passthrough: [] } : { destination: operands[0], passthrough };
  const destination = remoteOperand(operands);
  if (destination !== undefined) return { destination, passthrough };
  // sftp also takes a plain [user@]host with no path.
  const first = operands[0];
  if (name === "sftp" && first !== undefined && /^(?:[^@/:]+@)?\[?[^/:\]]+\]?$/.test(first)) {
    return { destination: first, passthrough };
  }
  return { passthrough: [] };
}

function expandHome(path: string): string {
  return path === "~" || path.startsWith("~/") ? join(homedir(), path.slice(1)) : path;
}

/** The files an ssh Include pattern names; undefined when it can't be expanded, so the caller refuses. */
function includeTargets(pattern: string, base: string): string[] | undefined {
  const path = expandHome(pattern.replace(/^"|"$/g, ""));
  const full = isAbsolute(path) ? path : join(base, path);
  if (!/[*?[]/.test(full)) return [full];
  if (/[*?[]/.test(dirname(full))) return undefined;
  const glob = new RegExp(`^${basename(full).replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
  try {
    return readdirSync(dirname(full)).filter((entry) => glob.test(entry)).sort().map((entry) => join(dirname(full), entry));
  } catch {
    return [];
  }
}

/** Whether ssh -G could run a command while reading its configs: a Match exec anywhere, or a file it can't check. */
function configRunsCommands(passthrough: readonly string[]): boolean {
  const homeSsh = join(homedir(), ".ssh");
  let config: string | undefined;
  for (let i = 0; i + 1 < passthrough.length; i += 2) if (passthrough[i] === "-F") config = passthrough[i + 1];
  if (config === "none") return false;
  if (config !== undefined && !isAbsolute(config)) return true;
  const pending: [string, string][] =
    config === undefined ? [[join(homeSsh, "config"), homeSsh], ["/etc/ssh/ssh_config", "/etc/ssh"]] : [[config, homeSsh]];
  const seen = new Set<string>();
  while (pending.length > 0) {
    const [path, base] = pending.pop() as [string, string];
    if (seen.has(path)) continue;
    seen.add(path);
    let text: string;
    try {
      const info = statSync(path, { throwIfNoEntry: false });
      if (info === undefined) continue;
      // Only small regular files are read, so a fifo or a huge file can't hold up the turn.
      if (seen.size > SSH_CONFIG_MAX_FILES || !info.isFile() || info.size > SSH_CONFIG_MAX_BYTES) return true;
      text = readFileSync(path, "utf8");
    } catch {
      return true;
    }
    for (const line of text.split(/\r?\n/)) {
      if (/^\s*match\b.*\bexec\b/i.test(line)) return true;
      const include = /^\s*include\s*[=\s]\s*(.+)/i.exec(line);
      for (const pattern of include?.[1]?.trim().split(/\s+/) ?? []) {
        const targets = includeTargets(pattern, base);
        if (targets === undefined) return true;
        pending.push(...targets.map((target): [string, string] => [target, base]));
      }
    }
  }
  return false;
}

async function ssh(name: string, args: string[], dir: string | undefined, state: State): Promise<DestinationAccount | undefined> {
  const { destination, passthrough } = sshDestination(name, args);
  if (destination === undefined) return undefined;
  // The lookup runs elsewhere, so a relative config path is resolved against the folder the command ran in.
  for (let i = 0; i + 1 < passthrough.length; i += 2) {
    const value = expandHome(passthrough[i + 1] as string);
    if (passthrough[i] === "-F" && !isAbsolute(value) && value !== "none") passthrough[i + 1] = join(dir ?? "", value);
  }
  if (configRunsCommands(passthrough)) return { platform: "ssh", source: "unknown" };
  const out = await run(["ssh", "-G", ...passthrough, destination], state);
  if (out === undefined) return { platform: "ssh", source: "unknown" };
  const settings = new Map<string, string>();
  for (const line of out.split(/\r?\n/)) {
    const [key, ...value] = line.trim().split(" ");
    if (key !== undefined && ["hostname", "user", "port"].includes(key) && !settings.has(key)) {
      settings.set(key, value.join(" ").trim());
    }
  }
  const host = (settings.get("hostname") ?? "").toLowerCase();
  if (host === "") return { platform: "ssh", source: "unknown" };
  const port = settings.get("port") ?? "22";
  const alias = (destination.split("@").pop() ?? "").replace(/^\[|\]$/g, "");
  return {
    platform: "ssh",
    host: port === "" || port === "22" ? host : `${host}:${port}`,
    user: settings.get("user") ?? "",
    context: alias.toLowerCase() !== host ? alias : "",
    source: "command",
  };
}

/** Drops empty identity fields, keeping platform and source. */
function compact(account: DestinationAccount): DestinationAccount {
  const out: DestinationAccount = { platform: account.platform, source: account.source };
  for (const key of ["host", "account", "user", "context"] as const) {
    if (account[key]) out[key] = account[key];
  }
  return out;
}

async function resolveOne(command: string, cwd: string | undefined, state: State): Promise<DestinationAccount | undefined> {
  let dir = cwd;
  let unresolved: DestinationAccount | undefined;
  for (const argv of segments(command)) {
    const { name, args, env } = program(argv);
    let account: DestinationAccount | undefined;
    if (name === "cd") {
      // Later segments run in the folder this one moves to.
      const target = expandHome(args[0] ?? "~");
      dir = isAbsolute(target) ? target : normalize(join(dir ?? "", target));
      continue;
    }
    if (name === "git") account = await gitPush(args, env, dir, state);
    else if (name === "gh") account = await gh(args, env, dir, state);
    else if (name !== undefined && SSH_TOOLS.has(name)) account = await ssh(name, args, dir, state);
    if (account === undefined) continue;
    if (account.source !== "unknown") return compact(account);
    unresolved ??= compact(account);
  }
  return unresolved;
}

export interface ShellCall {
  tool_name?: unknown;
  tool_use_id?: unknown;
  tool_input?: unknown;
  decision?: unknown;
}

/** The account each shell call of a turn reached, keyed by `tool_use_id`; each call starts in `cwd`. Never rejects. */
export async function resolveDestinationAccounts(
  calls: readonly ShellCall[], cwd: string | undefined, opts: ResolveOptions = {},
): Promise<Map<string, DestinationAccount>> {
  const accounts = new Map<string, DestinationAccount>();
  try {
    const now = opts.now ?? Date.now;
    const state: State = {
      run: opts.execFile ?? defaultExecFile,
      env: opts.env ?? process.env,
      now,
      deadline: now() + TURN_BUDGET_MS,
      ghUser: new Map(),
    };
    for (const call of calls) {
      const input = call.tool_input;
      const command =
        input !== null && typeof input === "object" && !Array.isArray(input)
          ? (input as Record<string, unknown>).command
          : undefined;
      if (typeof call.tool_name !== "string" || !SHELL_TOOLS.has(call.tool_name)) continue;
      if (typeof call.decision === "string" && NEVER_RAN.has(call.decision)) continue;
      if (typeof command !== "string" || command.trim() === "" || typeof call.tool_use_id !== "string") continue;
      const account = await resolveOne(command, cwd, state);
      if (account !== undefined) accounts.set(call.tool_use_id, account);
    }
  } catch {
    // Telemetry enrichment: whatever resolved before the failure is still returned.
  }
  return accounts;
}
