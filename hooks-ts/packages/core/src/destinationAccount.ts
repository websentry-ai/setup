// Destination account — which account a shell call reached, identity fields only.
// Parity with the Python hooks' `_destination_account` block: the same platforms (git push, gh, the ssh
// family), the same allowlisted local lookups, the same wire object on each `tool_use` entry.
//
// Total by construction: no `throw` escapes; a failed or slow lookup is `{platform, source: "unknown"}`,
// a command that reaches no account is `undefined`. Every lookup has a deadline and the turn shares one
// budget, so the turn log is never held up for long.

import { readFileSync } from "node:fs";
import { isAbsolute, join, normalize, basename } from "node:path";
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
  if (GH_TOKEN_ENV.some((k) => env[k] || state.env[k])) return "";
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
  const rest = [...args];
  while (rest.length > 0 && (rest[0] as string).startsWith("-")) {
    const flag = rest.shift() as string;
    if (flag === "-C" && rest.length > 0) {
      const path = expandHome(rest.shift() as string);
      gitDir = isAbsolute(path) ? path : gitDir === undefined ? undefined : join(gitDir, path);
    } else if (["-c", "--git-dir", "--work-tree", "--namespace"].includes(flag) && rest.length > 0) {
      rest.shift();
    }
  }
  if (rest[0] !== "push") return undefined;
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
): Promise<DestinationAccount> {
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

function sshDestination(name: string, args: string[]): { destination?: string; passthrough: string[] } {
  const passthrough: string[] = [];
  const positional: string[] = [];
  const valueFlags = SSH_VALUE_FLAGS[name] ?? "";
  // Only the options that change which host or user ssh -G resolves are passed through; scp's -l is a bandwidth limit.
  const identityFlags = name === "ssh" ? ["l", "o", "F", "J", "p"] : ["o", "F", "J", "P"];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (name === "rsync") {
      if (arg === "-e" || arg === "--rsh") i++;
      else if (!arg.startsWith("-")) positional.push(arg);
      continue;
    }
    if (arg.startsWith("-") && arg.length >= 2 && arg !== "--") {
      const flag = arg[1] as string;
      const attached = arg.slice(2);
      const takesValue = valueFlags.includes(flag);
      const value = attached !== "" ? attached : takesValue ? args[i + 1] : undefined;
      if (takesValue && value !== undefined && identityFlags.includes(flag)) {
        passthrough.push(flag === "P" ? "-p" : `-${flag}`, value);
      }
      if (attached === "" && takesValue) i++;
      continue;
    }
    positional.push(arg);
  }
  if (name === "ssh") return positional[0] === undefined ? { passthrough: [] } : { destination: positional[0], passthrough };
  // The last remote operand is where the copy goes.
  for (const arg of [...positional].reverse()) {
    if (arg.startsWith("rsync://") || arg.includes("::")) return { passthrough: [] };
    const match = /^((?:[^@/:]+@)?\[?[^/:\]]+\]?):/.exec(arg);
    if (match !== null && !/^[A-Za-z]:\\/.test(arg)) return { destination: match[1], passthrough };
  }
  const first = positional[0];
  if (name === "sftp" && first !== undefined && /^(?:[^@/:]+@)?\[?[^/:\]]+\]?$/.test(first)) {
    return { destination: first, passthrough };
  }
  return { passthrough: [] };
}

function expandHome(path: string): string {
  return path === "~" || path.startsWith("~/") ? join(homedir(), path.slice(1)) : path;
}

/** Whether the ssh config that ssh -G would read has a Match exec, which ssh runs while resolving. */
function configRunsCommands(passthrough: readonly string[]): boolean {
  let path = "~/.ssh/config";
  for (let i = 0; i + 1 < passthrough.length; i += 2) if (passthrough[i] === "-F") path = passthrough[i + 1] as string;
  try {
    return /^\s*match\b.*\bexec\b/im.test(readFileSync(expandHome(path), "utf8"));
  } catch {
    return false;
  }
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
