// Destination account — which account a shell call reached, identity fields only.
// Parity with the Python hooks' `_destination_account` block: the same platforms (git push, gh, the ssh
// family), the same allowlisted local lookups, the same wire object on each `tool_use` entry.
//
// Total by construction: no `throw` escapes; a failed or slow lookup is `{platform, source: "unknown"}`,
// a command that reaches no account is `undefined`. Every lookup has a deadline and the turn shares one
// budget, so the turn log is never held up for long.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
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
  ["git", "remote", "get-url"],
  ["git", "rev-parse", "--symbolic-full-name"],
  ["git", "symbolic-ref", "--short", "-q", "HEAD"],
  ["git", "config", "--get"],
  ["git", "config", "--get-regexp"],
  ["gh", "config", "get", "-h"],
  ["ssh", "-G"],
];
const RUN_TIMEOUT_MS = 5_000;
const TURN_BUDGET_MS = 10_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
/** Wrappers that run the command after them: short options that take a value, long ones that do, operands before it. */
const WRAPPERS: Record<string, { short: string; long: readonly string[]; operands: number }> = {
  sudo: {
    short: "ugCDhprtTU",
    // One string, for the same bundle-check reason as the rsync list below.
    long: "--user --group --close-from --chdir --host --prompt --role --type --command-timeout --other-user".split(" "),
    operands: 0,
  },
  doas: { short: "uC", long: [], operands: 0 },
  env: { short: "uCS", long: ["--unset", "--chdir", "--split-string"], operands: 0 },
  nice: { short: "n", long: ["--adjustment"], operands: 0 },
  timeout: { short: "ks", long: ["--kill-after", "--signal"], operands: 1 },
  time: { short: "fo", long: ["--format", "--output"], operands: 0 },
  stdbuf: { short: "ioe", long: ["--input", "--output", "--error"], operands: 0 },
  ionice: { short: "cnp", long: ["--class", "--classdata", "--pid"], operands: 0 },
  exec: { short: "a", long: [], operands: 0 },
  command: { short: "", long: [], operands: 0 },
  nohup: { short: "", long: [], operands: 0 },
};
/** Where `-C`/`--chdir` or `-D` moves a wrapped command. */
const WRAPPER_CHDIR: Record<string, readonly string[]> = { env: ["-C", "--chdir"], sudo: ["-D", "--chdir"] };
const SSH_TOOLS: ReadonlySet<string> = new Set(["ssh", "scp", "sftp", "rsync"]);
/** Options that take a value, per program; every other option is a switch. */
const SSH_VALUE_FLAGS: Record<string, string> = {
  ssh: "BbcDEeFIiJLlmOoPpQRSWw", scp: "cDFiJloPSX", sftp: "BbcDFiJloPRSsX", rsync: "efTMB@",
};
const GH_TOKEN_ENV = ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"];
const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell"]);
/** Of ssh's -o settings, only these change which host or user ssh -G resolves. */
const SSH_IDENTITY_OPTIONS: ReadonlySet<string> = new Set(["hostname", "user", "port", "proxyjump"]);
const SSH_CONFIG_MAX_BYTES = 256 * 1024;
const SSH_CONFIG_MAX_FILES = 32;
// One string, because a bundle-check treats `-from", "` between literals as an import.
const RSYNC_VALUE_OPTIONS: ReadonlySet<string> = new Set(
  ("--exclude --include --filter --exclude-from --include-from --files-from --rsync-path --log-file " +
    "--partial-dir --temp-dir --compare-dest --copy-dest --link-dest --backup-dir --chmod --chown --suffix " +
    "--password-file --port --bwlimit --timeout --max-size --min-size --out-format --remote-option --block-size " +
    "--modify-window").split(" "),
);
/** gh commands that reach no repository. */
const GH_NO_REPO: ReadonlySet<string> = new Set([
  "auth", "help", "version", "config", "alias", "extension", "completion", "--help", "-h", "--version",
]);
/** gh options whose value is never a repository, skipped so a value such as --title '-Rx/y' is not read as one. */
const GH_VALUE_OPTIONS: ReadonlySet<string> = new Set(
  ("-t --title -b --body -F --body-file -B --base -H --head -l --label -a --assignee -r --reviewer -m --milestone " +
    "--project -q --jq -T --template --json -S --search -s --state -L --limit -A --author -f --field --raw-field " +
    "--header -X --method --input --workflow --ref -n --notes --notes-file --target -j --job --branch --message --name " +
    "--description --visibility --color --env --org --key").split(" "),
);
/** gh commands that reach GitHub but not the checkout's repository, so only the host and login are known. */
const GH_NO_CHECKOUT: ReadonlySet<string> = new Set(["search", "gist", "org", "codespace", "ssh-key", "gpg-key", "status", "project"]);
/** gh picks among unresolved remotes in this order. */
const GH_REMOTE_ORDER = ["upstream", "github", "origin"];
/** Settings that move the repository or rewrite its config, so the remote read here may not be the one pushed to. */
const GIT_OVERRIDE_ENV = [
  "GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
];
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
  remotes: Map<string, Map<string, Record<string, string>>>;
  /** Pushes already resolved this turn, by the folder whose remotes they were read from. */
  pushResults: [string, DestinationAccount][];
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

export interface Segment {
  argv: string[];
  /** The operator before this command: "" for the first, "&&", "||", or ";" for any other separator. */
  operator: string;
}

/** The shell word starting at `start` after blanks, and the index after it; quotes and backslashes are undone. */
function readWord(text: string, start: number): [string, number] {
  let i = start;
  while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
  let word = "";
  let quote: string | undefined;
  for (; i < text.length; i++) {
    const ch = text[i] as string;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else if (ch === "\\" && quote === '"' && i + 1 < text.length) word += text[++i];
      else word += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "\\" && i + 1 < text.length) {
      word += text[++i];
    } else if (" \t\r\n;&|<>".includes(ch)) {
      break;
    } else {
      word += ch;
    }
  }
  return [word, i];
}

/** The command split into simple commands with the operator before each; redirections and heredoc bodies are left out. */
export function segments(command: string): Segment[] {
  const out: Segment[] = [];
  let current: string[] = [];
  let word = "";
  let inWord = false;
  let quote: "'" | '"' | undefined;
  let operator = "";
  const heredocs: [string, boolean][] = [];
  const endWord = (): void => {
    if (inWord) current.push(word);
    word = "";
    inWord = false;
  };
  const endSegment = (next: string): void => {
    endWord();
    if (current.length > 0) {
      out.push({ argv: current, operator });
      operator = next;
    } else if (next !== ";") {
      operator = next;
    }
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
    } else if (ch === "<" || ch === ">" || (ch === "&" && command[i + 1] === ">")) {
      // A redirection's operator, an fd number written against it, and its target are not arguments.
      if (inWord && !(/^\d+$/.test(word) && ch !== "&")) current.push(word);
      word = "";
      inWord = false;
      const op = (/^(?:&>>?|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>)/.exec(command.slice(i)) as RegExpExecArray)[0];
      const [target, next] = readWord(command, i + op.length);
      if (op === "<<" || op === "<<-") heredocs.push([target, op === "<<-"]);
      i = next - 1;
    } else if ((ch === "&" || ch === "|") && command[i + 1] === ch) {
      i++;
      endSegment(ch + ch);
    } else if (ch === ";" || ch === "&" || ch === "|" || ch === "\n") {
      endSegment(";");
      // A heredoc's body starts on the next line and is input, not commands.
      while (ch === "\n" && heredocs.length > 0) {
        const [delimiter, stripTabs] = heredocs.shift() as [string, boolean];
        while (i + 1 < command.length) {
          const end = command.indexOf("\n", i + 1);
          const line = end < 0 ? command.slice(i + 1) : command.slice(i + 1, end);
          i = end < 0 ? command.length - 1 : end;
          if ((stripTabs ? line.replace(/^\t+/, "") : line) === delimiter) break;
        }
      }
    } else if (ch === " " || ch === "\t" || ch === "\r") {
      endWord();
    } else {
      word += ch;
      inWord = true;
    }
  }
  if (quote !== undefined) return [];
  endSegment(";");
  return out;
}

/** A string's words, split as a shell would without its operators. */
function shellWords(text: string): string[] {
  return segments(text).flatMap((segment) => segment.argv);
}

function isAssignment(token: string): boolean {
  const eq = token.indexOf("=");
  return eq > 0 && !token.startsWith("-") && /^[A-Za-z0-9_]+$/.test(token.slice(0, eq));
}

function moveTo(cwd: string | undefined, path: string): string {
  const target = expandHome(path);
  return isAbsolute(target) ? target : normalize(join(cwd ?? "", target));
}

/** The program a simple command runs, its args, inline VAR=value settings and folder, past assignments and wrappers. */
function program(
  input: string[], cwd: string | undefined,
): { name?: string; args: string[]; env: Record<string, string>; cwd: string | undefined; otherUser: boolean } {
  const env: Record<string, string> = {};
  const argv = [...input];
  let otherUser = false;
  let wrapper: string | undefined;
  let operands = 0;
  let optionsDone = false;
  for (let i = 0; i < argv.length; ) {
    const token = argv[i++] as string;
    if (isAssignment(token) && (wrapper === undefined || optionsDone || wrapper === "env" || wrapper === "sudo")) {
      const eq = token.indexOf("=");
      env[token.slice(0, eq)] = token.slice(eq + 1);
      continue;
    }
    if (wrapper !== undefined && !optionsDone && token === "--") {
      optionsDone = true;
      continue;
    }
    if (wrapper !== undefined && !optionsDone && token.startsWith("-") && token !== "-") {
      const spec = WRAPPERS[wrapper] as { short: string; long: readonly string[] };
      if (wrapper === "command" && (token === "-v" || token === "-V")) return { args: [], env, cwd, otherUser }; // only looks it up
      let name = token;
      let value: string | undefined;
      if (token.startsWith("--")) {
        const eq = token.indexOf("=");
        if (eq >= 0) {
          name = token.slice(0, eq);
          value = token.slice(eq + 1);
        } else if (spec.long.includes(token) && i < argv.length) {
          value = argv[i++];
        }
      } else {
        for (let j = 1; j < token.length; j++) {
          const flag = token[j] as string;
          if (!spec.short.includes(flag)) continue;
          name = `-${flag}`;
          value = token.slice(j + 1);
          if (value === "" && i < argv.length) value = argv[i++];
          break;
        }
      }
      if (value !== undefined && (WRAPPER_CHDIR[wrapper] ?? []).includes(name)) cwd = moveTo(cwd, value);
      else if (value !== undefined && wrapper === "env" && (name === "-S" || name === "--split-string")) {
        argv.splice(i, 0, ...shellWords(value));
      }
      continue;
    }
    if (wrapper !== undefined && operands > 0) {
      operands--;
      continue;
    }
    const base = basename(token);
    if (base in WRAPPERS) {
      wrapper = base;
      optionsDone = false;
      operands = (WRAPPERS[base] as { operands: number }).operands;
      otherUser ||= base === "sudo" || base === "doas";
      continue;
    }
    return { name: base, args: argv.slice(i), env, cwd, otherUser };
  }
  return { args: [], env, cwd, otherUser };
}

function withoutLogin(host: string): string {
  return host.slice(host.lastIndexOf("@") + 1);
}

/** A remote URL with any login removed: everything up to the last @ before the path, with or without a scheme. */
function stripLogin(url: string): string {
  return url.trim().replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?[^/]*@/, "$1");
}

/** Whether a git remote or target names a URL rather than a remote. */
function looksLikeUrl(value: string): boolean {
  return /:\/\/|^[^/:]+@[^/:]+:|^[^/:]+:[^/]/.test(value);
}

function remoteParts(raw: string): { host: string; owner: string } {
  const url = stripLogin(raw);
  const match =
    /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/:]+)(?::\d+)?\/(.*)$/.exec(url) ?? /^(?:[^@/:]+@)?([^/:]+):(?!\/\/)(.*)$/.exec(url);
  if (match === null) return { host: "", owner: "" };
  const host = (match[1] ?? "").toLowerCase();
  if (host.includes("@")) return { host: "", owner: "" };
  const parts = (match[2] ?? "").replace(/^\/+|\/+$/g, "").replace(/\.git$/, "").split("/").filter(Boolean);
  const owner = parts[0] ?? "";
  return { host, owner: owner.includes("@") || owner.includes(":") ? "" : owner };
}

function platformForHost(host: string): string {
  if (host === "github.com" || host.endsWith(".ghe.com")) return "github";
  if (host === "gitlab.com") return "gitlab";
  return "git";
}

function firstLine(out: string | undefined): string {
  return (out ?? "").trim().split(/\r?\n/)[0] ?? "";
}

function realDir(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return normalize(path);
  }
}

async function ghUser(host: string, env: Record<string, string>, state: State): Promise<string> {
  if (GH_TOKEN_ENV.some((k) => env[k] || state.env[k]) || env.GH_CONFIG_DIR) return "";
  const cached = state.ghUser.get(host);
  if (cached !== undefined) return cached;
  const user = firstLine(await run(["gh", "config", "get", "-h", host, "user"], state));
  state.ghUser.set(host, user);
  return user;
}

/** The repo's remotes by name, each as its remote.<name>.* settings; read once per folder and turn. */
async function gitRemotes(dir: string, state: State): Promise<Map<string, Record<string, string>>> {
  const cached = state.remotes.get(dir);
  if (cached !== undefined) return cached;
  const remotes = new Map<string, Record<string, string>>();
  const out = (await run(["git", "-C", dir, "config", "--get-regexp", "^remote\\."], state)) ?? "";
  for (const line of out.split(/\r?\n/)) {
    const space = line.indexOf(" ");
    const match = /^remote\.(.+)\.([a-z-]+)$/.exec(space < 0 ? line : line.slice(0, space));
    if (match === null) continue;
    const settings = remotes.get(match[1] as string) ?? {};
    settings[match[2] as string] = space < 0 ? "" : line.slice(space + 1).trim();
    remotes.set(match[1] as string, settings);
  }
  state.remotes.set(dir, remotes);
  return remotes;
}

/** An explicit push URL after git's url.<base>.pushInsteadOf and insteadOf rules, longest match first. */
async function gitRewrite(url: string, base: string[], state: State): Promise<string> {
  const out = (await run([...base, "config", "--get-regexp", "^url\\..*\\.(pushinsteadof|insteadof)$"], state)) ?? "";
  const rules: [string, string, string][] = [];
  for (const line of out.split(/\r?\n/)) {
    const space = line.indexOf(" ");
    if (space < 0) continue;
    const match = /^url\.(.*)\.(pushinsteadof|insteadof)$/i.exec(line.slice(0, space));
    const prefix = line.slice(space + 1).trim();
    if (match !== null && prefix) rules.push([(match[2] as string).toLowerCase(), prefix, match[1] as string]);
  }
  for (const kind of ["pushinsteadof", "insteadof"]) {
    const best = rules
      .filter(([k, prefix]) => k === kind && url.startsWith(prefix))
      .sort((a, b) => b[1].length - a[1].length)[0];
    if (best !== undefined) return best[2] + url.slice(best[1].length);
  }
  return url;
}

/** The remote a bare git push uses: the one its branch pushes to, else pushRemote, pushDefault, the branch's remote, origin. */
async function defaultRemote(base: string[], dir: string, state: State): Promise<string> {
  const ref = firstLine(await run([...base, "rev-parse", "--symbolic-full-name", "@{push}"], state));
  if (ref.startsWith("refs/remotes/")) {
    // Remote names may hold a slash, so the longest configured name that prefixes the ref wins.
    const names = [...(await gitRemotes(dir, state)).keys()].filter((name) => ref.startsWith(`refs/remotes/${name}/`));
    if (names.length > 0) return names.sort((a, b) => b.length - a.length)[0] as string;
  }
  const branch = firstLine(await run([...base, "symbolic-ref", "--short", "-q", "HEAD"], state));
  const keys = branch ? [`branch.${branch}.pushRemote`, "remote.pushDefault", `branch.${branch}.remote`] : ["remote.pushDefault"];
  for (const key of keys) {
    const value = firstLine(await run([...base, "config", "--get", key], state));
    if (value) return value;
  }
  return "origin";
}

async function gitPush(
  args: string[], env: Record<string, string>, cwd: string | undefined, state: State,
): Promise<{ account?: DestinationAccount; dir?: string }> {
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
  if (rest[0] !== "push") return {};
  // Unknown is safe; the cwd repo's remote would be a confident wrong answer.
  if (overridden) return { account: { platform: "git", source: "unknown" } };
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
  const explicit = target !== undefined && looksLikeUrl(target);
  // Without the folder the push ran in, its remotes can't be read.
  if (!explicit && gitDir === undefined) return { account: { platform: "git", source: "unknown" } };
  let url: string | undefined;
  let remote = "";
  if (explicit) {
    url = await gitRewrite(target as string, base, state);
  } else {
    remote = target ?? (await defaultRemote(base, gitDir as string, state));
    // pushDefault and a branch's remote may name a URL instead of a remote.
    if (looksLikeUrl(remote)) {
      url = await gitRewrite(remote, base, state);
      remote = "";
    } else {
      url = firstLine(await run([...base, "remote", "get-url", "--push", remote], state)) || undefined;
    }
  }
  const { host, owner } = url === undefined ? { host: "", owner: "" } : remoteParts(url);
  if (host === "" || url === undefined) return { account: { platform: "git", source: "unknown" } };
  let user = "";
  if (/^https?:\/\//.test(url.trim())) {
    const helper =
      (await run([...base, "config", "--get", `credential.https://${host}.helper`], state)) ??
      (await run([...base, "config", "--get", "credential.helper"], state)) ??
      "";
    if (helper.includes("auth git-credential")) user = await ghUser(host, env, state);
  }
  return {
    account: { platform: platformForHost(host), host, account: owner, user, context: remote, source: "command" },
    ...(gitDir === undefined ? {} : { dir: realDir(gitDir) }),
  };
}

/** The URL of the remote gh queries: the one `gh repo set-default` chose, else upstream, github, origin, the first. */
async function ghRepoRemote(dir: string, state: State): Promise<string> {
  const remotes = await gitRemotes(dir, state);
  for (const settings of remotes.values()) {
    const resolved = settings["gh-resolved"] ?? "";
    if (resolved && resolved !== "base" && resolved.includes("/")) {
      return `https://${remoteParts(settings.url ?? "").host || "github.com"}/${resolved}`;
    }
    if (resolved === "base") return settings.url ?? "";
  }
  for (const name of [...GH_REMOTE_ORDER, ...[...remotes.keys()].sort()]) {
    const url = remotes.get(name)?.url;
    if (url) return url;
  }
  return "";
}

async function gh(
  args: string[], env: Record<string, string>, cwd: string | undefined, state: State,
): Promise<{ account?: DestinationAccount; dir?: string }> {
  if (args[0] === undefined || GH_NO_REPO.has(args[0])) return {};
  let repo = "";
  let flagHost = "";
  const positional: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if ((arg === "-R" || arg === "--repo") && i < args.length) repo = args[i++] as string;
    else if (arg.startsWith("--repo=")) repo = arg.slice("--repo=".length);
    else if (arg.startsWith("-R") && !arg.startsWith("--")) repo = arg.slice(2).replace(/^=/, "");
    else if (arg === "--hostname" && i < args.length) flagHost = withoutLogin((args[i++] as string).toLowerCase());
    else if (arg.startsWith("--hostname=")) flagHost = withoutLogin(arg.slice("--hostname=".length).toLowerCase());
    else if (GH_VALUE_OPTIONS.has(arg)) i++;
    else if (!arg.startsWith("-")) positional.push(arg);
  }
  // `gh repo view|clone|fork|… OWNER/REPO`, a pr or issue URL, and `gh api repos/OWNER/REPO/…` name the repository.
  const third = positional[2];
  if (repo === "" && positional[0] === "repo" && third !== undefined && third.includes("/")) repo = third;
  if (repo === "" && positional[0] !== "api") {
    const url = positional.slice(1).map((a) => /^https?:\/\/([^/@]+\/[^/@]+\/[^/@]+)/.exec(stripLogin(a))).find((m) => m !== null);
    if (url) repo = url[1] as string;
  }
  let lookupDir = cwd;
  const listOrCreate = positional[0] === "repo" && (positional[1] === "list" || positional[1] === "create");
  if (GH_NO_CHECKOUT.has(positional[0] ?? "") || (listOrCreate && repo === "")) lookupDir = undefined;
  if (repo === "" && positional[0] === "api") {
    const named = positional.slice(1).map((a) => /^\/?repos\/([^/{}@]+\/[^/{}@]+)/.exec(a)).find((m) => m !== null);
    if (named) repo = named[1] as string;
    else if (!positional.some((a) => a.includes("{owner}") || a.includes("{repo}"))) lookupDir = undefined;
  }
  repo = repo || env.GH_REPO || state.env.GH_REPO || "";
  // A host never carries a login, so anything before an @ is dropped.
  const envHost = withoutLogin((env.GH_HOST ?? state.env.GH_HOST ?? "").toLowerCase());
  let host = "";
  let owner = "";
  let dir: string | undefined;
  if (repo !== "") {
    repo = stripLogin(repo); // never keep a login or token
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
    const url = await ghRepoRemote(lookupDir, state);
    if (url !== "") {
      ({ host, owner } = remoteParts(firstLine(url)));
      dir = realDir(lookupDir);
    }
  }
  if (host.includes("@") || owner.includes("@")) {
    host = "";
    owner = "";
  }
  host = flagHost || host || envHost || "github.com";
  return {
    account: { platform: "github", host, account: owner, user: await ghUser(host, env, state), context: "", source: "command" },
    ...(dir === undefined ? {} : { dir }),
  };
}

/** The last remote [user@]host operand of a copy and its port; nothing for an rsync daemon or only local paths. */
function remoteOperand(operands: readonly string[]): { destination?: string; port?: string } {
  for (const arg of [...operands].reverse()) {
    // A scp:// or sftp:// URI names the login and port itself; anything after the user (a password) is dropped.
    const uri = /^(scp|sftp):\/\/(?:([^@/;:]+)(?:[;:][^@/]*)?@)?(\[[^\]/]+\]|[^/:[\]@]+)(?::(\d+))?(?=\/|$)/.exec(arg);
    if (uri !== null) {
      const destination = uri[2] === undefined ? (uri[3] as string) : `${uri[2]}@${uri[3]}`;
      return uri[4] === undefined ? { destination } : { destination, port: uri[4] };
    }
    if (arg.includes("://")) return {};
    // A bracketed host may hold an IPv6 address; a second colon after the host marks an rsync daemon.
    const match = /^((?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)):(:)?/.exec(arg);
    // A drive letter (C:\x or C:/x) is a local path, not a host.
    if (match !== null && !/^[A-Za-z]:[\\/]/.test(arg)) return match[2] === undefined ? { destination: match[1] as string } : {};
  }
  return {};
}

/** rsync's last remote operand, reached through its remote shell, with that shell's ssh identity options. */
function rsyncDestination(
  args: string[], env: Record<string, string>, processEnv: Record<string, string | undefined>,
): { destination?: string; passthrough: string[] } {
  let shell = env.RSYNC_RSH || processEnv.RSYNC_RSH || undefined;
  const operands: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--rsh" && i < args.length) shell = args[i++];
    else if (arg.startsWith("--rsh=")) shell = arg.slice("--rsh=".length);
    else if (RSYNC_VALUE_OPTIONS.has(arg)) i++;
    else if (arg.startsWith("-") && !arg.startsWith("--")) {
      // Walk a cluster such as -avze: the first option that takes a value takes the rest of it, or the next word.
      for (let j = 1; j < arg.length; j++) {
        const flag = arg[j] as string;
        if (!(SSH_VALUE_FLAGS.rsync as string).includes(flag)) continue;
        let value = arg.slice(j + 1);
        if (value === "" && i < args.length) value = args[i++] as string;
        if (flag === "e") shell = value;
        break;
      }
    } else if (!arg.startsWith("-")) operands.push(arg);
  }
  let passthrough: string[] = [];
  if (shell) {
    const shellArgv = shellWords(shell);
    // A remote shell other than ssh never reads the ssh config.
    if (shellArgv[0] === undefined || basename(shellArgv[0]) !== "ssh") return { passthrough: [] };
    passthrough = sshDestination("ssh", [...shellArgv.slice(1), "-"], env, processEnv).passthrough;
  }
  const { destination, port } = remoteOperand(operands);
  if (destination === undefined) return { passthrough: [] };
  return { destination, passthrough: port === undefined ? passthrough : [...passthrough, "-p", port] };
}

function sshDestination(
  name: string, args: string[], env: Record<string, string>, processEnv: Record<string, string | undefined>,
): { destination?: string; passthrough: string[] } {
  if (name === "rsync") return rsyncDestination(args, env, processEnv);
  const passthrough: string[] = [];
  const operands: string[] = [];
  const valueFlags = SSH_VALUE_FLAGS[name] ?? "";
  // Only the options that change which host or user ssh -G resolves are passed through; scp's -l is a bandwidth limit.
  const identityFlags = name === "ssh" ? ["l", "o", "F", "J", "p"] : ["o", "F", "J", "P"];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    // ssh reads options before and right after its destination; the first other word starts the remote command.
    const readingOptions = operands.length === 0 || (name === "ssh" && operands.length === 1);
    if (!readingOptions || !arg.startsWith("-") || arg === "-") {
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
  const { destination, port } = remoteOperand(operands);
  if (destination !== undefined) return { destination, passthrough: port === undefined ? passthrough : [...passthrough, "-p", port] };
  // sftp also takes a plain [user@]host with no path.
  const first = operands[0];
  if (name === "sftp" && first !== undefined && /^(?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)$/.test(first)) {
    return { destination: first, passthrough };
  }
  return { passthrough: [] };
}

function expandHome(path: string): string {
  return path === "~" || path.startsWith("~/") ? join(homedir(), path.slice(1)) : path;
}

/** Whether a file name matches a glob of literal characters, `*` and `?`. */
function globMatch(pattern: string, name: string): boolean {
  let p = 0;
  let n = 0;
  let star = -1;
  let mark = 0;
  while (n < name.length) {
    if (p < pattern.length && (pattern[p] === "?" || pattern[p] === name[n])) {
      p++;
      n++;
    } else if (p < pattern.length && pattern[p] === "*") {
      star = p++;
      mark = n;
    } else if (star >= 0) {
      p = star + 1;
      n = ++mark;
    } else {
      return false;
    }
  }
  while (pattern[p] === "*") p++;
  return p === pattern.length;
}

/** The files an ssh Include pattern names; undefined when it can't be expanded, so the caller refuses. */
function includeTargets(pattern: string, base: string): string[] | undefined {
  // `~user` names another account's home, which only ssh itself can resolve.
  if (pattern.startsWith("~") && pattern !== "~" && !pattern.startsWith("~/")) return undefined;
  // ssh globs the path, and glob reads a backslash as escaping the next character.
  const path = expandHome(pattern).replace(/\\(.)/g, "$1");
  const full = isAbsolute(path) ? path : join(base, path);
  if (!/[*?[]/.test(full)) return [full];
  if (/[*?[]/.test(dirname(full)) || basename(full).includes("[")) return undefined;
  try {
    return readdirSync(dirname(full)).filter((entry) => globMatch(basename(full), entry)).sort().map((entry) => join(dirname(full), entry));
  } catch {
    return [];
  }
}

/** An ssh config line split the way OpenSSH splits it; undefined for an unbalanced quote, which ssh rejects. */
function configWords(line: string): string[] | undefined {
  const words: string[] = [];
  let word = "";
  let inWord = false;
  let quote: string | undefined;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] as string;
    const next = line[i + 1];
    // A backslash escapes a quote, a backslash, or (outside quotes) a space; any other backslash is kept.
    if (ch === "\\" && next !== undefined && (`'"\\`.includes(next) || (quote === undefined && next === " "))) {
      word += next;
      inWord = true;
      i++;
    } else if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (ch === " " || ch === "\t") {
      if (inWord) words.push(word);
      word = "";
      inWord = false;
    } else if (ch === "#" && !inWord) {
      break;
    } else {
      word += ch;
      inWord = true;
    }
  }
  if (quote !== undefined) return undefined;
  if (inWord) words.push(word);
  return words;
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
      const words = configWords(line);
      if (words === undefined) return true;
      const [first = "", ...rest] = words;
      const [keyword = "", attached = ""] = first.split(/=(.*)/s);
      // ssh allows `Keyword=value` and `Keyword =value`, so a leading = is only a separator.
      const args = (attached ? [attached, ...rest] : rest).map((w) => w.replace(/^=+/, "")).filter(Boolean);
      if (keyword.toLowerCase() === "match" && args.some((w) => w.toLowerCase().replace(/^!/, "").startsWith("exec"))) {
        return true;
      }
      for (const pattern of keyword.toLowerCase() === "include" ? args : []) {
        const targets = includeTargets(pattern, base);
        if (targets === undefined) return true;
        pending.push(...targets.map((target): [string, string] => [target, base]));
      }
    }
  }
  return false;
}

async function ssh(
  name: string, args: string[], env: Record<string, string>, dir: string | undefined, state: State, otherUser = false,
): Promise<DestinationAccount | undefined> {
  const { destination, passthrough } = sshDestination(name, args, env, state.env);
  if (destination === undefined) return undefined;
  // Under sudo, ssh reads that user's config, which this hook can't.
  if (otherUser && !passthrough.some((flag, i) => i % 2 === 0 && flag === "-F")) return { platform: "ssh", source: "unknown" };
  // The lookup runs elsewhere, so a relative config path is resolved against the folder the command ran in.
  for (let i = 0; i + 1 < passthrough.length; i += 2) {
    const value = expandHome(passthrough[i + 1] as string);
    if (passthrough[i] === "-F") passthrough[i + 1] = value === "none" || isAbsolute(value) ? value : join(dir ?? "", value);
  }
  if (configRunsCommands(passthrough)) return { platform: "ssh", source: "unknown" };
  const out = await run(["ssh", "-G", ...passthrough, destination.replace(/[[\]]/g, "")], state);
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

/** Whether a git command changes remote or URL settings, and the folder whose remotes it changes (none: all of them). */
function rewritesRemotes(args: string[], cwd: string | undefined): { rewrites: boolean; dir?: string } {
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
  const dir = gitDir === undefined ? undefined : realDir(gitDir);
  const at = (index: number): string => rest[index] ?? "";
  if (at(0) === "remote" && ["add", "set-url", "rename", "remove", "rm"].includes(at(1))) {
    return dir === undefined ? { rewrites: true } : { rewrites: true, dir };
  }
  if (at(0) === "config") {
    const options = new Set(rest.slice(1).filter((a) => a.startsWith("-")));
    let keys = rest.slice(1).filter((a) => !a.startsWith("-")).map((a) => a.toLowerCase());
    const reads =
      ["--get", "--get-all", "--get-regexp", "--list", "-l", "--get-urlmatch"].some((o) => options.has(o)) ||
      keys[0] === "get" || keys[0] === "list";
    // git 2.46 also takes `git config set|unset <key>`.
    if (keys[0] === "set" || keys[0] === "unset") keys = keys.slice(1);
    if (!reads && /^(remote|url|branch)\./.test(keys[0] ?? "")) {
      const scoped = ["--global", "--system", "--file", "-f"].some((o) => options.has(o));
      return scoped || dir === undefined ? { rewrites: true } : { rewrites: true, dir };
    }
  }
  return { rewrites: false };
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
  let found: DestinationAccount | undefined;
  let unresolved: DestinationAccount | undefined;
  const exported: Record<string, string> = {};
  let status: number | undefined;
  for (const { argv, operator } of segments(command)) {
    // A literal true or false decides whether && or || runs the next command; any other status is unknown.
    if ((operator === "&&" && status === 1) || (operator === "||" && status === 0)) continue;
    const parsed = program(argv, dir);
    const { name, args } = parsed;
    const env = { ...exported, ...parsed.env };
    status = name === "true" || name === ":" ? 0 : name === "false" ? 1 : undefined;
    if (name === "export") {
      for (const arg of args) if (isAssignment(arg)) exported[arg.slice(0, arg.indexOf("="))] = arg.slice(arg.indexOf("=") + 1);
      continue;
    }
    if (name === "unset") {
      for (const arg of args) delete exported[arg];
      continue;
    }
    if (name === "cd") {
      // Later segments run in the folder this one moves to.
      dir = moveTo(parsed.cwd, args[0] ?? "~");
      continue;
    }
    if (name === "git") {
      const { rewrites, dir: rewritten } = rewritesRemotes(args, parsed.cwd);
      if (rewrites) {
        // A push already resolved against these remotes in this turn can no longer be trusted.
        for (const [resultDir, result] of state.pushResults) {
          if (rewritten !== undefined && resultDir !== rewritten) continue;
          for (const key of Object.keys(result)) delete (result as unknown as Record<string, unknown>)[key];
          Object.assign(result, { platform: "git", source: "unknown" });
        }
        continue;
      }
    }
    if (found !== undefined) continue;
    let account: DestinationAccount | undefined;
    let pushDir: string | undefined;
    if (name === "git") ({ account, dir: pushDir } = await gitPush(args, env, parsed.cwd, state));
    else if (name === "gh") ({ account, dir: pushDir } = await gh(args, env, parsed.cwd, state));
    else if (name !== undefined && SSH_TOOLS.has(name)) account = await ssh(name, args, env, parsed.cwd, state, parsed.otherUser);
    if (account === undefined) continue;
    const result = compact(account);
    if (result.source === "unknown") {
      unresolved ??= result;
      continue;
    }
    found = result;
    if (pushDir !== undefined) state.pushResults.push([pushDir, result]);
  }
  return found ?? unresolved;
}

export interface ShellCall {
  tool_name?: unknown;
  tool_use_id?: unknown;
  tool_input?: unknown;
  decision?: unknown;
  /** `false` when the call is known not to have run, such as a confirm the person declined. */
  ran?: unknown;
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
      remotes: new Map(),
      pushResults: [],
    };
    for (const call of calls) {
      const input = call.tool_input;
      const command =
        input !== null && typeof input === "object" && !Array.isArray(input)
          ? (input as Record<string, unknown>).command
          : undefined;
      if (typeof call.tool_name !== "string" || !SHELL_TOOLS.has(call.tool_name)) continue;
      if ((typeof call.decision === "string" && NEVER_RAN.has(call.decision)) || call.ran === false) continue;
      if (typeof command !== "string" || command.trim() === "" || typeof call.tool_use_id !== "string") continue;
      const account = await resolveOne(command, cwd, state);
      if (account !== undefined) accounts.set(call.tool_use_id, account);
    }
  } catch {
    // Telemetry enrichment: whatever resolved before the failure is still returned.
  }
  return accounts;
}
