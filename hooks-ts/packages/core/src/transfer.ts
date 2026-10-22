// Transfer resolution — where each shell transfer went, as host and address kind only.
// Parity with the Python hooks' transfer block: the same tools, directions, shell reading, ssh -G lookup and
// address kinds, and the same wire object on each `tool_use` entry.
//
// Total by construction: no `throw` escapes. A failed or slow lookup leaves the host as written and its address
// `unresolved`; every lookup has a deadline and the turn shares one budget, so the turn log is never held up long.

import { lookup as dnsLookup } from "node:dns/promises";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { BlockList, isIP } from "node:net";
import { homedir, userInfo } from "node:os";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

import { defaultExecFile, type ExecFileLike } from "./accountIdentity.ts";

export type AddressKind = "private" | "public" | "loopback" | "link_local" | "cgnat" | "unresolved";

export interface TransferEndpoint {
  /** Absent when the tool doesn't say which way data moved, such as a bare `nc host port`. */
  direction?: "out" | "in";
  /** The host as written, without any login. */
  host: string;
  /** The host after ssh's own lookup of a nickname; the same as `host` otherwise. */
  resolved_host: string;
  address: AddressKind;
}

export interface Transfer {
  tool: string;
  endpoints: TransferEndpoint[];
}

/** Only these lookups are ever run; anything else is refused before it starts. DNS is a resolver call. */
const ALLOWED_RUNS: readonly (readonly string[])[] = [["ssh", "-G"]];
const RUN_TIMEOUT_MS = 5_000;
const DNS_TIMEOUT_MS = 1_500;
const TURN_BUDGET_MS = 10_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_ENDPOINTS = 10;
/** How deep substitutions and `sh -c` strings are followed. */
const MAX_DEPTH = 8;
/** Wrappers that run the command after them: short options that take a value, long ones that do, operands before it. */
const WRAPPERS: Record<string, { short: string; long: readonly string[]; operands: number }> = {
  sudo: {
    short: "ugCDhprtTU",
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
/** Reserved words that open, divide or close a compound command. */
const KEYWORDS: ReadonlySet<string> = new Set(
  "{ } if then elif else fi while until for select do done ! function".split(" "),
);
/** Reserved words after which the next word still starts a command. */
const LEADING_WORDS: ReadonlySet<string> = new Set("{ if then elif else while until do !".split(" "));
const LOOPS: readonly string[] = ["while", "until", "for", "select"];
const SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash"]);
const POWERSHELLS: ReadonlySet<string> = new Set(["powershell", "pwsh"]);
/** Set in a command's env by `env -i`: nothing is inherited from the hook's environment. */
const CLEAN_ENV = "\0clean";
/** Stands in for a substitution's output inside a word, so no host is read from it. */
const SUBSTITUTED = "\0";
const TOOLS: Record<string, string> = {
  curl: "curl", wget: "wget", scp: "scp", rsync: "rsync", sftp: "sftp", ssh: "ssh",
  nc: "nc", ncat: "nc", netcat: "nc", socat: "socat", http: "httpie", https: "httpie",
  "invoke-webrequest": "powershell", "invoke-restmethod": "powershell", iwr: "powershell", irm: "powershell",
};
const SENDING_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH"]);
/** Options that take a value, per program; every other option is a switch. */
const SSH_VALUE_FLAGS: Record<string, string> = {
  ssh: "BbcDEeFIiJLlmOoPpQRSWw", scp: "cDFiJloPSX", sftp: "BbcDFiJloPRSsX", rsync: "efTMB@",
};
/** Of ssh's -o settings, only these change which host or user ssh -G resolves. */
const SSH_IDENTITY_OPTIONS: ReadonlySet<string> = new Set(["hostname", "user", "port", "proxyjump"]);
const SSH_CONFIG_MAX_BYTES = 256 * 1024;
const SSH_CONFIG_MAX_FILES = 32;
// Option lists are single literals split on blanks, because the bundle check reads `-from", "` as an import.
const RSYNC_VALUE_OPTIONS: ReadonlySet<string> = new Set(
  `--exclude --include --filter --exclude-from --include-from --files-from --rsync-path --log-file --partial-dir
   --temp-dir --compare-dest --copy-dest --link-dest --backup-dir --chmod --chown --suffix --password-file --port
   --bwlimit --timeout --max-size --min-size --out-format --remote-option --block-size --modify-window`.split(/\s+/),
);
/** curl's options that take a value (`curl --help all`), so a value is never read as a URL. */
const CURL_SHORT_VALUES = "ACDEFHKPQTUXYbcdemortuwxyz";
const CURL_LONG_VALUES: ReadonlySet<string> = new Set(
  `--abstract-unix-socket --alt-svc --aws-sigv4 --cacert --capath --cert --cert-type --ciphers --config
   --connect-timeout --connect-to --continue-at --cookie --cookie-jar --create-file-mode --crlfile --curves --data
   --data-ascii --data-binary --data-raw --data-urlencode --delegation --dns-interface --dns-ipv4-addr
   --dns-ipv6-addr --dns-servers --doh-url --dump-header --egd-file --engine --etag-compare --etag-save
   --expect100-timeout --form --form-string --ftp-account --ftp-alternative-to-user --ftp-method --ftp-port
   --ftp-ssl-ccc-mode --happy-eyeballs-timeout-ms --haproxy-clientip --header --hostpubmd5 --hostpubsha256 --hsts
   --interface --ipfs-gateway --json --keepalive-time --key --key-type --krb --libcurl --limit-rate --local-port
   --login-options --mail-auth --mail-from --mail-rcpt --max-filesize --max-redirs --max-time --netrc-file
   --noproxy --oauth2-bearer --output --output-dir --parallel-max --pass --pinnedpubkey --preproxy --proto
   --proto-default --proto-redir --proxy --proxy-cacert --proxy-capath --proxy-cert --proxy-cert-type
   --proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass --proxy-pinnedpubkey
   --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype --proxy-tlspassword --proxy-tlsuser --proxy-user
   --pubkey --quote --random-file --range --rate --referer --request --request-target --resolve --retry
   --retry-delay --retry-max-time --sasl-authzid --service-name --socks4 --socks4a --socks5
   --socks5-gssapi-service --socks5-hostname --speed-limit --speed-time --stderr --telnet-option --tftp-blksize
   --time-cond --tls-max --tls13-ciphers --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii
   --trace-config --unix-socket --upload-file --url --url-query --user --user-agent --variable --write-out`.split(/\s+/),
);
const CURL_UPLOADS: ReadonlySet<string> = new Set(["-T", "--upload-file", "-F", "--form", "--form-string", "--json"]);
const CURL_BODIES: ReadonlySet<string> = new Set(
  ["-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode"],
);
const WGET_SHORT_VALUES = "aABDeIilnOoPQRtTUwX";
const WGET_LONG_VALUES: ReadonlySet<string> = new Set(
  `--output-file --append-output --execute --input-file --base --config --rejected-log --tries
   --retry-on-http-error --output-document --backups --timeout --dns-timeout --connect-timeout --read-timeout
   --wait --waitretry --bind-address --limit-rate --quota --user --password --header --compression --max-redirect
   --proxy-user --proxy-password --referer --save-cookies --load-cookies --post-data --post-file --method
   --body-data --body-file --default-page --directory-prefix --cut-dirs --level --accept --reject --accept-regex
   --reject-regex --regex-type --domains --exclude-domains --follow-tags --ignore-tags --include-directories
   --exclude-directories --user-agent --secure-protocol --certificate --certificate-type --private-key
   --private-key-type --ca-certificate --ca-directory --crl-file --pinnedpubkey --random-file --egd-file --ciphers
   --hsts-file --ftp-user --ftp-password --http-user --http-password --warc-file --warc-header --warc-max-size
   --warc-dedup --warc-tempdir --local-encoding --remote-encoding --restrict-file-names --prefer-family
   --report-speed --progress --use-askpass`.split(/\s+/),
);
const WGET_UPLOADS: ReadonlySet<string> = new Set(["--post-data", "--post-file", "--body-data", "--body-file"]);
const NC_SHORT_VALUES = "eGgIiMmOoPpqsTVWwXx";
const NC_LONG_VALUES: ReadonlySet<string> = new Set(
  `--proxy --proxy-type --proxy-auth --proxy-dns --source --source-port --wait --idle-timeout --exec --sh-exec
   --lua-exec --output --hex-dump --allow --allowfile --deny --denyfile --max-conns --delay --ssl-cert --ssl-key
   --ssl-trustfile --ssl-ciphers --ssl-servername --ssl-alpn`.split(/\s+/),
);
const SOCAT_VALUE_OPTIONS: ReadonlySet<string> = new Set(["-b", "-t", "-T", "-L", "-W", "-lf", "-lp"]);
const HTTPIE_SHORT_VALUES = "aAoPps";
const HTTPIE_LONG_VALUES: ReadonlySet<string> = new Set(
  `--auth --auth-type --session --session-read-only --output --print --history-print --pretty --style
   --format-options --response-charset --response-mime --verify --cert --cert-key --cert-key-pass --ssl --ciphers
   --timeout --max-redirects --max-headers --proxy --default-scheme --boundary --raw`.split(/\s+/),
);
/** Invoke-WebRequest and Invoke-RestMethod parameters that take no value. */
const PS_SWITCHES: ReadonlySet<string> = new Set(
  `usebasicparsing usedefaultcredentials proxyusedefaultcredentials disablekeepalive passthru skipcertificatecheck
   skipheadervalidation skiphttperrorcheck allowunencryptedauthentication allowinsecureredirect noproxy
   preserveauthorizationonredirect preservehttpmethodonredirect resume followrellink verbose debug whatif
   confirm`.split(/\s+/),
);
/** Address kinds, checked in order; any other address is public. */
const ADDRESS_KINDS: readonly [AddressKind, readonly string[]][] = [
  ["loopback", ["127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128"]],
  ["private", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]],
  ["link_local", ["169.254.0.0/16", "fe80::/10"]],
  ["cgnat", ["100.64.0.0/10"]],
];

export type LookupLike = (host: string) => Promise<readonly string[]>;

export interface ResolveOptions {
  execFile?: ExecFileLike;
  lookup?: LookupLike;
  env?: Record<string, string | undefined>;
  now?: () => number;
  /** The turn's wall-clock budget, for a test; the hook always uses the default. */
  budgetMs?: number;
  /** The home folder whose ~/.ssh/config ssh reads, for a test; the account's own by default. */
  home?: string;
}

interface State {
  run: ExecFileLike;
  lookup: LookupLike;
  env: Record<string, string | undefined>;
  now: () => number;
  deadline: number;
  home: string;
  sshHosts: Map<string, string>;
  addresses: Map<string, AddressKind>;
}

type Env = Record<string, string>;
type Raw = [direction: string, destination: string, sshOptions: string[] | undefined];

async function run(argv: string[], state: State): Promise<string | undefined> {
  try {
    if (!ALLOWED_RUNS.some((p) => p.every((part, i) => argv[i] === part))) return undefined;
    const remaining = state.deadline - state.now();
    if (remaining <= 0) return undefined;
    const [file, ...args] = argv;
    if (file === undefined) return undefined;
    return await state.run(file, args, { timeoutMs: Math.min(RUN_TIMEOUT_MS, remaining), maxBytes: MAX_OUTPUT_BYTES });
  } catch {
    return undefined;
  }
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
    } else if (" \t\r\n;&|<>()".includes(ch)) {
      break;
    } else {
      word += ch;
    }
  }
  return [word, i];
}

/** The index of the ) that closes a ( just before `start`, past quotes and nested parentheses; -1 when none does. */
function parenEnd(text: string, start: number): number {
  let depth = 1;
  let quote: string | undefined;
  for (let i = start; i < text.length; i++) {
    const ch = text[i] as string;
    if (quote === "'") {
      if (ch === "'") quote = undefined;
    } else if (ch === "\\") {
      i++;
    } else if (quote === '"') {
      if (ch === '"') quote = undefined;
      else if (text.startsWith("$(", i)) {
        i = parenEnd(text, i + 2);
        if (i < 0) return -1;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "(" || ch === ")") {
      depth += ch === "(" ? 1 : -1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** The index of the backtick that closes one just before `start`; -1 when none does. */
function backtickEnd(text: string, start: number): number {
  for (let i = start; i < text.length; i += text[i] === "\\" ? 2 : 1) if (text[i] === "`") return i;
  return -1;
}

/** One simple command, or a marker around a subshell, substitution, function body or case arm. */
interface Item {
  kind: "cmd" | "(" | "$(" | ")" | "func" | "case" | "arm" | "esac";
  argv: string[];
  /** The operator before: "" first, "&&", "||", "|", "&", or ";" for any other separator. */
  before: string;
  after: string;
  /** "in" when stdin comes from a file or heredoc, "out" when stdout goes to a file. */
  io: Set<string>;
}

/** Reads a command the way the shell does into items, in the order they run. */
class Lexer {
  private i = 0;
  private quote: string | undefined;
  private readonly items: Item[] = [];
  private argv: string[] = [];
  private word = "";
  private inWord = false;
  private before = "";
  private io = new Set<string>();
  private readonly heredocs: [string, boolean][] = [];
  private readonly cases: string[] = [];
  private readonly text: string;
  private readonly depth: number;

  constructor(text: string, depth = 0) {
    this.text = text;
    this.depth = depth;
  }

  /** The items, or undefined when the command can't be read the way the shell reads it. */
  read(): Item[] | undefined {
    if (this.depth > MAX_DEPTH) return undefined;
    for (; this.i < this.text.length; this.i++) {
      if (!(this.quote !== undefined ? this.quoted() : this.unquoted())) return undefined;
    }
    if (this.quote !== undefined) return undefined;
    this.endCommand("");
    return this.items;
  }

  private marker(kind: Item["kind"], before = ""): void {
    this.items.push({ kind, argv: [], before, after: "", io: new Set() });
  }

  private quoted(): boolean {
    const ch = this.text[this.i] as string;
    if (ch === this.quote) {
      this.quote = undefined;
    } else if (this.quote === '"' && (ch === "$" || ch === "`")) {
      const found = this.substitution();
      if (found !== undefined) return found;
      this.word += ch;
    } else if (this.quote === '"' && ch === "\\" && this.i + 1 < this.text.length) {
      this.word += this.text[++this.i];
    } else {
      this.word += ch;
    }
    return true;
  }

  private unquoted(): boolean {
    const { text, i } = this;
    const ch = text[i] as string;
    if ("$`<>".includes(ch)) {
      const found = this.substitution();
      if (found !== undefined) return found;
    }
    if (ch === "'" || ch === '"') {
      this.quote = ch;
      this.inWord = true;
    } else if (ch === "\\" && text[i + 1] === "\n") {
      this.i++; // a backslash-newline continues the line
    } else if (ch === "\\" && i + 1 < text.length) {
      this.word += text[++this.i];
      this.inWord = true;
    } else if (ch === "#" && !this.inWord) {
      const end = text.indexOf("\n", i);
      this.i = (end < 0 ? text.length : end) - 1; // a comment runs to the end of its line
    } else if (ch === "(") {
      this.open();
    } else if (ch === ")") {
      this.close();
    } else if (ch === "<" || ch === ">" || text.startsWith("&>", i)) {
      this.redirect();
    } else if (";&|\n".includes(ch)) {
      this.separator(ch);
    } else if (ch === " " || ch === "\t" || ch === "\r") {
      this.endWord();
    } else {
      this.word += ch;
      this.inWord = true;
    }
    return true;
  }

  /** Read a $( ), $(( )), backtick or <( ) substitution starting here; undefined when none starts here. */
  private substitution(): boolean | undefined {
    const { text, i } = this;
    let end: number;
    let inner: string | undefined;
    if (text.startsWith("$((", i)) {
      end = parenEnd(text, i + 2); // arithmetic runs no commands
    } else if (text.startsWith("$(", i) || (this.quote === undefined && (text.startsWith("<(", i) || text.startsWith(">(", i)))) {
      end = parenEnd(text, i + 2);
      inner = text.slice(i + 2, end);
    } else if (text[i] === "`") {
      end = backtickEnd(text, i + 1);
      if (end < 0) return undefined; // a lone backtick, as PowerShell writes its escapes
      inner = text.slice(i + 1, end);
    } else {
      return undefined;
    }
    if (end < 0) return false;
    if (inner !== undefined) {
      const items = new Lexer(inner, this.depth + 1).read();
      if (items === undefined) return false;
      this.flushLeading();
      this.marker("$(", this.before);
      this.items.push(...items);
      this.marker(")");
    }
    this.word += SUBSTITUTED;
    this.inWord = true;
    this.i = end;
    return true;
  }

  private open(): void {
    if (this.cases.at(-1) === "pattern") return; // the optional ( before a case pattern
    const rest = this.text.slice(this.i + 1).trimStart();
    const bare = this.argv.length === 0 || (this.argv.length === 1 && this.argv[0] === "function");
    if (this.inWord && bare && rest.startsWith(")") && /^[\w.:-]+$/.test(this.word)) {
      // `name()` defines a function; the body that follows runs only when it's called.
      this.marker("func", this.before);
      this.argv = [];
      this.word = "";
      this.inWord = false;
      this.i = this.text.indexOf(")", this.i);
      return;
    }
    this.endWord();
    this.flush();
    this.marker("(", this.before);
    this.before = "";
  }

  private close(): void {
    if (this.cases.at(-1) === "pattern") {
      // A case pattern ends at its ), and the arm's commands follow.
      this.cases[this.cases.length - 1] = "body";
      this.word = "";
      this.inWord = false;
      this.marker("arm");
      return;
    }
    this.endCommand("");
    this.marker(")");
    this.before = ";";
  }

  /** A redirection's operator, an fd number written against it, and its target are not arguments. */
  private redirect(): void {
    const { text } = this;
    const fd = this.inWord && /^\d+$/.test(this.word) && text[this.i] !== "&" ? Number(this.word) : undefined;
    if (fd === undefined) this.endWord();
    this.word = "";
    this.inWord = false;
    const op = (/^(?:&>>?|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>)/.exec(text.slice(this.i)) as RegExpExecArray)[0];
    const [target, end] = readWord(text, this.i + op.length);
    if (op === "<<" || op === "<<-") this.heredocs.push([target, op === "<<-"]);
    const toStdio = fd === undefined;
    const reads = ["<", "<<", "<<-", "<<<", "<>"].includes(op) && (toStdio || fd === 0);
    const writes =
      ([">", ">>", ">|"].includes(op) && (toStdio || fd === 1)) ||
      op === "&>" || op === "&>>" ||
      (op === ">&" && (toStdio || fd === 1) && !/^\d+$/.test(target) && target !== "-");
    if (target !== "/dev/null" || op.startsWith("<<")) {
      if (reads) this.io.add("in");
      if (writes) this.io.add("out");
    }
    this.i = end - 1;
  }

  private separator(ch: string): void {
    const { text, i } = this;
    const pair = text.slice(i, i + 2);
    const state = this.cases.at(-1);
    if (state === "pattern" && ch === "|") return; // pattern alternatives
    if (state === "body" && (pair === ";;" || pair === ";&")) {
      this.endCommand(";");
      this.cases[this.cases.length - 1] = "pattern";
      this.i += text.startsWith(";;&", i) ? 2 : 1;
      return;
    }
    if (pair === "&&" || pair === "||" || pair === "|&") {
      this.endCommand(pair === "|&" ? "|" : pair);
      this.i++;
    } else {
      this.endCommand(ch === "&" || ch === "|" ? ch : ";");
    }
    if (ch === "\n") this.skipHeredocs();
  }

  /** A heredoc's body starts on the next line and is input, not commands. */
  private skipHeredocs(): void {
    const { text } = this;
    while (this.heredocs.length > 0) {
      const [delimiter, stripTabs] = this.heredocs.shift() as [string, boolean];
      while (this.i + 1 < text.length) {
        const end = text.indexOf("\n", this.i + 1);
        const line = end < 0 ? text.slice(this.i + 1) : text.slice(this.i + 1, end);
        this.i = end < 0 ? text.length - 1 : end;
        if ((stripTabs ? line.replace(/^\t+/, "") : line) === delimiter) break;
      }
    }
  }

  private endWord(): void {
    if (!this.inWord) return;
    const word = this.word;
    const state = this.cases.at(-1);
    this.word = "";
    this.inWord = false;
    const atStart = this.argv.every((w) => LEADING_WORDS.has(w));
    if (state === "head") {
      if (word === "in") this.cases[this.cases.length - 1] = "pattern"; // `case WORD in` runs nothing
    } else if (state === "pattern") {
      if (word === "esac") this.esac();
    } else if (word === "case" && atStart) {
      this.flush();
      this.marker("case", this.before);
      this.cases.push("head");
    } else if (word === "esac" && atStart && state === "body") {
      this.esac();
    } else {
      this.argv.push(word);
    }
  }

  private esac(): void {
    this.flush();
    this.cases.pop();
    this.marker("esac");
  }

  /** Emit the reserved words that lead the current command, so a substitution in it runs only when they let it. */
  private flushLeading(): void {
    let n = 0;
    while (n < this.argv.length && (LEADING_WORDS.has(this.argv[n] as string) || this.argv[n] === "function")) {
      n += this.argv[n] === "function" ? 2 : 1;
    }
    if (n === 0) return;
    this.items.push({ kind: "cmd", argv: this.argv.slice(0, n), before: this.before, after: "", io: new Set() });
    this.argv = this.argv.slice(n);
    this.before = "";
  }

  /** Emit the reserved words read so far ahead of the compound command they lead. */
  private flush(): void {
    if (this.argv.length === 0) return;
    this.items.push({ kind: "cmd", argv: this.argv, before: this.before, after: "", io: this.io });
    this.argv = [];
    this.io = new Set();
    this.before = "";
  }

  private endCommand(after: string): void {
    this.endWord();
    if (this.argv.length > 0) {
      this.items.push({ kind: "cmd", argv: this.argv, before: this.before, after, io: this.io });
      this.before = after;
    } else if (after !== ";" && after !== "") {
      this.before = after;
    }
    this.argv = [];
    this.io = new Set();
  }
}

/** A string's words, split as the shell splits them, without its operators. */
function words(text: string): string[] {
  return (new Lexer(text).read() ?? []).filter((item) => item.kind === "cmd").flatMap((item) => item.argv);
}

/** A variable as the command sees it: set or unset in the command, else inherited from the hook's environment. */
function envValue(env: Env, processEnv: Record<string, string | undefined>, key: string): string {
  if (key in env) return env[key] as string;
  return CLEAN_ENV in env ? "" : (processEnv[key] ?? "");
}

function isAssignment(token: string): boolean {
  const eq = token.indexOf("=");
  return eq > 0 && !token.startsWith("-") && /^[A-Za-z0-9_]+$/.test(token.slice(0, eq));
}

/** A program as it's matched: its file name in lower case, without a Windows .exe. */
function programName(token: string): string {
  const name = (token.split(/[\\/]/).pop() ?? "").toLowerCase();
  return name.endsWith(".exe") ? name.slice(0, -4) : name;
}

function moveTo(cwd: string | undefined, path: string): string {
  const target = expandHome(path);
  return isAbsolute(target) ? target : normalize(join(cwd ?? "", target));
}

interface Program {
  name?: string;
  args: string[];
  env: Env;
  cwd: string | undefined;
  otherUser: boolean;
}

/** The program a simple command runs, its args, inline VAR=value settings and folder, past assignments and wrappers. */
function program(input: string[], start: string | undefined): Program {
  const argv = [...input];
  const out: Program = { args: [], env: {}, cwd: start, otherUser: false };
  let wrapper: string | undefined;
  let operands = 0;
  let optionsDone = false;
  for (let i = 0; i < argv.length; ) {
    const token = argv[i++] as string;
    if (isAssignment(token) && (wrapper === undefined || optionsDone || wrapper === "env" || wrapper === "sudo")) {
      out.env[token.slice(0, token.indexOf("="))] = token.slice(token.indexOf("=") + 1);
    } else if (wrapper !== undefined && !optionsDone && token === "--") {
      optionsDone = true;
    } else if (wrapper === "env" && !optionsDone && (token === "-" || token === "--ignore-environment")) {
      out.env = { [CLEAN_ENV]: "" };
    } else if (wrapper !== undefined && !optionsDone && token.startsWith("-") && token !== "-") {
      if (wrapper === "command" && (token === "-v" || token === "-V")) return { ...out, args: [] }; // only looks it up
      i = wrapperOption(wrapper, token, argv, i, out);
    } else if (wrapper !== undefined && operands > 0) {
      operands--;
    } else if (programName(token) in WRAPPERS) {
      wrapper = programName(token);
      optionsDone = false;
      operands = (WRAPPERS[wrapper] as { operands: number }).operands;
      out.otherUser ||= wrapper === "sudo" || wrapper === "doas";
    } else {
      return { ...out, name: programName(token), args: argv.slice(i) };
    }
  }
  return out;
}

/** Read one wrapper option, and its value when it takes one; the next index. */
function wrapperOption(wrapper: string, token: string, argv: string[], start: number, out: Program): number {
  const spec = WRAPPERS[wrapper] as { short: string; long: readonly string[] };
  let i = start;
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
      if (wrapper === "env" && flag === "i") out.env = { [CLEAN_ENV]: "" };
      if (!spec.short.includes(flag)) continue;
      name = `-${flag}`;
      value = token.slice(j + 1);
      if (value === "" && i < argv.length) value = argv[i++];
      break;
    }
  }
  if (value === undefined) return i;
  if ((WRAPPER_CHDIR[wrapper] ?? []).includes(name)) out.cwd = moveTo(out.cwd, value);
  else if (wrapper === "env" && (name === "-S" || name === "--split-string")) argv.splice(i, 0, ...words(value));
  else if (wrapper === "env" && (name === "-u" || name === "--unset")) out.env[value] = "";
  return i;
}

type Maybe = boolean | undefined;

/** Whether two conditions both hold: false when either fails, undefined when either is unknown. */
function both(a: Maybe, b: Maybe): Maybe {
  if (a === false || b === false) return false;
  return a === undefined || b === undefined ? undefined : true;
}

/** Whether a command runs after its && or ||, given the last literal true (0) or false (1). */
function follows(before: string, status: number | undefined): boolean {
  return !((before === "&&" && status === 1) || (before === "||" && status === 0));
}

interface Frame {
  kind: string;
  base: Maybe;
  runs: Maybe;
  decided: Maybe;
  /** The state before a body that only maybe runs, restored when it ends. */
  saved?: [string | undefined, Env];
  /** The state when the frame opened, restored when a subshell closes. */
  state: [string | undefined, Env];
  status: number | undefined;
}

interface Shell {
  cwd: string | undefined;
  exported: Env;
  status: number | undefined;
  frames: Frame[];
  function: boolean;
  negate: boolean;
  start: [string | undefined, Env];
  processEnv: Record<string, string | undefined>;
}

/** One simple command that runs or may run. */
interface Call {
  name: string;
  args: string[];
  env: Env;
  cwd: string | undefined;
  otherUser: boolean;
  io: Set<string>;
  pipedIn: boolean;
  pipedOut: boolean;
}

function runs(shell: Shell): Maybe {
  return shell.frames.at(-1)?.runs ?? true;
}

function snapshot(shell: Shell): [string | undefined, Env] {
  return [shell.cwd, { ...shell.exported }];
}

function restore(shell: Shell, saved: [string | undefined, Env] | undefined): void {
  if (saved === undefined) return;
  shell.cwd = saved[0];
  shell.exported = { ...saved[1] };
}

/** Close the innermost compound command of one of these kinds. */
function pop(frames: Frame[], kinds: readonly string[]): Frame | undefined {
  while (frames.length > 0) {
    const frame = frames.pop() as Frame;
    if (kinds.includes(frame.kind)) return frame;
  }
  return undefined;
}

/** Open a compound command; a function's body is only defined, so it never runs here. */
function openFrame(kind: string, runsHere: Maybe, shell: Shell): void {
  let value = runsHere;
  if (shell.function && kind !== "$(") {
    value = false;
    shell.function = false;
  }
  shell.frames.push({ kind, base: value, runs: value, decided: false, state: snapshot(shell), status: shell.status });
}

/** Start the body a then, elif, else or do opens: run, skipped or maybe run, by the literal status before it.
 *  A body that only maybe runs keeps its cd and exports to itself. */
function branch(keyword: string, frame: Frame, shell: Shell): void {
  let holds: Maybe = shell.status === 0 ? true : shell.status === 1 ? false : undefined;
  let taken: Maybe;
  if (keyword === "then" && frame.kind === "if") {
    taken = both(frame.runs, holds);
    if (taken === true) frame.decided = true;
    else if (taken === undefined && frame.decided === false) frame.decided = undefined;
  } else if ((keyword === "elif" || keyword === "else") && frame.kind === "if") {
    restore(shell, frame.saved);
    frame.saved = undefined;
    taken = both(frame.base, frame.decided === undefined ? undefined : !frame.decided);
  } else if (keyword === "do" && LOOPS.includes(frame.kind)) {
    if (frame.kind === "for" || frame.kind === "select") holds = undefined;
    taken = both(frame.runs, holds === undefined || frame.kind === "while" ? holds : !holds);
  } else {
    return;
  }
  frame.runs = taken;
  if (taken === undefined && frame.saved === undefined) frame.saved = snapshot(shell);
}

/** Apply a command's leading reserved word to the open compound commands; the words after it. */
function keyword(argv: string[], followsHere: boolean, shell: Shell): string[] {
  const [word = "", ...rest] = argv;
  if (word === "{" || word === "if" || LOOPS.includes(word)) {
    openFrame(word, both(runs(shell), followsHere), shell);
    return word === "for" || word === "select" ? [] : rest; // a for loop's header runs nothing
  }
  if (word === "function") {
    shell.function = true;
    return rest.slice(1);
  }
  if (word === "!") {
    shell.negate = true;
    return rest;
  }
  if (word === "}" || word === "fi" || word === "done") {
    const frame = pop(shell.frames, word === "}" ? ["{"] : word === "fi" ? ["if"] : LOOPS);
    restore(shell, frame?.saved);
    if (word !== "}") shell.status = undefined; // an if or loop that ran no body still succeeds
    return rest;
  }
  const top = shell.frames.at(-1);
  if (top !== undefined) branch(word, top, shell);
  return rest;
}

/** Apply a subshell, substitution, function or case marker to the open compound commands. */
function marker(item: Item, shell: Shell): void {
  const { frames } = shell;
  const runsHere = both(runs(shell), follows(item.before, shell.status));
  if (item.kind === "(" || item.kind === "$(" || item.kind === "case") {
    openFrame(item.kind, runsHere, shell);
    if (item.kind === "case") (frames.at(-1) as Frame).runs = false; // nothing runs until an arm opens
  } else if (item.kind === "func") {
    shell.function = true;
  } else if (item.kind === "arm" && frames.at(-1)?.kind === "case") {
    const frame = frames.at(-1) as Frame;
    restore(shell, frame.saved);
    frame.runs = both(frame.base, undefined);
    frame.saved = snapshot(shell);
  } else if (item.kind === ")" || item.kind === "esac") {
    const frame = pop(frames, item.kind === ")" ? ["(", "$("] : ["case"]);
    if (frame === undefined) return;
    // A subshell's cd and exports end with it, as do a case arm's, which may not have run.
    restore(shell, item.kind === ")" ? frame.state : frame.saved);
    if (frame.kind === "$(" || frame.runs === false) shell.status = frame.status;
    else if (item.kind === "esac") shell.status = undefined;
  }
}

/** Apply a cd, export or unset to the commands after it. */
function builtin(name: string, args: string[], cwd: string | undefined, shell: Shell): void {
  if (name === "export") {
    for (const arg of args) if (isAssignment(arg)) shell.exported[arg.slice(0, arg.indexOf("="))] = arg.slice(arg.indexOf("=") + 1);
  } else if (name === "unset") {
    // Unset hides the inherited value too, so it is kept as empty rather than dropped.
    for (const arg of args) if (!arg.startsWith("-")) shell.exported[arg] = "";
  } else {
    shell.cwd = moveTo(cwd, args[0] ?? "~");
  }
}

/** The command string `sh -c` or `powershell -Command` runs; undefined for any other command. */
function shellString(name: string, args: string[]): string | undefined {
  if (SHELLS.has(name)) {
    let hasC = false;
    for (let i = 0; i < args.length; ) {
      const arg = args[i++] as string;
      if (["-o", "+o", "-O", "+O"].includes(arg)) i++;
      else if ((arg.startsWith("-") || arg.startsWith("+")) && !arg.startsWith("--") && arg.length > 1) hasC ||= arg.includes("c");
      else if (!arg.startsWith("--")) return hasC ? arg : undefined;
    }
  }
  if (POWERSHELLS.has(name)) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      const flag = arg.startsWith("-") || arg.startsWith("/") ? arg.slice(1).toLowerCase() : "";
      if (flag === "c" || (flag.length >= 3 && "command".startsWith(flag))) return args.slice(i + 1).join(" ");
    }
  }
  return undefined;
}

/** The calls one simple command makes, after applying its cd, export or unset. */
function simple(argv: string[], item: Item, shell: Shell, depth: number): Call[] {
  const parsed = program(argv, shell.cwd);
  const { name, args } = parsed;
  const env = CLEAN_ENV in parsed.env ? parsed.env : { ...shell.exported, ...parsed.env };
  shell.status = name === "true" || name === ":" ? 0 : name === "false" ? 1 : undefined;
  if (name === "cd" || name === "export" || name === "unset") {
    // A pipeline's commands run in subshells, so their cd and exports end with them.
    if (item.before !== "|" && item.after !== "|") builtin(name, args, parsed.cwd, shell);
    return [];
  }
  const inner = name === undefined ? undefined : shellString(name, args);
  if (inner !== undefined) {
    // The string's commands run as the wrapper's user and read its stdin and write its stdout.
    return walk(new Lexer(inner, depth + 1).read() ?? [], parsed.cwd, env, shell.processEnv, depth + 1).map((call) => ({
      ...call,
      otherUser: call.otherUser || parsed.otherUser,
      io: new Set([...call.io, ...item.io]),
      pipedIn: call.pipedIn || item.before === "|",
      pipedOut: call.pipedOut || item.after === "|",
    }));
  }
  if (name === undefined) return [];
  return [{ name, args, env, cwd: parsed.cwd, otherUser: parsed.otherUser, io: item.io, pipedIn: item.before === "|", pipedOut: item.after === "|" }];
}

/** The calls one simple command makes, if it runs or may run. */
function command(item: Item, shell: Shell, depth: number): Call[] {
  let argv = item.argv;
  let followsHere = follows(item.before, shell.status);
  if (!["&&", "||", "|"].includes(item.before)) shell.start = snapshot(shell);
  while (argv.length > 0 && KEYWORDS.has(argv[0] as string)) {
    argv = keyword(argv, followsHere, shell);
    followsHere = true;
  }
  let calls: Call[] = [];
  if (argv.length > 0 && both(runs(shell), followsHere) !== false) {
    calls = simple(argv, item, shell, depth);
    if (shell.negate) shell.status = shell.status === 0 ? 1 : shell.status === 1 ? 0 : undefined;
    shell.negate = false;
  }
  if (item.after === "&") restore(shell, shell.start); // a backgrounded list runs in a subshell
  return calls;
}

/** Each simple command that runs or may run; commands a literal true or false skips, untaken branches and
 *  function bodies are left out. */
function walk(items: Item[], cwd: string | undefined, exported: Env, processEnv: Record<string, string | undefined>, depth: number): Call[] {
  const shell: Shell = {
    cwd, exported: { ...exported }, status: undefined, frames: [], function: false, negate: false,
    start: [cwd, { ...exported }], processEnv,
  };
  const calls: Call[] = [];
  for (const item of items) {
    if (item.kind === "cmd") calls.push(...command(item, shell, depth));
    else marker(item, shell);
  }
  return calls;
}

/** The option in a cluster such as -sSLo that takes a value, its value and the next index; switches go to `seen`. */
function shortOption(arg: string, args: readonly string[], start: number, valueFlags: string, seen: Set<string>): [string, string | undefined, number] {
  let i = start;
  for (let j = 1; j < arg.length; j++) {
    const flag = arg[j] as string;
    if (valueFlags.includes(flag)) {
      let value = arg.slice(j + 1);
      if (value === "" && i < args.length) value = args[i++] as string;
      return [`-${flag}`, value, i];
    }
    seen.add(`-${flag}`);
  }
  return [arg, undefined, i];
}

/** The host a URL names, with any login, port and path dropped; empty when it names none. */
function urlHost(url: string): string {
  try {
    const text = url.trim();
    const host = new URL(text.includes("://") ? text : `http://${text}`).hostname.toLowerCase();
    return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  } catch {
    return "";
  }
}

function curl(args: string[]): Raw[] {
  const urls: string[] = [];
  const flags = new Set<string>();
  let method = "";
  for (let i = 0; i < args.length; ) {
    let arg = args[i++] as string;
    let value: string | undefined;
    if (arg.startsWith("--")) {
      // curl reads --name=value as --name value, and --expand-name as --name with variables expanded.
      const eq = arg.indexOf("=");
      if (eq >= 0) value = arg.slice(eq + 1);
      arg = eq >= 0 ? arg.slice(0, eq) : arg;
      if (arg.startsWith("--expand-")) arg = `--${arg.slice("--expand-".length)}`;
      if (eq < 0 && CURL_LONG_VALUES.has(arg) && i < args.length) value = args[i++];
    } else if (arg.startsWith("-") && arg.length > 1) {
      [arg, value, i] = shortOption(arg, args, i, CURL_SHORT_VALUES, flags);
    } else {
      urls.push(arg);
      continue;
    }
    flags.add(arg);
    if (arg === "--url" && value) urls.push(value);
    else if ((arg === "-X" || arg === "--request") && value) method = value.toUpperCase();
  }
  const has = (set: ReadonlySet<string>): boolean => [...flags].some((f) => set.has(f));
  const sends = has(CURL_UPLOADS) || SENDING_METHODS.has(method) || (has(CURL_BODIES) && !flags.has("-G") && !flags.has("--get"));
  return urls.map((url): Raw => [sends ? "out" : "in", urlHost(url), undefined]);
}

function wget(args: string[]): Raw[] {
  const urls: string[] = [];
  const flags = new Set<string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq < 0 ? arg : arg.slice(0, eq);
      if (eq < 0 && WGET_LONG_VALUES.has(name)) i++;
      flags.add(name);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag: string;
      [flag, , i] = shortOption(arg, args, i, WGET_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      urls.push(arg);
    }
  }
  const direction = [...flags].some((f) => WGET_UPLOADS.has(f)) ? "out" : "in";
  return urls.map((url): Raw => [direction, urlHost(url), undefined]);
}

/** The operands, and the options that change which host or user ssh -G resolves, for ssh, scp or sftp. */
function sshArgs(name: string, args: string[]): [string[], string[]] {
  const passthrough: string[] = [];
  const operands: string[] = [];
  const valueFlags = SSH_VALUE_FLAGS[name] ?? "";
  // scp's -l is a bandwidth limit, not a login.
  const identityFlags = name === "ssh" ? ["l", "o", "F", "J", "p"] : ["o", "F", "J", "P"];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    // ssh reads options before and right after its destination; the first other word starts the remote command.
    const readingOptions = operands.length === 0 || (name === "ssh" && operands.length === 1);
    if (!readingOptions || !arg.startsWith("-") || arg === "-") {
      operands.push(arg);
      continue;
    }
    if (arg === "--") {
      operands.push(...args.slice(i));
      break;
    }
    let flag: string;
    let value: string | undefined;
    [flag, value, i] = shortOption(arg, args, i, valueFlags, new Set());
    const option = ((value ?? "").trim().split(/[\s=]/)[0] ?? "").toLowerCase();
    if (value && identityFlags.includes(flag.slice(1)) && (flag !== "-o" || SSH_IDENTITY_OPTIONS.has(option))) {
      passthrough.push(flag === "-P" ? "-p" : flag, value);
    }
  }
  return [operands, passthrough];
}

/** The operands, and ssh options for its remote shell (undefined when that shell isn't ssh), for rsync. */
function rsyncArgs(args: string[], env: Env, processEnv: Record<string, string | undefined>): [string[], string[] | undefined] {
  let shell = envValue(env, processEnv, "RSYNC_RSH");
  const operands: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--rsh" && i < args.length) shell = args[i++] as string;
    else if (arg.startsWith("--rsh=")) shell = arg.slice("--rsh=".length);
    else if (RSYNC_VALUE_OPTIONS.has(arg)) i++;
    else if (arg.startsWith("-") && !arg.startsWith("--")) {
      let flag: string;
      let value: string | undefined;
      [flag, value, i] = shortOption(arg, args, i, SSH_VALUE_FLAGS.rsync as string, new Set());
      if (flag === "-e" && value !== undefined) shell = value;
    } else if (!arg.startsWith("-")) operands.push(arg);
  }
  if (!shell) return [operands, []];
  const shellArgv = words(shell);
  if (shellArgv[0] === undefined || programName(shellArgv[0]) !== "ssh") return [operands, undefined];
  return [operands, sshArgs("ssh", [...shellArgv.slice(1), "-"])[1]];
}

/** The destination, port and whether ssh carries it, for a remote copy operand; undefined for a local path. */
function remote(arg: string): [string, string | undefined, boolean] | undefined {
  const uri = /^(scp|sftp|rsync):\/\/(?:([^@/;:]+)(?:[;:][^@/]*)?@)?(\[[^\]/]+\]|[^/:[\]@]+)(?::(\d+))?(?=\/|$)/.exec(arg);
  if (uri !== null) {
    // A URI names the login and port itself; anything after the user (a password) is dropped.
    return [uri[2] === undefined ? (uri[3] as string) : `${uri[2]}@${uri[3]}`, uri[4], uri[1] !== "rsync"];
  }
  if (arg.includes("://")) return undefined;
  // A bracketed host may hold an IPv6 address; a second colon after the host marks an rsync daemon.
  const match = /^((?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)):(:)?/.exec(arg);
  // A drive letter is a local path only on Windows; elsewhere scp dials host C.
  if (match === null || (process.platform === "win32" && /^[A-Za-z]:[\\/]/.test(arg))) return undefined;
  return [match[1] as string, undefined, match[2] === undefined];
}

function copy(name: string, args: string[], env: Env, processEnv: Record<string, string | undefined>): Raw[] {
  const [operands, options] = name === "rsync" ? rsyncArgs(args, env, processEnv) : sshArgs(name, args);
  let remotes: [ReturnType<typeof remote>, string][];
  if (name === "sftp" && operands.length > 0) {
    // sftp takes one destination: a bare host opens a session, a host:path or URI fetches that path.
    const first = operands[0] as string;
    const plain = /^(?:[^@/:[\]]+@)?(?:\[[^\]/]+\]|[^/:[\]]+)$/.test(first);
    remotes = [[plain ? [first, undefined, true] : remote(first), plain ? "" : "in"]];
  } else if (operands.length === 1) {
    remotes = [[remote(operands[0] as string), name === "rsync" ? "in" : ""]]; // rsync lists a lone remote
  } else {
    remotes = operands.map((op, i): [ReturnType<typeof remote>, string] => [remote(op), i === operands.length - 1 ? "out" : "in"]);
  }
  const out: Raw[] = [];
  for (const [found, direction] of remotes) {
    if (found === undefined) continue;
    const [destination, port, viaSsh] = found;
    const sshOptions = viaSsh && options !== undefined ? [...options, ...(port === undefined ? [] : ["-p", port])] : undefined;
    out.push([direction, destination, sshOptions]);
  }
  return out;
}

function sshPipe(args: string[], sends: boolean, receives: boolean): Raw[] {
  const [operands, options] = sshArgs("ssh", args);
  const destination = operands[0];
  if (destination === undefined) return [];
  return ([["out", sends], ["in", receives]] as const).filter(([, used]) => used).map(([d]): Raw => [d, destination, options]);
}

function netcat(args: string[], sends: boolean): Raw[] {
  const positional: string[] = [];
  const flags = new Set<string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg.startsWith("--")) {
      if (!arg.includes("=") && NC_LONG_VALUES.has(arg)) i++;
      flags.add(arg);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag: string;
      [flag, , i] = shortOption(arg, args, i, NC_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      positional.push(arg);
    }
  }
  if (positional[0] === undefined || ["-l", "--listen", "-U", "--unixsock"].some((f) => flags.has(f))) return [];
  return [[sends ? "out" : "", positional[0], undefined]];
}

function socat(args: string[], sends: boolean): Raw[] {
  const addresses: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (SOCAT_VALUE_OPTIONS.has(arg)) i++;
    else if (arg === "-" || !arg.startsWith("-")) addresses.push(arg);
  }
  const out: Raw[] = [];
  for (const address of addresses.slice(0, 2)) {
    const match =
      /^(?:(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?|(?:proxy|socks4a?|socks5):[^:,]+):(\[[^\]]+\]|[^:,]+):/i.exec(address);
    if (match !== null) out.push([sends ? "out" : "", match[1] as string, undefined]);
  }
  return out;
}

/** Whether an HTTPie request item is data (=, :=, @, =@, :=@) rather than a header (:) or a query (==). */
function httpieItem(item: string): boolean {
  const match = /^(?:\\.|[^\\=:@])*(:=@|=@|:=|==|=|@|:)/.exec(item);
  return match !== null && match[1] !== "==" && match[1] !== ":";
}

function httpie(args: string[], sends: boolean): Raw[] {
  const positional: string[] = [];
  const flags = new Set<string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq < 0 ? arg : arg.slice(0, eq);
      if (eq < 0 && HTTPIE_LONG_VALUES.has(name)) i++;
      flags.add(name);
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag: string;
      [flag, , i] = shortOption(arg, args, i, HTTPIE_SHORT_VALUES, flags);
      flags.add(flag);
    } else {
      positional.push(arg);
    }
  }
  if (positional.length === 0 || flags.has("--offline")) return [];
  const method = positional.length > 1 && /^[A-Za-z]+$/.test(positional[0] as string) ? (positional[0] as string).toUpperCase() : "";
  const url = (method ? positional[1] : positional[0]) as string;
  const items = positional.slice(method ? 2 : 1);
  const readsStdin = sends && !flags.has("-I") && !flags.has("--ignore-stdin");
  const out = SENDING_METHODS.has(method) || flags.has("--raw") || readsStdin || items.some(httpieItem);
  return [[out ? "out" : "in", url.startsWith(":") ? "localhost" : urlHost(url), undefined]];
}

function webCmdlet(args: string[], sends: boolean): Raw[] {
  let uri = "";
  let out = sends;
  const positional: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (!/^-[A-Za-z]/.test(arg)) {
      positional.push(arg);
      continue;
    }
    const colon = arg.indexOf(":");
    const name = (colon < 0 ? arg.slice(1) : arg.slice(1, colon)).toLowerCase();
    let value = colon < 0 ? "" : arg.slice(colon + 1);
    if (colon < 0 && !PS_SWITCHES.has(name) && i < args.length) value = args[i++] as string;
    if (name === "uri") uri = value;
    else if (name === "body" || name === "infile" || name === "form") out = true;
    else if ((name === "method" || name === "custommethod") && SENDING_METHODS.has(value.toUpperCase())) out = true;
  }
  uri ||= positional[0] ?? "";
  return uri ? [[out ? "out" : "in", urlHost(uri), undefined]] : [];
}

/** The tool and its raw endpoints for a transfer command; undefined for any other. */
function parse(call: Call, processEnv: Record<string, string | undefined>): [string, Raw[]] | undefined {
  const tool = TOOLS[call.name];
  const sends = call.io.has("in") || call.pipedIn;
  let raw: Raw[];
  if (tool === "scp" || tool === "sftp" || tool === "rsync") raw = copy(tool, call.args, call.env, processEnv);
  else if (tool === "ssh") raw = sshPipe(call.args, sends, call.io.has("out") || call.pipedOut);
  else if (tool === "curl") raw = curl(call.args);
  else if (tool === "wget") raw = wget(call.args);
  else if (tool === "nc") raw = netcat(call.args, sends);
  else if (tool === "socat") raw = socat(call.args, sends);
  else if (tool === "httpie") raw = httpie(call.args, sends);
  else if (tool === "powershell") raw = webCmdlet(call.args, sends);
  else return undefined;
  // Under sudo, ssh runs as that user, with that user's config, which this can't read.
  return [tool, raw.map(([d, dest, options]): Raw => [d, dest, call.otherUser ? undefined : options])];
}

/** A host name or address in lower case without brackets; empty when it isn't one. */
function cleanHost(value: string): string {
  let host = value.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (/^[a-z0-9_][a-z0-9_.-]{0,252}$/.test(host)) return host;
  const bare = host.split("%")[0] as string;
  return host.includes(":") && isIP(bare) === 6 ? normalizeV6(bare) : "";
}

/** An IPv6 address in the compressed form the Python hooks print. */
function normalizeV6(address: string): string {
  try {
    return new URL(`http://[${address}]/`).hostname.slice(1, -1);
  } catch {
    return address;
  }
}

function expandHome(path: string, home = homedir()): string {
  return path === "~" || path.startsWith("~/") ? join(home, path.slice(1)) : path;
}

/** The home folder ssh reads its config from: the account's own, which $HOME does not change. */
function accountHome(): string {
  try {
    return userInfo().homedir || homedir();
  } catch {
    return homedir();
  }
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

/** The files an ssh Include pattern names, resolved against every home and folder ssh may use; undefined when it
 *  can't be expanded, so the caller refuses. */
function includeTargets(pattern: string, bases: readonly string[], homes: readonly string[]): string[] | undefined {
  // `~user` names another account's home, and ssh may expand a variable or token, so only ssh can resolve those.
  if ((pattern.startsWith("~") && pattern !== "~" && !pattern.startsWith("~/")) || /[$%]/.test(pattern)) return undefined;
  // ssh globs the path, and glob reads a backslash as escaping the next character.
  const unescaped = pattern.replace(/\\(.)/g, "$1");
  const fulls = unescaped === "~" || unescaped.startsWith("~/")
    ? homes.map((home) => expandHome(unescaped, home))
    : bases.map((base) => (isAbsolute(unescaped) ? unescaped : join(base, unescaped)));
  const out: string[] = [];
  for (const full of new Set(fulls)) {
    const found = globTargets(full);
    if (found === undefined) return undefined;
    out.push(...found);
  }
  return out;
}

/** The files a path with `*` or `?` in its last part names; undefined for a glob this can't expand. */
function globTargets(full: string): string[] | undefined {
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
  const out: string[] = [];
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
      if (inWord) out.push(word);
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
  if (inWord) out.push(word);
  return out;
}

/** Whether config lines could run a command or a DNS lookup in ssh -G; their Includes are queued on `pending`. */
function configRuns(text: string, bases: readonly string[], homes: readonly string[], pending: [string, readonly string[]][]): boolean {
  for (const line of text.split(/\r?\n/)) {
    const lineWords = configWords(line);
    if (lineWords === undefined) return true;
    const [first = "", ...rest] = lineWords;
    const [keyword = "", attached = ""] = first.split(/=(.*)/s);
    // ssh allows `Keyword=value` and `Keyword =value`, so a leading = is only a separator.
    const args = (attached ? [attached, ...rest] : rest).map((w) => w.replace(/^=+/, "")).filter(Boolean);
    if (keyword.toLowerCase() === "match" && args.some((w) => w.toLowerCase().replace(/^!/, "").startsWith("exec"))) return true;
    if (keyword.toLowerCase() === "canonicalizehostname" && ["yes", "always"].includes((args[0] ?? "").toLowerCase())) return true;
    for (const pattern of keyword.toLowerCase() === "include" ? args : []) {
      const targets = includeTargets(pattern, bases, homes);
      if (targets === undefined) return true;
      pending.push(...targets.map((target): [string, readonly string[]] => [target, bases]));
    }
  }
  return false;
}

/** Whether ssh -G could run a command or a DNS lookup while reading its configs, or reads a file this can't check. */
function configUnsafe(passthrough: readonly string[], home: string, processEnv: Record<string, string | undefined>): boolean {
  // ssh reads ~/.ssh/config from the account's home but expands an Include's ~ and relative path with $HOME.
  const homes = [...new Set([home, processEnv.HOME || home])];
  const userBases = homes.map((h) => join(h, ".ssh"));
  let config: string | undefined;
  for (let i = 0; i + 1 < passthrough.length; i += 2) if (passthrough[i] === "-F") config = passthrough[i + 1];
  if (config === "none") return false;
  if (config !== undefined && !isAbsolute(config)) return true;
  // Whichever ssh is on PATH reads its own system config, so every one that exists is checked.
  const system = ["/etc/ssh", "/opt/homebrew/etc/ssh", "/usr/local/etc/ssh", join(processEnv.PROGRAMDATA || "/nonexistent", "ssh")];
  const pending: [string, readonly string[]][] =
    config === undefined
      ? [[join(home, ".ssh", "config"), userBases], ...system.map((d): [string, readonly string[]] => [join(d, "ssh_config"), [d]])]
      : [[config, userBases]];
  const seen = new Set<string>();
  while (pending.length > 0) {
    const [path, bases] = pending.pop() as [string, readonly string[]];
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
    if (configRuns(text, bases, homes, pending)) return true;
  }
  return false;
}

/** The host ssh connects to for a destination, read from ssh -G; empty when it can't be looked up safely. */
async function sshHostname(destination: string, options: string[], cwd: string | undefined, state: State): Promise<string> {
  // The lookup runs elsewhere, so a relative config path is resolved against the folder the command ran in.
  const resolved = options.map((value, i) => {
    if (options[i - 1] !== "-F") return value;
    const path = expandHome(value);
    return path === "none" || isAbsolute(path) || cwd === undefined ? path : join(cwd, path);
  });
  const key = JSON.stringify([destination, resolved]);
  const cached = state.sshHosts.get(key);
  if (cached !== undefined) return cached;
  state.sshHosts.set(key, "");
  // A destination starting with - would reach ssh -G as an option.
  if (destination.startsWith("-") || configUnsafe(resolved, state.home, state.env)) return "";
  const out = (await run(["ssh", "-G", ...resolved, "--", destination.replace(/[[\]]/g, "")], state)) ?? "";
  const line = out.split(/\r?\n/).find((l) => l.startsWith("hostname "));
  const host = line === undefined ? "" : cleanHost(line.slice("hostname ".length));
  state.sshHosts.set(key, host);
  return host;
}

const KIND_LISTS: [AddressKind, BlockList][] = ADDRESS_KINDS.map(([kind, networks]) => {
  const list = new BlockList();
  for (const network of networks) {
    const [address = "", prefix = ""] = network.split("/");
    list.addSubnet(address, Number(prefix), address.includes(":") ? "ipv6" : "ipv4");
  }
  return [kind, list];
});

function kindOf(raw: string): AddressKind {
  // An IPv4-mapped IPv6 address is the IPv4 address it carries.
  const address = /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(raw) ? raw.slice(7) : raw.split("%")[0] as string;
  const family = isIP(address) === 6 ? "ipv6" : "ipv4";
  for (const [kind, list] of KIND_LISTS) if (list.check(address, family)) return kind;
  return "public";
}

/** Lookups still in flight after their timeout; while one is, no other starts, so a hung resolver holds at most
 *  one libuv thread, which pi's file reads share. */
let hungLookups = 0;

const systemLookup: LookupLike = async (host) =>
  (await dnsLookup(host, { all: true, verbatim: true })).map((entry) => entry.address);

/** The host's addresses from the system resolver; [] when it fails or takes longer than `timeoutMs`. */
async function resolveAddresses(host: string, timeoutMs: number, state: State): Promise<readonly string[]> {
  if (hungLookups > 0) return [];
  let timer: NodeJS.Timeout | undefined;
  let settled = false;
  let timedOut = false;
  const pending = Promise.resolve().then(() => state.lookup(host)).then((found) => found, () => [] as string[]).finally(() => {
    settled = true;
    if (timedOut) hungLookups--;
  });
  const timeout = new Promise<readonly string[]>((done) => {
    timer = setTimeout(() => {
      if (!settled) {
        timedOut = true;
        hungLookups++;
      }
      done([]);
    }, timeoutMs);
  });
  try {
    return await Promise.race([pending, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** The kind of address a host resolves to, looked up once per turn: public when any address is public, else the
 *  first address's kind; unresolved when the lookup fails or the turn's budget is spent. */
async function address(host: string, state: State): Promise<AddressKind> {
  const cached = state.addresses.get(host);
  if (cached !== undefined) return cached;
  let found: readonly string[];
  if (isIP(host) !== 0) {
    found = [host];
  } else {
    const remaining = state.deadline - state.now();
    found = remaining > 0 ? await resolveAddresses(host, Math.min(DNS_TIMEOUT_MS, remaining), state) : [];
  }
  const kinds = found.map(kindOf);
  const kind: AddressKind = kinds.length === 0 ? "unresolved" : kinds.includes("public") ? "public" : (kinds[0] as AddressKind);
  state.addresses.set(host, kind);
  return kind;
}

/** One place a transfer reached: its host as written without any login, the host ssh resolves it to, and the kind
 *  of address that host has. */
async function endpoint(raw: Raw, cwd: string | undefined, state: State): Promise<TransferEndpoint | undefined> {
  const [direction, rawDestination, sshOptions] = raw;
  const destination = rawDestination.trim();
  const host = cleanHost(destination.includes("://") ? urlHost(destination) : (destination.split("@").pop() ?? ""));
  if (host === "") return undefined;
  const resolved = (sshOptions === undefined ? "" : await sshHostname(destination, sshOptions, cwd, state)) || host;
  const out: TransferEndpoint = { host, resolved_host: resolved, address: await address(resolved, state) };
  return direction === "out" || direction === "in" ? { direction, ...out } : out;
}

/** Where one shell command's transfers went; undefined when it ran none. */
async function transferOf(command: string, cwd: string | undefined, state: State): Promise<Transfer | undefined> {
  let tool: string | undefined;
  const endpoints: TransferEndpoint[] = [];
  for (const call of walk(new Lexer(command).read() ?? [], cwd, {}, state.env, 0)) {
    const found = parse(call, state.env);
    for (const raw of found?.[1] ?? []) {
      if (endpoints.length >= MAX_ENDPOINTS) break;
      const one = await endpoint(raw, call.cwd, state);
      if (one !== undefined && !endpoints.some((e) => JSON.stringify(e) === JSON.stringify(one))) {
        endpoints.push(one);
        tool ??= found?.[0];
      }
    }
  }
  return tool === undefined ? undefined : { tool, endpoints };
}

export interface ShellCall {
  tool_name?: unknown;
  tool_use_id?: unknown;
  tool_input?: unknown;
  decision?: unknown;
  /** `false` when the call is known not to have run, such as a confirm the person declined. */
  ran?: unknown;
}

const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell"]);
/** Policy outcomes under which the call never ran, so it moved nothing. */
const NEVER_RAN: ReadonlySet<string> = new Set(["deny", "unavailable"]);

/** Where each shell call of a turn sent to or fetched from, keyed by `tool_use_id`; each call starts in `cwd`.
 *  Never rejects. */
export async function resolveTransfers(
  calls: readonly ShellCall[], cwd: string | undefined, opts: ResolveOptions = {},
): Promise<Map<string, Transfer>> {
  const transfers = new Map<string, Transfer>();
  try {
    const now = opts.now ?? Date.now;
    const state: State = {
      run: opts.execFile ?? defaultExecFile,
      lookup: opts.lookup ?? systemLookup,
      env: opts.env ?? process.env,
      now,
      deadline: now() + (opts.budgetMs ?? TURN_BUDGET_MS),
      home: opts.home ?? accountHome(),
      sshHosts: new Map(),
      addresses: new Map(),
    };
    for (const call of calls) {
      const input = call.tool_input;
      const command = input !== null && typeof input === "object" && !Array.isArray(input) ? (input as Record<string, unknown>).command : undefined;
      if (typeof call.tool_name !== "string" || !SHELL_TOOLS.has(call.tool_name)) continue;
      if ((typeof call.decision === "string" && NEVER_RAN.has(call.decision)) || call.ran === false) continue;
      if (typeof command !== "string" || command.trim() === "" || typeof call.tool_use_id !== "string") continue;
      const transfer = await transferOf(command, cwd, state);
      if (transfer !== undefined) transfers.set(call.tool_use_id, transfer);
    }
  } catch {
    // Telemetry enrichment: whatever resolved before the failure is still returned.
  }
  return transfers;
}
