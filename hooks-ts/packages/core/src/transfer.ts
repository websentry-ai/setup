// Transfer resolution: where each shell transfer went, as host and address kind only, in parity with the Python
// hooks' transfer block. No `throw` escapes: a failed or slow lookup leaves the address `unresolved`, and every
// lookup has a deadline within one turn budget, so the turn log is never held up long.

import { lookup as dnsLookup } from "node:dns/promises";
import {
  closeSync, constants, fstatSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, realpathSync, rmSync, statSync,
  writeFileSync,
} from "node:fs";
import { BlockList, isIP } from "node:net";
import { homedir, tmpdir, userInfo } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, normalize, sep } from "node:path";

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
/** How many function calls are followed in one command, so a recursive function stays cheap. */
const MAX_CALLS = 32;
/** How many words one brace expansion or curl URL glob is expanded into. */
const MAX_WORDS = 64;
/** A longer command, or one nesting compounds deeper, is skipped whole so it can't hold up the turn. */
const MAX_CHARS = 20_000;
const MAX_NESTING = 100;
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
  builtin: { short: "", long: [], operands: 0 },
  nohup: { short: "", long: [], operands: 0 },
};
/** Where `-C`/`--chdir` or `-D` moves a wrapped command. */
const WRAPPER_CHDIR: Record<string, readonly string[]> = { env: ["-C", "--chdir"], sudo: ["-D", "--chdir"] };
/** Reserved words that open, divide or close a compound command. */
const KEYWORDS: ReadonlySet<string> = new Set(
  "{ } if then elif else fi while until for select do done ! function time".split(" "),
);
/** Reserved words after which the next word still starts a command. */
const LEADING_WORDS: ReadonlySet<string> = new Set("{ if then elif else while until do ! time".split(" "));
const LOOPS: readonly string[] = ["while", "until", "for", "select"];
const DECLARES: readonly string[] = ["declare", "typeset", "local", "readonly"];
const SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash"]);
const POWERSHELLS: ReadonlySet<string> = new Set(["powershell", "pwsh"]);
/** Set in a command's env by `env -i`: nothing is inherited from the hook's environment. */
const CLEAN_ENV = "\0clean";
/** Set after eval or source, whose text may set any variable: one not set since then is unknown. */
const UNKNOWN_ENV = "\0unknown";
/** Set by set -a: "1" on, "" off, and a substitution when it may be either; plain assignments are then exported. */
const ALLEXPORT = "\0allexport";
/** Set by set -e, held as allexport is: a command that fails then ends the shell. */
const ERREXIT = "\0errexit";
/** Stands in for a substitution's output inside a word, so no host is read from it. */
const SUBSTITUTED = "\0";
/** Mark a word's unquoted { , and }, which bash may brace-expand, and turn them back once it has. */
const BRACE_MARKS: Record<string, string> = { "{": "\x01", ",": "\x02", "}": "\x03" };
/** Marks a quoted or escaped ~ that starts a word, which the shell leaves as it is; `tilde` turns it back. */
const LITERAL_TILDE = "\x05";
function unmark(word: string): string {
  return word.replace(/[\x01-\x03]/g, (mark) => "{,}"[mark.charCodeAt(0) - 1] as string);
}
const TOOLS: Record<string, string> = {
  curl: "curl", wget: "wget", scp: "scp", rsync: "rsync", sftp: "sftp", ssh: "ssh",
  nc: "nc", ncat: "nc", netcat: "nc", socat: "socat", http: "httpie", https: "httpie",
  "invoke-webrequest": "powershell", "invoke-restmethod": "powershell", iwr: "powershell", irm: "powershell",
};
const SENDING_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH"]);
/** The port a URL connects to when it names none, by scheme. */
const DEFAULT_PORTS: Record<string, number> = {
  http: 80, https: 443, ftp: 21, ftps: 990, ws: 80, wss: 443, scp: 22, sftp: 22, imap: 143, imaps: 993, pop3: 110,
  pop3s: 995, smtp: 25, smtps: 465, ldap: 389, ldaps: 636, dict: 2628, gopher: 70, gophers: 70, rtsp: 554, telnet: 23,
  tftp: 69, mqtt: 1883, smb: 445, smbs: 445,
};
/** The URL schemes each tool speaks; a URL with any other reaches no host. */
const CURL_SCHEMES: ReadonlySet<string> = new Set(("dict ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 " +
  "pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss").split(" "));
const WGET_SCHEMES: ReadonlySet<string> = new Set(["http", "https", "ftp", "ftps"]);
const HTTPIE_SCHEMES: ReadonlySet<string> = new Set(["http", "https"]);
const POWERSHELL_SCHEMES: ReadonlySet<string> = new Set(["http", "https", "ftp"]);
/** The switches a --no- option turns back off, so the last of them decides. */
const CURL_UNDOES: Record<string, readonly string[]> = { "--no-globoff": ["-g", "--globoff"], "--no-get": ["-G", "--get"] };
/** Options that take a value, per program; every other option is a switch. */
const SSH_VALUE_FLAGS: Record<string, string> = {
  ssh: "BbcDEeFIiJLlmOoPpQRSWw", scp: "cDFiJloPSX", sftp: "BbcDFiJloPRSsX", rsync: "efTMB@",
};
/** Of ssh's -o settings, only these change which host or user ssh -G resolves. */
const SSH_IDENTITY_OPTIONS: ReadonlySet<string> = new Set(["hostname", "user", "port", "proxyjump", "proxycommand"]);
/** A host reached through one of these is resolved by the proxy, so it is never looked up here. */
/** curl's proxy options and the kind of proxy each names; -x, --proxy and --preproxy name it by their URL's scheme. */
const CURL_PROXIES: Record<string, string> = {
  "-x": "", "--proxy": "", "--proxy1.0": "", "--preproxy": "", "--socks4": "socks4", "--socks4a": "socks4a",
  "--socks5": "socks5", "--socks5-hostname": "socks5h",
};
const PROXY_ENV = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ftp_proxy", "FTP_PROXY", "all_proxy", "ALL_PROXY"];
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
   --trace-config --unix-socket --upload-file --url --url-query --user --user-agent --variable --write-out --proxy1.0
   --krb4 --ech --httpsig-algo --httpsig-headers --httpsig-key --httpsig-keyid --ip-tos --knownhosts --sigalgs
   --ssl-sessions --upload-flags`.split(/\s+/),
);
/** curl 8.5's long options without the --, the last curl that reads a prefix as the one option it starts. */
const CURL_LONG_OPTIONS: ReadonlySet<string> = new Set(
  `abstract-unix-socket alpn alt-svc anyauth append aws-sigv4 basic buffer ca-native cacert capath cert cert-status
   cert-type ciphers clobber compressed compressed-ssh config connect-timeout connect-to continue-at cookie
   cookie-jar create-dirs create-file-mode crlf crlfile curves data data-ascii data-binary data-raw data-urlencode
   delegation digest disable disable-eprt disable-epsv disallow-username-in-url dns-interface dns-ipv4-addr
   dns-ipv6-addr dns-servers doh-cert-status doh-insecure doh-url dump-header egd-file engine eprt epsv etag-compare
   etag-save expect100-timeout fail fail-early fail-with-body false-start form form-escape form-string ftp-account
   ftp-alternative-to-user ftp-create-dirs ftp-method ftp-pasv ftp-port ftp-pret ftp-skip-pasv-ip ftp-ssl
   ftp-ssl-ccc ftp-ssl-ccc-mode ftp-ssl-control ftp-ssl-reqd get globoff happy-eyeballs-timeout-ms haproxy-clientip
   haproxy-protocol head header help hostpubmd5 hostpubsha256 hsts http0.9 http1.0 http1.1 http2
   http2-prior-knowledge http3 http3-only ignore-content-length include insecure interface ipfs-gateway ipv4 ipv6
   json junk-session-cookies keepalive keepalive-time key key-type krb krb4 libcurl limit-rate list-only local-port
   location location-trusted login-options mail-auth mail-from mail-rcpt mail-rcpt-allowfails manual max-filesize
   max-redirs max-time metalink negotiate netrc netrc-file netrc-optional next noproxy npn ntlm ntlm-wb
   oauth2-bearer output output-dir parallel parallel-immediate parallel-max pass path-as-is pinnedpubkey post301
   post302 post303 preproxy progress-bar progress-meter proto proto-default proto-redir proxy proxy-anyauth
   proxy-basic proxy-ca-native proxy-cacert proxy-capath proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile
   proxy-digest proxy-header proxy-http2 proxy-insecure proxy-key proxy-key-type proxy-negotiate proxy-ntlm
   proxy-pass proxy-pinnedpubkey proxy-service-name proxy-ssl-allow-beast proxy-ssl-auto-client-cert
   proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword proxy-tlsuser proxy-tlsv1 proxy-user proxy1.0 proxytunnel
   pubkey quote random-file range rate raw referer remote-header-name remote-name remote-name-all remote-time
   remove-on-error request request-target resolve retry retry-all-errors retry-connrefused retry-delay
   retry-max-time sasl-authzid sasl-ir service-name sessionid show-error silent socks4 socks4a socks5 socks5-basic
   socks5-gssapi socks5-gssapi-nec socks5-gssapi-service socks5-hostname speed-limit speed-time ssl ssl-allow-beast
   ssl-auto-client-cert ssl-no-revoke ssl-reqd ssl-revoke-best-effort sslv2 sslv3 stderr styled-output
   suppress-connect-headers tcp-fastopen tcp-nodelay telnet-option test-event tftp-blksize tftp-no-options time-cond
   tls-max tls13-ciphers tlsauthtype tlspassword tlsuser tlsv1 tlsv1.0 tlsv1.1 tlsv1.2 tlsv1.3 tr-encoding trace
   trace-ascii trace-config trace-ids trace-time unix-socket upload-file url url-query use-ascii user user-agent
   variable verbose version wdebug write-out xattr`.split(/\s+/),
);
/** Bodies curl sends to every URL of a request; each -T or --upload-file goes to one URL instead, in order. */
const CURL_UPLOADS: ReadonlySet<string> = new Set(["-F", "--form", "--form-string", "--json"]);
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
   --report-speed --progress --use-askpass --bind-dns-address --dns-servers --dot-style --http-passwd
   --input-metalink --metalink-index --no --preferred-location --proxy-passwd --start-pos`.split(/\s+/),
);
/** GNU wget's long options without the --, each --no- form included, for getopt's reading of a prefix as one option. */
const WGET_LONG_OPTIONS: ReadonlySet<string> = new Set(
  `accept accept-regex adjust-extension append-output ask-password auth-no-challenge background backup-converted
   backups base bind-address bind-dns-address body-data body-file ca-certificate ca-directory cache certificate
   certificate-type check-certificate ciphers clobber compression config connect-timeout content-disposition
   content-on-error continue convert-file-only convert-links cookies crl-file cut-dirs debug default-page
   delete-after directories directory-prefix dns-cache dns-servers dns-timeout domains dont-remove-listing dot-style
   egd-file exclude-directories exclude-domains execute follow-ftp follow-tags force-directories force-html
   ftp-password ftp-stmlf ftp-user ftps-clear-data-connection ftps-fallback-to-ftp ftps-implicit ftps-resume-ssl
   glob header help host-directories hsts hsts-file html-extension htmlify http-keep-alive http-passwd http-password
   http-user https-only if-modified-since ignore-case ignore-length ignore-tags include-directories inet4-only
   inet6-only input-file input-metalink iri keep-badhash keep-session-cookies level limit-rate load-cookies
   local-encoding max-redirect metalink-index metalink-over-http method mirror netrc no no-adjust-extension
   no-ask-password no-auth-no-challenge no-background no-backup-converted no-backups no-cache no-check-certificate
   no-clobber no-config no-content-disposition no-content-on-error no-continue no-convert-file-only no-convert-links
   no-cookies no-debug no-delete-after no-directories no-dns-cache no-follow-ftp no-force-directories no-force-html
   no-ftp-stmlf no-ftps-clear-data-connection no-ftps-fallback-to-ftp no-ftps-implicit no-ftps-resume-ssl no-glob
   no-host-directories no-hsts no-html-extension no-htmlify no-http-keep-alive no-https-only no-if-modified-since
   no-ignore-case no-ignore-length no-inet4-only no-inet6-only no-iri no-keep-badhash no-keep-session-cookies
   no-metalink-over-http no-mirror no-netrc no-no-clobber no-no-config no-no-parent no-page-requisites no-parent
   no-passive-ftp no-preserve-permissions no-protocol-directories no-proxy no-quiet no-random-wait no-recursive
   no-relative no-remove-listing no-report-speed no-restrict-file-names no-retr-symlinks no-retry-connrefused
   no-retry-on-host-error no-save-headers no-server-response no-show-progress no-span-hosts no-spider
   no-strict-comments no-timestamping no-trust-server-names no-unlink no-use-server-timestamps no-verbose
   no-warc-cdx no-warc-compression no-warc-digests no-warc-keep-log no-wdebug no-xattr output-document output-file
   page-requisites parent passive-ftp password pinnedpubkey post-data post-file prefer-family preferred-location
   preserve-permissions private-key private-key-type progress protocol-directories proxy proxy-passwd proxy-password
   proxy-user proxy__compat quiet quota random-file random-wait read-timeout recursive referer regex-type reject
   reject-regex rejected-log relative remote-encoding remove-listing report-speed restrict-file-names retr-symlinks
   retry-connrefused retry-on-host-error retry-on-http-error save-cookies save-headers secure-protocol
   server-response show-progress span-hosts spider start-pos strict-comments timeout timestamping tries
   trust-server-names unlink use-askpass use-server-timestamps user user-agent verbose version wait waitretry
   warc-cdx warc-compression warc-dedup warc-digests warc-file warc-header warc-keep-log warc-max-size warc-tempdir
   wdebug xattr`.split(/\s+/),
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
   preserveauthorizationonredirect preservehttpmethodonredirect resume followrellink preserveheaderscase verbose debug
   whatif confirm`.split(/\s+/),
);
/** Their own parameters that take a value, the common ones, and the aliases, for PowerShell's resolving of a name. */
const PS_COMMON: ReadonlySet<string> = new Set(
  `verbose debug whatif confirm erroraction warningaction informationaction progressaction errorvariable
   warningvariable informationvariable outvariable outbuffer pipelinevariable`.split(/\s+/),
);
const PS_OWN: ReadonlySet<string> = new Set([
  ...[...PS_SWITCHES].filter((name) => !PS_COMMON.has(name)),
  ...`uri method body headers outfile infile contenttype useragent proxy credential timeoutsec websession
   sessionvariable form maximumredirection maximumretrycount retryintervalsec certificatethumbprint certificate
   authentication token custommethod sslprotocol transferencoding proxycredential connectiontimeoutseconds
   operationtimeoutseconds httpversion responseheadersvariable statuscodevariable maximumfollowrellink
   unixsocket`.split(/\s+/),
]);
const PS_ALIASES: Record<string, string> = {
  vb: "verbose", db: "debug", wi: "whatif", cf: "confirm", ea: "erroraction", wa: "warningaction",
  infa: "informationaction", proga: "progressaction", ev: "errorvariable", wv: "warningvariable",
  iv: "informationvariable", ov: "outvariable", ob: "outbuffer", pv: "pipelinevariable", cm: "custommethod",
  sv: "sessionvariable", rhv: "responseheadersvariable",
};
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
  sshHosts: Map<string, [string, boolean]>;
  addresses: Map<string, AddressKind>;
  /** Every call's input in the turn, and the command being read, to tell whether any names an ssh config. */
  turnText: string;
  callText: string;
}

type Env = Record<string, string>;
/** Where curl connects for a URL when --connect-to or --resolve change it: the host, and the addresses pinned for it. */
type Dial = [resolvedHost: string, addresses: string[]];
type Raw = [direction: string, destination: string, sshOptions: string[] | undefined, dial?: Dial | undefined, proxied?: boolean];

/** Run one allowlisted lookup within its timeout and the turn's budget; undefined when refused, slow or failing. ssh -G
 *  is checked here, and reads only the vetted copy of its configs made here, so no call reaches it unchecked. */
async function run(argv: string[], state: State): Promise<string | undefined> {
  let folder: string | undefined;
  try {
    if (!ALLOWED_RUNS.some((p) => p.every((part, i) => argv[i] === part))) return undefined;
    const remaining = state.deadline - state.now();
    if (remaining <= 0) return undefined;
    let [file, ...args] = argv;
    if (file === undefined) return undefined;
    if (file === "ssh" && args[0] === "-G") {
      folder = mkdtempSync(join(tmpdir(), "unbound-ssh-"));
      const end = argv.indexOf("--");
      const options = end < 0 ? undefined : vetted(argv.slice(2, end), state.home, state.env, folder);
      if (options === undefined) return undefined;
      args = ["-G", ...options, ...argv.slice(end)];
    }
    return await state.run(file, args, { timeoutMs: Math.min(RUN_TIMEOUT_MS, remaining), maxBytes: MAX_OUTPUT_BYTES });
  } catch {
    return undefined;
  } finally {
    if (folder !== undefined) rmSync(folder, { recursive: true, force: true });
  }
}

/** The index after the shell word starting at `start` after blanks, and the $( ) and backtick bodies in it, which run;
 *  the index is -1 when one of them is not closed. */
function wordEnd(text: string, start: number): [number, string[]] {
  let i = start;
  while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
  const bodies: string[] = [];
  let quote: string | undefined;
  for (; i < text.length; i++) {
    const ch = text[i] as string;
    const at = i;
    if (quote === "'") {
      if (ch === "'") quote = undefined;
    } else if (ch === "\\") {
      i++;
    } else if (text.startsWith("$(", i) || ch === "`") {
      const arithmetic = text.startsWith("$((", i) && arithmeticEnd(text, i + 2) > 0;
      i = ch === "$" ? parenEnd(text, i + 2) : backtickEnd(text, i + 1);
      const inner = arithmetic ? textBodies(text.slice(at + 3, i - 1)) : [];
      if (i < 0 || inner === undefined) return [-1, bodies];
      bodies.push(...(arithmetic ? inner : [ch === "$" ? text.slice(at + 2, i) : text.slice(at + 1, i)]));
    } else if (quote === '"') {
      if (ch === '"') quote = undefined;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (" \t\r\n;&|<>()".includes(ch)) {
      break;
    }
  }
  return [i, bodies];
}

/** The $( ) and backtick bodies that run when an unquoted heredoc or an arithmetic expression is expanded, those
 *  inside $(( )) too; quotes are plain text there and a backslash escapes. Undefined when one is not closed. */
function textBodies(body: string): string[] | undefined {
  const bodies: string[] = [];
  for (let i = 0; i < body.length; i++) {
    const at = i;
    if (body[i] === "\\") {
      i++;
    } else if (body.startsWith("$(", i) || body[i] === "`") {
      const arithmetic = body.startsWith("$((", i) && arithmeticEnd(body, i + 2) > 0;
      i = body[i] === "$" ? parenEnd(body, i + 2) : backtickEnd(body, i + 1);
      const inner = arithmetic ? textBodies(body.slice(at + 3, i - 1)) : [];
      if (i < 0 || inner === undefined) return undefined;
      bodies.push(...(arithmetic ? inner : [body[at] === "$" ? body.slice(at + 2, i) : body.slice(at + 1, i)]));
    }
  }
  return bodies;
}

/** An unquoted heredoc's text as the shell hands it on: each $( ), $(( )) and backtick output unknown, and a
 *  backslash before $, `, \\ or a newline removed. */
function expanded(body: string): string {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const at = i;
    if (body[i] === "\\" && ["$", "`", "\\", "\n"].includes(body[i + 1] ?? "")) {
      out += body[i + 1] === "\n" ? "" : body[i + 1];
      i++;
    } else if (body.startsWith("$(", i) || body[i] === "`") {
      i = body[i] === "$" ? parenEnd(body, i + 2) : backtickEnd(body, i + 1);
      if (i < 0) return body.slice(0, at) + SUBSTITUTED;
      out += SUBSTITUTED;
    } else {
      out += body[i];
    }
  }
  return out;
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

const arithmeticEnds = new Map<string, Map<number, number>>();

/** For a (( whose second ( is at `start`, the index of the last ) of the )) that closes it, past quotes, backticks and
 *  $( ). -1 when the ) matching that ( is not followed by another: bash and zsh then read ( ( … ) … ) as commands. */
function arithmeticEnd(text: string, start: number): number {
  let ends = arithmeticEnds.get(text);
  if (ends === undefined) {
    arithmeticEnds.clear(); // kept for the last text only: the scans nest, and each would otherwise be repeated
    ends = new Map<number, number>();
    arithmeticEnds.set(text, ends);
  }
  let end = ends.get(start);
  if (end === undefined) {
    end = scanArithmetic(text, start);
    ends.set(start, end);
  }
  return end;
}

function scanArithmetic(text: string, start: number): number {
  let depth = 0;
  let quote: string | undefined;
  for (let i = start; i < text.length; i++) {
    const ch = text[i] as string;
    if (quote === "'") {
      if (ch === "'") quote = undefined;
    } else if (ch === "\\") {
      i++;
    } else if (ch === "`" && backtickEnd(text, i + 1) > 0) {
      i = backtickEnd(text, i + 1);
    } else if (text.startsWith("$(", i)) {
      i = parenEnd(text, i + 2);
      if (i < 0) return -1;
    } else if (quote === '"') {
      if (ch === '"') quote = undefined;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "(" || ch === ")") {
      depth += ch === "(" ? 1 : -1;
      if (depth === 0) return text[i + 1] === ")" ? i + 1 : -1;
    }
  }
  return -1;
}

/** The index of the ) that closes a ( just before `start`, past quotes, backticks, nested parentheses, the ) after a
 *  case pattern, comments and heredoc bodies; for a ((, the end of its arithmetic when it is one. -1 if none closes it. */
function parenEnd(text: string, start: number): number {
  const arithmetic = text.slice(start - 1, start + 1) === "((" ? arithmeticEnd(text, start) : -1;
  if (arithmetic > 0) return arithmetic;
  let depth = 1;
  let quote: string | undefined;
  const cases: string[] = [];
  const heredocs: [string, boolean][] = [];
  let word = "";
  let last = "";
  let atStart = true;
  for (let i = start; i < text.length; i++) {
    const ch = text[i] as string;
    if (quote === "'") {
      if (ch === "'") quote = undefined;
    } else if (ch === "\\") {
      i++;
      word += "\0";
    } else if (ch === "`" && backtickEnd(text, i + 1) > 0) {
      i = backtickEnd(text, i + 1);
      word += "\0";
    } else if (quote === '"') {
      if (ch === '"') quote = undefined;
      else if (text.startsWith("$(", i)) {
        i = parenEnd(text, i + 2);
        if (i < 0) return -1;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      word += "\0";
    } else if (
      text.startsWith("((", i) && (atStart || last === "for") &&
      (word === "" || word === "for" || LEADING_WORDS.has(word)) && arithmeticEnd(text, i + 1) > 0
    ) {
      // An arithmetic command inside: a # or << there is arithmetic, not a comment or heredoc.
      i = arithmeticEnd(text, i + 1);
      word += "\0";
    } else if (text.startsWith("$((", i) && arithmeticEnd(text, i + 2) > 0) {
      i = arithmeticEnd(text, i + 2); // likewise an arithmetic expansion
      word += "\0";
    } else if (ch === "#" && word === "") {
      i = text.indexOf("\n", i) - 1; // a comment runs to the end of its line
      if (i < 0) return -1;
    } else if (!" \t\r\n;&|()<>".includes(ch)) {
      word += ch;
    } else {
      if (word !== "") {
        atStart = caseWord(word, atStart, cases);
        last = word;
      }
      word = "";
      if (text.startsWith("<<<", i)) {
        i += 2;
      } else if (text.startsWith("<<", i)) {
        const strip = text.startsWith("<<-", i);
        const [delimiter, wordStop] = readWord(text, i + (strip ? 3 : 2));
        heredocs.push([delimiter, strip]);
        i = wordStop - 1;
      } else if (cases.at(-1) === "pattern" && (ch === "(" || ch === ")")) {
        if (ch === ")") [cases[cases.length - 1], atStart] = ["body", true]; // ( may open a pattern
      } else if (ch === "(" || ch === ")") {
        depth += ch === "(" ? 1 : -1;
        if (depth === 0) return i;
      }
      if (";&|\n(".includes(ch)) atStart = true;
      if (cases.at(-1) === "body" && (text.startsWith(";;", i) || text.startsWith(";&", i))) {
        cases[cases.length - 1] = "pattern";
        i += text.startsWith(";;&", i) ? 2 : 1;
      }
      if (ch === "\n") i = heredocsEnd(text, i, heredocs);
    }
  }
  return -1;
}

/** Past the bodies of the heredocs pending at the newline at `i`: the index of the last body's delimiter line end. */
function heredocsEnd(text: string, start: number, heredocs: [string, boolean][]): number {
  let i = start;
  while (heredocs.length > 0) {
    const [delimiter, stripTabs] = heredocs.shift() as [string, boolean];
    while (i + 1 < text.length) {
      const end = text.indexOf("\n", i + 1);
      const line = end < 0 ? text.slice(i + 1) : text.slice(i + 1, end);
      i = end < 0 ? text.length - 1 : end;
      if ((stripTabs ? line.replace(/^\t+/, "") : line) === delimiter) break;
    }
  }
  return i;
}

/** Follow a word through the case commands open in a $( ): case opens one, in starts its patterns, esac ends it;
 *  whether the next word starts a command. */
function caseWord(word: string, atStart: boolean, cases: string[]): boolean {
  if (word === "case" && atStart) cases.push("head");
  else if (word === "in" && cases.at(-1) === "head") cases[cases.length - 1] = "pattern";
  else if (word === "esac" && cases.length > 0 && cases.at(-1) !== "head") cases.pop();
  else return LEADING_WORDS.has(word);
  return false;
}

/** An arithmetic for header's start, test and step, split at the ; outside any substitution; undefined if not three. */
function arithmeticParts(text: string): string[] | undefined {
  const parts: string[] = [];
  let begin = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.startsWith("$(", i) || text[i] === "`") {
      i = text[i] === "$" ? parenEnd(text, i + 2) : backtickEnd(text, i + 1);
      if (i < 0) return undefined;
    } else if (text[i] === ";") {
      parts.push(text.slice(begin, i));
      begin = i + 1;
    }
  }
  return parts.length === 2 ? [...parts, text.slice(begin)] : undefined;
}

/** The index of the backtick that closes one just before `start`; -1 when none does. */
function backtickEnd(text: string, start: number): number {
  for (let i = start; i < text.length; i += text[i] === "\\" ? 2 : 1) if (text[i] === "`") return i;
  return -1;
}

/** One redirection, in the order written: the fd it sets and what that fd then holds, a file or heredoc, nothing
 *  (/dev/null or a closed fd), or the fd it copies. */
/** An fd and what it then holds; a heredoc or here-string also carries its text, for a shell or tool reading stdin. */
type Redirection = [fd: number, value: "file" | "null" | number, fed?: { text?: string }];

/** One simple command, or a marker around a subshell, substitution, function body or case arm. */
interface Item {
  kind: "cmd" | "(" | "$(" | ")" | "func" | "case" | "arm" | "esac";
  /** A command's words, or the name a function marker defines. */
  argv: string[];
  /** The operator before: "" first, "&&", "||", "|", "&", or ";" for any other separator. */
  before: string;
  after: string;
  io: Redirection[];
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
  private io: Redirection[] = [];
  /** Each heredoc still to read: its delimiter, whether tabs are stripped, where an unquoted one's substitutions go,
   *  and where its text goes. */
  private readonly heredocs: [string, boolean, [number, string] | undefined, { text?: string }][] = [];
  private failed = false;
  /** Where in the text each simple command ends. */
  readonly ends = new Map<Item, number>();
  private readonly cases: string[] = [];
  private readonly text: string;
  private readonly depth: number;
  /** How deep the reader is inside a ${…} parameter, and where the word's last unquoted $ is. */
  private param = 0;
  private dollar = -1;

  constructor(text: string, depth = 0) {
    this.text = text;
    this.depth = depth;
  }

  /** The items, or undefined when the command can't be read the way the shell reads it. */
  read(): Item[] | undefined {
    if (this.depth > MAX_DEPTH || this.text.length > MAX_CHARS) return undefined;
    for (; this.i < this.text.length; this.i++) {
      if (!(this.quote !== undefined ? this.quoted() : this.unquoted()) || this.failed) return undefined;
    }
    if (this.quote !== undefined) return undefined;
    this.endCommand("");
    return this.failed ? undefined : this.items;
  }

  private marker(kind: Item["kind"], before = "", argv: string[] = []): void {
    this.items.push({ kind, argv, before, after: "", io: [] });
  }

  private quoted(): boolean {
    const ch = this.text[this.i] as string;
    if (ch === this.quote) {
      this.quote = undefined;
    } else if (this.quote === '"' && (ch === "$" || ch === "`")) {
      const found = this.substitution();
      if (found !== undefined) return found;
      this.word += ch;
    } else if (this.quote === '"' && ch === "\\" && ["$", "`", '"', "\\", "\n"].includes(this.text[this.i + 1] ?? "")) {
      // Only these lose the backslash in double quotes; before anything else it stays.
      const next = this.text[++this.i] as string;
      this.word += next === "\n" ? "" : this.literal(next);
    } else {
      this.word += this.literal(ch);
    }
    return true;
  }

  /** A quoted or escaped character as it goes into the word: a ~ where an unquoted one would be expanded is marked, as
   *  one the shell leaves. */
  private literal(ch: string): string {
    return ch === "~" && this.tildePlace() ? LITERAL_TILDE : ch;
  }

  /** Whether a ~ here starts a tilde prefix: at the start of the word, or of an assignment's value or a part of it after
   *  a :. */
  private tildePlace(): boolean {
    return this.word === "" || ((this.word.endsWith("=") || this.word.endsWith(":")) && /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(this.word));
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
      this.word += this.literal(text[++this.i] as string);
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
    } else if (ch === "~" && this.inWord && this.word === "") {
      this.word += SUBSTITUTED; // after empty quotes: bash leaves the ~, zsh expands it
    } else {
      this.word += this.mark(ch);
      this.inWord = true;
    }
    return true;
  }

  /** An unquoted character as it goes into the word: a { , or } bash may brace-expand is marked, unless it is part
   *  of a ${…} parameter. */
  private mark(ch: string): string {
    if (ch === "{" && (this.param > 0 || (this.dollar >= 0 && this.dollar === this.word.length - 1))) this.param++;
    else if (ch === "}" && this.param > 0) this.param--;
    else if (ch === "$") this.dollar = this.word.length;
    else if (this.param === 0) return BRACE_MARKS[ch] ?? ch;
    return ch;
  }

  /** Read a $( ), $(( )), backtick or <( ) substitution starting here; undefined when none starts here. */
  private substitution(): boolean | undefined {
    const { text, i } = this;
    let end: number;
    let inner: string | undefined;
    if (text.startsWith("$((", i) && arithmeticEnd(text, i + 2) > 0) {
      end = arithmeticEnd(text, i + 2);
      const bodies = textBodies(text.slice(i + 3, end - 1)); // what its $( ) run
      if (bodies === undefined) return false;
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : undefined);
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
    if (this.inWord && this.text.startsWith("((", this.i) && (this.word === "for" || LEADING_WORDS.has(this.word))) {
      this.endWord(); // a reserved word ends at a (, as in for((…)) or while((…))
    }
    const lead = this.argv.at(-1) === "for" ? this.argv.slice(0, -1) : this.argv;
    const close = this.text.startsWith("((", this.i) ? arithmeticEnd(this.text, this.i + 1) : -1;
    if (close > 0 && !this.inWord && lead.every((w) => LEADING_WORDS.has(w))) {
      // An arithmetic command, or a for loop's (( )) header, is one word, and runs only its substitutions; a header's
      // step runs after each pass of the body, so the walker runs that part there.
      const inner = this.text.slice(this.i + 2, close - 1);
      const parts = this.argv.at(-1) === "for" ? arithmeticParts(inner) : undefined;
      const bodies = textBodies(parts === undefined ? inner : parts.slice(0, 2).join(";"));
      if (bodies === undefined || (parts !== undefined && textBodies(parts[2] as string) === undefined)) {
        this.failed = true;
        return;
      }
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : undefined);
      this.argv.push(this.text.slice(this.i, close + 1));
      this.i = close;
      return;
    }
    const rest = this.text.slice(this.i + 1).trimStart();
    const name = this.inWord ? this.word : (this.argv.at(-1) ?? "");
    const head = this.inWord ? this.argv : this.argv.slice(0, -1);
    const leading = head.at(-1) === "function" ? head.slice(0, -1) : head;
    if (rest.startsWith(")") && leading.every((w) => LEADING_WORDS.has(w)) && /^[\w.:-]+$/.test(name)) {
      // `name()` or `name ()` defines a function; the body that follows runs only when it's called.
      this.argv = leading;
      this.word = "";
      this.inWord = false;
      this.flush(); // a then, do or { before it still opens its compound
      this.marker("func", this.before, [name]);
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

  /** A redirection's operator, an fd number written against it, and its target are not arguments; it is kept as the fd
   *  it sets and what that fd then holds. */
  private redirect(): void {
    const { text } = this;
    const fd = this.inWord && /^\d+$/.test(this.word) && text[this.i] !== "&" ? Number(this.word) : undefined;
    if (fd === undefined) this.endWord();
    this.word = "";
    this.inWord = false;
    const op = (/^(?:&>>?|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>)/.exec(text.slice(this.i)) as RegExpExecArray)[0];
    let [target, end] = readWord(text, this.i + op.length);
    const fed: { text?: string } = {}; // a heredoc or here-string feeds its text
    if (op === "<<" || op === "<<-") {
      // An unquoted delimiter leaves the body's substitutions to run, with the command, before it does.
      const quoted = /['"\\]/.test(text.slice(this.i + op.length, end));
      this.heredocs.push([target, op === "<<-", quoted ? undefined : this.substitutionsAt(), fed]);
    } else {
      // A target's substitutions run with the command too, such as a here-string's "$(curl …)".
      const start = this.i + op.length;
      const [wordStop, bodies] = wordEnd(text, start);
      if (wordStop < 0) {
        this.failed = true;
        return;
      }
      end = wordStop;
      this.substitute(bodies, bodies.length > 0 ? this.substitutionsAt() : undefined);
      const fedWords = op === "<<<" ? words(text.slice(start, end)) : [];
      if (fedWords.length > 0) fed.text = fedWords.join(" ");
    }
    const to = fd ?? (op.startsWith("<") ? 0 : 1);
    if ((op === "<&" || op === ">&") && /^(\d+-?|-)$/.test(target)) {
      this.io.push([to, target === "-" ? "null" : Number(target.replace(/-$/, ""))]);
      // <&N- moves N, which is then closed.
      if (/^\d+-$/.test(target)) this.io.push([Number(target.slice(0, -1)), "null"]);
    } else if (op.startsWith("<<")) {
      this.io.push([to, "file", fed]);
    } else {
      this.io.push([to, target === "/dev/null" ? "null" : "file"]);
      if (op.startsWith("&") || (op === ">&" && fd === undefined)) this.io.push([2, 1]); // &> and >&file send stderr there too
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
    if (pair === "|&") this.io.push([2, 1]); // |& also pipes stderr, after the command's own redirections
    if (pair === "&&" || pair === "||" || pair === "|&") {
      this.endCommand(pair === "|&" ? "|" : pair);
      this.i++;
    } else {
      this.endCommand(ch === "&" || ch === "|" ? ch : ";");
    }
    if (ch === "\n") this.skipHeredocs();
  }

  /** A heredoc's body starts on the next line and is input, not commands, but for the substitutions in one whose
   *  delimiter is unquoted, which run with its command. */
  private skipHeredocs(): void {
    const { text } = this;
    let shift = 0;
    while (this.heredocs.length > 0) {
      const [delimiter, stripTabs, at, fed] = this.heredocs.shift() as [string, boolean, [number, string] | undefined, { text?: string }];
      const lines: string[] = [];
      while (this.i + 1 < text.length) {
        const end = text.indexOf("\n", this.i + 1);
        const raw = end < 0 ? text.slice(this.i + 1) : text.slice(this.i + 1, end);
        const line = stripTabs ? raw.replace(/^\t+/, "") : raw;
        this.i = end < 0 ? text.length - 1 : end;
        if (line === delimiter) break;
        lines.push(line);
      }
      const body = lines.join("\n");
      fed.text = at === undefined ? body : expanded(body);
      const bodies = at === undefined ? [] : textBodies(body);
      if (bodies === undefined) {
        this.failed = true;
        return;
      }
      shift += this.substitute(bodies, at === undefined ? undefined : [at[0] + shift, at[1]]);
    }
  }

  /** Where substitutions that run with the current command go: after the reserved words that lead it, so they run
   *  only when it does; [index in items, operator before]. */
  private substitutionsAt(): [number, string] {
    this.flushLeading();
    return [this.items.length, this.before];
  }

  /** Insert each body as a substitution at `at` [index in items, operator before]; how many items that added. */
  private substitute(bodies: string[], at: [number, string] | undefined): number {
    const added: Item[] = [];
    for (const body of bodies) {
      const items = new Lexer(body, this.depth + 1).read();
      if (items === undefined) {
        this.failed = true;
        return 0;
      }
      added.push({ kind: "$(", argv: [], before: at?.[1] ?? "", after: "", io: [] }, ...items, { kind: ")", argv: [], before: "", after: "", io: [] });
    }
    if (at !== undefined && added.length > 0) this.items.splice(at[0], 0, ...added);
    return added.length;
  }

  private endWord(): void {
    if (!this.inWord) return;
    const marked = this.word;
    const word = unmark(marked);
    const state = this.cases.at(-1);
    this.word = "";
    this.inWord = false;
    this.param = 0;
    this.dollar = -1;
    const atStart = this.argv.every((w) => LEADING_WORDS.has(w));
    // bash's time -p sets only how the timing is printed; zsh runs -p as the command.
    if (word === "-p" && this.argv.at(-1) === "time" && atStart) return;
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
    } else if (word === "do" && this.loopHeader()) {
      this.endCommand(";"); // `for x do` reads as `for x; do`
      this.argv.push(word);
    } else if (isAssignment(word) && this.argv.every((w) => isAssignment(w) || LEADING_WORDS.has(w))) {
      this.argv.push(word); // an assignment before the command is not brace-expanded
    } else {
      const expanded = braces(marked).map(unmark);
      this.argv.push(...(expanded.length === 1 ? expanded : expanded.filter((w) => w !== ""))); // an empty result is no word
    }
  }

  /** Whether the words so far end in a for or select header with no `in` list, which a `do` may follow at once. */
  private loopHeader(): boolean {
    let n = 0;
    while (n < this.argv.length && LEADING_WORDS.has(this.argv[n] as string)) n++;
    const core = this.argv.slice(n);
    return core.length === 2 && (core[0] === "for" || core[0] === "select") && core[1] !== "in";
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
    this.items.push({ kind: "cmd", argv: this.argv.slice(0, n), before: this.before, after: "", io: [] });
    this.argv = this.argv.slice(n);
    this.before = "";
  }

  /** Emit the reserved words read so far ahead of the compound command they lead. */
  private flush(): void {
    if (this.argv.length === 0) return;
    this.items.push({ kind: "cmd", argv: this.argv, before: this.before, after: "", io: this.io });
    this.argv = [];
    this.io = [];
    this.before = "";
  }

  private endCommand(after: string): void {
    this.endWord();
    if (this.argv.length > 0) {
      const item: Item = { kind: "cmd", argv: this.argv, before: this.before, after, io: this.io };
      this.items.push(item);
      this.ends.set(item, this.i);
      this.before = after;
    } else {
      const last = this.items.at(-1);
      if (last !== undefined && (last.kind === ")" || last.kind === "esac") && (after !== "" || this.io.length > 0)) {
        // A pipe, redirection or & after a subshell or case applies to the whole compound.
        last.after = after;
        last.io = this.io;
      }
      if (after !== ";" && after !== "") this.before = after;
    }
    this.argv = [];
    this.io = [];
  }
}

/** A word's brace expansions, as bash makes them from its marked { , }: a {a,b} list or a {1..3} or {a..c} sequence,
 *  nested and in order; a brace that is neither is kept as written. */
function braces(word: string): string[] {
  for (let start = word.indexOf("\x01"); start >= 0; start = word.indexOf("\x01", start + 1)) {
    let depth = 0;
    let end = -1;
    const commas: number[] = [];
    for (let j = start; j < word.length && end < 0; j++) {
      if (word[j] === "\x01") depth++;
      else if (word[j] === "\x03") depth--;
      if (word[j] === "\x02" && depth === 1) commas.push(j);
      if (depth === 0) end = j;
    }
    if (end < 0) continue;
    const bounds = [start, ...commas, end];
    const parts = commas.length > 0
      ? bounds.slice(1).map((bound, k) => word.slice((bounds[k] as number) + 1, bound))
      : sequence(word.slice(start + 1, end));
    if (parts === undefined) continue;
    const tails = braces(word.slice(end + 1));
    const out: string[] = [];
    for (const whole of parts) {
      for (const part of braces(whole)) {
        for (const tail of tails) {
          if (out.length >= MAX_WORDS) return out;
          out.push(word.slice(0, start) + part + tail);
        }
      }
    }
    return out;
  }
  return [word];
}

/** The words a {x..y} or {x..y..step} sequence of integers or letters makes, as bash 5 makes them; undefined for any
 *  other brace. */
function sequence(body: string): string[] | undefined {
  const match = /^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?$/.exec(body);
  if (match === null) return undefined;
  const [, first = "", last = "", by] = match;
  const letters = /^[A-Za-z]$/.test(first);
  if (letters !== /^[A-Za-z]$/.test(last)) return undefined;
  const step = Math.abs(Number(by ?? 1)) || 1;
  const a = letters ? first.charCodeAt(0) : Number(first);
  const b = letters ? last.charCodeAt(0) : Number(last);
  const width = !letters && (/^-?0\d/.test(first) || /^-?0\d/.test(last)) ? Math.max(first.length, last.length) : 0;
  const out: string[] = [];
  for (let n = a; (b >= a ? n <= b : n >= b) && out.length < MAX_WORDS; n += b >= a ? step : -step) {
    const digits = String(Math.abs(n)).padStart(width - (n < 0 ? 1 : 0), "0");
    out.push(letters ? String.fromCharCode(n) : n < 0 ? `-${digits}` : digits);
  }
  return out;
}

/** A string's words, split as the shell splits them, without its operators. */
function words(text: string): string[] {
  return (new Lexer(text).read() ?? []).filter((item) => item.kind === "cmd").flatMap((item) => item.argv);
}

/** A variable as the command sees it: set or unset in the command, else unknown when the hook's environment has it,
 *  whose values never reach a host or a lookup. */
function envValue(env: Env, processEnv: Record<string, string | undefined>, key: string): string {
  if (key in env) return env[key] as string;
  if (UNKNOWN_ENV in env) return SUBSTITUTED;
  return CLEAN_ENV in env || !processEnv[key] ? "" : SUBSTITUTED;
}

/** NAME=value, or NAME+=value, which appends to the value. */
function isAssignment(token: string): boolean {
  const eq = token.indexOf("=");
  return eq > 0 && /^[A-Za-z_][A-Za-z0-9_]*\+?$/.test(token.slice(0, eq));
}

/** The words with each leading NAME+=value made NAME=value: appended to the earlier or shell value in a command of
 *  only assignments, and unknown before a command, where bash 3 appends to nothing and bash 5 and zsh to that value. */
function appends(argv: string[], shell: Shell): string[] {
  const given = new Map<string, string>();
  const out = [...argv];
  const bare = argv.every(isAssignment);
  for (let i = 0; i < out.length && isAssignment(out[i] as string); i++) {
    const word = out[i] as string;
    let name = word.slice(0, word.indexOf("="));
    let value = word.slice(word.indexOf("=") + 1);
    if (name.endsWith("+")) {
      name = name.slice(0, -1);
      value = (bare ? given.get(name) ?? variable(shell, name)[0] ?? "" : SUBSTITUTED) + value;
      out[i] = `${name}=${value}`;
    }
    given.set(name, value);
  }
  return out;
}

/** A program as it's matched: its file name in lower case, without a Windows .exe. */
function programName(token: string): string {
  const name = (token.split(/[\\/]/).pop() ?? "").toLowerCase();
  return name.endsWith(".exe") ? name.slice(0, -4) : name;
}

/** A cd's option letters and its folders: options come first, -- ends them, and a lone - is a folder. */
function cdWords(args: string[]): [string, string[]] {
  const folders = [...args];
  let letters = "";
  while (folders[0]?.startsWith("-") && folders[0] !== "-") {
    const option = folders.shift() as string;
    if (option === "--") break;
    letters += option.slice(1);
  }
  return [letters, folders];
}

/** [the folder a cd lands in from `cwd`, the status it leaves]: 0 where it lands, the old folder and 1 when every
 *  shell rejects it; undefined for either when that is not known, as for a folder not there now. */
function cdTarget(args: string[], cwd: string | undefined, shell: Shell, given: Env): [string | undefined, number | undefined] {
  const [letters, folders] = cdWords(args);
  if (/[^LPeqs@0-9]/.test(letters)) return [cwd, 1]; // every shell rejects the cd and stays
  // Bash 5 rejects a second folder, bash 3 ignores it and zsh substitutes it; -e, -q, -s vary.
  if (folders.length > 1 || /[^LP]/.test(letters)) return [undefined, undefined];
  const path = cdPath(folders, shell, given);
  if (path === undefined) return [undefined, undefined];
  // Bash follows the last of -L and -P, zsh any -P; -P resolves each link, so a later `cd ..` leaves the real folder.
  const last = letters === "" ? "L" : letters[Math.max(letters.lastIndexOf("L"), letters.lastIndexOf("P"))];
  const landed = new Set([last === "P", letters.includes("P")].map((physical) => moveTo(cwd, path, physical)));
  const target = isAbsolute(path) ? path : cwd === undefined || path === "-" ? undefined : join(cwd, path);
  if (target !== undefined && isFile(target)) return [cwd, 1]; // a file is no folder to land in
  // The folder is read after the command ran, so one the command names elsewhere may have been made or removed by it.
  if (target === undefined || shell.names.has(basename(normalize(target))) || landed.size > 1) return [undefined, undefined];
  const folder = [...landed][0];
  return folder === undefined ? [undefined, undefined] : [folder, 0];
}

/** A word with a leading ~ or ~/ made the shell's HOME, which the shell reads before a VAR=value in front of the command
 *  applies; marked unknown when that HOME, or the account a ~user names, is not known. A quoted ~ stays. */
function tilde(word: string, shell: Shell): string {
  if (word.startsWith(LITERAL_TILDE)) return `~${word.slice(1)}`;
  if (!word.startsWith("~")) return word;
  const head = word.split("/")[0] as string;
  const home = head === "~" ? variable(shell, "HOME")[0] : undefined;
  const known = !!home && !home.includes("$") && !home.includes(SUBSTITUTED);
  return (known ? home : SUBSTITUTED) + word.slice(head.length);
}

/** A NAME=value with each ~ the shell expands in the value made a folder: the one it starts with, and any after a :,
 *  as for a word that starts with ~. */
function assignedTilde(word: string, shell: Shell): string {
  const at = word.indexOf("=");
  return `${word.slice(0, at + 1)}${word.slice(at + 1).split(":").map((part) => tilde(part, shell)).join(":")}`;
}

const READERS: readonly string[] = ["read", "mapfile", "readarray", "getopts", "printf"];

/** The variables a read, mapfile, getopts or printf -v may set, which hold what it read and so are unknown. Every word
 *  that could name one is taken, which at worst leaves an extra name unknown. */
function readNames(name: string, args: string[]): Set<string> {
  if (name === "printf") {
    return new Set(args.flatMap((a, i) => (a.startsWith("-v") ? [a.slice(2) || (args[i + 1] ?? "")] : [])).filter(Boolean));
  }
  if (name === "getopts") return new Set([...args.slice(1, 2), "OPTARG", "OPTIND"]);
  const names = args.map((a) => a.split("?")[0] as string).filter((n) => isAssignment(`${n}=`));
  return new Set([...names, name === "read" ? "REPLY" : "MAPFILE"]);
}

/** Where a cd goes as the shell expands its folder, HOME for none; undefined when not known, including a relative
 *  folder that CDPATH may find somewhere else first. */
function cdPath(folders: string[], shell: Shell, given: Env): string | undefined {
  const known = (value: string | undefined): value is string => !!value && !value.includes("$") && !value.includes(SUBSTITUTED);
  const folder = folders[0];
  if (folder === undefined) {
    const home = "HOME" in given ? given.HOME : variable(shell, "HOME")[0];
    return known(home) ? home : undefined;
  }
  const cdpath = "CDPATH" in given ? given.CDPATH : variable(shell, "CDPATH")[0];
  const searched = !!cdpath && folder !== "-" && !folder.startsWith("/") && !folder.startsWith("~") &&
    ![".", ".."].includes(folder.split("/")[0] as string);
  if (searched || [..."$*?[", SUBSTITUTED].some((c) => folder.includes(c))) return undefined;
  return folder.startsWith("~") ? `./${folder}` : folder;
}

/** Whether `path` is there and is not a folder. */
function isFile(path: string): boolean {
  try {
    return !statSync(path).isDirectory();
  } catch {
    return false;
  }
}

const LOOKS: ReadonlySet<string> = new Set(["cd", "pushd", "popd", "dirs", "[", "[[", "test", "ls", "echo", "printf", "stat",
  "cat", "wc", "head", "tail", "grep", "diff", "file", "du", "readlink", "realpath", "basename", "dirname"]);
const MAKES_PARENTS: ReadonlySet<string> = new Set(["mkdir", "install", "git", "unzip"]);

/** The folders the commands in `list` name, as path segments: each word's last, or every one for a command that may
 *  make parent folders (mkdir -p); a command that only looks, such as cd, test or wc, names none. */
function namedSegments(list: Item[]): Set<string> {
  const names = new Set<string>();
  for (const item of list) {
    const argv = item.kind === "cmd" ? item.argv.filter((w) => !KEYWORDS.has(w)) : [];
    const first = argv.find((w) => !isAssignment(w));
    const name = first === undefined ? undefined : programName(first);
    if (name === undefined || LOOKS.has(name)) continue;
    for (const word of argv) {
      const segments = word.split("/").filter((segment) => segment !== "");
      for (const segment of MAKES_PARENTS.has(name) ? segments : segments.slice(-1)) names.add(segment);
    }
  }
  return names;
}

/** The folder a cd to `path` lands in from `cwd`, links resolved when `physical`; undefined when `cwd` is not known,
 *  for `cd -`, or when the folder is not there now, so the cd may have failed. */
function moveTo(cwd: string | undefined, path: string, physical: boolean): string | undefined {
  const target = expandHome(path);
  // Joined as written, as chdir reads it: a link before a `..` is followed, and a missing folder there fails.
  const folder = isAbsolute(target) ? target : cwd === undefined || target === "-" ? undefined
    : cwd.endsWith(sep) ? cwd + target : cwd + sep + target;
  try {
    if (folder === undefined || !statSync(folder).isDirectory()) return undefined;
    // The native realpath, since the other one drops a `..` before resolving the link ahead of it.
    const landed = physical ? realpathSync.native(folder) : normalize(folder);
    return statSync(landed).isDirectory() ? landed : undefined;
  } catch {
    return undefined;
  }
}

interface Program {
  name?: string;
  args: string[];
  env: Env;
  cwd: string | undefined;
  otherUser: boolean;
  /** Whether a wrapper that is a program of its own runs it, so a builtin's name is a program too. */
  external: boolean;
}

/** The program a simple command runs, its args, inline VAR=value settings and folder, past assignments and wrappers. */
function program(input: string[], start: string | undefined): Program {
  const argv = [...input];
  const out: Program = { args: [], env: {}, cwd: start, otherUser: false, external: false };
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
      out.external ||= !["command", "builtin", "exec"].includes(wrapper);
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
  if ((WRAPPER_CHDIR[wrapper] ?? []).includes(name)) out.cwd = moveTo(out.cwd, value, true); // a chdir: links resolve
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

/** Whether a pipeline runs after its && or ||, given the last literal true (0) or false (1). */
function follows(before: string, status: number | undefined): boolean {
  return !((before === "&&" && status === 1) || (before === "||" && status === 0));
}

/** A shell variable: its value, undefined once unset, and whether it is exported, undefined when that is not known. */
type Variable = [value: string | undefined, exported: boolean | Lent | undefined];
/** The export flags of a function call's VAR=value, kept by an assignment, unset or local declaration in the body: the
 *  second when the name had a value before the call, which an unset in the body brings back in bash but not in zsh. */
const LENT = ["lent", "lent over a value"] as const;
type Lent = (typeof LENT)[number];

function isLent(exported: Variable[1]): exported is Lent {
  return exported === LENT[0] || exported === LENT[1];
}

/** The folder, variables and defined functions at one point, to return to. */
type Snapshot = [cwd: string | undefined, vars: Record<string, Variable>, functions: Map<string, [Item[], boolean]>];

/** A pipeline being read: whether it runs, and the operator and status before it, which settle the status it leaves. */
interface Pipeline {
  before: string;
  prior: number | undefined;
  runs: Maybe;
  negate: boolean;
  /** A `!` or a function name was read, and the command it leads is still to come. */
  leading: boolean;
}

/** What a return, exit, break or continue may change in a frame, to put back after a subshell. */
type JumpMarks = Pick<Frame, "runs" | "alive" | "left" | "jumped" | "repeats">;

/** The jump marks of the open frames, and whether the shell itself still runs. */
type Liveness = [frames: JumpMarks[], live: Maybe];

interface Frame {
  kind: string;
  base: Maybe;
  runs: Maybe;
  /** Whether the current body runs, as far as the compound itself runs. */
  rel: Maybe;
  /** False once a return, exit, break or continue certainly cut the compound short, undefined when it may have. */
  alive: Maybe;
  decided: Maybe;
  /** The state before a body that only maybe runs, returned to when it ends. */
  saved?: Snapshot;
  /** The state when the frame opened, restored when a subshell closes. */
  state: Snapshot;
  status: number | undefined;
  /** Where the frame's calls start in the walk's list, so a pipe or redirection around it can reach them. */
  calls: number;
  pipedIn: boolean;
  /** Piped or backgrounded at its end, so a subshell from the start. */
  pipedOut: boolean;
  /** The pipeline and list around the compound, resumed when it closes. */
  outer: [Pipeline, Snapshot];
  /** The function this compound is the body of. */
  defines?: string;
  /** Where the compound starts in the walk's items, and the item that starts it, kept for a function's calls. */
  head: [number, Item];
  /** Whether a for loop's word list runs the body: at least once, never, or not known. */
  iterates: Maybe;
  /** A loop that may run its body again. */
  repeats: boolean;
  /** A loop whose test never fails, and an arithmetic for's counter. */
  forever: boolean;
  /** A continue reached the loop's next pass: surely, maybe (undefined) or not. */
  continued: Maybe;
  counter?: string;
  /** The status a return, exit, break or continue left the compound with; undefined inside when not known. */
  left?: [number | undefined];
  /** Reached only through an && or || after a status that is not known. */
  doubt: boolean;
  /** The state when a return, exit, break or continue that may not run first cut the compound short. */
  jumped?: Snapshot;
  /** What may or may not have changed inside, made unknown when the compound ends. */
  unsure: Set<string>;
  outside: Liveness;
  /** In an if, while or until condition, where set -e is ignored. */
  cond: boolean;
  /** Run in an && or || list but as its last command, or behind a !, so set -e is ignored inside. */
  exempt: boolean;
}

interface Shell {
  cwd: string | undefined;
  vars: Record<string, Variable>;
  status: number | undefined;
  frames: Frame[];
  /** The function the definition being read names. */
  function: string | undefined;
  start: Snapshot;
  processEnv: Record<string, string | undefined>;
  calls: Call[];
  /** Whether the compound the current command opens is piped into. */
  openingPipe: boolean;
  /** The compound the current command's closing keyword closed. */
  closed?: Frame;
  pipe: Pipeline;
  /** Each defined function's body, and whether its definition may not have run. */
  functions: Map<string, [Item[], boolean]>;
  callsLeft: number;
  /** The items being walked, and the one being read. */
  items: Item[];
  at: number;
  /** Whether commands outside every compound still run, after an exit that did or may have. */
  live: Maybe;
  /** Where the frames of the function being run start, when one is. */
  floor: number | undefined;
  /** The positional parameters, undefined when not known. */
  args: string[] | undefined;
  /** The path segments the walk's commands name, other than those that only look at a folder. */
  names: Set<string>;
  /** The names declared local in each function call being walked, put back when it returns. */
  scoped: Set<string>[];
  /** What follows the end of each compound in `items`, by where it opens. */
  ends: Map<string, [string, number]>;
  /** How many function calls being walked run with set -e ignored. */
  exempt: number;
}

/** The pipes and redirections around a call at one level: piped in, piped out, and its redirections. */
type Layer = [pipedIn: boolean, pipedOut: boolean, redirections: readonly Redirection[]];

/** One simple command that runs or may run. */
interface Call {
  name: string;
  args: string[];
  env: Env;
  cwd: string | undefined;
  otherUser: boolean;
  /** The pipes and redirections around the call, from its own outward. */
  layers: Layer[];
  /** Whether the call may not have run, so it is never looked up. */
  unsure?: boolean;
}

function runs(shell: Shell): Maybe {
  const top = shell.frames.at(-1);
  return top === undefined ? shell.live : top.runs;
}

function snapshot(shell: Shell): Snapshot {
  return [shell.cwd, { ...shell.vars }, new Map(shell.functions)];
}

/** Undo the cd and variables since `saved`. A subshell also undoes its function definitions; one defined in a body
 *  that may not have run is kept, so its calls are still followed. */
function restore(shell: Shell, saved: Snapshot | undefined, subshell = false): void {
  if (saved === undefined) return;
  shell.cwd = saved[0];
  shell.vars = { ...saved[1] };
  if (subshell) shell.functions = new Map(saved[2]);
}

/** What a cd, assignment, export or unset changed since `saved`: "" for the folder, else each variable. */
function changes(shell: Shell, saved: Snapshot): Set<string> {
  const names = new Set<string>();
  for (const key of new Set([...Object.keys(saved[1]), ...Object.keys(shell.vars)])) {
    const [before, now] = [saved[1][key], shell.vars[key]];
    if (before?.[0] !== now?.[0] || before?.[1] !== now?.[1]) names.add(key);
  }
  if (shell.cwd !== saved[0]) names.add("");
  return names;
}

/** Make what may or may not have changed unknown: the folder, so no config is read from a guessed one, and each
 *  variable, which then reads like a substitution's output. */
function forget(shell: Shell, names: Set<string>): void {
  for (const name of names) {
    if (name === "") shell.cwd = undefined;
    else shell.vars[name] = [SUBSTITUTED, undefined];
  }
}

/** A shell variable; one the shell never set is the hook's own environment's, which is exported. */
function variable(shell: Shell, name: string): Variable {
  const set = shell.vars[name];
  if (set !== undefined) return set;
  if (UNKNOWN_ENV in shell.vars) return [SUBSTITUTED, undefined];
  const inherited = !(CLEAN_ENV in shell.vars) && shell.processEnv[name] !== undefined;
  // Only HOME and CDPATH, which place folders, are read from the hook's environment; any other value stays unknown.
  const value = name === "HOME" || name === "CDPATH" ? shell.processEnv[name] : SUBSTITUTED;
  return [inherited ? value : undefined, inherited];
}

/** The variables a command gets from the shell; one unset or not exported hides the hook's own value, and one that
 *  may or may not be exported reads like a substitution's output. */
function exportedEnv(shell: Shell): Env {
  const env: Env = {};
  for (const [name, [value, exported]] of Object.entries(shell.vars)) {
    env[name] = exported === undefined ? SUBSTITUTED : exported && value !== undefined ? value : "";
  }
  return env;
}

/** Whether a pipeline runs only through an && or || after a status that is not known. */
function doubt(pipe: Pipeline): boolean {
  return pipe.prior === undefined && (pipe.before === "&&" || pipe.before === "||");
}

/** Close the innermost compound command of one of these kinds. */
function pop(frames: Frame[], kinds: readonly string[]): Frame | undefined {
  while (frames.length > 0) {
    const frame = frames.pop() as Frame;
    if (kinds.includes(frame.kind)) return frame;
  }
  return undefined;
}

/** Start a pipeline: whether it runs, and the operator and status before it, which settle the status it leaves. */
function pipeline(before: string, runsHere: Maybe, shell: Shell): void {
  shell.pipe = { before, prior: shell.status, runs: runsHere, negate: false, leading: false };
}

/** Start the pipeline a command or compound begins, unless it continues one after a | or a leading `!`; && and ||
 *  decide whether the whole pipeline runs, and any other operator also starts a list. */
function begin(before: string, shell: Shell): void {
  // A later command of a pipeline sees the status from before it in bash 5 but 0 in bash 3, so only 0 is known.
  if (before === "|") shell.status = shell.pipe.prior === 0 ? 0 : undefined;
  if (before === "|" || shell.pipe.leading) return;
  if (before !== "&&" && before !== "||") shell.start = snapshot(shell);
  pipeline(before, both(runs(shell), follows(before, shell.status)), shell);
}

/** Set the status a finished pipeline leaves: the one before it when it never ran, else its last command's, flipped
 *  by `!`, and unknown when an unknown status let it run and skipping it would have left another. */
function end(shell: Shell): void {
  const { pipe } = shell;
  let status = shell.status;
  if (pipe.runs === false) {
    status = pipe.prior;
  } else {
    if (pipe.negate) status = status === 0 ? 1 : status === 1 ? 0 : undefined;
    const skipped = pipe.before === "&&" ? 1 : pipe.before === "||" ? 0 : undefined;
    if (pipe.prior === undefined && skipped !== undefined && status !== skipped) status = undefined;
  }
  shell.status = status;
}

/** End a pipeline element: the pipeline ends unless a | follows, and a backgrounded list runs in a subshell. */
function finish(after: string, shell: Shell): void {
  if (after !== "|") end(shell);
  if (after === "&") {
    restore(shell, shell.start, true);
    shell.status = 0; // starting a background job succeeds
  }
}

/** Open a compound command, setting the pipeline and list around it aside until it closes; a function's body is only
 *  defined, so it never runs here. `head` is the item that starts it, kept for a function's calls. */
function openFrame(kind: string, runsHere: Maybe, shell: Shell, head: Item): void {
  const name = kind === "$(" ? undefined : shell.function;
  let value = runsHere;
  if (name !== undefined) {
    value = false;
    shell.function = undefined;
  }
  if (kind !== "$(") shell.pipe.leading = false; // a substitution runs inside the command that a leading `!` still awaits
  if (shell.frames.length >= MAX_NESTING) throw new Error("nested too deep"); // transferOf catches it
  shell.frames.push({
    kind, base: value, runs: value, rel: true, alive: true, decided: false, state: snapshot(shell),
    status: shell.status, calls: shell.calls.length, pipedIn: shell.openingPipe, pipedOut: endsPiped(head, shell),
    outer: [shell.pipe, shell.start],
    defines: name, head: [shell.at, head], iterates: undefined, repeats: false, forever: false, continued: false, doubt: doubt(shell.pipe), unsure: new Set(),
    outside: liveness(shell), cond: kind === "if" || kind === "while" || kind === "until",
    exempt: exempt(shell) || shell.pipe.negate || endsList(head, shell),
  });
  shell.openingPipe = false;
  shell.start = snapshot(shell); // the body starts a list of its own
  pipeline("", value, shell);
}

/** The status a closed compound leaves: a jump's that ended it, 0 for a definition or an if or loop that ran no body,
 *  the one before it when it never ran, unknown when a body may have run, else its last command's. */
function frameStatus(frame: Frame, status: number | undefined): number | undefined {
  const { kind, rel } = frame;
  if (frame.left !== undefined) return frame.left[0];
  if (frame.defines !== undefined) return 0;
  if (frame.base === false || kind === "$(") return frame.status;
  if (kind === "if" && rel !== true && frame.decided !== true) return rel === false && frame.decided === false ? 0 : undefined;
  if (LOOPS.includes(kind)) {
    if (rel === false) return 0;
    return kind === "for" && rel === true ? status : undefined;
  }
  if (kind === "case") return rel === false ? 0 : undefined;
  return status;
}

/** Close a compound: set the status it leaves, resume the pipeline and list around it, and keep a defined function's
 *  body, from its head item to `tail`, for the calls that run it. */
function settle(frame: Frame, tail: Item, shell: Shell): void {
  shell.status = frameStatus(frame, shell.status);
  [shell.pipe, shell.start] = frame.outer;
  if (frame.defines !== undefined && shell.pipe.runs !== false) {
    const [at, head] = frame.head;
    const maybe = shell.pipe.runs === undefined || doubt(shell.pipe); // the definition may not have run
    shell.functions.set(frame.defines, [[head, ...shell.items.slice(at + 1, shell.at), tail], maybe]);
  }
}

/** Leave a body that may not have run: what it changed is remembered as unknown, and the state before it returns. */
function leave(frame: Frame, shell: Shell): void {
  if (frame.saved === undefined) return;
  for (const name of changes(shell, frame.saved)) frame.unsure.add(name);
  restore(shell, frame.saved);
  frame.saved = undefined;
}

/** At a compound's end, make unknown what may not have happened: a body that may not have run, what followed a jump
 *  that may have run, and all of it when an unknown status guarded the compound or it is a loop that may repeat. */
function doubtful(frame: Frame, shell: Shell): void {
  for (const since of [frame.jumped, frame.doubt || frame.repeats ? frame.state : undefined]) {
    if (since !== undefined) for (const name of changes(shell, since)) frame.unsure.add(name);
  }
  leave(frame, shell);
  forget(shell, frame.unsure);
}

/** Wrap each call from `first` on in one more level of pipes and redirections. */
function wrap(shell: Shell, first: number, layer: Layer): void {
  for (let i = first; i < shell.calls.length; i++) {
    const call = shell.calls[i] as Call;
    shell.calls[i] = { ...call, layers: [...call.layers, layer] };
  }
}

/** Mark each call from `first` on as one that may not have run, which is never looked up. */
function markUnsure(calls: Call[], first = 0): void {
  for (let i = first; i < calls.length; i++) calls[i] = { ...(calls[i] as Call), unsure: true };
}

/** What a return, exit, break or continue may change in the open compounds and the shell, to put back. */
function liveness(shell: Shell): Liveness {
  return [shell.frames.map(({ runs: r, alive, left, jumped, repeats }) => ({ runs: r, alive, left, jumped, repeats })), shell.live];
}

/** Undo what a return, exit, break or continue did beyond a compound that turned out to run in a subshell. */
function revive(outside: Liveness, shell: Shell): void {
  outside[0].forEach((marks, i) => Object.assign(shell.frames[i] as Frame, marks));
  shell.live = outside[1];
}

/** Wrap the commands inside a closed compound in the pipes and redirections around it; a piped or backgrounded
 *  compound runs in a subshell, so its cd, exports, functions and any exit inside it end with it. */
/** Wrap a closed compound's commands in the pipes and redirections around it. Piped or backgrounded, its changes end
 *  with it; as a pipeline's last command, zsh keeps them and bash does not, so they are unknown. */
function closeFrame(frame: Frame, layer: Layer, shell: Shell, background = false): void {
  wrap(shell, frame.calls, layer);
  if (layer[0] && !(layer[1] || background || frame.kind === "(" || frame.kind === "$(")) {
    unsure(shell, frame.state);
    revive(frame.outside, shell);
  } else if (layer[0] || layer[1] || background) {
    restore(shell, frame.state, true);
    revive(frame.outside, shell);
  }
}

/** Make what changed since `saved` unknown, for what may or may not have happened: the folder and variables, and each
 *  function defined or removed, which then may or may not be there. */
function unsure(shell: Shell, saved: Snapshot): void {
  forget(shell, changes(shell, saved));
  for (const [name, known] of saved[2]) if (!shell.functions.has(name)) shell.functions.set(name, [known[0], true]);
  for (const [name, known] of [...shell.functions]) {
    if (saved[2].get(name) !== known) shell.functions.set(name, [known[0], true]);
  }
}

/** Start the body a then, elif, else or do opens: run, skipped or maybe run, by the literal status before it, as far
 *  as the compound itself runs. */
function branch(keyword: string, frame: Frame, shell: Shell): void {
  let holds: Maybe = shell.status === 0 ? true : shell.status === 1 ? false : undefined;
  let taken: Maybe;
  if (keyword === "then" && frame.kind === "if") {
    taken = both(frame.rel, holds);
    if (taken === true) frame.decided = true;
    else if (taken === undefined && frame.decided === false) frame.decided = undefined;
  } else if ((keyword === "elif" || keyword === "else") && frame.kind === "if") {
    leave(frame, shell);
    taken = frame.decided === undefined ? undefined : !frame.decided;
  } else if (keyword === "do" && LOOPS.includes(frame.kind)) {
    if (frame.kind === "for" || frame.kind === "select") holds = frame.iterates;
    else if (frame.kind === "until" && holds !== undefined) holds = !holds;
    if (frame.kind === "while" || frame.kind === "until") frame.forever = holds === true; // a literal test holds every time
    taken = both(frame.rel, holds);
  } else {
    return;
  }
  take(frame, taken, shell);
}

/** Set whether the body now starting runs; a body that may not run keeps the state before it to return to. */
function take(frame: Frame, taken: Maybe, shell: Shell): void {
  frame.rel = taken;
  frame.runs = both(both(frame.base, taken), frame.alive);
  if (taken === undefined && frame.saved === undefined) frame.saved = snapshot(shell);
  shell.start = snapshot(shell);
}

/** Stop what a return, exit, break or continue cuts short: the rest of the function, the shell or subshell, or the
 *  loop body. One that may not run leaves the rest maybe running, and what that rest changes unknown. */
function jump(name: string, args: string[], shell: Shell): void {
  const { frames, floor } = shell;
  // None of them reaches past a subshell, and a break or continue does not leave the function it is in.
  let bound = -1;
  frames.forEach((f, i) => {
    if (f.kind === "(" || f.kind === "$(" || f.pipedIn || f.pipedOut) bound = i;
  });
  let target: number;
  if (name === "break" || name === "continue") {
    // A loop that is itself piped is its own subshell, so a break inside still reaches it.
    const loops = frames.flatMap((f, i) => (LOOPS.includes(f.kind) && i >= Math.max(bound, floor ?? 0) ? [i] : []));
    if (loops.length === 0) return;
    const count = /^\d+$/.test(args[0] ?? "") && Number(args[0]) > 0 ? Number(args[0]) : 1;
    target = loops[loops.length - Math.min(count, loops.length)] as number;
  } else if (name === "return") {
    if (floor === undefined) return; // outside a function, return only complains
    target = Math.max(floor, bound);
  } else {
    target = Math.max(bound, 0);
  }
  // Sure once the compound it ends is running: nothing between here and there can skip it, and an if or case it ends
  // surely took the branch it is in. It ends the whole shell only when the outermost compound surely runs as well.
  const sure = !doubt(shell.pipe) &&
    frames.slice(target + 1).every((f) => f.rel === true && f.alive === true && !f.doubt) &&
    !frames.slice(target, target + 1).some((f) => (f.kind === "if" || f.kind === "case") && f.rel !== true);
  const outermost = frames[0];
  const whole = outermost === undefined
    ? sure && shell.pipe.runs === true
    : sure && outermost.base === true && outermost.rel === true && !outermost.doubt;
  frames.slice(target).forEach((frame, i) => {
    frame.alive = both(frame.alive, sure ? false : undefined);
    frame.runs = both(frame.runs, frame.alive);
    // A sure break, return or exit ends the loops it leaves for good, while a continue runs its own loop again.
    frame.repeats &&= !(sure && (name !== "continue" || i > 0));
  });
  if (name === "exit" && bound < 0) shell.live = both(shell.live, whole ? false : undefined);
  const frame = frames[target];
  if (frame === undefined) return;
  // The compound ends with the jump's status, unknown when it may not have jumped, or may have earlier. A `!` still
  // flips a break or continue, while a return or exit leaves at once.
  const status = name === "break" || name === "continue" ? Number(shell.pipe.negate) : shell.status;
  frame.left = [sure && frame.left === undefined ? status : undefined];
  if (!sure && frame.jumped === undefined) frame.jumped = snapshot(shell);
  if (name === "continue") frame.continued = frame.continued === true || sure ? true : undefined;
}

/** Apply a command's leading reserved word to the open compound commands and its pipeline; the words after it. */
function keyword(argv: string[], item: Item, shell: Shell): string[] {
  const [word = "", ...rest] = argv;
  const { frames } = shell;
  if (word === "{" || word === "if" || LOOPS.includes(word)) {
    openFrame(word, shell.pipe.runs, shell, { kind: "cmd", argv, before: "", after: item.after, io: item.io });
    if (LOOPS.includes(word)) {
      const frame = frames.at(-1) as Frame;
      [frame.iterates, frame.repeats, frame.forever, frame.counter] = loop(word, rest, shell);
      touched(frame, loopCommands(frame, shell, shell.ends.get(`${shell.at},${item.argv.length - argv.length}`)?.[1]));
      const name = word === "for" || word === "select" ? rest[0] ?? "" : "";
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && frame.iterates !== false) {
        // Each pass sets the name, exported if it was or allexport is on.
        shell.vars[name] = [SUBSTITUTED, autoExport(shell, variable(shell, name)[1])];
      }
    }
    return word === "for" || word === "select" ? [] : rest; // a for loop's header runs nothing
  }
  if (word === "!" || word === "function" || word === "time") {
    // `!` flips the status of the whole pipeline it leads, a compound included, and a second one flips it back;
    // `time` leads a pipeline and leaves its status.
    if (word === "!") shell.pipe.negate = !shell.pipe.negate;
    else if (word === "function") shell.function = rest[0] ?? "";
    shell.pipe.leading = true;
    return word === "function" ? rest.slice(1) : rest;
  }
  if (word === "}" || word === "fi" || word === "done") {
    const frame = pop(frames, word === "}" ? ["{"] : word === "fi" ? ["if"] : LOOPS);
    if (frame !== undefined) {
      stepSubstitutions(frame, shell);
      const ends = endless(frame, shell);
      doubtful(frame, shell);
      settle(frame, { kind: "cmd", argv: [word], before: item.before, after: "", io: item.io }, shell);
      if (ends) jump("exit", [], shell); // nothing after a loop that never ends runs
    }
    shell.closed = frame;
    return rest;
  }
  const top = frames.at(-1);
  if (top !== undefined) {
    branch(word, top, shell);
    top.cond = word === "elif"; // a then or do starts the body, and an elif another condition
  }
  pipeline("", runs(shell), shell);
  return rest;
}

type LoopRead = [iterates: Maybe, repeats: boolean, forever: boolean, counter: string | undefined];

/** [whether a loop runs its body at least once: true, false or undefined; whether it may run it again; whether its
 *  test never fails; an arithmetic for's counter], from its header, or the positional parameters with no `in`. */
function loop(word: string, rest: string[], shell: Shell): LoopRead {
  if (word === "for" && rest[0]?.startsWith("((")) return counted(rest[0]);
  if (word !== "for" && word !== "select") return [undefined, true, false, undefined];
  const listed = rest[1] === "in" ? rest.slice(2) : shell.args;
  const literal = word === "for" && (listed ?? []).some((w) => !w.includes("$") && !w.includes(SUBSTITUTED));
  const plain = listed?.length === 1 && ![..."$*?[", SUBSTITUTED].some((c) => (listed[0] as string).includes(c));
  return [literal ? true : listed?.length === 0 ? false : undefined, word !== "for" || !plain, false, undefined];
}

const TESTS: Record<string, (a: bigint, b: bigint) => boolean> = {
  "<": (a, b) => a < b, "<=": (a, b) => a <= b, ">": (a, b) => a > b, ">=": (a, b) => a >= b,
  "==": (a, b) => a === b, "!=": (a, b) => a !== b,
};

/** `loop`'s answer for an arithmetic for: read when it starts its counter at a number, tests it against a number and
 *  steps it by a number; with no test it runs until something leaves it. */
function counted(word: string): LoopRead {
  const unknown: LoopRead = [undefined, true, false, undefined];
  const parts = word.endsWith("))") ? (arithmeticParts(word.slice(2, -2)) ?? []).map((p) => p.trim()) : [];
  if (parts.length !== 3) return unknown;
  const [init, check, step] = parts as [string, string, string];
  const start = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0|[1-9][0-9]*)$/.exec(init);
  if (init !== "" && start === null) return unknown;
  if (check === "") return [true, true, true, undefined];
  const test = /^([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*(0|[1-9][0-9]*)$/.exec(check);
  if (start === null || test === null || start[1] !== test[1]) return unknown;
  const [a, op, b] = [BigInt(start[2] as string), test[2] as string, BigInt(test[3] as string)];
  const holds = TESTS[op] as (a: bigint, b: bigint) => boolean;
  if (!holds(a, b)) return [false, false, false, start[1]];
  const by = stepOf(step, start[1] as string);
  if (by === undefined) return [true, true, false, start[1]]; // a step it can't read may repeat the body
  // The counter runs a, a + by, a + 2 by, ...: a != test fails only if it lands on the number, any other only if the
  // counter moves toward failing it.
  const forever = op === "!=" ? by === 0n || (b - a) % by !== 0n || (b - a) / by < 0n
    : op === "==" ? by === 0n
    : by === 0n || (by > 0n) === (op === ">" || op === ">=");
  return [true, holds(a + by, b), forever, start[1]];
}

/** How much an arithmetic for's step adds to its counter: nothing, ++ or --, += or -= a number, or the counter plus
 *  or minus a number; undefined for anything else. */
function stepOf(step: string, name: string): bigint | undefined {
  if (step === "") return 0n;
  let match = /^(\+\+|--)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--)?$/.exec(step);
  if (match !== null && match[2] === name && (match[1] === undefined) !== (match[3] === undefined)) {
    return (match[1] ?? match[3]) === "++" ? 1n : -1n;
  }
  match = /^([A-Za-z_][A-Za-z0-9_]*)\s*([+-])=\s*(0|[1-9][0-9]*)$/.exec(step);
  if (match !== null && match[1] === name) return BigInt(match[3] as string) * (match[2] === "+" ? 1n : -1n);
  match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*([+-])\s*(0|[1-9][0-9]*)$/.exec(step);
  if (match !== null && match[1] === name && match[2] === name) return BigInt(match[4] as string) * (match[3] === "+" ? 1n : -1n);
  return undefined;
}

/** Run the substitutions in an arithmetic for's step where a pass of its body ends or a continue skips to: never after
 *  a sure break. */
function stepSubstitutions(frame: Frame, shell: Shell): void {
  const header = frame.kind === "for" ? frame.head[1].argv[1] : undefined;
  const parts = header?.startsWith("((") ? arithmeticParts(header.slice(2, -2)) : undefined;
  const items: Item[] = [];
  for (const body of parts === undefined ? [] : textBodies(parts[2] as string) ?? []) {
    items.push({ kind: "$(", argv: [], before: "", after: "", io: [] }, ...(new Lexer(body).read() ?? []),
      { kind: ")", argv: [], before: "", after: "", io: [] });
  }
  if (items.length === 0) return;
  const ended: Maybe[] = [frame.alive, frame.continued];
  const reached: Maybe = ended.includes(true) ? true : ended.every((e) => e === false) ? false : undefined;
  const runsBefore = frame.runs;
  frame.runs = both(both(frame.base, frame.rel), reached);
  shell.frames.push(frame); // inside the loop, as far as a pass of its body reached its end
  walkItems(items, shell, 0);
  shell.frames.pop();
  frame.runs = runsBefore;
}

/** The words of each command a loop runs in this shell, from its condition up to the item `end`, leaving out those in
 *  a subshell or substitution; undefined when its end is not known. */
function loopCommands(frame: Frame, shell: Shell, end: number | undefined): string[][] | undefined {
  const [at, head] = frame.head;
  if (end === undefined) return undefined;
  return [head.argv.slice(head.argv[0] === "for" || head.argv[0] === "select" ? 2 : 1), ...ownCommands(shell.items.slice(at + 1, end))];
}

/** The words of each command in `list` that runs in this shell, not in a subshell or substitution. */
function ownCommands(list: Item[]): string[][] {
  let depth = 0;
  const commands: string[][] = [];
  for (const item of list) {
    depth += item.kind === "(" || item.kind === "$(" ? 1 : item.kind === ")" ? -1 : 0;
    if (item.kind === "cmd" && depth === 0) commands.push(item.argv);
  }
  return commands;
}

/** An arithmetic for that may change its counter may run its body again, and its test may fail after all; a plain
 *  $name or ${name} only reads it. */
function touched(frame: Frame, commands: string[][] | undefined): void {
  const name = frame.counter;
  if (name === undefined) return;
  for (const word of (commands ?? [[name]]).flat()) {
    for (let at = word.indexOf(name); at >= 0; at = word.indexOf(name, at + 1)) {
      const [before, after] = [word.slice(0, at), word.slice(at + name.length)];
      const whole = !/[A-Za-z0-9_]/.test(before.slice(-1) + after.slice(0, 1));
      if (whole && !(before.endsWith("$") || (before.endsWith("${") && after.startsWith("}")))) {
        [frame.repeats, frame.forever] = [true, false];
        return;
      }
    }
  }
}

/** Whether `commands` could leave the loop they run in: a break, a continue past it, a return (but in a called
 *  function, where it only ends the call), eval or source, or a call to a function that could. */
function leaves(commands: string[][], shell: Shell, called: boolean, seen: Set<string>): boolean {
  for (const words of commands) {
    // Only the word in command position runs; an argument that names break, eval or a function does not.
    let lead = words.filter((w) => !KEYWORDS.has(w) && !isAssignment(w));
    while (lead[0] === "command" || lead[0] === "builtin") lead = lead.slice(1);
    const word = lead[0];
    if (word === undefined) continue;
    const count = lead[1] ?? "1";
    if (["break", "eval", "source", "."].includes(word) || (word === "return" && !called) ||
        (word === "continue" && !(/^\d+$/.test(count) && Number(count) <= 1))) return true;
    const known = shell.functions.get(word);
    if (known !== undefined && !seen.has(word)) {
      seen.add(word);
      if (leaves(ownCommands(known[0]), shell, true, seen)) return true;
    }
  }
  return false;
}

/** Whether a loop now closing never ends: its test never fails, and nothing it runs in this shell could leave it. */
function endless(frame: Frame, shell: Shell): boolean {
  const commands = LOOPS.includes(frame.kind) ? loopCommands(frame, shell, shell.at) : undefined;
  return commands !== undefined && frame.forever && frame.base !== false && !leaves(commands, shell, false, new Set());
}

/** The status a (( N )) with a decimal number leaves: 0 for one that is not zero, 1 for zero; undefined otherwise. A
 *  leading zero is octal in bash and decimal in zsh, but zero either way. */
function arithmetic(word: string): number | undefined {
  const inner = word.startsWith("((") && word.endsWith("))") ? word.slice(2, -2).trim() : "";
  return /^(?:0+|[1-9][0-9]*)$/.test(inner) ? Number(/^0+$/.test(inner)) : undefined;
}

/** Apply a subshell, substitution, function or case marker to the open compound commands. */
function marker(item: Item, shell: Shell): void {
  const { frames, pipe } = shell;
  if (item.kind === "(" || item.kind === "case") {
    begin(item.before, shell);
    shell.openingPipe = item.before === "|";
    openFrame(item.kind, shell.pipe.runs, shell, { kind: item.kind, argv: [], before: "", after: "", io: [] });
    if (item.kind === "case") {
      // Nothing runs until an arm opens.
      const frame = frames.at(-1) as Frame;
      frame.rel = false;
      frame.runs = false;
    }
  } else if (item.kind === "$(") {
    // A substitution runs when its command does, and reads the stdin piped into that command.
    const runsHere = item.before === "|" || pipe.leading ? pipe.runs : both(runs(shell), follows(item.before, shell.status));
    shell.openingPipe = item.before === "|";
    openFrame(item.kind, runsHere, shell, item);
  } else if (item.kind === "func") {
    begin(item.before, shell);
    shell.function = item.argv[0] ?? "";
    shell.pipe.leading = true;
  } else if (item.kind === "arm" && frames.at(-1)?.kind === "case") {
    const frame = frames.at(-1) as Frame;
    leave(frame, shell);
    take(frame, undefined, shell);
  } else if (item.kind === ")" || item.kind === "esac") {
    const frame = pop(frames, item.kind === ")" ? ["(", "$("] : ["case"]);
    if (frame === undefined) return;
    // A subshell's cd, exports and functions end with it.
    if (item.kind === ")") restore(shell, frame.state, true);
    else doubtful(frame, shell);
    settle(frame, { ...item, after: "" }, shell);
    if (frame.kind === "$(") {
      closeFrame(frame, [frame.pipedIn, false, [[1, "null"]]], shell); // its output is captured
    } else {
      closeFrame(frame, [frame.pipedIn, item.after === "|", item.io], shell, item.after === "&");
      finish(item.after, shell);
      if (frame.kind === "(") errexit(item.after, shell); // a subshell that fails is a command that fails
    }
  }
}

/** Apply an export, unset or declaration, or a command made only of assignments (name ""), to the commands after it. */
function builtin(name: string, args: string[], shell: Shell): void {
  if (name === "unset") unset(args, shell);
  else if (SETS.includes(name)) setOptions(name, args, shell);
  else if (DECLARES.includes(name)) declare(name, args, shell);
  else assign(name, args, shell);
}

/** Apply an export, or a command made only of assignments (name ""). */
function assign(name: string, args: string[], shell: Shell): void {
  for (const arg of args.filter((a) => !a.startsWith("-"))) {
    const eq = arg.indexOf("=");
    const key = eq < 0 ? arg : arg.slice(0, eq);
    const value = eq < 0 ? undefined : arg.slice(eq + 1);
    if (key.endsWith("+")) forget(shell, new Set([key.slice(0, -1)].filter(Boolean))); // bash appends, zsh rejects it
    else if (name === "export") shell.vars[key] = [value ?? variable(shell, key)[0], !args.includes("-n")];
    else shell.vars[key] = [value, autoExport(shell, variable(shell, key)[1])];
  }
}

const SETS: readonly string[] = ["set", "setopt", "unsetopt"];
const SET_OPTIONS: Record<string, string> = { allexport: ALLEXPORT, errexit: ERREXIT };
const SET_FLAGS: Record<string, string> = { a: "allexport", e: "errexit" };

/** The options a zsh spelling such as all_export or noerrexit names, ignoring case and underscores. */
function zshOptions(name: string): string[] {
  const plain = name.toLowerCase().replaceAll("_", "");
  return Object.entries(SET_OPTIONS)
    .filter(([option]) => plain === option || plain === `no${option}`)
    .map(([, key]) => key);
}

/** set -a or -e, -o allexport or errexit, or a cluster with a or e turns the option on, and the + forms off. setopt,
 *  unsetopt and zsh's spellings such as all_export leave it unknown, as bash has none of them. */
function setOptions(name: string, args: string[], shell: Shell): void {
  let i = 0;
  while (name === "set" && /^[-+]/.test(args[i] ?? "") && !["-", "--", "+"].includes(args[i] as string)) {
    const arg = args[i++] as string;
    for (const flag of arg.slice(1)) {
      const option = flag === "o" ? args[i++] ?? "" : SET_FLAGS[flag] ?? "";
      const key = Object.hasOwn(SET_OPTIONS, option) ? SET_OPTIONS[option] : undefined;
      if (key !== undefined) shell.vars[key] = [arg[0] === "-" ? "1" : "", true];
      else forget(shell, new Set(zshOptions(option)));
    }
  }
  if (name !== "set") forget(shell, new Set(args.flatMap(zshOptions)));
}

/** Whether a variable assigned now is exported: always while allexport is on, maybe while it may be, else as before. */
function autoExport(shell: Shell, exported: Variable[1]): Variable[1] {
  const allexport = shell.vars[ALLEXPORT]?.[0] ?? "";
  if (exported === true || isLent(exported) || allexport === "") return exported;
  return allexport === "1" ? true : undefined;
}

/** unset -f removes functions, and -v or a bare name variables with their export. A bare name with no variable set
 *  removes the function in bash but not zsh, so it may or may not remain, as after an unset -f that may not run. */
function unset(args: string[], shell: Shell): void {
  const sure = shell.pipe.runs === true && !doubt(shell.pipe);
  for (const name of args.filter((a) => !a.startsWith("-"))) {
    const value = variable(shell, name)[0];
    const known = shell.functions.get(name);
    const exported = variable(shell, name)[1];
    if (!args.includes("-f") && isLent(exported)) shell.vars[name] = [exported === LENT[1] ? SUBSTITUTED : undefined, exported];
    else if (!args.includes("-f")) shell.vars[name] = [undefined, false];
    const unsetsFunction = args.includes("-f") ||
      (!args.includes("-v") && (value === undefined || value.includes(SUBSTITUTED)));
    if (known === undefined || !unsetsFunction) continue;
    if (sure && args.includes("-f")) shell.functions.delete(name);
    else shell.functions.set(name, [known[0], true]);
  }
}

/** declare or typeset outside a function set NAME=value, exporting with -x and not with +x. Other options, +=, local,
 *  readonly, and declarations in a function leave the names unknown; a local one put back after its call. */
function declare(name: string, args: string[], shell: Shell): void {
  let on = "";
  let off = "";
  let i = 0;
  for (; i < args.length && /^[-+]./.test(args[i] as string); i++) {
    const option = args[i] as string;
    if (option === "--") {
      i++;
      break;
    }
    if (option[0] === "-") on += option.slice(1);
    else off += option.slice(1);
  }
  const plain = (name === "declare" || name === "typeset") && shell.floor === undefined && /^x*$/.test(on + off) &&
    !(on !== "" && off !== "");
  const sure = shell.pipe.runs === true && !doubt(shell.pipe);
  for (const arg of args.slice(i)) {
    const eq = arg.indexOf("=");
    const key = eq < 0 ? arg : arg.slice(0, eq);
    const lent = variable(shell, key.replace(/\+$/, ""))[1];
    // Both shells export a local -x NAME=value to the call's commands; other local values they pass on differently.
    const exportedLocal = name === "local" && on.includes("x") && off === "" && eq >= 0 && !key.endsWith("+");
    if (isLent(lent) && name !== "readonly" && !(on + off).includes("g")) {
      shell.vars[key.replace(/\+$/, "")] = [exportedLocal ? arg.slice(eq + 1) : SUBSTITUTED, lent]; // call-local
      continue;
    }
    if (exportedLocal) {
      shell.vars[key] = [arg.slice(eq + 1), true];
    } else if (!plain || key.endsWith("+")) {
      forget(shell, new Set([key.replace(/\+$/, "")].filter(Boolean)));
    }
    if (!plain || key.endsWith("+")) {
      // Local to the call in both shells, unless zsh makes it global: declare or typeset -x.
      if (shell.scoped.length > 0 && sure && (name === "local" || (name !== "readonly" && !/[gx]/.test(on + off)))) {
        shell.scoped.at(-1)?.add(key.replace(/\+$/, ""));
      }
      continue;
    }
    const [current, exported] = variable(shell, key);
    shell.vars[key] = [eq < 0 ? current : arg.slice(eq + 1),
      on !== "" ? true : off !== "" ? false : eq >= 0 ? autoExport(shell, exported) : exported];
  }
}

/** The positional parameters of a shell that reads its script from stdin, with no -c string and no script file;
 *  undefined for any other command. */
function stdinScript(name: string, args: string[]): string[] | undefined {
  if (!SHELLS.has(name)) return undefined;
  const [i, letters, , end] = shellFlags(args);
  if (letters.has("c")) return undefined;
  return letters.has("s") || end === "-" ? args.slice(i) : i >= args.length ? [] : undefined; // else a script file
}

const SHELL_FLAGS: Record<string, string> = { a: "allexport", e: "errexit", n: "noexec" };
const ZSH_SPELLINGS: Record<string, string> = {
  allexport: "allexport", noallexport: "allexport", errexit: "errexit", noerrexit: "errexit",
  exec: "noexec", noexec: "noexec",
};

/** A shell's startup options as bash reads them: [where its operands start, the option letters given, the options set
 *  as {name: "1" on, "" off, or a substitution when not known}, the - or -- that ended them, else ""]. */
function shellFlags(args: string[]): [number, Set<string>, Record<string, string>, string] {
  const letters = new Set<string>();
  const options: Record<string, string> = {};
  let i = 0;
  while (i < args.length) {
    const arg = args[i++] as string;
    if (arg === "-" || arg === "--") return [i, letters, options, arg];
    if (arg === "--rcfile" || arg === "--init-file") i++;
    else if (!(arg.length > 1 && (arg[0] === "-" || arg[0] === "+"))) return [i - 1, letters, options, ""];
    else if (!arg.startsWith("--")) {
      for (const flag of arg.slice(1)) {
        letters.add(flag);
        // -o and -O take the word after the cluster, as in -eo pipefail.
        const option = flag === "o" || flag === "O" ? args[i++] ?? "" : SHELL_FLAGS[flag] ?? "";
        const spelled = Object.hasOwn(ZSH_SPELLINGS, option.toLowerCase().replaceAll("_", ""))
          ? ZSH_SPELLINGS[option.toLowerCase().replaceAll("_", "")] : undefined;
        if (flag !== "O" && Object.values(SHELL_FLAGS).includes(option)) options[option] = arg[0] === "-" ? "1" : "";
        // zsh's spellings, which bash rejects.
        else if (flag !== "O" && spelled !== undefined) options[spelled] = SUBSTITUTED;
      }
    }
  }
  return [i, letters, options, ""];
}

/** A script read from stdin: each command's stdin is the script's lines after the one it ends on, which a command
 *  that reads stdin, such as curl -K - or nc, takes for its input. */
function scriptStdin(text: string, lexer: Lexer, list: Item[]): Item[] {
  return list.map((item) => {
    const end = lexer.ends.get(item);
    const lineEnd = end === undefined ? -1 : text.indexOf("\n", end);
    const rest = lineEnd >= 0 ? text.slice(lineEnd + 1) : "";
    return rest.trim() === "" ? item : { ...item, io: [[0, "file", { text: rest }] as Redirection, ...item.io] };
  });
}

/** The heredoc or here-string text a call's stdin reads, as its pipes and redirections set it, a <&N taking the text on
 *  N; undefined otherwise. */
function stdinText(layers: readonly Layer[]): string | undefined {
  const fds = new Map<number, { text?: string } | undefined>();
  for (const [pipedIn, , redirections] of [...layers].reverse()) {
    if (pipedIn) fds.set(0, undefined);
    for (const [fd, value, text] of redirections) {
      fds.set(fd, text ?? (typeof value === "number" ? fds.get(value) : undefined));
    }
  }
  return fds.get(0)?.text;
}

/** curl's or wget's arguments, with a config (curl -K -) or a URL list (wget -i -) read from stdin put in place. */
function stdinArgs(tool: string, args: string[], text: string | undefined): string[] {
  const names = tool === "curl" ? ["-K", "--config"] : ["-i", "--input-file"];
  const out: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    const joined = arg === `${names[0]}-` || arg === `${names[1]}=-`;
    if (text === undefined || !(joined || (names.includes(arg) && args[i] === "-"))) {
      out.push(arg);
      continue;
    }
    if (!joined) i++;
    out.push(...(tool === "curl" ? curlConfig(text) : text.split("\n").map((line) => line.trim()).filter(Boolean)));
  }
  return out;
}

/** A curl config's options as arguments: one per line, with or without its dashes, its value after blanks, = or :,
 *  quoted or not; # starts a comment. */
function curlConfig(text: string): string[] {
  const args: string[] = [];
  for (const line of text.split("\n").map((l) => l.trim())) {
    const match = /^(-{0,2}[A-Za-z0-9][A-Za-z0-9-]*)(?:\s*[=:]\s*|\s+|$)(.*)$/.exec(line);
    if (match === null || line.startsWith("#")) continue;
    const [name, value] = [match[1] as string, (match[2] as string).trim()];
    args.push(name.startsWith("-") ? name : `--${name}`);
    if (value !== "") args.push(value.length > 1 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value);
  }
  return args;
}

/** The command string `sh -c` or `powershell -Command` runs; undefined for any other command. */
function shellString(name: string, args: string[]): string | undefined {
  if (SHELLS.has(name)) {
    const [i, letters] = shellFlags(args);
    return letters.has("c") && i < args.length ? args[i] : undefined;
  }
  if (POWERSHELLS.has(name)) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      const flag = arg.startsWith("-") || arg.startsWith("/") ? arg.slice(1).toLowerCase() : "";
      if (flag === "c" || (flag.length >= 3 && "command".startsWith(flag))) return hashtablesEmptied(args.slice(i + 1).join(" "));
    }
  }
  return undefined;
}

/** A PowerShell command with each @{ } hashtable made empty: a ; in one separates its entries, not commands, and what
 *  it holds names no host the cmdlet reaches. */
function hashtablesEmptied(text: string): string {
  let out = "";
  let quote: string | undefined;
  for (let i = 0; i < text.length; ) {
    if (quote === undefined && text.startsWith("@{", i)) {
      out += "@{}";
      i = hashtableEnd(text, i + 2);
      continue;
    }
    const ch = text[i] as string;
    quote = quote !== undefined ? (ch === quote ? undefined : quote) : ch === "'" || ch === '"' ? ch : undefined;
    out += ch;
    i++;
  }
  return out;
}

/** The index after the } that closes a PowerShell @{ whose contents start at `start`, past quotes and nested braces. */
function hashtableEnd(text: string, start: number): number {
  let depth = 1;
  let quote: string | undefined;
  let i = start;
  for (; i < text.length && depth > 0; i++) {
    const ch = text[i] as string;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else {
      depth += ch === "{" ? 1 : ch === "}" ? -1 : 0;
    }
  }
  return i;
}

/** Set a function call's leading VAR=value words for its body, exported, as bash and zsh do; each name's entry from
 *  before the call, undefined when it had none. */
function lend(shell: Shell, assignments: string[]): Map<string, Variable | undefined> {
  const before = new Map<string, Variable | undefined>();
  const flags = new Map<string, Lent>();
  for (const word of assignments) {
    const at = word.indexOf("=");
    const name = word.slice(0, at);
    if (!before.has(name)) {
      before.set(name, shell.vars[name]);
      flags.set(name, LENT[variable(shell, name)[0] !== undefined ? 1 : 0]);
    }
    shell.vars[name] = [word.slice(at + 1), flags.get(name) as Lent];
  }
  return before;
}

/** Put each lent name back as it was before the call, as bash and zsh do after the body assigns, unsets or declares it
 *  locally. One the body exported or left unknown is unknown: bash keeps an exported value, zsh does not. */
function takeBack(shell: Shell, before: Map<string, Variable | undefined>): void {
  for (const [name, entry] of before) {
    if (!isLent((shell.vars[name] ?? [undefined, undefined])[1])) shell.vars[name] = [SUBSTITUTED, undefined];
    else if (entry === undefined) delete shell.vars[name];
    else shell.vars[name] = entry;
  }
}

/** Run a function's body (`known`: body, whether it may not exist) where called, in a subshell when piped or
 *  backgrounded; one that may not run, or a pipeline's last command (`subshell` undefined), leaves its changes unknown. */
function callFunction(known: [Item[], boolean], layer: Layer, subshell: Maybe, shell: Shell, depth: number): void {
  const [body, maybe] = known;
  if (depth >= MAX_DEPTH || shell.callsLeft <= 0) {
    shell.status = undefined;
    return;
  }
  shell.callsLeft--;
  const first = shell.calls.length;
  const state = snapshot(shell);
  const outer: [Pipeline, Snapshot, number | undefined] = [shell.pipe, shell.start, shell.floor];
  const outside = liveness(shell);
  shell.floor = shell.frames.length;
  shell.scoped.push(new Set());
  walkItems(body, shell, depth + 1);
  for (const name of shell.scoped.pop() ?? []) {
    // A local ends with the call, and the value from before it is back.
    const before = state[1][name];
    if (before !== undefined) shell.vars[name] = before;
    else delete shell.vars[name];
  }
  [shell.pipe, shell.start, shell.floor] = outer;
  wrap(shell, first, layer);
  if (maybe) markUnsure(shell.calls, first);
  if (subshell) {
    restore(shell, state, true);
    revive(outside, shell);
  } else if (subshell === undefined || maybe || doubt(shell.pipe)) {
    unsure(shell, state);
    soften(outside, shell);
  }
}

/** Make what a return, exit, break or continue did beyond a call that may not run a maybe: what follows may run, and
 *  the compound it would have ended leaves an unknown status. */
function soften(outside: Liveness, shell: Shell): void {
  outside[0].forEach((marks, i) => {
    const frame = shell.frames[i] as Frame;
    if (frame.alive === false && marks.alive !== false) {
      frame.alive = undefined;
      frame.runs = both(marks.runs, undefined);
      frame.jumped ??= snapshot(shell);
    }
    if (frame.left !== marks.left) frame.left = [undefined];
    frame.repeats = marks.repeats;
  });
  if (shell.live === false && outside[1] !== false) shell.live = undefined;
}

/** The calls one simple command makes, after applying its cd, export, unset or declaration; a defined function runs
 *  its body with the command's words as its positional parameters. */
function simple(words: string[], item: Item, before: string, shell: Shell, depth: number): Call[] {
  const layer: Layer = [before === "|", item.after === "|", item.io];
  const lead = words.findIndex((word) => !isAssignment(word));
  const assigned = lead < 0 ? words.length : lead;
  const expanded = [...words.slice(0, assigned).map((word) => assignedTilde(word, shell)), ...words.slice(assigned)];
  const substituted = expanded.some((word) => word.includes(SUBSTITUTED));
  const argv = appends(expanded, shell);
  // A piped or backgrounded command runs in a subshell; the last command of a pipeline (undefined) does in bash, but
  // runs in this shell in zsh.
  const subshell: Maybe = item.after === "|" || item.after === "&" ? true : before === "|" ? undefined : false;
  const called = argv.find((word) => !isAssignment(word));
  const known = called === undefined ? undefined : shell.functions.get(called);
  if (known !== undefined) {
    const outer = shell.args;
    shell.args = argv.slice(argv.indexOf(called as string) + 1);
    const lent = lend(shell, argv.slice(0, argv.indexOf(called as string)));
    // A body called in an && or || list but as its last command, or behind a !, runs with set -e ignored.
    const ignored = item.after === "&&" || item.after === "||" || shell.pipe.negate || exempt(shell) ? 1 : 0;
    shell.exempt += ignored;
    callFunction(known, layer, subshell, shell, depth);
    shell.exempt -= ignored;
    takeBack(shell, lent);
    shell.args = outer;
    if (!known[1]) return [];
    // A function that may not have been defined may leave the name to the program.
  }
  const parsed = program(argv, shell.cwd);
  const { name } = parsed;
  // After a wrapper that is a program of its own, a builtin's name is a program too, and changes nothing here.
  const own = parsed.external ? undefined : name;
  const declares = name === "export" || DECLARES.includes(name as string);
  const args = parsed.args.map((arg) => (declares && isAssignment(arg) ? assignedTilde(arg, shell) : tilde(arg, shell)));
  const env = CLEAN_ENV in parsed.env ? parsed.env : { ...exportedEnv(shell), ...parsed.env };
  // A command of nothing but assignments sets them in the shell, and succeeds unless a substitution in it fails.
  const assigns = name === undefined && argv.every(isAssignment);
  const status = shell.status;
  shell.status = name === "true" || own === ":" || own === "break" || own === "continue" ? 0 : name === "false" ? 1
    : argv.length === 1 ? arithmetic(argv[0] as string) : undefined;
  if (assigns && !substituted) shell.status = 0;
  let moved = own === "cd" ? cdTarget(args, parsed.cwd, shell, parsed.env) : undefined;
  if (own === "pushd" || own === "popd") {
    // pushd DIR lands as cd DIR does; popd and any other pushd move by a folder stack this does not keep.
    const folders = args[0] === "--" ? args.slice(1) : args;
    const sure = name === "pushd" && folders.length === 1 && !/^[+-]/.test(folders[0] as string);
    moved = sure ? cdTarget(folders, parsed.cwd, shell, parsed.env) : [undefined, undefined];
  }
  if (moved !== undefined) shell.status = moved[1];
  if (own === "set" || own === "shift") shell.args = undefined; // the positional parameters may have changed
  if (own === "return" || own === "exit") {
    // Either leaves the status it is given, or else the one before it; a return outside a function fails.
    const given = args[0];
    shell.status = given === undefined ? status : /^\d+$/.test(given) ? Number(BigInt(given) % 256n > 0n) : undefined;
    if (name === "return" && shell.floor === undefined) shell.status = 1;
  }
  if (own === "return" || own === "exit" || own === "break" || own === "continue") jumpFrom(own, args, subshell, shell);
  if (READERS.includes(own as string) && ((before !== "|" && item.after !== "|") || subshell === undefined)) {
    forget(shell, readNames(name as string, args));
  }
  if ((own === "eval" || own === "source" || own === ".") && ((before !== "|" && item.after !== "|") || subshell === undefined)) {
    // Their text may set any variable or change folder, so every one, inherited ones included, becomes unknown.
    const names = Object.keys(shell.vars).filter((key) => !key.startsWith("\0"));
    forget(shell, new Set([...names, "", ...Object.values(SET_OPTIONS)]));
    shell.vars[UNKNOWN_ENV] = [undefined, undefined];
    // It may also redefine any function, so each one known may no longer run as written.
    for (const [fname, known] of shell.functions) shell.functions.set(fname, [known[0], true]);
  }
  if (own === "cd" || own === "pushd" || own === "popd" || own === "export" || own === "unset" ||
    SETS.includes(own as string) || DECLARES.includes(own as string) || assigns) {
    // A pipeline's commands run in subshells, so their cd and variables end with them, but for the last in zsh.
    if (((before !== "|" && item.after !== "|") || subshell === undefined) && execsThrough(argv) === false) {
      const saved = snapshot(shell);
      if (moved !== undefined) shell.cwd = moved[0];
      else builtin(name ?? "", assigns ? argv : args, shell);
      if (subshell === undefined) unsure(shell, saved);
      else if (doubt(shell.pipe)) forget(shell, changes(shell, saved)); // it may not have run
    }
    replaceShell(argv, subshell, shell);
    return []; // a builtin run through exec does not run: bash finds no such program, and zsh exits after it
  }
  let inner = name === undefined ? undefined : shellString(name, args);
  // Its words after the string are $0 and then the positional parameters; a shell may read its script from stdin.
  let positional = inner !== undefined && SHELLS.has(name as string) ? args.slice(args.indexOf(inner) + 2) : [];
  const script = name !== undefined && inner === undefined ? stdinScript(name, args) : undefined;
  if (script !== undefined) {
    // The shell has already read the script from its stdin, so the script's commands find nothing more there.
    [inner, positional] = [stdinText([layer]), script];
    layer[2] = layer[2].map(([fd, value]): Redirection => [fd, fd === 0 ? "null" : value]);
  }
  if (inner !== undefined) {
    // The string's commands run as the wrapper's user and read its stdin and write its stdout.
    const lexer = new Lexer(inner, depth + 1);
    const read = lexer.read() ?? [];
    // A new shell starts with its own options, not the outer shell's: -e, -a and -n, or their -o names.
    const options = SHELLS.has(name as string) ? shellFlags(args)[2] : {};
    const ownKeys = Object.values(SET_OPTIONS);
    const nested: Env = Object.fromEntries(Object.entries(env).filter(([key]) => !ownKeys.includes(key)));
    for (const [option, value] of Object.entries(options)) {
      if (option !== "noexec") nested[SET_OPTIONS[option] as string] = value;
    }
    const items = script === undefined ? read : scriptStdin(inner, lexer, read);
    const calls = options.noexec === "1" ? [] : walk(items, parsed.cwd, nested, shell.processEnv, depth + 1, positional);
    // zsh's spelling of -n, which bash rejects: it may not run them.
    if (options.noexec !== undefined && options.noexec !== "") markUnsure(calls);
    return replaced(argv, subshell, shell, calls.map((call) => ({
      ...call,
      otherUser: call.otherUser || parsed.otherUser,
      layers: [...call.layers, layer],
    })));
  }
  if (name === undefined) return [];
  return replaced(argv, subshell, shell, [{ name, args, env, cwd: parsed.cwd, otherUser: parsed.otherUser, layers: [layer] }]);
}

/** The calls of a command, after which nothing runs when it ran through exec. */
function replaced(argv: string[], subshell: Maybe, shell: Shell, calls: Call[]): Call[] {
  replaceShell(argv, subshell, shell);
  return calls;
}

/** After a command run through exec, which replaces the shell, nothing runs; only maybe for one behind command. */
function replaceShell(argv: string[], subshell: Maybe, shell: Shell): void {
  const replacing = execsThrough(argv);
  if (replacing !== false) jumpFrom("exit", [], replacing === true || subshell === true ? subshell : undefined, shell);
}

/** Whether a command runs through exec: true for exec, or exec behind time or builtin; undefined behind command, which
 *  bash runs as the builtin and zsh looks up as a program; false otherwise. */
function execsThrough(argv: string[]): Maybe {
  let rest = argv.filter((word) => !isAssignment(word));
  let behindCommand = false;
  while (rest.length > 0 && ["command", "builtin", "time", "-p", "--"].includes(rest[0] as string)) {
    behindCommand ||= rest[0] === "command";
    rest = rest.slice(1);
  }
  return rest.length > 1 && rest[0] === "exec" ? (behindCommand ? undefined : true) : false;
}

/** A return, exit, break or continue where it runs: nothing beyond a subshell, and only maybe from the last command
 *  of a pipeline (`subshell` undefined), which ends its subshell in bash but runs in this shell in zsh. */
function jumpFrom(name: string, args: string[], subshell: Maybe, shell: Shell): void {
  if (subshell === true) return;
  const outside = liveness(shell);
  jump(name, args, shell);
  if (subshell === undefined) soften(outside, shell);
}

/** The calls one simple command makes, if it runs or may run, after the reserved words that lead it. */
function command(item: Item, shell: Shell, depth: number): Call[] {
  let argv = item.argv;
  let before = item.before;
  if (!["}", "fi", "done"].includes(argv[0] as string)) begin(before, shell);
  shell.openingPipe = before === "|";
  while (argv.length > 0 && KEYWORDS.has(argv[0] as string)) {
    // A body's first command is reached by its compound's pipe, which its own redirections then override.
    if (argv[0] !== "!" && argv[0] !== "function" && argv[0] !== "time") before = "";
    argv = keyword(argv, item, shell);
  }
  shell.openingPipe = false;
  const closed = shell.closed;
  shell.closed = undefined;
  if (closed !== undefined) closeFrame(closed, [closed.pipedIn, item.after === "|", item.io], shell, item.after === "&");
  let calls: Call[] = [];
  if (argv.length > 0) {
    shell.pipe.leading = false;
    if (shell.pipe.runs !== false) {
      // Under a condition, or an && or || after a status, that is not known, it may not have run.
      const sure = shell.pipe.runs === true && !doubt(shell.pipe) && !shell.frames.some((frame) => frame.doubt);
      const first = shell.calls.length;
      calls = simple(argv, item, before, shell, depth);
      if (!sure) {
        markUnsure(calls);
        markUnsure(shell.calls, first); // and what a function it called ran
      }
    }
  }
  if (argv.length > 0 || closed !== undefined) finish(item.after, shell);
  if (argv.length > 0) errexit(item.after, shell);
  return calls;
}

/** Walk items in this shell, adding each call that runs or may run to its calls. */
function walkItems(list: Item[], shell: Shell, depth: number): void {
  const outer: [Item[], number, Map<string, [string, number]>] = [shell.items, shell.at, shell.ends];
  shell.items = list;
  shell.ends = compoundEnds(list);
  for (let at = 0; at < list.length; at++) {
    shell.at = at;
    const item = list[at] as Item;
    if (item.kind === "cmd") shell.calls.push(...command(item, shell, depth));
    else marker(item, shell);
  }
  [shell.items, shell.at, shell.ends] = outer;
}

/** Where each compound in `list` ends, [operator after it, item], by where it opens ("item,word"): one piped or
 *  backgrounded at its end is a subshell, which no jump inside it leaves. */
function compoundEnds(list: Item[]): Map<string, [string, number]> {
  const ends = new Map<string, [string, number]>();
  const opened: string[] = [];
  list.forEach(({ kind, argv, after }, at) => {
    if (kind === "(" || kind === "$(" || kind === "case") opened.push(`${at},0`);
    else if ((kind === ")" || kind === "esac") && opened.length > 0) ends.set(opened.pop() as string, [after, at]);
    for (let k = 0; kind === "cmd" && k < argv.length && KEYWORDS.has(argv[k] as string); ) {
      const word = argv[k] as string;
      if ((word === "}" || word === "fi" || word === "done") && opened.length > 0) {
        ends.set(opened.pop() as string, [k === argv.length - 1 ? after : "", at]);
      } else if (word === "{" || word === "if" || LOOPS.includes(word)) {
        opened.push(`${at},${k}`);
        if (word === "for" || word === "select") break; // the rest is its header
      }
      k += word === "function" ? 2 : 1;
    }
  });
  return ends;
}

/** Whether the compound opening at `head`, in the item being read, is followed by && or ||. */
function endsList(head: Item, shell: Shell): boolean {
  const item = shell.items[shell.at] ?? head;
  const k = head.kind === "cmd" && item.kind === "cmd" ? item.argv.length - head.argv.length : 0;
  const after = shell.ends.get(`${shell.at},${k}`)?.[0];
  return after === "&&" || after === "||";
}

/** Whether set -e is ignored here: in a condition, or in a compound or function body run in an && or || list but as
 *  its last command, or behind a !. */
function exempt(shell: Shell): boolean {
  return shell.exempt > 0 || shell.frames.some((frame) => frame.exempt || frame.cond);
}

/** Under set -e, a command that surely fails where it is not ignored ends the shell or subshell; one whose status isn't
 *  known goes on. bash ignores set -e in a command substitution and zsh does not, so there it only may end it. */
function errexit(after: string, shell: Shell): void {
  const on = shell.vars[ERREXIT]?.[0] ?? "";
  if (on === "" || ["&&", "||", "|"].includes(after) || shell.status === 0 || shell.status === undefined ||
    shell.pipe.runs === false || shell.pipe.negate || exempt(shell)) return;
  const outside = liveness(shell);
  jump("exit", [], shell);
  if (on !== "1" || shell.frames.some((frame) => frame.kind === "$(")) {
    soften(outside, shell);
  }
}

/** Whether the compound opening at `head`, in the item being read, is piped or backgrounded at its end. */
function endsPiped(head: Item, shell: Shell): boolean {
  const item = shell.items[shell.at] ?? head;
  const k = head.kind === "cmd" && item.kind === "cmd" ? item.argv.length - head.argv.length : 0;
  const after = shell.ends.get(`${shell.at},${k}`)?.[0];
  return after === "|" || after === "&";
}

/** Each simple command that runs or may run; commands a literal true or false skips, untaken branches and function
 *  bodies are left out, and a function's body runs where it is called. */
/** A fresh shell has no positional parameters, and one a string runs gets the words after it. */
function walk(items: Item[], cwd: string | undefined, exported: Env, processEnv: Record<string, string | undefined>, depth: number, positional: string[] = []): Call[] {
  const vars = Object.fromEntries(Object.entries(exported).map(([key, value]): [string, Variable] => [key, [value, true]]));
  const shell: Shell = {
    cwd, vars, status: undefined, frames: [], function: undefined,
    start: [cwd, { ...vars }, new Map()], processEnv, calls: [], openingPipe: false,
    pipe: { before: "", prior: undefined, runs: true, negate: false, leading: false },
    functions: new Map(), callsLeft: MAX_CALLS, items, at: 0, live: true, floor: undefined, args: [...positional],
    ends: new Map(), names: namedSegments(items), scoped: [], exempt: 0,
  };
  walkItems(items, shell, depth);
  return shell.calls;
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

/** A URL as the tools read it: a scheme only at its start, and http when it has none. */
function urlText(url: string): string {
  const text = url.trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`;
}

/** The host a URL names, with any login, port and path dropped; empty when it names none, or when the tool does not
 *  speak its scheme. */
function urlHost(url: string, schemes: ReadonlySet<string>): string {
  try {
    // curl and wget reject a //host with no scheme, and a path names no host, though the URL standard reads one.
    if (url.trim().startsWith("/")) return "";
    const full = urlText(url);
    // A backslash is no part of a host, though the URL standard reads it as a slash.
    if (/^[^/]*:\/\/[^/?#]*\\/.test(full)) return "";
    const parsed = new URL(full);
    if (!schemes.has(parsed.protocol.slice(0, -1).toLowerCase())) return "";
    const host = parsed.hostname.toLowerCase();
    return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  } catch {
    return "";
  }
}

/** curl's URLs: sent to when their request uploads or sends data, else fetched from. Each --next starts a request,
 *  --resolve pins carry on, and globs reach every host unless --globoff; a rejected glob stops curl. */
/** A proxy or no_proxy variable as the tool sees it, undefined when unset: set or unset in the command, else inherited
 *  from the agent's environment. It only decides whether a host is looked up here, and is never sent. */
function proxySetting(env: Env, processEnv: Record<string, string | undefined>, name: string): string | undefined {
  if (name in env) return env[name];
  if (UNKNOWN_ENV in env) return SUBSTITUTED;
  return CLEAN_ENV in env ? undefined : processEnv[name];
}

/** Whether curl, wget, HTTPie or PowerShell finds a proxy in its environment, the command's or the agent's. */
function proxiedEnv(env: Env, processEnv: Record<string, string | undefined>): boolean {
  return PROXY_ENV.some((key) => Boolean(proxySetting(env, processEnv, key)));
}

/** The kind of proxy a curl proxy string names: its scheme, or `fallback` when it has none; empty for none. */
function proxyKind(value: string, fallback = "http"): string {
  const text = value.trim();
  if (text === "") return "";
  const kind = text.includes("://") ? (text.split("://")[0] as string).toLowerCase() : fallback;
  return kind === "https" ? "http" : kind;
}

/** Whether a proxy resolves a curl URL's name: HTTP, SOCKS4A and socks5h do, SOCKS4 and SOCKS5 resolve here, and an
 *  empty -x or a --noproxy (else no_proxy) entry turns it off. `kind` undefined is curl's environment proxy. */
function curlRemote(url: string, kind: string | undefined, noproxy: string | undefined, env: Env, processEnv: Record<string, string | undefined>): boolean {
  let parsed: URL;
  try {
    parsed = new URL(urlText(url));
  } catch {
    return false;
  }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  let proxy = kind;
  if (proxy === undefined) {
    const names = [`${scheme}_proxy`, ...(scheme === "http" ? [] : [`${scheme.toUpperCase()}_PROXY`]), "all_proxy", "ALL_PROXY"];
    proxy = proxyKind(names.map((name) => proxySetting(env, processEnv, name)).find((value) => value !== undefined) ?? "");
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  // --noproxy overrides a no_proxy or NO_PROXY the command set.
  const bypass = noproxy ?? ["no_proxy", "NO_PROXY"].map((name) => proxySetting(env, processEnv, name)).find((value) => value !== undefined) ?? "";
  // As curl reads the list: * alone bypasses every host, else entries split on commas and blanks, their dots aside.
  const entries = bypass.split(/[,\s]+/).map((entry) => entry.toLowerCase().replace(/^\.+|\.+$/g, ""));
  if (!proxy || bypass === "*" || entries.some((entry) => entry !== "" && (host === entry || host.endsWith(`.${entry}`)))) return false;
  return proxy !== "socks4" && proxy !== "socks5";
}

/** curl's URLs, sent to when their request uploads or sends data, else fetched from, each with whether a proxy
 *  resolves its name (it then gets the --connect-to target and no --resolve pin). */
function curl(args: string[], env: Env = {}, processEnv: Record<string, string | undefined> = {}): Raw[] {
  const raws: Raw[] = [];
  const pins: string[] = [];
  for (let i = 0; ; ) {
    const [urls, [sends, uploads, local], overrides, globoff, next, [kind, noproxy], scheme] = curlRequest(args, i);
    if (urls === undefined) return []; // curl reads every option before it sends anything
    pins.push(...overrides.filter(([option]) => option === "--resolve").map(([, value]) => value));
    const connects = overrides.filter(([option]) => option === "--connect-to").map(([, value]) => value);
    // Through --unix-socket or --abstract-unix-socket, the request reaches a local socket, not the URL's host.
    for (const [index, written] of (local ? [] : urls).entries()) {
      // The Nth -T uploads to the Nth URL; a URL past them is fetched unless the request sends a body.
      const out = sends || index < uploads;
      // A URL with no scheme takes --proto-default's, and so that scheme's port.
      const url = scheme && !/^\s*[a-z][a-z0-9+.-]*:\/\//i.test(written) ? `${scheme}://${written.trim()}` : written;
      const expanded = globoff ? [url] : curlGlob(url);
      if (expanded === undefined) return raws;
      for (const one of expanded) {
        const remote = curlRemote(one, kind, noproxy, env, processEnv);
        raws.push([out ? "out" : "in", urlHost(one, CURL_SCHEMES), undefined, curlDial(one, connects, remote ? [] : pins), remote]);
      }
    }
    if (next >= args.length) return raws;
    i = next;
  }
}

/** The URLs curl makes of one by expanding its {a,b} sets and [1-3] or [a-c] ranges, as far as they change the host;
 *  undefined for a glob curl rejects. */
function curlGlob(url: string): string[] | undefined {
  const pieces = globPieces(url);
  if (pieces === undefined) return undefined;
  let urls = [""];
  for (const [text, values] of pieces) {
    urls = urls.map((u) => u + text);
    // Past the host a glob only changes the path, so one of its values stands for all.
    const inHost = !urls.every((u) => /[/?#]/.test(u.includes("://") ? u.slice(u.indexOf("://") + 3) : u));
    urls = urls.flatMap((u) => (inHost ? values : values.slice(0, 1)).map((v) => u + v)).slice(0, MAX_WORDS);
  }
  return urls;
}

/** A curl URL as [literal text, the values of the glob after it] pieces, as curl reads {a,b}, [1-3] or [a-c] with a
 *  :step, a bracketed IPv6 address and backslash escapes; undefined for a glob it rejects. */
function globPieces(url: string): [string, string[]][] | undefined {
  const pieces: [string, string[]][] = [];
  let text = "";
  for (let i = 0; i < url.length; ) {
    const ch = url[i] as string;
    if (ch === "\\" && "{}[],".includes(url[i + 1] ?? "x")) {
      text += url[i + 1];
      i += 2;
      continue;
    }
    if (ch === "}" || ch === "]") return undefined; // a close with no open
    if (ch !== "{" && ch !== "[") {
      text += ch;
      i++;
      continue;
    }
    const close = ch === "{" ? "}" : "]";
    let end = i + 1;
    while (end < url.length && url[end] !== close) {
      if (url[end] === ch) return undefined; // a nested open
      end += url[end] === "\\" ? 2 : 1;
    }
    if (end >= url.length) return undefined;
    const body = url.slice(i + 1, end);
    if (ch === "[" && body.includes(":") && ipOf(body) !== "") {
      text += url.slice(i, end + 1); // an IPv6 address, not a range
    } else {
      const values = ch === "{" ? body.split(/(?<!\\),/).map((v) => v.replace(/\\(.)/g, "$1")) : globRange(body);
      if (values === undefined) return undefined;
      pieces.push([text, values]);
      text = "";
    }
    i = end + 1;
  }
  return [...pieces, [text, [""]]];
}

/** The values a curl [1-3], [01-10:2] or [a-c] range takes; undefined for one curl rejects. */
function globRange(body: string): string[] | undefined {
  const match = /^(?:(\d+)-(\d+)|([a-z])-([a-z])|([A-Z])-([A-Z]))(?::(\d+))?$/.exec(body);
  const step = match === null ? 0 : Number(match[7] ?? 1);
  if (match === null || step === 0) return undefined;
  const values: string[] = [];
  if (match[1] !== undefined) {
    const first = match[1];
    const width = first.startsWith("0") ? first.length : 0;
    for (let n = Number(first); n <= Number(match[2]) && values.length < MAX_WORDS; n += step) values.push(String(n).padStart(width, "0"));
  } else {
    const first = (match[3] ?? match[5]) as string;
    const last = (match[4] ?? match[6]) as string;
    for (let c = first.charCodeAt(0); c <= last.charCodeAt(0); c += step) values.push(String.fromCharCode(c));
  }
  return values.length > 0 ? values : undefined;
}

/** The IP address a string holds, brackets allowed, in the form the Python hooks print; empty when it holds none. */
function ipOf(text: string): string {
  const bare = text.trim().replace(/^\[+|\]+$/g, "");
  const family = isIP(bare);
  return family === 6 ? normalizeV6(bare) : family === 4 ? bare : "";
}

/** Where a URL's request connects, as curl applies the first matching --connect-to and then the last --resolve pin
 *  for that host and port, a named host before *; undefined when neither applies. */
function curlDial(url: string, connects: readonly string[], pins: readonly string[]): Dial | undefined {
  const host = urlHost(url, CURL_SCHEMES);
  let port: string;
  try {
    const parsed = new URL(urlText(url));
    port = parsed.port || String(DEFAULT_PORTS[parsed.protocol.slice(0, -1).toLowerCase()] ?? "");
  } catch {
    return undefined;
  }
  // Colons inside [ ] belong to an IPv6 address.
  const fields = (rule: string): string[] => rule.split(/:(?![^[]*\])/);
  let target: [string, string] = [host, port];
  for (const rule of connects) {
    const parts = fields(rule);
    const [from = "", fromPort = "", to = "", toPort = ""] = parts;
    if (parts.length === 4 && ["", host].includes(cleanHost(from)) && ["", port].includes(fromPort)) {
      target = [cleanHost(to) || host, toPort || port];
      break;
    }
  }
  const pinned = new Map<string, string[]>();
  for (const pin of pins) {
    const parts = fields(pin.replace(/^[+-]+/, ""));
    const key = `${parts[0] === "*" ? "*" : cleanHost(parts[0] ?? "")} ${parts[1] ?? ""}`;
    pinned.delete(key);
    if (!pin.startsWith("-") && parts.length > 2) {
      pinned.set(key, parts.slice(2).join(":").split(",").map(ipOf).filter((ip) => ip !== ""));
    }
  }
  const named = pinned.get(`${target[0]} ${target[1]}`) ?? [];
  const addresses = named.length > 0 ? named : (pinned.get(`* ${target[1]}`) ?? []);
  if (target[0] === host && addresses.length === 0) return undefined;
  return [addresses[0] ?? target[0], addresses];
}

/** A long option as getopt and curl up to 8.5 read it: the exact name, else the one option it starts; "" when it starts
 *  several, which the tool rejects, and the name as written when it starts none. */
function prefixed(name: string, options: ReadonlySet<string>): string {
  const word = name.slice(2);
  const hits = word === "" || options.has(word) ? [word] : [...options].filter((option) => option.startsWith(word));
  return hits.length === 1 ? `--${hits[0]}` : hits.length > 1 ? "" : name;
}

/** A curl long option, read ignoring case as curl up to 8.5 does; a --no- or --expand- form must be exact. */
function curlLong(name: string): string {
  const word = name.slice(2).toLowerCase();
  if (word === "" || /^(no|expand)-/.test(word)) return word === "" ? name : `--${word}`;
  return prefixed(`--${word}`, CURL_LONG_OPTIONS);
}

/** The curl request at args[start]: URLs (undefined when curl rejects it), [sends body, -T count, local socket],
 *  --resolve and --connect-to, globoff, next start, [proxy kind: '' off, undefined unnamed; --noproxy], scheme. */
function curlRequest(
  args: string[], start: number,
): [
  string[] | undefined, [boolean, number, boolean], [string, string][], boolean, number,
  [string | undefined, string | undefined], string,
] {
  const urls: string[] = [];
  const flags = new Set<string>();
  const overrides: [string, string][] = [];
  let method = "";
  // The kind of proxy the request names, empty for none and undefined when it names none, and its --noproxy value.
  let kind: string | undefined;
  let preproxy: string | undefined;
  let noproxy: string | undefined;
  let scheme = "";
  let uploads = 0;
  let local = false;
  let i = start;
  while (i < args.length) {
    let arg = args[i++] as string;
    if (arg === "--") {
      urls.push(...args.slice(i)); // every word after it is a URL, a --next too
      i = args.length;
      break;
    }
    let value: string | undefined;
    if (arg === "-:") break;
    if (arg.startsWith("--")) {
      // curl reads --name=value as --name value, and --expand-name as --name with variables expanded.
      const eq = arg.indexOf("=");
      if (eq >= 0) value = arg.slice(eq + 1);
      arg = curlLong(eq >= 0 ? arg.slice(0, eq) : arg);
      // curl rejects an option that starts several.
      if (arg === "") return [undefined, [false, 0, false], [], false, args.length, [undefined, undefined], ""];
      if (arg === "--next") break;
      if (arg.startsWith("--expand-")) arg = `--${arg.slice("--expand-".length)}`;
      if (eq < 0 && CURL_LONG_VALUES.has(arg) && i < args.length) value = args[i++];
    } else if (arg.startsWith("-") && arg.length > 1) {
      [arg, value, i] = shortOption(arg, args, i, CURL_SHORT_VALUES, flags);
    } else {
      urls.push(arg);
      continue;
    }
    flags.add(arg);
    for (const flag of CURL_UNDOES[arg] ?? []) flags.delete(flag);
    if (arg === "--url" && value) urls.push(value);
    else if ((arg === "-X" || arg === "--request") && value) method = value.toUpperCase();
    else if ((arg === "--resolve" || arg === "--connect-to") && value) overrides.push([arg, value]);
    else if (arg === "--preproxy" && value !== undefined) preproxy = proxyKind(value, "socks4a"); // curl sends a scheme-less one the name
    // An empty one turns the proxy off; a --socks option names its kind, and -x its URL's scheme.
    else if (Object.hasOwn(CURL_PROXIES, arg) && value !== undefined) kind = value.trim() === "" ? "" : CURL_PROXIES[arg] || proxyKind(value);
    else if (arg === "--noproxy" && value !== undefined) noproxy = value;
    else if (arg === "--proto-default" && value !== undefined) scheme = value.trim().toLowerCase();
    else if ((arg === "-T" || arg === "--upload-file") && value !== undefined) uploads++;
    else if ((arg === "--unix-socket" || arg === "--abstract-unix-socket") && value !== undefined) local = true;
  }
  const has = (set: ReadonlySet<string>): boolean => [...flags].some((f) => set.has(f));
  const sends = has(CURL_UPLOADS) || SENDING_METHODS.has(method) || (has(CURL_BODIES) && !flags.has("-G") && !flags.has("--get"));
  // Without -x, a --preproxy is the SOCKS proxy the request goes through.
  return [urls, [Boolean(sends), uploads, local], overrides, flags.has("-g") || flags.has("--globoff"), i, [kind ?? preproxy, noproxy], scheme];
}

/** wget's URLs: sent to when it posts data or a file; else fetched from. Each carries whether it goes through a proxy:
 *  one the command set or an -e proxy setting, unless --no-proxy or -e use_proxy=off turns proxies off. */
function wget(args: string[], proxied = false): Raw[] {
  const urls: string[] = [];
  const flags = new Set<string>();
  const settings = new Map<string, string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--") {
      urls.push(...args.slice(i)); // every word after it is a URL
      break;
    }
    let name: string | undefined;
    let value: string | undefined;
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      name = prefixed(eq < 0 ? arg : arg.slice(0, eq), WGET_LONG_OPTIONS);
      if (name === "") return []; // wget rejects an option that starts several, and fetches nothing
      value = eq < 0 ? undefined : arg.slice(eq + 1);
      if (eq < 0 && WGET_LONG_VALUES.has(name)) value = args[i++];
      flags.add(name);
    } else if (arg.startsWith("-") && arg.length > 1) {
      [name, value, i] = shortOption(arg, args, i, WGET_SHORT_VALUES, flags);
      flags.add(name);
    } else {
      urls.push(arg);
    }
    if ((name === "-e" || name === "--execute") && value) {
      const [key = "", ...setting] = value.replace(/ /g, "").toLowerCase().split("=");
      settings.set(key.replace(/_/g, ""), setting.join("="));
    }
  }
  const on = ["on", "yes", "1"].includes(settings.get("useproxy") ?? "on") && !flags.has("--no-proxy");
  const proxy = on && (proxied || ["httpproxy", "httpsproxy", "ftpproxy"].some((k) => Boolean(settings.get(k))));
  const direction = [...flags].some((f) => WGET_UPLOADS.has(f)) ? "out" : "in";
  return urls.map((url): Raw => [direction, urlHost(url, WGET_SCHEMES), undefined, undefined, proxy]);
}

/** (operands, the options that change which host or user ssh -G resolves) for ssh, scp or sftp; `switches` collects
 *  the flags such as -n, and the first -o StdinNull as StdinNull=yes, =no, or =bad for a value ssh rejects. */
function sshArgs(name: string, args: string[], switches = new Set<string>()): [string[], string[]] {
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
    [flag, value, i] = shortOption(arg, args, i, valueFlags, switches);
    const option = ((value ?? "").trim().split(/[\s=]/)[0] ?? "").toLowerCase();
    if (flag === "-o" && option === "stdinnull") {
      // The first counts. ssh takes yes or true and no or false, and runs nothing for any other value, wherever.
      const said = ((value ?? "").trim().split(/[\s=]+/).at(-1) ?? "").toLowerCase();
      const meaning: Record<string, string> = { yes: "yes", true: "yes", no: "no", false: "no" };
      const setting = Object.hasOwn(meaning, said) ? (meaning[said] as string) : "bad";
      if (setting === "bad" || (!switches.has("StdinNull=yes") && !switches.has("StdinNull=no"))) switches.add(`StdinNull=${setting}`);
    }
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
    if (arg === "--") {
      operands.push(...args.slice(i)); // every word after it is an operand
      break;
    }
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

/** ssh used as a pipe: sent to when its stdin is fed in, fetched from when its stdout is kept. -n, -f, which implies
 *  it, and a first -o StdinNull=yes keep stdin unread; ForkAfterAuthentication=yes still sends it. */
function sshPipe(args: string[], fed: boolean, receives: boolean): Raw[] {
  const switches = new Set<string>();
  const [operands, options] = sshArgs("ssh", args, switches);
  const destination = operands[0];
  if (destination === undefined || switches.has("StdinNull=bad")) return [];
  const sends = fed && !switches.has("-n") && !switches.has("-f") && !switches.has("StdinNull=yes");
  return ([["out", sends], ["in", receives]] as const).filter(([, used]) => used).map(([d]): Raw => [d, destination, options]);
}

/** nc's host, sent to when stdin is fed in; ncat --proxy or nc -x resolve it remotely unless ncat --proxy-dns
 *  local/both or nc -X 4 resolves it here; a listener reaches no host and -X without -x connects directly. */
function netcat(args: string[], sends: boolean): Raw[] {
  const positional: string[] = [];
  const flags = new Set<string>();
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--") {
      positional.push(...args.slice(i)); // every word after it is an operand
      break;
    }
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("="); // --proxy=host:port is --proxy
      const name = eq < 0 ? arg : arg.slice(0, eq);
      const value = eq >= 0 ? arg.slice(eq + 1) : NC_LONG_VALUES.has(name) ? (args[i++] ?? "") : "";
      flags.add(name);
      values.set(name, value.toLowerCase());
    } else if (arg.startsWith("-") && arg.length > 1) {
      let flag: string;
      let value: string | undefined;
      [flag, value, i] = shortOption(arg, args, i, NC_SHORT_VALUES, flags);
      flags.add(flag);
      values.set(flag, (value ?? "").toLowerCase());
    } else {
      positional.push(arg);
    }
  }
  if (positional[0] === undefined || ["-l", "--listen", "-U", "--unixsock"].some((f) => flags.has(f))) return [];
  let remote: boolean;
  if (flags.has("--proxy")) {
    const dns = values.get("--proxy-dns");
    remote = dns !== "local" && dns !== "both"; // SOCKS4 too sends ncat the name
  } else {
    remote = flags.has("-x") && values.get("-X") !== "4";
  }
  return [[sends ? "out" : "", positional[0], undefined, undefined, remote]];
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
    const target = socatTarget(address);
    if (target !== undefined) out.push([sends ? "out" : "", target[0], undefined, undefined, target[1]]);
  }
  return out;
}

/** [the host a socat address connects to, whether a proxy reaches it], read from its colon fields, a bracketed address
 *  being one field; undefined for an address that connects to none, or one socat rejects. */
function socatTarget(address: string): [string, boolean] | undefined {
  const [body = "", ...options] = address.split(/,(?![^[]*\])/);
  const [first = "", ...fields] = body.split(/:(?![^[]*\])/);
  const kind = first.toLowerCase();
  const optionNames = new Set(options.map((option) => (option.split("=")[0] as string).trim().toLowerCase()));
  // Each type's fields, the target's place among them, and whether a proxy reaches it. SOCKS4 sends the server an
  // address, so socat looks the target up itself; SOCKS4A and SOCKS5 send the name.
  const shapes: Record<string, [number, number, boolean]> = {
    proxy: [3, 1, true], "proxy-connect": [3, 1, true], socks4: [3, 1, false], socks4a: [3, 1, true],
    socks5: [4, 2, true], "socks5-connect": [4, 2, true],
  };
  let shape = Object.hasOwn(shapes, kind) ? shapes[kind] : undefined;
  if (shape === undefined && /^(?:tcp|udp|sctp|dccp|openssl|ssl)[46]?(?:-connect|-sendto|-datagram)?$/.test(kind)) {
    // A proxy option on a direct address is one socat refuses, so it connects nowhere.
    shape = optionNames.has("proxyport") || optionNames.has("socksport") ? undefined : [2, 0, false];
  }
  if (shape === undefined || fields.length !== shape[0]) return undefined;
  return [fields[shape[1]] as string, shape[2]];
}

/** Whether an HTTPie request item is data (=, :=, @, =@, :=@) rather than a header (:) or a query (==). */
function httpieItem(item: string): boolean {
  const match = /^(?:\\.|[^\\=:@])*(:=@|=@|:=|==|=|@|:)/.exec(item);
  return match !== null && match[1] !== "==" && match[1] !== ":";
}

function httpie(args: string[], sends: boolean, proxied = false): Raw[] {
  const positional: string[] = [];
  const flags = new Set<string>();
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--") {
      positional.push(...args.slice(i)); // every word after it is an operand
      break;
    }
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
  const host = url.startsWith(":") ? "localhost" : urlHost(url, HTTPIE_SCHEMES);
  // It goes through a proxy with --proxy or one the command set.
  return [[out ? "out" : "in", host, undefined, undefined, proxied || flags.has("--proxy")]];
}

/** The web cmdlet parameter a -Name binds to, as PowerShell resolves it: exact name or alias, else the one it prefixes,
 *  cmdlet's own first; empty when ambiguous and the name itself when it prefixes none. */
function psParameter(written: string): string {
  const name = written.toLowerCase();
  if (PS_OWN.has(name) || PS_COMMON.has(name)) return name;
  if (Object.hasOwn(PS_ALIASES, name)) return PS_ALIASES[name] as string;
  for (const group of [PS_OWN, PS_COMMON]) {
    const found = [...group].filter((parameter) => parameter.startsWith(name));
    if (found.length > 0) return found.length === 1 ? (found[0] as string) : "";
  }
  return name;
}

function webCmdlet(args: string[], sends: boolean, proxied = false): Raw[] {
  let uri = "";
  let out = sends;
  let proxy: boolean | undefined;
  const positional: string[] = [];
  for (let i = 0; i < args.length; ) {
    const arg = args[i++] as string;
    if (arg === "--") {
      positional.push(...args.slice(i)); // PowerShell's end of parameters: every word after it is an argument
      break;
    }
    if (!/^-[A-Za-z]/.test(arg)) {
      positional.push(arg);
      continue;
    }
    const colon = arg.indexOf(":");
    const name = psParameter(colon < 0 ? arg.slice(1) : arg.slice(1, colon));
    if (name === "") return []; // a name that starts several parameters, which PowerShell rejects
    let value = colon < 0 ? "" : arg.slice(colon + 1);
    // -Name: value binds the next word, even for a switch.
    if ((colon >= 0 ? value === "" : !PS_SWITCHES.has(name)) && i < args.length) value = args[i++] as string;
    if (name === "uri") uri = value;
    else if (name === "body" || name === "infile" || name === "form") out = true;
    else if ((name === "method" || name === "custommethod") && SENDING_METHODS.has(value.toUpperCase())) out = true;
    else if (name === "proxy") proxy = value !== "";
    // -NoProxy:$false, or a value not known here, leaves the proxy on.
    else if (name === "noproxy" && (colon < 0 || ["$true", "1"].includes(value.toLowerCase()))) proxy ??= false;
  }
  uri ||= positional[0] ?? "";
  // It goes through a proxy with -Proxy, or one the command set unless -NoProxy.
  return uri ? [[out ? "out" : "in", urlHost(uri, POWERSHELL_SCHEMES), undefined, undefined, proxy ?? proxied]] : [];
}

/** Whether a call's stdin is fed from a file or pipe, and whether its stdout goes to one, from the pipes and
 *  redirections around it applied as the shell does: the outermost first, each one's pipes before its redirections. */
function stdio(layers: readonly Layer[]): [boolean, boolean] {
  // The agent's own stdin and stdout carry no transfer.
  const fds = new Map<number, string>([[0, "null"], [1, "null"], [2, "null"]]);
  for (const [pipedIn, pipedOut, redirections] of [...layers].reverse()) {
    if (pipedIn) fds.set(0, "pipe");
    if (pipedOut) fds.set(1, "pipe");
    for (const [fd, value] of redirections) fds.set(fd, typeof value === "number" ? (fds.get(value) ?? "null") : value);
  }
  const fed = (fd: number): boolean => fds.get(fd) === "file" || fds.get(fd) === "pipe";
  return [fed(0), fed(1)];
}

/** The tool and its raw endpoints for a transfer command; undefined for any other. */
function parse(call: Call, processEnv: Record<string, string | undefined>): [string, Raw[]] | undefined {
  const tool = TOOLS[call.name];
  const [sends, keeps] = stdio(call.layers);
  let raw: Raw[];
  if (tool === "scp" || tool === "sftp" || tool === "rsync") raw = copy(tool, call.args, call.env, processEnv);
  else if (tool === "ssh") raw = sshPipe(call.args, sends, keeps);
  else if (tool === "curl") raw = curl(stdinArgs(tool, call.args, stdinText(call.layers)), call.env, processEnv);
  else if (tool === "wget") raw = wget(stdinArgs(tool, call.args, stdinText(call.layers)), proxiedEnv(call.env, processEnv));
  else if (tool === "nc") raw = netcat(call.args, sends);
  else if (tool === "socat") raw = socat(call.args, sends);
  else if (tool === "httpie") raw = httpie(call.args, sends, proxiedEnv(call.env, processEnv));
  else if (tool === "powershell") raw = webCmdlet(call.args, sends, proxiedEnv(call.env, processEnv));
  else return undefined;
  // Under sudo, ssh reads that user's config, which isn't known here, so the host is never looked up.
  const unknown = call.otherUser ? ["-F", SUBSTITUTED] : [];
  return [tool, raw.map(([d, dest, options, dial, proxied]): Raw => [d, dest, options && [...options, ...unknown], dial,
    proxied])];
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
/** Whether a Match line's criteria include exec, read as ssh reads them: each a keyword, negated with !, taking an
 *  argument after a space or = unless it is all, canonical or final. */
function matchExecs(words: readonly string[]): boolean {
  for (let i = 0; i < words.length; ) {
    const word = words[i] as string;
    const criterion = word.split("=")[0]?.toLowerCase().replace(/^!/, "") ?? "";
    if (criterion === "exec") return true;
    i += word.includes("=") || ["all", "canonical", "final"].includes(criterion) ? 1 : 2;
  }
  return false;
}

/** One ssh config line read as ssh reads it: [whether it is an Include, the files it names, resolved against every
 *  home and folder ssh may use]; undefined when it could run a command or a DNS lookup, or ssh may read it differently. */
function configLine(line: string, bases: readonly string[], homes: readonly string[]): [boolean, string[]] | undefined {
  // ssh joins no lines, but a line ending in a backslash is refused too, as a reader that joins them would differ.
  const odd = /[\x00-\x08\x0a-\x1f\x7f]/.test(line) || /\\[ \t]*$/.test(line);
  const lineWords = odd ? undefined : configWords(line);
  if (lineWords === undefined) return undefined;
  if (lineWords.length === 0) return [false, []];
  const [first = "", ...rest] = lineWords;
  const [word = "", attached = ""] = first.split(/=(.*)/s);
  const keyword = word.toLowerCase();
  // ssh allows `Keyword=value` and `Keyword =value`, so a leading = is only a separator.
  const args = (attached ? [attached, ...rest] : rest).map((w) => w.replace(/^=+/, "")).filter(Boolean);
  if (keyword === "match" && matchExecs(args)) return undefined;
  if (keyword === "canonicalizehostname" && ["yes", "always"].includes((args[0] ?? "").toLowerCase())) return undefined;
  if (keyword !== "include") return [false, []];
  const paths: string[] = [];
  for (const pattern of args) {
    const targets = includeTargets(pattern, bases, homes);
    if (targets === undefined) return undefined;
    paths.push(...targets);
  }
  return [true, paths];
}

/** The folder of the system config the ssh on PATH reads: its install prefix's etc/ssh, /etc/ssh for one in /usr, and
 *  PROGRAMDATA's ssh on Windows. */
function sshSystemDir(processEnv: Record<string, string | undefined>): string {
  if (process.platform === "win32") return join(processEnv.PROGRAMDATA ?? "", "ssh");
  const bin = (processEnv.PATH ?? "").split(delimiter).find((dir) => dir !== "" && isFile(join(dir, "ssh")));
  const prefix = dirname(bin ?? "/usr/bin");
  return prefix === "/usr" || prefix === "/" ? "/etc/ssh" : join(prefix, "etc", "ssh");
}

/** A small regular file's text, read once without blocking on a fifo; undefined when it is not one. Throws when it
 *  can't be opened. */
function readOnce(path: string): string | undefined {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > SSH_CONFIG_MAX_BYTES) return undefined;
    const buffer = Buffer.alloc(SSH_CONFIG_MAX_BYTES + 1);
    let size = 0;
    for (let n = 1; n > 0 && size < buffer.length; size += n) n = readSync(fd, buffer, size, buffer.length - size, null);
    return size > SSH_CONFIG_MAX_BYTES ? undefined : buffer.subarray(0, size).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/** ssh -G's options with -F set to a copy, in `folder`, of exactly the configs this read once and checked, with each
 *  Include pointed at the copies, so ssh reads nothing else; undefined when one could run a command or can't be checked. */
function vetted(options: readonly string[], home: string, processEnv: Record<string, string | undefined>, folder: string): string[] | undefined {
  // ssh reads ~/.ssh/config from the account's home but expands an Include's ~ and relative path with $HOME.
  const homes = [...new Set([home, processEnv.HOME || home])];
  const userBases = homes.map((h) => join(h, ".ssh"));
  if (options.length % 2 !== 0) return undefined;
  const configs: string[] = [];
  const rest: string[] = [];
  for (let i = 0; i < options.length; i += 2) {
    if (options[i] === "-F") configs.push(options[i + 1] as string);
    else rest.push(options[i] as string, options[i + 1] as string);
  }
  const config = configs.at(-1);
  if (config === "none") return [...options];
  if (config !== undefined && !isAbsolute(config)) return undefined;
  const system = sshSystemDir(processEnv);
  // ssh reads only a -F file; else the user's config, then the system's.
  const sources: [string, readonly string[]][] = config !== undefined
    ? [[config, userBases]]
    : [[join(home, ".ssh", "config"), userBases], [join(system, "ssh_config"), [system]]];
  const copies = new Map<string, string>();
  const queue: [string, readonly string[]][] = [];
  const copyOf = (path: string, bases: readonly string[]): string => {
    const key = JSON.stringify([path, bases]);
    let copy = copies.get(key);
    if (copy === undefined) {
      copy = join(folder, String(copies.size));
      copies.set(key, copy);
      queue.push([path, bases]);
    }
    return copy;
  };
  const tops = sources.map(([path, bases]) => copyOf(path, bases));
  while (queue.length > 0) {
    const [path, bases] = queue.shift() as [string, readonly string[]];
    if (copies.size > SSH_CONFIG_MAX_FILES) return undefined;
    let text: string | undefined;
    try {
      text = readOnce(path);
    } catch (error) {
      // ssh refuses a -F file that isn't there, and skips any other.
      if ((error as NodeJS.ErrnoException).code !== "ENOENT" || config !== undefined) return undefined;
      text = "";
    }
    if (text === undefined) return undefined;
    const lines: string[] = [];
    for (const raw of text.split("\n")) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      const read = configLine(line, bases, homes);
      if (read === undefined) return undefined;
      lines.push(!read[0] ? line : read[1].length > 0 ? `Include ${read[1].map((found) => `"${copyOf(found, bases)}"`).join(" ")}` : "");
    }
    writeFileSync(copies.get(JSON.stringify([path, bases])) as string, `${lines.join("\n")}\n`, { mode: 0o600 });
  }
  let top = tops[0] as string;
  if (config === undefined) {
    top = join(folder, "config");
    writeFileSync(top, tops.map((copy) => `Include "${copy}"\n`).join(""), { mode: 0o600 });
  }
  return ["-F", top, ...rest];
}

/** The host ssh connects to for a destination, read from ssh -G; empty when it can't be looked up safely. */
/** Whether ssh options send the connection through a jump host or a proxy command, which reach the host from there. */
function sshJumps(options: readonly string[]): boolean {
  for (let i = 0; i + 1 < options.length; i += 2) {
    const [flag, value] = [options[i] as string, options[i + 1] as string];
    if (flag !== "-J" && flag !== "-o") continue;
    const [key = "", setting = ""] = flag === "-J" ? ["proxyjump", value] : value.trim().split(/[\s=]+(.*)/s);
    if (["proxyjump", "proxycommand"].includes(key.toLowerCase()) && !["", "none"].includes(setting.trim().toLowerCase())) return true;
  }
  return false;
}

/** The user's and the system's ssh configs, as a command names them. */
const SSH_CONFIG_NAMES = /\.ssh\/config\b|ssh_config\b/;

/** Whether a call in the turn names an ssh config this lookup reads (user, system, or a -F file other than as -F);
 *  rewriting one can move an earlier transfer, as ssh -G reads configs only at turn end. */
function sshConfigNamed(options: readonly string[], state: State): boolean {
  const text = `${state.turnText}\n${state.callText}`;
  if (SSH_CONFIG_NAMES.test(text)) return true;
  const names = options.filter((v, i) => options[i - 1] === "-F" && v !== "none").map((v) => basename(v));
  const rest = text.replace(/-F\s*\S+/g, " ");
  return names.some((name) => name !== "" && namesWord(rest, name));
}

/** Whether `word` stands in `text` as a word of its own: no letter, digit, _, . or - right before or after it. */
function namesWord(text: string, word: string): boolean {
  const part = /[\w.-]/;
  for (let at = text.indexOf(word); at >= 0; at = text.indexOf(word, at + 1)) {
    if (!part.test(text[at - 1] ?? " ") && !part.test(text[at + word.length] ?? " ")) return true;
  }
  return false;
}

/** [the host ssh connects to for a destination, read from ssh -G, empty when it can't be looked up safely, whether
 *  ssh -G reports a jump host or proxy command for it]. */
async function sshHostname(destination: string, options: string[], cwd: string | undefined, state: State): Promise<[string, boolean]> {
  // The lookup runs elsewhere, so a relative config path is resolved against the folder the command ran in.
  // A HOME not known, or a ~ the shell left, which ssh reads as it is, as in rsync -e, names no file this can read.
  if (options.some((v, i) => options[i - 1] === "-F" && (v.startsWith("~") || v.startsWith(SUBSTITUTED)))) return ["", false];
  // A config it reads may have changed since the transfer, so neither ssh -G nor DNS runs.
  if (sshConfigNamed(options, state)) return ["", true];
  const resolved = options.map((value, i) => {
    if (options[i - 1] !== "-F") return value;
    return value === "none" || isAbsolute(value) || cwd === undefined ? value : join(cwd, value);
  });
  const key = JSON.stringify([destination, resolved]);
  const cached = state.sshHosts.get(key);
  if (cached !== undefined) return cached;
  state.sshHosts.set(key, ["", false]);
  // A destination starting with - would reach ssh -G as an option.
  if (destination.startsWith("-")) return ["", false];
  const out = (await run(["ssh", "-G", ...resolved, "--", destination.replace(/[[\]]/g, "")], state)) ?? "";
  const lines = out.split(/\r?\n/);
  const line = lines.find((l) => l.startsWith("hostname "));
  const found: [string, boolean] = [line === undefined ? "" : cleanHost(line.slice("hostname ".length)),
    // Some ssh versions print `proxyjump none` and `proxycommand none` for a host with neither.
    lines.some((l) => /^(?:proxyjump|proxycommand)\s+(?!none\s*$)\S/i.test(l))];
  state.sshHosts.set(key, found);
  return found;
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
async function address(host: string, state: State, lookup = true): Promise<AddressKind> {
  if (isIP(host) !== 0) return addressKind([host]);
  // Whatever an earlier call found: this one may not have run, or a proxy reaches the host.
  if (!lookup) return "unresolved";
  const cached = state.addresses.get(host);
  if (cached !== undefined) return cached;
  const remaining = state.deadline - state.now();
  const kind = addressKind(remaining > 0 ? await resolveAddresses(host, Math.min(DNS_TIMEOUT_MS, remaining), state) : []);
  state.addresses.set(host, kind);
  return kind;
}

/** public when any address is public, else the first address's kind; unresolved when there is none. */
function addressKind(found: readonly string[]): AddressKind {
  const kinds = found.map(kindOf);
  return kinds.length === 0 ? "unresolved" : kinds.includes("public") ? "public" : (kinds[0] as AddressKind);
}

/** One place a transfer reached: host as written without login, the host it connects to (ssh -G or curl's dial) and
 *  its address kind. Without lookup only a literal address is classified; a proxy or jump host's target never is. */
async function endpoint(raw: Raw, cwd: string | undefined, state: State, sure = true): Promise<TransferEndpoint | undefined> {
  const [direction, rawDestination, sshOptions, dial, proxied] = raw;
  let lookup = sure && proxied !== true;
  const destination = rawDestination.trim();
  const host = cleanHost(destination.includes("://") ? urlHost(destination, CURL_SCHEMES) : (destination.split("@").pop() ?? ""));
  if (host === "") return undefined;
  let resolved: string;
  let kind: AddressKind;
  if (dial !== undefined) {
    resolved = dial[0];
    kind = dial[1].length > 0 ? addressKind(dial[1]) : await address(dial[0], state, lookup);
  } else {
    lookup &&= !(sshOptions !== undefined && sshJumps(sshOptions));
    const [name, jumps] = sshOptions === undefined || !lookup ? ["", false] : await sshHostname(destination, sshOptions, cwd, state);
    // A failed or refused ssh -G leaves where a config sends the host unknown, so the host isn't looked up instead.
    const failed = sshOptions !== undefined && lookup && name === "";
    // Through a jump host or proxy command the bytes go where it sends them, not to the config's HostName.
    resolved = jumps || failed ? host : name || host;
    kind = failed ? "unresolved" : await address(resolved, state, lookup && !jumps);
  }
  const out: TransferEndpoint = { host, resolved_host: resolved, address: kind };
  return direction === "out" || direction === "in" ? { direction, ...out } : out;
}

/** Where one shell command's transfers went; undefined when it ran none. */
async function transferOf(command: string, cwd: string | undefined, state: State): Promise<Transfer | undefined> {
  state.callText = command;
  let tool: string | undefined;
  const endpoints: TransferEndpoint[] = [];
  let calls: Call[];
  try {
    calls = walk(new Lexer(command).read() ?? [], cwd, {}, state.env, 0);
  } catch {
    return undefined; // nested past MAX_NESTING, or unreadable: this call sends no transfer, and later calls still do
  }
  for (const call of calls) {
    const found = parse(call, state.env);
    for (const raw of found?.[1] ?? []) {
      if (endpoints.length >= MAX_ENDPOINTS) break;
      const one = await endpoint(raw, call.cwd, state, call.unsure !== true);
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
  /** The command before the audit cap, as `transferCommand` bounds it; read in place of `tool_input.command`. */
  transfer_command?: unknown;
  decision?: unknown;
  /** `false` when the call is known not to have run, such as a confirm the person declined. */
  ran?: unknown;
}

const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash", "powershell"]);
/** Policy outcomes under which the call never ran, so it moved nothing. */
const NEVER_RAN: ReadonlySet<string> = new Set(["deny", "unavailable"]);

/** Where each shell call of a turn sent to or fetched from, keyed by `tool_use_id`; each call starts in `cwd`.
 *  Never rejects. */
/** A shell command bounded for `transfer_command`: only past MAX_CHARS is cut, and a cut one is still skipped whole. */
export function transferCommand(command: string): string {
  return command.length > MAX_CHARS ? command.slice(0, MAX_CHARS + 1) : command;
}

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
      // Every call's input, so a turn that names an ssh config makes no ssh lookups.
      turnText: calls.map((call) => {
        try {
          const full = typeof call.transfer_command === "string" ? `${call.transfer_command}\n` : "";
          return full + (typeof call.tool_input === "string" ? call.tool_input : JSON.stringify(call.tool_input) ?? "");
        } catch {
          return "";
        }
      }).join("\n"),
      callText: "",
    };
    for (const call of calls) {
      const input = call.tool_input;
      const command = typeof call.transfer_command === "string"
        ? call.transfer_command
        : input !== null && typeof input === "object" && !Array.isArray(input) ? (input as Record<string, unknown>).command : undefined;
      if (typeof call.tool_name !== "string" || !SHELL_TOOLS.has(call.tool_name)) continue;
      if ((typeof call.decision === "string" && NEVER_RAN.has(call.decision)) || call.ran === false) continue;
      if (typeof command !== "string" || command.trim() === "" || typeof call.tool_use_id !== "string") continue;
      // A PowerShell tool's ; inside an @{ } hashtable separates its entries, not commands.
      const transfer = await transferOf(call.tool_name === "powershell" ? hashtablesEmptied(command) : command, cwd, state);
      if (transfer !== undefined) transfers.set(call.tool_use_id, transfer);
    }
  } catch {
    // Telemetry enrichment: whatever resolved before the failure is still returned.
  }
  return transfers;
}
