// `AgentProfile` — the only place an agent identity enters core.
//
// Core is the decision pipeline every adapter shares: payload, client, verdict, fail-open, breaker,
// revoked-key latch, cache, turn record, telemetry. What differs between agents is a short list of
// facts — the label on the wire, the turn-log route, which env var holds the key, where the agent
// keeps its files, which of its tools take a path, how it stores a sign-in. Those facts are this
// contract. An adapter package builds one profile and passes it to core; core never names an agent.
//
// **Why inject a profile instead of copying core per agent.** The resilience code (breaker,
// revoked-key latch, fail-closed carve-out, egress allowlist, the turn log's hash-only rule) is where
// the review findings landed. Two copies would drift on exactly the behaviours that matter.
//
// **Every function on a profile must be total.** Core calls them on the decision path, and an
// exception that escapes there reaches a host handler — where, in pi, a throw out of a `tool_call`
// handler is a BLOCK whose message leaks to the model. A profile function answers a safe default
// (`undefined`, `"<agent>/unknown"`) for any input, including a hostile one; it never throws.
//
// Type-only module: no runtime code, so importing it adds nothing to a bundle. Core may not import
// from an adapter package; adapter packages import from core.

/** Which of an agent's native tools are evaluated on a file path, and how to read that path. */
export interface AgentFileTools {
  /** path optional → defaults to cwd (pi: grep, find, ls) */
  readonly defaulting: ReadonlySet<string>;
  /** path required (pi: read, write, edit) */
  readonly required: ReadonlySet<string>;
  /** the raw path argument for a file tool call (pi: input.path); total, may return anything */
  pathOf(toolName: string, input: Record<string, unknown>): unknown;
}

/** What an agent's credential store says about the current sign-in. Never leaves the process. */
export interface AgentAuthSummary {
  /** provider the session is signed in with, when knowable */
  provider: string | undefined;
  /** an entry exists for `provider` in the agent's store */
  hasCredential: boolean;
  /** that entry is an Anthropic subscription (OAuth) sign-in */
  anthropicOAuth: boolean;
  /** in memory only, for the one profile request */
  accessToken?: string;
  expiresAt?: number;
}

export interface AgentProfile {
  /** `unbound_app_label` on the wire ("pi") */
  readonly appLabel: string;
  /** `hook_source` on `/v1/hooks/errors`, and the `<hookSource> hook <category>` message prefix ("pi") */
  readonly hookSource: string;
  /** the turn-log route, appended to the gateway base URL ("/v1/hooks/pi") */
  readonly turnLogPath: `/v1/hooks/${string}`;
  /** the agent-specific key env var, read before `UNBOUND_API_KEY` ("UNBOUND_PI_API_KEY") */
  readonly envApiKey: string;
  /** the heartbeat metadata key that carries the agent version ("pi_version") */
  readonly versionMetadataKey: string;
  /** `client_entrypoint`: "<agent>/<version>", or "<agent>/unknown" ("pi/0.87.1") */
  resolveClientEntrypoint(env: NodeJS.ProcessEnv, argv1?: string): string;
  /** the agent's own data directory (absolute), or `undefined` when no safe base exists */
  resolveAgentDir(env: NodeJS.ProcessEnv, homeDir: string): string | undefined;
  readonly fileTools: AgentFileTools;
  /** optional: an agent with no readable credential store omits it, and no account identity is sent */
  readAuth?(agentDir: string | undefined, modelProvider: string | undefined): AgentAuthSummary | undefined;
}
