// The wire contract, declared locally.
//
// `PretoolRequestBody` mirrors ai-gateway `src/handlers/preToolUseHandler.ts:350-382` (RESEARCH §B1)
// narrowed to what Phase 8 sends: the Phase-9 / Future fields (`account_identity`, `repo_gate`,
// `first_approval_check`, `pull_policies`, `user_prompts`) are intentionally absent from the type so
// they cannot be added by accident.
//
// `account_identity` has since joined the type (parity with the Claude Code hook): optional, and
// only ever set through `withAccountIdentity`, which forwards the six wire strings and nothing else.
//
// `PretoolPayloadInput.mcp` is the one input that changes the body's SHAPE: an MCP call handed over
// by the pi-mcp-adapter approval broker goes to the gateway's MCP path (Path 3) as
// `tool_name: "mcp__<server>__<tool>"` with `metadata.mcp_server` / `mcp_tool` / `tool_input` (the
// arguments, whole up to 1 MiB) and, when the config could be read unambiguously,
// `mcp_server_config`. The native-tool allowlist still governs every other call; MCP arguments are
// the one explicit exception.
//
// Type-only file. Core stays free of any `@earendil-works/*` import, even a type-only one, so a
// future opencode adapter can reuse it unchanged.

import type { AccountIdentity } from "./accountIdentity.ts";

export interface PretoolMessage {
  role: "user";
  content: string;
}

export interface PreToolUseData {
  tool_name: string;
  /** May be `''` — file tools send a `metadata.file_path` instead (§B3). */
  command: string;
  tool_use_id?: string;
  metadata: Record<string, unknown>;
}

export interface PretoolRequestBody {
  conversation_id: string;
  model: string;
  /** Always `'tool_use'` in Phase 8. */
  event_name: string;
  pre_tool_use_data: PreToolUseData;
  /** Required by the server type; may be an empty array. */
  messages: PretoolMessage[];
  unbound_app_label: "pi";
  client_entrypoint?: string;
  /**
   * Ask the response to carry the policy payload (RES-03).
   *
   * **Only honoured on the command-policy path** (§C2): `handleCommandPolicy` attaches
   * `tools_to_check` when this is set, while `handleGuardrails` — the `user_prompt` path —
   * deliberately omits it so a prompt check cannot clobber the tool cache, and the unrecognised-event
   * fall-through carries no policy payload at all. So the field is meaningful on a genuine tool call
   * and inert everywhere else; it is never sent as `false`, because an absent key and a false one
   * mean the same thing to the server and the shorter body is the honest one.
   */
  pull_policies?: boolean;
  /**
   * RES-05. Read at `preToolUseHandler.ts:860` → `:2239`, where it suppresses **duplicate
   * Slack-approval logging** and nothing else — in particular it has no effect on `tools_to_check`
   * (§C2). Sent on the heartbeat because 09-CONTEXT locks it and because it is the honest description
   * of a session's first contact; it is deliberately not sent on ordinary tool calls, where
   * suppressing approval logging would be wrong.
   */
  first_approval_check?: boolean;
  /** Who pi is signed in as (`preToolUseHandler.ts` `account_identity`). Absent when unknown. */
  account_identity?: AccountIdentity;
}

/** The four-value response enum (`DECISION`, `preToolUseHandler.ts:278-283`). */
export type Decision = "allow" | "deny" | "ask" | "approval_required";

/**
 * Phase 8 parses `decision` and `reason` only; everything else is opaque (§B2), hence the index
 * signature. `decision` is typed `string` deliberately — the response is untrusted input (ASVS V5)
 * and an unrecognised value must fall back to allow rather than be assumed valid.
 */
export interface PreToolResponseBody {
  decision: string;
  reason?: string;
  /** `'allow' | 'block'` in practice; Phase 8 stores the last-seen value in memory. */
  policy_check_failure_action?: string;
  tools_to_check?: string[];
  [key: string]: unknown;
}

/**
 * The structural input `packages/pi` passes in. Core never sees a pi type.
 *
 * `model` is `string | undefined` because `ctx.model` is `Model | undefined` (§A4); the builder
 * substitutes `'auto'` rather than sending `undefined` on a required field.
 */
export interface PretoolPayloadInput {
  toolName: string;
  command: string;
  toolUseId?: string;
  toolInput: Record<string, unknown>;
  cwd: string;
  sessionId: string;
  model: string | undefined;
  clientEntrypoint: string;
  lastUserPrompt?: string;
  /** Sets `pull_policies` on the body when true; when false or absent the key is omitted. */
  pullPolicies?: boolean;
  /** The process's settled account identity, when known. */
  accountIdentity?: AccountIdentity;
  /**
   * A resolved MCP call (see the header). When set, `toolName`/`command`/`toolInput` no longer shape
   * the body: the builder sends the Path-3 MCP shape instead. Absent for every native/custom tool.
   */
  mcp?: McpCallInfo;
}

/**
 * One MCP call as the pi-mcp-adapter approval broker describes it — the adapter's own resolution of
 * (server, original tool, args), never re-derived here — and what the MCP branch of
 * `buildPretoolPayload` consumes.
 */
export interface McpCallInfo {
  /** The configured server name, verbatim (the broker's `serverName`). */
  server: string;
  /** The MCP tool's ORIGINAL name (the broker's `originalToolName`). */
  tool: string;
  /** The arguments the tool will receive. Sent whole up to 1 MiB, never redacted (gateway DLP). */
  args: Record<string, unknown>;
  /**
   * The server's config as `{url, type?}` or `{command, args?, type?}`, read from the adapter's config
   * files by exact server name — the same fields the Claude Code hook sends. `env`, `headers`, bearer
   * tokens and OAuth settings are never read into it, but a `url` query string or an `args` entry can
   * itself carry a credential, and is sent as written, exactly as the Python hook sends it. Absent
   * when any config source was unreadable, imports were in play, or the server was not found.
   */
  serverConfig?: Record<string, unknown>;
  /** The broker's `origin`: `proxy` | `direct` | `script` | `resource` | `iframe`. Audit only. */
  origin?: string;
}

/**
 * The structural input for a **prompt** check (HOOK-05). Separate from `PretoolPayloadInput` because
 * a prompt has no tool semantics at all: no tool name, no command, no tool input, no file path.
 * Sharing one input type would make every one of those absences an optional field somebody could
 * accidentally fill.
 *
 * `images` is absent on purpose and must stay that way: `InputEvent.images` is base64 image data,
 * potentially megabytes, that nothing server-side reads (§F5).
 */
export interface PromptPayloadInput {
  prompt: string;
  cwd: string;
  sessionId: string;
  model: string | undefined;
  clientEntrypoint: string;
  hasUI: boolean;
  pullPolicies?: boolean;
  accountIdentity?: AccountIdentity;
}
