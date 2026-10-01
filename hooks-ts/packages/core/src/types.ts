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
// Type-only file. Core imports no agent SDK, even as a type, so every adapter package reuses it
// unchanged.

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
  /**
   * Set from `AgentProfile.appLabel`. A plain string here on purpose: which labels exist is the
   * server's decision (`KNOWN_APP_LABELS`), not this type's.
   */
  unbound_app_label: string;
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
   * Explicit MCP attribution. Becomes `metadata.mcp_server` / `metadata.mcp_tool`, the API's
   * explicit-attribution contract (PLAT-12). Only the adapter knows a call is an MCP call; core never
   * infers this from a tool name. Each name is sent only when it is a non-blank string of at most
   * `MAX_MCP_NAME_CHARS`; `mcp_tool` only alongside a valid `mcp_server`.
   */
  mcp?: { server: string; tool: string };
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
