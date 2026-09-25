// The wire contract, declared locally.
//
// `PretoolRequestBody` mirrors ai-gateway `src/handlers/preToolUseHandler.ts:350-382` (RESEARCH §B1)
// narrowed to what Phase 8 sends: the Phase-9 / Future fields (`account_identity`, `repo_gate`,
// `first_approval_check`, `pull_policies`, `user_prompts`) are intentionally absent from the type so
// they cannot be added by accident.
//
// Type-only file. Core stays free of any `@earendil-works/*` import, even a type-only one, so a
// future opencode adapter can reuse it unchanged.

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
}
