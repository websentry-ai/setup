// Structural slices of the opencode v2 plugin API (`@opencode/plugin` 2.0.22, the version
// 14-SPIKES.md tested), hand-written.
//
// Why not import `@opencode/plugin`: it pulls `effect`, `zod`, `@opencode/{ai,client,protocol,
// schema,util}` (~280 packages) into the lockfile, and the bundle must stay dependency-free. These
// types claim only what this adapter reads or registers; every field is treated as untrusted at
// runtime anyway. `conformance/v2.ts` checks them against the real package (installed `--no-save`),
// in both directions. If opencode changes one of these shapes, that check is the drift alarm.
//
// Citations: `npm:` = the installed `@opencode/plugin@2.0.22` / `@opencode/client@2.0.22` packages;
// `log:` = a 14-SPIKES.md observation.
//
// Type-only: no runtime statement may appear in this file.

/** `Registration` (`npm:@opencode/plugin/dist/promise/registration.d.ts:1-3`). */
export interface V2Registration {
  dispose(): Promise<void>;
}

/** A hook callback may mutate its input and may return a Promise (`registration.d.ts:8`). */
export type V2HookCallback<E> = (input: E) => Promise<void> | void;

/** `tool.hook("execute.before")` input (`npm:…/promise/tool.d.ts:29-37`). `tool`/`input` are mutable. */
export interface V2ToolBefore {
  tool: string;
  sessionID: string;
  agent: string;
  messageID: string;
  /** The provider tool-call id; equals `permission.evaluate`'s `source.id` (`log:` V2-2). */
  id: string;
  input: unknown;
}

/** `tool.hook("execute.after")` input (`npm:…/promise/tool.d.ts:38-51`). */
export interface V2ToolAfter {
  tool: string;
  sessionID: string;
  agent: string;
  messageID: string;
  id: string;
  input: unknown;
  status: "completed" | "error";
  result?: unknown;
  error?: unknown;
}

/** `Permission.Effect` (`npm:@opencode/schema/dist/permission.d.ts:297`). */
export type V2PermissionEffect = "allow" | "deny" | "ask";

/** `Permission.Source` (`npm:@opencode/schema/dist/permission.d.ts:7-11`). */
export interface V2PermissionSource {
  type: "tool";
  messageID: string;
  id: string;
}

/**
 * `permission.hook("evaluate")` input (`npm:…/promise/permission.d.ts:6-15`). Called on every
 * `Permission.assert` with the computed effect (`allow` included). Mutating `effect`/`message` is
 * the deny / ask lever (14-SPIKES HV2-02, HV2-03).
 */
export interface V2PermissionEvaluate {
  sessionID: string;
  agent?: string;
  action: string;
  resources: ReadonlyArray<string>;
  metadata?: Record<string, unknown>;
  source?: V2PermissionSource;
  effect: V2PermissionEffect;
  message?: string;
}

/** `PromptInput.Prompt` (`npm:@opencode/schema/dist/prompt-input.d.ts`), a mutable structured clone. */
export interface V2PromptInput {
  text: string;
  files?: unknown[];
  agents?: unknown[];
  skills?: unknown[];
}

/**
 * `session.hook("prompt")` input (`npm:…/promise/session.d.ts:13-19`). No model, no parent marker:
 * a child prompt fires BEFORE the child's `session.created` (`log:` child-session probe). The mutated
 * `prompt` is what is persisted and sent (HV2-05 lever).
 */
export interface V2SessionPrompt {
  sessionID: string;
  messageID: string;
  prompt: V2PromptInput;
  metadata?: Record<string, unknown>;
  delivery: string;
}

/** `Model.Ref` (`npm:@opencode/schema/dist/model.d.ts:76`). */
export interface V2ModelRef {
  id: string;
  providerID: string;
  variant?: string;
}

/** `session.hook("model.request")` input (`npm:…/promise/session.d.ts:57-64`). HV2-07 source. */
export interface V2SessionModelRequest {
  sessionID: string;
  agent: string;
  model: V2ModelRef;
  kind: "primary" | "compaction" | "title" | "generate";
  baseURL?: string;
  headers: Record<string, string>;
}

/** `shell.hook("create.before")` input (`npm:…/promise/shell.d.ts:2-8`). No session id, no callID. */
export interface V2ShellCreateBefore {
  command: string;
  cwd: string;
  timeout: number;
  shell: string;
  env: Record<string, string | undefined>;
}

/** `SessionInfo` slice returned by `ctx.session.get({ sessionID })` (`npm:@opencode/client` types). */
export interface V2SessionInfo {
  id: string;
  parentID?: string;
  agent?: string;
  model?: V2ModelRef;
}

/** One bus event (`npm:@opencode/client` `V2Event`): only the envelope; `data` is read per type. */
export interface V2BusEvent {
  id: string;
  type: string;
  /** Absent on `server.connected`. */
  created?: number;
  location?: { directory: string };
  data: unknown;
}

// --- per-type event payloads the adapter reads (`npm:@opencode/client` `V2Event` members) --------

/** `session.created` `data` (`log:` V2-5). `version` is the host version (HV2-06). */
export interface V2SessionCreatedData {
  sessionID: string;
  parentID?: string;
  agent?: string;
  model?: V2ModelRef;
  version?: string;
}

/** `session.execution.succeeded` `data`: the turn end on 2.0.22 (`session.idle` is never emitted). */
export interface V2SessionExecutionSucceededData {
  sessionID: string;
}

/** `session.execution.interrupted` `data`. */
export interface V2SessionExecutionInterruptedData {
  sessionID: string;
}

/** `session.text.ended` `data`: the assistant text of one text part. */
export interface V2SessionTextEndedData {
  sessionID: string;
  assistantMessageID: string;
  text: string;
}

/** `session.step.started` `data`: the model of a step. */
export interface V2SessionStepStartedData {
  sessionID: string;
  model: V2ModelRef;
}

/** `session.step.ended` `data`: tokens and cost of a step. */
export interface V2SessionStepEndedData {
  sessionID: string;
  finish: string;
  cost: unknown;
  tokens: unknown;
}

/** `session.tool.input.started` `data`: the only tool event that carries the tool name. */
export interface V2SessionToolInputStartedData {
  sessionID: string;
  id: string;
  name: string;
}

/** `session.tool.failed` `data`. */
export interface V2SessionToolFailedData {
  sessionID: string;
  id: string;
  error: unknown;
}

/** `mcp.status.changed` `data`. */
export interface V2McpStatusChangedData {
  server: string;
}

// --- the ctx domains the adapter uses ----------------------------------------------------------

export interface V2ToolHooks {
  "execute.before": V2ToolBefore;
  "execute.after": V2ToolAfter;
}

export interface V2PermissionHooks {
  evaluate: V2PermissionEvaluate;
}

export interface V2SessionHooks {
  prompt: V2SessionPrompt;
  "model.request": V2SessionModelRequest;
}

export interface V2ShellHooks {
  "create.before": V2ShellCreateBefore;
}

/** `ctx.<domain>.hook(name, cb, options?)` (`registration.d.ts:8-11`). */
export type V2Hook<Spec> = <Name extends keyof Spec>(name: Name, callback: V2HookCallback<Spec[Name]>) => Promise<V2Registration>;

export interface V2ToolDomainLike {
  hook: V2Hook<V2ToolHooks>;
}

export interface V2PermissionDomainLike {
  hook: V2Hook<V2PermissionHooks>;
}

export interface V2SessionDomainLike {
  hook: V2Hook<V2SessionHooks>;
  /** `SessionApi.get` (`npm:@opencode/client/dist/promise/client.d.ts`); `.parentID` marks a child. */
  get(input: { sessionID: string }): Promise<V2SessionInfo>;
}

export interface V2ShellDomainLike {
  hook: V2Hook<V2ShellHooks>;
}

export interface V2EventDomainLike {
  subscribe(options?: { signal?: AbortSignal }): AsyncIterable<V2BusEvent>;
}

/** The argument the adapter passes to `ctx.mcp.list` (`McpListInput`, `npm:@opencode/client` 2.0.24). */
export interface V2McpListInput {
  location?: { directory?: string };
}

export interface V2McpDomainLike {
  /** `McpApi.list` → `{ data: [{ name, status }] }` (empty before servers connect, `log:` V2-3). */
  list(input?: V2McpListInput): Promise<{ data: Array<{ name: string }> }>;
}

/** `App` (`npm:@opencode/plugin/dist/app.d.ts`). */
export interface V2AppLike {
  name: string;
  version: string;
  channel: string;
}

/**
 * The slice of `Plugin.Context` (`npm:…/promise/plugin.d.ts:25-53`) the adapter reads. Every key is
 * optional: a 1.18 host's embedded core ctx lacks `tool`/`permission`/`session` (Phase 13 rule), and
 * the adapter checks each before use.
 */
export interface V2ContextLike {
  app?: V2AppLike;
  location?: { directory: string };
  tool?: V2ToolDomainLike;
  permission?: V2PermissionDomainLike;
  session?: V2SessionDomainLike;
  shell?: V2ShellDomainLike;
  event?: V2EventDomainLike;
  mcp?: V2McpDomainLike;
}

/** `Cleanup` (`npm:…/promise/plugin.d.ts:54`). */
export type V2Cleanup = () => Promise<void> | void;

/** The v2 `setup` entry as registered (`Plugin.setup`, `npm:…/promise/plugin.d.ts:55-58`). */
export type V2SetupEntry = (ctx: unknown) => Promise<V2Cleanup | undefined>;
