// Host-type conformance: the hand-written structural types in `../src/hostTypesV2.ts` against the
// REAL `@opencode/plugin@2.0.x` types (the version 14-SPIKES.md tested: 2.0.22).
//
// Type-only, compile-time. It is NOT part of the root tsconfig and `@opencode/plugin` is NOT a
// dependency of this repo: install it with `--no-save` (locally, or in the nightly job) and run
//
//   npx tsc -p packages/opencode/conformance/tsconfig.v2.json
//
// A red compile here means opencode changed a shape the v2 entry reads (or registers). Two
// directions are checked, as in v1.ts:
//
//   * what the host PASSES (hook inputs, `Plugin.Context`, bus events) must be assignable to what
//     the adapter DECLARES it reads;
//   * what the adapter REGISTERS (each handler, the `{ id, setup }` module) must be assignable to
//     what the host ACCEPTS.

import type { V2Event } from "@opencode/client";
import type { Plugin } from "@opencode/plugin";
import type { PermissionHooks } from "@opencode/plugin/promise/permission";
import type { Hooks } from "@opencode/plugin/promise/registration";
import type { SessionHooks } from "@opencode/plugin/promise/session";
import type { ShellHooks } from "@opencode/plugin/promise/shell";
import type { ToolDomain } from "@opencode/plugin/promise/tool";

import type {
  V2BusEvent,
  V2ContextLike,
  V2HookCallback,
  V2McpListInput,
  V2McpStatusChangedData,
  V2PermissionEvaluate,
  V2SessionCreatedData,
  V2SessionExecutionFailedData,
  V2SessionExecutionInterruptedData,
  V2SessionExecutionSucceededData,
  V2SessionModelRequest,
  V2SessionPrompt,
  V2SessionStepEndedData,
  V2SessionStepStartedData,
  V2SessionTextEndedData,
  V2SessionToolFailedData,
  V2SessionToolInputStartedData,
  V2SetupEntry,
  V2ShellCreateBefore,
  V2ToolAfter,
  V2ToolBefore,
} from "../src/hostTypesV2.ts";

/** Fails to compile unless `T` is exactly `true`. */
type Assert<T extends true> = T;
/** `true` when `A` is assignable to `B` (non-distributive). */
type Extends<A, B> = [A] extends [B] ? true : false;

/** `ToolHooks` is not exported; recover it from `ToolDomain["hook"]`. */
type ToolHooks = ToolDomain["hook"] extends Hooks<infer Spec> ? Spec : never;
/** The payload of one bus event type. */
type DataOf<T extends string> = Extract<V2Event, { type: T }>["data"];
/** A host hook callback type for one hook. */
type HostCallback<E> = (input: E) => Promise<void> | void;

// --- host -> adapter: what opencode passes is what the adapter reads --------------------------

export type ToolHooksRecovered = Assert<Extends<"execute.before" | "execute.after", keyof ToolHooks>>;
export type HostPassesToolBefore = Assert<Extends<ToolHooks["execute.before"], V2ToolBefore>>;
export type HostPassesToolAfter = Assert<Extends<ToolHooks["execute.after"], V2ToolAfter>>;
export type HostPassesEvaluate = Assert<Extends<PermissionHooks["evaluate"], V2PermissionEvaluate>>;
export type HostPassesPrompt = Assert<Extends<SessionHooks["prompt"], V2SessionPrompt>>;
export type HostPassesModelRequest = Assert<Extends<SessionHooks["model.request"], V2SessionModelRequest>>;
export type HostPassesShellCreate = Assert<Extends<ShellHooks["create.before"], V2ShellCreateBefore>>;
export type HostPassesContext = Assert<Extends<Plugin.Context, V2ContextLike>>;
export type HostPassesBusEvent = Assert<Extends<V2Event, V2BusEvent>>;
export type HostPassesSessionCreated = Assert<Extends<DataOf<"session.created">, V2SessionCreatedData>>;
export type HostPassesExecSucceeded = Assert<Extends<DataOf<"session.execution.succeeded">, V2SessionExecutionSucceededData>>;
export type HostPassesExecInterrupted = Assert<
  Extends<DataOf<"session.execution.interrupted">, V2SessionExecutionInterruptedData>
>;
export type HostPassesExecFailed = Assert<Extends<DataOf<"session.execution.failed">, V2SessionExecutionFailedData>>;
export type HostPassesTextEnded = Assert<Extends<DataOf<"session.text.ended">, V2SessionTextEndedData>>;
export type HostPassesStepStarted = Assert<Extends<DataOf<"session.step.started">, V2SessionStepStartedData>>;
export type HostPassesStepEnded = Assert<Extends<DataOf<"session.step.ended">, V2SessionStepEndedData>>;
export type HostPassesToolInputStarted = Assert<
  Extends<DataOf<"session.tool.input.started">, V2SessionToolInputStartedData>
>;
export type HostPassesToolFailed = Assert<Extends<DataOf<"session.tool.failed">, V2SessionToolFailedData>>;
export type HostPassesMcpStatus = Assert<Extends<DataOf<"mcp.status.changed">, V2McpStatusChangedData>>;

// --- adapter -> host: what the adapter registers is what opencode accepts ---------------------

export type RegistersToolBefore = Assert<
  Extends<V2HookCallback<V2ToolBefore>, HostCallback<ToolHooks["execute.before"]>>
>;
export type RegistersToolAfter = Assert<Extends<V2HookCallback<V2ToolAfter>, HostCallback<ToolHooks["execute.after"]>>>;
export type RegistersEvaluate = Assert<
  Extends<V2HookCallback<V2PermissionEvaluate>, HostCallback<PermissionHooks["evaluate"]>>
>;
export type RegistersPrompt = Assert<Extends<V2HookCallback<V2SessionPrompt>, HostCallback<SessionHooks["prompt"]>>>;
export type RegistersModelRequest = Assert<
  Extends<V2HookCallback<V2SessionModelRequest>, HostCallback<SessionHooks["model.request"]>>
>;
export type RegistersShellCreate = Assert<
  Extends<V2HookCallback<V2ShellCreateBefore>, HostCallback<ShellHooks["create.before"]>>
>;
/**
 * The argument the adapter passes to `ctx.mcp.list` is one the host's `McpApi.list` accepts, and the
 * answer carries `data[].name` (14-REVIEW WR-06).
 */
type HostMcpList = Plugin.Context["mcp"]["list"];
export type PassesMcpListInput = Assert<Extends<V2McpListInput, NonNullable<Parameters<HostMcpList>[0]>>>;
export type HostMcpListNames = Assert<Extends<Awaited<ReturnType<HostMcpList>>["data"][number]["name"], string>>;
/** The `setup` the module exports is a valid `Plugin.setup`. */
export type ModuleShape = Assert<Extends<{ id: string; setup: V2SetupEntry }, Plugin.Plugin>>;
