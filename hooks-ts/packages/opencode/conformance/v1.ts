// Host-type conformance: the hand-written structural types in `../src/hostTypes.ts` against the
// REAL `@opencode-ai/plugin` types (CORE-05, Pitfall 10).
//
// Type-only, compile-time. It is NOT part of the root tsconfig and `@opencode-ai/plugin` is NOT a
// dependency of this repo: the nightly workflow (`hooks-ts-opencode-nightly.yml`, job `types-v1`)
// installs `@opencode-ai/plugin@latest` with `--no-save` and runs
//
//   npx tsc -p packages/opencode/conformance/tsconfig.json
//
// A red compile here means opencode changed a shape the adapter reads (or registers). The adapter
// treats every field as untrusted at runtime, so drift is not a crash, but it can be a hook that
// silently stops matching - which is exactly what this alarm exists to catch.
//
// Two directions are checked:
//
//   * what the host PASSES (hook inputs/outputs, `PluginInput`) must be assignable to what the
//     adapter DECLARES it reads, so every field the adapter relies on still exists with that type;
//   * what the adapter REGISTERS (each `HooksLike` handler, the `{ id, server }` module) must be
//     assignable to what the host ACCEPTS (`Hooks`, `PluginModule`).

import type { Hooks, PluginInput, PluginModule } from "@opencode-ai/plugin";

import type {
  ChatMessageInput,
  ChatMessageOutput,
  EventInput,
  HooksLike,
  PluginInputLike,
  ServerFactory,
  ShellEnvInput,
  ShellEnvOutput,
  ToolAfterInput,
  ToolAfterOutput,
  ToolBeforeInput,
  ToolBeforeOutput,
} from "../src/hostTypes.ts";

/** Fails to compile unless `T` is exactly `true`. */
type Assert<T extends true> = T;
/** `true` when `A` is assignable to `B` (non-distributive). */
type Extends<A, B> = [A] extends [B] ? true : false;

/** The function-valued hooks the adapter registers (`Hooks` also has object members: tool, auth, provider). */
type HookName = "tool.execute.before" | "tool.execute.after" | "chat.message" | "shell.env" | "event" | "config" | "dispose";
type Real<K extends HookName> = NonNullable<Hooks[K]>;
type In<K extends HookName> = Parameters<Real<K>>[0];
type Out<K extends HookName> = Parameters<Real<K>>[1];

// --- host -> adapter: what opencode passes is what the adapter reads --------------------------

export type HostPassesBeforeInput = Assert<Extends<In<"tool.execute.before">, ToolBeforeInput>>;
export type HostPassesBeforeOutput = Assert<Extends<Out<"tool.execute.before">, ToolBeforeOutput>>;
export type HostPassesAfterInput = Assert<Extends<In<"tool.execute.after">, ToolAfterInput>>;
export type HostPassesAfterOutput = Assert<Extends<Out<"tool.execute.after">, ToolAfterOutput>>;
export type HostPassesChatInput = Assert<Extends<In<"chat.message">, ChatMessageInput>>;
export type HostPassesChatOutput = Assert<Extends<Out<"chat.message">, ChatMessageOutput>>;
export type HostPassesShellEnvInput = Assert<Extends<In<"shell.env">, ShellEnvInput>>;
export type HostPassesShellEnvOutput = Assert<Extends<Out<"shell.env">, ShellEnvOutput>>;
export type HostPassesEvent = Assert<Extends<In<"event">, EventInput>>;
export type HostPassesPluginInput = Assert<Extends<PluginInput, PluginInputLike>>;

// --- adapter -> host: what the adapter registers is what opencode accepts ---------------------

export type RegistersBefore = Assert<Extends<NonNullable<HooksLike["tool.execute.before"]>, Real<"tool.execute.before">>>;
export type RegistersAfter = Assert<Extends<NonNullable<HooksLike["tool.execute.after"]>, Real<"tool.execute.after">>>;
export type RegistersChat = Assert<Extends<NonNullable<HooksLike["chat.message"]>, Real<"chat.message">>>;
export type RegistersShellEnv = Assert<Extends<NonNullable<HooksLike["shell.env"]>, Real<"shell.env">>>;
export type RegistersEvent = Assert<Extends<NonNullable<HooksLike["event"]>, Real<"event">>>;
export type RegistersConfig = Assert<Extends<NonNullable<HooksLike["config"]>, Real<"config">>>;
export type RegistersDispose = Assert<Extends<NonNullable<HooksLike["dispose"]>, Real<"dispose">>>;
export type RegistersHookSet = Assert<Extends<HooksLike, Hooks>>;
export type ModuleShape = Assert<Extends<{ id: string; server: ServerFactory }, PluginModule>>;
