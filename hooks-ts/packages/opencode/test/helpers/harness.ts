// A small harness over the real plugin entry for the hook tests that need several hooks at once
// (`chat.message`, `event`, `tool.execute.before`, `tool.execute.after`, `shell.env`).

import assert from "node:assert/strict";

import type { MockApi, MockMode } from "../../../core/test/helpers/mockApi.ts";
import { createServerPlugin } from "../../src/plugin.ts";
import type { Deps } from "../../src/plugin.ts";
import { makeDeps, makeFakeInput } from "./fakeHost.ts";
import type { FakeInput, ToastMode } from "./fakeHost.ts";

export type AnyHook = (...args: unknown[]) => Promise<unknown>;
export type Hooks = Record<string, AnyHook | undefined>;

export interface Harness {
  hooks: Hooks;
  hook(name: string): AnyHook;
  fake: FakeInput;
  server: ReturnType<typeof createServerPlugin>;
  homeDir: string;
  /** Deliver one bus event to the `event` hook. */
  emit(type: string, properties: unknown): Promise<unknown>;
  cleanup(): void;
}

export interface HarnessOptions {
  directory?: string;
  toast?: ToastMode;
  deps?: Partial<Deps> & { withKey?: boolean };
  /** Runs against the temp home before the plugin is built (e.g. to drop an auth.json). */
  prepareHome?: (homeDir: string) => void;
}

export async function startHarness(mock: MockApi | undefined, mode: MockMode, opts: HarnessOptions = {}): Promise<Harness> {
  if (mock !== undefined) {
    mock.requests.length = 0;
    mock.setMode(mode);
    mock.setTurnLogMode("ok");
    mock.setErrorsMode("ok");
  }
  const t = makeDeps(mock, opts.deps ?? {});
  opts.prepareHome?.(t.homeDir);
  const server = createServerPlugin(t.deps);
  const fake = makeFakeInput({
    directory: opts.directory ?? "/repo",
    ...(opts.toast === undefined ? {} : { toast: opts.toast }),
  });
  const hooks = (await server(fake.input)) as Hooks;
  const hook = (name: string): AnyHook => {
    const fn = hooks[name];
    assert.equal(typeof fn, "function", `${name} is registered`);
    return fn as AnyHook;
  };
  return {
    hooks,
    hook,
    fake,
    server,
    homeDir: t.homeDir,
    emit: (type, properties) => hook("event")({ event: { type, properties } }),
    cleanup: t.cleanup,
  };
}

/** Resolves to the rejection message, or `undefined` if the promise resolved. */
export async function outcome(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (err) {
    assert.ok(err instanceof Error, "only Error instances are raised");
    return err.message;
  }
}

/** A Proxy whose every trap raises. */
export function hostile(): object {
  const raise = (): never => {
    throw new Error("hostile");
  };
  return new Proxy(
    {},
    {
      get: raise,
      has: raise,
      ownKeys: raise,
      getOwnPropertyDescriptor: raise,
      getPrototypeOf: raise,
      set: raise,
      defineProperty: raise,
      deleteProperty: raise,
      apply: raise,
      construct: raise,
      isExtensible: raise,
      preventExtensions: raise,
      setPrototypeOf: raise,
    },
  );
}

/** `session.created` properties for a session. */
export function created(id: string, extra: { parentID?: string; directory?: string; version?: string } = {}): unknown {
  return {
    sessionID: id,
    info: {
      id,
      directory: extra.directory ?? "/repo",
      version: extra.version ?? "1.18.34",
      ...(extra.parentID === undefined ? {} : { parentID: extra.parentID }),
    },
  };
}

export const OPENROUTER_MODEL = { providerID: "openrouter", modelID: "openai/gpt-4.1-nano" } as const;
