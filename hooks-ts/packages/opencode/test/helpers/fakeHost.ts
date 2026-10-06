// A fake opencode v1 host for the adapter's tests: a `PluginInput`-shaped object with a client whose
// toast is observable, the core mock API, and a `Deps` bundle that never touches the developer's
// real home, real env or the process-wide sentinel slot.

import { createFakeHome } from "../../../core/test/helpers/fakeHome.ts";
import { startMockApi } from "../../../core/test/helpers/mockApi.ts";
import type { CapturedRequest, MockApi, MockMode } from "../../../core/test/helpers/mockApi.ts";
import { TEST_KEY } from "../../../core/test/helpers/testKey.ts";
import { createScopedStates } from "../../../core/src/scopedState.ts";
import { createModuleToken } from "../../src/plugin.ts";
import type { Deps } from "../../src/plugin.ts";

export { TEST_KEY };

export type ToastMode = "resolve" | "hang" | "raise";

export interface ToastCall {
  message: string;
  variant: string;
  title?: string;
}

export interface FakeInput {
  input: {
    client: {
      tui: { showToast(opts: unknown): Promise<unknown> };
      session: { get(opts: unknown): Promise<unknown> };
    };
    directory: string | undefined;
    worktree: string | undefined;
    serverUrl: URL;
    project: { id: string };
  };
  toasts: ToastCall[];
}

export function makeFakeInput(opts: { directory?: string; toast?: ToastMode } = {}): FakeInput {
  const toasts: ToastCall[] = [];
  const mode = opts.toast ?? "resolve";
  const input = {
    client: {
      tui: {
        showToast(arg: unknown): Promise<unknown> {
          const body = (arg as { body?: ToastCall } | undefined)?.body;
          if (body !== undefined) toasts.push({ ...body });
          if (mode === "raise") throw new Error("toast raised");
          if (mode === "hang") return new Promise<unknown>(() => {});
          return Promise.resolve({ data: true });
        },
      },
      session: {
        get(): Promise<unknown> {
          return Promise.resolve({ data: undefined });
        },
      },
    },
    directory: "directory" in opts ? opts.directory : "/repo",
    worktree: "directory" in opts ? opts.directory : "/repo",
    serverUrl: new URL("http://127.0.0.1:4096"),
    project: { id: "proj" },
  };
  return { input, toasts };
}

export function startOpencodeMock(mode: MockMode = "allow"): Promise<MockApi> {
  return startMockApi({ mode });
}

export interface TestDeps {
  deps: Partial<Deps>;
  homeDir: string;
  cleanup(): void;
}

/**
 * `Deps` for one test: a temp home, an env naming the mock and a key, fresh scoped state, small
 * client timeouts, and a private sentinel symbol so no test claims the real process-wide slot.
 * `withKey: false` leaves every key source empty (no env key, a home with no config file).
 */
export function makeDeps(
  mock: Pick<MockApi, "url"> | undefined,
  overrides: Partial<Deps> & { withKey?: boolean } = {},
): TestDeps {
  const { withKey = true, ...rest } = overrides;
  const home = createFakeHome();
  const env: NodeJS.ProcessEnv = {};
  if (mock !== undefined) env.UNBOUND_GATEWAY_URL = mock.url;
  if (withKey) env.UNBOUND_OPENCODE_API_KEY = TEST_KEY;
  const sentinelKey = Symbol("unbound.opencode.test");
  const deps: Partial<Deps> = {
    env,
    homeDir: home.homeDir,
    scopes: createScopedStates(),
    timeouts: { pretoolMs: 2000, errorsMs: 2000, turnLogMs: 2000 },
    sentinelKey,
    moduleToken: createModuleToken(),
    // No real serial probe in tests: an unknown platform probes nothing and settles at once.
    identity: { platform: "unbound-test" },
    ...rest,
  };
  return {
    deps,
    homeDir: home.homeDir,
    cleanup() {
      home.cleanup();
      // A claimed slot is non-configurable (WR-04) and cannot be deleted; its key is private to
      // this test, so leaving it is harmless.
      try {
        delete (globalThis as Record<symbol, unknown>)[sentinelKey];
      } catch {
        // Non-configurable.
      }
    },
  };
}

/** Requests to `/v1/hooks/errors` whose single entry has `category`. */
export function signalsOf(mock: Pick<MockApi, "requests">, category: string): CapturedRequest[] {
  return mock.requests.filter((r) => {
    if (r.path !== "/v1/hooks/errors") return false;
    const errors = (r.body as { errors?: Array<{ category?: string }> } | undefined)?.errors;
    return Array.isArray(errors) && errors.some((e) => e?.category === category);
  });
}

export function pretoolRequests(mock: Pick<MockApi, "requests">): CapturedRequest[] {
  return mock.requests.filter((r) => r.path === "/v1/hooks/pretool");
}

export async function waitFor(predicate: () => boolean, timeoutMs = 2000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return predicate();
}

export function tick(ms = 50): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
