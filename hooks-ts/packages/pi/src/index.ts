// The Unbound policy extension for pi. Be honest about what this is:
//
//   * **It is fail-open.** If the Unbound API times out, refuses the connection, answers non-2xx or
//     returns unparseable JSON, the tool call is ALLOWED and the bypass is self-reported. The single
//     exception is an organisation whose last successful response asked for block-on-failure. A
//     policy engine that cannot be reached must not stop a developer working; that trade-off is the
//     product decision, and every bypass leaves an audit trail rather than silence.
//   * **It can never throw.** pi does not guard the handlers it calls: an exception escaping one is
//     treated as a decision to BLOCK, and the exception text is handed to the model as the tool
//     result. Both handler bodies below therefore open `try` before their first statement, with
//     nothing computed, read from `ctx`, or awaited outside it — key resolution and the payload
//     build both touch the filesystem and can fail with EACCES.
//   * **Without a UI it blocks on confirmation.** Under `pi -p` / `--mode json` there is nobody to
//     ask, so a verdict that needs confirmation blocks with an explanatory reason instead of
//     silently allowing or silently denying.
//   * **Without an API key it does nothing at all.** No requests, no verdicts, no blocks — just one
//     notice at session start.
//
// Everything else in the extension — the file tools, the shell-escape path, prompt checks, the turn
// log, the session heartbeat and the on-disk policy cache — is Phase 9. Only the two events below
// are registered; no placeholder handlers.
//
// Built and tested against pi 0.87.1 on Node >= 22.19.0.

import { homedir } from "node:os";

import type { ExtensionAPI, ExtensionFactory } from "@earendil-works/pi-coding-agent";

import { createApiClient } from "../../core/src/client.ts";
import { NO_KEY_NOTICE } from "../../core/src/constants.ts";
import { resolveApiKey, resolveGatewayUrl } from "../../core/src/config.ts";
import { resolveClientEntrypoint } from "../../core/src/piVersion.ts";
import { createPolicyChecker } from "../../core/src/policy.ts";
import type { PolicyChecker } from "../../core/src/policy.ts";
import { policyState } from "../../core/src/policyState.ts";
import { createTelemetry } from "../../core/src/telemetry.ts";
import { decideToolCall } from "./decide.ts";
import { notifySafe } from "./ui.ts";

/** The injectable seam. Production uses every default; tests replace what they need to observe. */
export interface Deps {
  env: NodeJS.ProcessEnv;
  homeDir: string;
  makeChecker(apiKey: string, baseUrl: string): PolicyChecker;
  /** `undefined` means "resolve the pi version lazily, on first use". */
  entrypoint: string | undefined;
}

interface Resolved {
  apiKey: string | undefined;
  entrypoint: string;
  /** Absent exactly when no key resolved — the inactive state. */
  checker: PolicyChecker | undefined;
}

/** The real composition: one client shared by the policy path and the bypass reporter. */
function defaultMakeChecker(apiKey: string, baseUrl: string): PolicyChecker {
  const client = createApiClient({ baseUrl, apiKey });
  return createPolicyChecker({
    client,
    state: policyState,
    telemetry: createTelemetry({ client, apiKey }),
  });
}

function safeHomeDir(): string {
  try {
    return homedir();
  } catch {
    return "";
  }
}

export function createExtension(overrides: Partial<Deps> = {}): ExtensionFactory {
  const deps: Deps = {
    env: overrides.env ?? process.env,
    homeDir: overrides.homeDir ?? safeHomeDir(),
    makeChecker: overrides.makeChecker ?? defaultMakeChecker,
    entrypoint: overrides.entrypoint,
  };

  let resolved: Resolved | undefined;
  let notified = false;

  /**
   * Lazy and cached. pi loads extensions in invocations that never start a session, and the docs
   * are explicit that the factory must not do work (§A1/§F9) — so the filesystem is first touched
   * by a handler, not at load time.
   */
  function init(): Resolved {
    if (resolved === undefined) {
      const apiKey = resolveApiKey(deps.env, deps.homeDir);
      resolved = {
        apiKey,
        entrypoint: deps.entrypoint ?? resolveClientEntrypoint(deps.env, process.argv[1]),
        checker:
          apiKey === undefined
            ? undefined
            : deps.makeChecker(apiKey, resolveGatewayUrl(deps.env, deps.homeDir)),
      };
    }
    return resolved;
  }

  return (pi: ExtensionAPI) => {
    pi.on("session_start", async (_event, ctx) => {
      try {
        const state = init();
        // One notice per extension instance. pi clears the module cache on `/reload`, so a reload
        // legitimately produces a fresh notice (§A7).
        if (state.apiKey === undefined && !notified) {
          notified = true;
          notifySafe(ctx, NO_KEY_NOTICE, "info");
        }
      } catch {
        // Startup is never worth failing.
      }
      return undefined;
    });

    pi.on("tool_call", async (event, ctx) => {
      try {
        const state = init();
        // No key ⇒ inert. Never a block, never a request (RES-06).
        if (state.apiKey === undefined || state.checker === undefined) return undefined;
        return await decideToolCall(event, ctx, {
          checker: state.checker,
          apiKey: state.apiKey,
          entrypoint: state.entrypoint,
        });
      } catch {
        // The fail-open net of last resort: allow, rather than let pi read an exception as a block.
        return undefined;
      }
    });
  };
}

/** What pi actually loads. */
export default createExtension();
