// One circuit breaker per gateway URL (CORE-04).
//
// A breaker counts consecutive failures of ONE gateway. In a host process that serves several
// project directories, two projects can point at different gateways; with a single shared breaker,
// one gateway being down would take the other out of circuit too, and its tool calls would be
// allowed without being checked for the length of the open window.
//
// The key is `normalizeGatewayUrl(baseUrl)` — the same normalisation the config layer applies before
// a URL is ever called. That gives both halves of the property:
//
//   * different gateways  -> different breakers: A's failures never open B's;
//   * one gateway, spelled differently (trailing slash, query, case of the host) -> ONE breaker, so
//     its failures add up to one count instead of being spread over several that never reach the
//     threshold.
//
// A URL the normaliser refuses (not https and not loopback http, carrying userinfo, unparseable) is
// never called by the client either, so it gets a private breaker that is not stored.
//
// This is the seam for a multi-directory adapter: it creates one registry and hands
// `createPolicyChecker({ breaker: registry.forUrl(baseUrl) })` the breaker for the URL that checker
// talks to. pi does not use it: pi builds one breaker per checker, which is already one per resolved
// base URL in a single-session process.
//
// Bounded and total like every `createKeyedState` registry. An evicted breaker simply starts closed
// again on its next use, which costs at most `threshold` real attempts against a gateway that is
// still down. No module-scope instance: each adapter owns its registry.

import { createBreaker, type Breaker } from "./breaker.ts";
import { normalizeGatewayUrl } from "./config.ts";
import { MAX_TRACKED_GATEWAYS } from "./constants.ts";
import { createKeyedState } from "./keyedState.ts";

export interface BreakerRegistry {
  /** The breaker for a gateway URL, created closed on first use. An unusable URL gets an unstored one. */
  forUrl(baseUrl: unknown): Breaker;
  size(): number;
  clear(): void;
}

export interface BreakerRegistryOptions {
  /** How many gateways are tracked. Defaults to `MAX_TRACKED_GATEWAYS`. */
  max?: number;
  /** Injected clock, passed to every breaker. Defaults to `Date.now`. */
  now?: () => number;
  /** Passed to every breaker; see `BreakerOptions`. */
  threshold?: number;
  /** Passed to every breaker; see `BreakerOptions`. */
  openMs?: number;
}

export function createBreakerRegistry(opts: BreakerRegistryOptions = {}): BreakerRegistry {
  const fresh = (): Breaker =>
    createBreaker({ now: opts?.now, threshold: opts?.threshold, openMs: opts?.openMs });

  const breakers = createKeyedState<Breaker>({
    max: opts?.max ?? MAX_TRACKED_GATEWAYS,
    normalizeKey: normalizeGatewayUrl,
    create: fresh,
    fallback: fresh,
  });

  return {
    forUrl: (baseUrl) => breakers.get(baseUrl),
    size: () => breakers.size(),
    clear: () => breakers.clear(),
  };
}
