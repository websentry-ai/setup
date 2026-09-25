# unbound-hooks-ts

Unbound policy hooks for TypeScript coding agents. `packages/core` holds the transport-shaped
logic (API key / gateway URL resolution, `/v1/hooks/pretool` payload building, a client that
never throws, verdict mapping, failure telemetry) and `packages/pi` is a thin adapter that turns
[pi](https://github.com/earendil-works/pi) extension events into those core calls and the
resulting verdict into in-editor behaviour. `npm run build` bundles both into a single
dependency-free ESM file at `dist/pi/index.js`, which pi loads from
`~/.pi/agent/extensions/unbound/index.js` on Node >= 22.19.0.

Tested against **pi 0.87.1**. `@earendil-works/pi-coding-agent` is a **devDependency pinned to
`0.87.x` for types only** — the built file must import nothing from it at runtime, because a value
import would inline the whole agent and its bare (non-`node:`) imports cannot resolve under pi's
jiti loader.

## Commands

| Command | What it does |
| --- | --- |
| `npm run typecheck` | `tsc -p tsconfig.json` (no emit) across both packages, tests and scripts |
| `npm run build` | esbuild -> `dist/pi/index.js` (ESM, `node22`, bundled, nothing external) |
| `npm run test:unit` | `node --test --experimental-strip-types` over `packages/*/test/*.test.ts` |
| `npm run test:build` | the INST-05 build assertions against a built `dist/pi/index.js` |
| `npm test` | `typecheck` + `build` + `test:unit` |
| `npm run mock-api` | standalone scripted mock gateway for the manual pi smoke test |

Tests always use **explicit globs**, never bare directories: on Node 22 `node --test <dir>` treats
the directory as an entry-point module and aborts the whole run.

## Cross-package import rule

Modules import each other by **relative `.ts` path**, never by package name:

```ts
// packages/pi/src/decide.ts
import type { Verdict } from "../../core/src/verdict.ts";
```

`allowImportingTsExtensions` makes that typecheck and esbuild bundles it. Importing
`@unbound/hooks-core` through the npm-workspace symlink would break every test, because Node's
`--experimental-strip-types` refuses to strip types for files resolved inside `node_modules/`.
`packages/core` and `packages/pi` therefore declare no dependency on each other.

## Contract the built file must keep

- **Fail-open**: an API failure (timeout, network error, non-2xx, malformed JSON) allows the tool.
  A thrown handler blocks in pi, so every handler catches everything.
- **Headless blocks**: when `ctx.hasUI === false`, an `ask` / `approval_required` verdict blocks,
  because there is no way to prompt.
