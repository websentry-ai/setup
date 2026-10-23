# unbound-hook — Go rewrite (WEB-4809)

Phase 1 scaffold of a Go port of the PyInstaller `unbound-hook` binary in
`binary/`. Rationale: a single static Go binary avoids the PyInstaller
onedir bundle that EDR/AV agents flag and slow-scan on managed fleets.

## Contract

The CLI surface mirrors `binary/` exactly — see `binary/README.md` and
`binary/src/unbound_hook/main.py` / `hook_cmd.py`:

- `unbound-hook hook <tool> [<event>]` — tools: claude-code | cursor |
  copilot | codex. stdin event JSON → stdout response JSON. **Fail-open:**
  unknown tool, bad input, or any dispatcher failure prints `{}` and exits 0;
  this process sits between the user and their editor.
- `unbound-hook setup|backfill|clear` — admin commands, NOT fail-open;
  currently exit 1 with "not implemented".
- `unbound-hook --version` / `version` — `unbound-hook <version>`, never
  reads stdin (pkg postinstall pre-warm contract, packaging/README.md
  "Version contract"). Version is baked via `-ldflags "-X main.Version=..."`.

Phase 1 status: each tool handler is a fail-open stub (reads stdin, prints
`{}`, exits 0). The real per-tool ports come next; sources are named in the
TODO header of each `internal/hooks/*.go` file.

Phase 2 status: the shared core the four python hook modules duplicate is
ported as stdlib-only packages (not yet wired into the stubs). Each package
doc comment names the python lines it mirrors; `claude-code/hooks/unbound.py`
is the canonical reference:

- `internal/pyjson` — python-`json.dumps`-byte-identical encode/decode
  (ordered objects, ensure_ascii, repr(float)); required for stdout and
  audit-line parity, since Go's encoding/json formats differently
- `internal/config` — ~/.unbound/config.json + UNBOUND_GATEWAY_URL /
  UNBOUND_<TOOL>_API_KEY precedence (codex is env-only, quirk kept)
- `internal/httpc` — HTTP via curl subprocess (house rule: corporate-CA /
  Zscaler compat; never net/http), exact python argv, fail-open
- `internal/report` — error.log (25-line cap) + rate-limited best-effort
  POST to /v1/hooks/errors
- `internal/audit` — agent-audit.log JSONL load/append/save + session-keyed
  cleanup (grouping key is per tool, supplied by callers)
- `internal/locks` — mtime-TTL lock files (self-update lock, dispatch
  claim-and-steal, staleness probe, touch)
- `internal/transcript` — claude-code Stop-path transcript JSONL parsing
  (parse_transcript_file), including its abort-on-exception quirks

## Build & test

```
./build.sh      # Go 1.22+ + lipo: universal2 dist/unbound-hook/unbound-hook
                # UNBOUND_HOOK_VERSION=1.2.3 bakes the release version

UNBOUND_GO_BINARY=$PWD/dist/unbound-hook/unbound-hook \
  python3 -m pytest ../binary/tests/ -q     # opt-in tool×event parity
```

Stdlib only — zero Go dependencies.

The python path in `binary/` remains the golden reference; the parity
harness in `binary/tests/test_hook_cli.py` compares this binary's stdout +
exit code against `python3 <tool>/unbound.py` for every tool × event when
`UNBOUND_GO_BINARY` is set (skipped otherwise, so CI is unchanged).
