# Injection end-to-end harness

Proves skill injection against a real Claude Code process, not a mock of one.

```
python3 run_injection_e2e.py
```

Exits 0 on PASS. Takes a few minutes; it runs a real agent turn.

## What it proves

`run_injection_e2e.py` starts `stub_gateway.py` on a free port, points the real
`unbound.py` at it through `UNBOUND_GATEWAY_URL` and `UNBOUND_CLAUDE_API_KEY`, and runs
`claude -p` with a prompt whose command matches the stub's pattern. It then asserts:

1. the first matching tool call was denied and carried `inject_skills`
2. the slug was not reported as loaded on that first call
3. `~/.claude/skills/unbound-<slug>/SKILL.md` was written with the exact body the
   gateway sent, alongside the `.unbound-managed` marker
4. the retry reported the slug in `loaded_skills`, which only happens if the agent
   actually invoked the skill and the hook read that back out of the transcript
5. the retry was allowed and the original task completed

Assertion 4 is the one that cannot be faked. It cannot pass unless the agent obeyed the deny,
the harness-written transcript record appeared, and the hook's transcript scan found it.

## Why it writes to the real skills directory

Because production does. The install path is what is under test, and sandboxing `HOME`
would break the agent's own credentials.

The directory is removed on exit, and only when it carries the `.unbound-managed`
marker. An unmarked directory of the same name is reported and left alone, which is the
same ownership rule the hook itself follows.

Pass `--keep` to leave the workspace and the installed skill in place for inspection.

## Scope

The stub stands in for ai-gateway. It mirrors `resolveInjection` closely enough to drive
the device, and no further; the gateway's matching, caps, and precedence are unit-tested
in that repo. This harness owns the device half.
