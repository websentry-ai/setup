---
name: identify-drift
description: Find out whether what a coding tool did locally is what we actually recorded. Compares each tool's own transcripts and our hook's audit log against gateway_metrics, prompts and prompt_analytics, and reports where the loss happened. Use when a hook may be dropping prompts, tool calls or tokens, or after changing hook capture logic.
---

# Identify drift

A tool writes its own transcript. Our hook watches and logs what it sees. The gateway
stores what we upload. When those three disagree, we are losing data, and the
direction of the disagreement says where.

This is how queued prompts and unattributed subagent tokens were found.

---

## 1. Ask, in this order

Ask all of it before doing any work. Use one AskUserQuestion per item so the answers
stay separable.

**Environment.** `development`, `staging`, or `production`.

**Window.** How many days back. **Maximum 14.** Refuse a larger number and ask again;
scanning further is slow and the audit log will not reach that far anyway.

**Tools.** Any combination of `claude-code`, `cursor`, `copilot`, `codex`, `augment`.
Offer multi-select.

**Email.** Whose activity to check. If `~/.unbound/config.json` holds an `email`,
offer it as the default rather than asking cold.

---

## 2. Get a database connection

This skill never carries connection details. It takes a DSN and uses it; where that
DSN comes from is the operator's business, and for anything other than a local
development database it should be a read-only role reached through the company's
normal audited access path.

**Never ask for, type, or echo a password.** This skill runs inside the hooks it is
checking: what you put in a prompt or a Bash command is captured into the transcripts,
the audit log and the stored prompt rows that the comparison then reads. A password
handled here would be sitting in the very data being audited. `compare.py` refuses a
DSN that carries one, in the userinfo and in the query string alike. If a connection
needs a password, the operator puts it in `~/.pgpass` (which libpq requires be
owner-only) or names a file with `?passfile=`, and the DSN stays passwordless.

The DSN is the only thing that decides where this connects and how. `compare.py`
starts psql from an environment stripped of every `PG*` variable, so an inherited
`PGHOST`, `PGSSLMODE` or `PGSERVICE` cannot send it somewhere the DSN did not name.
Anything but a loopback host gets `sslmode=verify-full` unless the DSN names a mode
itself, so the server is authenticated and not merely encrypted to. Pass
`?sslrootcert=` alongside it when the certificate needs a specific root. The modes
that allow a plaintext session are refused outright.

**development.** A local Postgres. Read the database name, user, host and port from
`ai-gateway-data/.env` (`DATABASE_NAME`, `DATABASE_USER`, `DATABASE_HOST`,
`DATABASE_PORT`) and build a passwordless DSN from those. Do not read or copy
`DATABASE_PASSWORD`. Do not assume names; they differ between machines.

**staging / production.** Ask the operator to open their usual read-only tunnel and
to say when it is up. The tunnel authenticates them, so its DSN is host, port, user
and database only. Wait for them; never open a tunnel yourself and never complete an
MFA prompt on their behalf. If they ask how, point them at the internal
database-access runbook rather than repeating it here.

Production rows are customer data. Keep them in the run: do not write them to disk
beyond the temporary files this skill uses, and keep the excerpts in the report to the
few characters a finding needs to be actionable.

## 3. Run the scan

```bash
WORK=$(mktemp -d)                       # not /tmp directly: the scan quotes transcripts
trap 'rm -rf "$WORK"' EXIT              # and there is no reason to leave them behind

python3 .claude/skills/identify-drift/scan_local.py \
  --tools <tools> --days <n> --out "$WORK/local.json"

export IDENTIFY_DRIFT_DSN="<passwordless dsn>"      # never on the command line:
                                                   # arguments are visible in ps
python3 .claude/skills/identify-drift/compare.py \
  --local "$WORK/local.json" \
  --email "<email>" --environment "<env>" \
  --out "$WORK/report.json"                        # not a shell redirect: that
                                                   # would use the umask
```

If it refuses the `psql` it found, that is the check working, not a bug. Whoever can
write the binary, the file a symlink points at, or any directory above either, can
change what this hands the database connection to. A package-manager prefix is often
shared this way.

`--psql` names a different one; it is checked the same way, so it is a way to point at
a better binary and not a way to skip the question. If the operator has no such binary
and accepts the risk, `--allow-shared-psql` runs the shared one and says on stderr
which path was accepted. Ask them before using it, and never reach for it to make a
refusal go away.

`--out` creates both files owner-only, and refuses a symlink at the destination. The
scan holds every prompt and reply in the window and the report quotes excerpts from
it, so do not put either in a shared directory and do not keep them after the report
is read.

Only `development` shows prompt text. `staging` and `production` show a digest, and
`--redact` forces the same anywhere. `--environment` accepts those three spellings
only, so a typo cannot quietly turn redaction off.

`scan_local.py` reads each tool's transcripts and our audit log. `compare.py` queries
the database and diffs the three.

---

## 4. What the two sides are

You do not need to read the scripts to work here. This is everything they know.

**Local.** `scan_local.py` normalises every tool into one record shape: `kind`, `session`,
`at`, plus `text`, `tool`, `call_id`, or token counts. `kind` is one of `user_prompt`,
`assistant_message`, `tool_call`, `usage`, `usage_total`, `turn_end`.

The scanner asks every tool for a timestamp and a tool-call id. The last column is
what a tool does not actually write, measured, not what the reader fails to look for.

| Tool | Transcripts | Recognised by | Does not write |
|---|---|---|---|
| claude-code | `~/.claude/projects/*/*.jsonl` | `type` user/assistant; `tool_use` blocks in `message.content`; `message.usage` per message | |
| cursor | `~/.cursor/projects/*/agent-transcripts/*/*.jsonl` | `role`; blocks typed `tool_use` or `toolUse` | **timestamps, tool ids**, tokens. Records carry `role` and `message` and nothing else, so age comes from the file's mtime and calls can only be counted |
| copilot | `~/.copilot/session-state/*/events.jsonl` and `~/Library/Application Support/Code/User/workspaceStorage/*/GitHub.copilot-chat/transcripts/*.jsonl` | `type` `user.message`, `assistant.message`, `tool.execution_start`; `data.toolName`, `data.toolCallId` | tokens |
| codex | `~/.codex/sessions/*/*/*/rollout-*.jsonl` | `payload.type` `message` or `function_call`; session id from a `session_meta` line | per-message tokens, only a running `token_count` |
| augment | none | keeps no transcript | everything except the audit log |

Every tool writes the same audit log, `~/.<tool>/hooks/agent-audit.log`, keyed on
`hook_event_name`: `PreToolUse`, `PostToolUse`, `UserPromptSubmit` or
`beforeSubmitPrompt`, `Stop`. It holds its last hundred entries, which is usually
under an hour.

**Stored.** Everything hangs off one join. `app_label` is the tool, and it is the join
key: four tools use their own name, augment is `augment_code`. Get it wrong and every
query returns nothing.

```
gateway_users.id  ←  applications.owner_user_id
applications.id   ←  gateway_metrics.application_id
gateway_metrics.id ←  prompts.gateway_metrics_id
                   ←  prompt_analytics.gateway_metrics_id
```

| Wanted | Where |
|---|---|
| the window | `gateway_metrics.request_initialized_at`. There is no `created_at` |
| tokens | `gateway_metrics.input_token_size`, `output_token_size` |
| prompts | `prompts.prompt`, a JSON object with `user_prompt` and `assistant_prompt` |
| tool calls | `prompt_analytics.tool_name`, and `parameters->>'tool_use_id'` where present |
| sessions | `prompt_analytics.thread_id` |
| the user | `gateway_users.email`, matched case-insensitively |

**What is compared.** Tokens, user prompts, assistant messages, tool calls, sessions.
Prompts match on a sha256 of the whitespace-normalised text, computed the same way on
both sides, so no prompt text crosses the wire. Tool calls match on `tool_use_id` when
both sides carry one, and by count when they do not.

---

## 5. What the comparison means

The audit log keeps only its last hundred entries, often under an hour. `scan_local.py`
records the window it still covers, and both audit checks run only inside it: the
database side is queried for that same interval, so a stored row from days earlier
cannot stand in for a recently lost one. Outside the window a missing audit entry has
aged out; it is not evidence.

Tool calls are matched by `tool_use_id` when both sides record one, and counted when
they do not. Counting cannot tell one call from another of the same name, so a run
that had to count says so, and a clean result from it is weaker than a clean match.

Direction tells you where to look:

| Gap | Meaning |
|---|---|
| in transcript, not in audit log | the hook never saw it, a capture bug |
| in audit log, not in the database | the upload lost it, ingest or network |
| in the database, not locally | duplicate, or attributed to the wrong user |

Some findings are structural, not faults. Expect them, say so once, and do not
investigate them:

| Finding | Why it is expected |
|---|---|
| cursor: tool calls reconciled by count | its transcripts carry no ids, so identity matching is impossible |
| codex: token totals not reconciled | it reports a running total per turn, not a delta per message |
| augment: no transcript to compare | it keeps none, so only the upload direction is checkable |
| any tool: could not be checked for this window | an aggregate hit the row cap. Re-run over fewer days |
| any tool: audit log is full | it holds a hundred entries, so absence from it is not evidence |

A token difference under 5% is not reported. Above it, the usual cause is work billed
to no turn: subagent messages outside the turn window, or turns that never uploaded.

---

## 6. Report

Header first, then the points. Nothing else.

```
Identify drift: <environment>
Window   <n> days (since <date>)
Tools    <comma separated>
User     <email>

<n> issue(s)
```

Then one block per issue, in this shape, at most a short paragraph each:

```
1. <what is wrong, one line>
   Where     <file or table the gap is between>
   Evidence  <counts, and one concrete example>
   Why       <the mechanism, one or two sentences>
```

Order by how much is missing, most first. Name the tool in each title when more than
one was scanned.

If nothing is wrong, the whole report is the header plus `No issues found.` Do not pad
it with what you checked.

Do not recommend fixes unless asked. This skill reports; the ticket decides.
