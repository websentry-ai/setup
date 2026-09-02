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

## 1. What to settle before scanning

Settle these without asking where you can. The point is a quick answer, so only put a
question to the operator when the answer is not already on the machine.

**Email.** Whose activity to check. `~/.unbound/config.json` holds an `email`; use it.
Ask only when that file has none, and ask for nothing else at the same time.

**Environment.** `staging` unless the operator said production, or said something only
production can answer. Prod rows are customer data.

**Tools.** Any of `claude-code`, `cursor`, `copilot`, `codex`, `augment`. Default to
the ones this machine actually has transcripts for rather than asking; scanning a tool
that was never used costs a directory listing and finds nothing.

**Window.** 7 days unless the operator named one. **Maximum 14** -- refuse a larger
number, because the audit log will not reach that far anyway.

---

## 2. Get a database connection

**Use the `access-db` skill.** Prefer the copy in the sibling `ai-gateway-data`
repository (`../ai-gateway-data/.claude/skills/access-db`); fall back to the one in
the operator's own config (`~/.claude/skills/access-db`). It exists so this skill does
not have to ask anything about connections: it prints one command, the operator runs
it and completes the MFA prompt, and the tunnel is up. Never open a tunnel yourself
and never complete an MFA prompt on somebody's behalf.

The ports and names are fixed, so nothing here needs a question:

| Env | Command for the operator to run | DSN once it is up |
|---|---|---|
| staging | `tsh proxy db gateway-data-staging-read-replica --db-user=reporting_ro --db-name=gateway_staging --tunnel --port=15433 --mfa-mode=platform` | `postgres://reporting_ro@127.0.0.1:15433/gateway_staging` |
| prod | `tsh proxy db gateway-data-prod-read-replica --db-user=reporting_ro --db-name=gateway_data --tunnel --port=15432 --mfa-mode=platform` | `postgres://reporting_ro@127.0.0.1:15432/gateway_data` |

`reporting_ro` is read-only, enforced server-side. `--mfa-mode=platform` is not
optional: without it the ceremony goes to the browser, the phone answers `No passkey
found`, and psql then reports `connection refused` -- which is noise, the MFA routing
is the cause. The tunnel dies when the operator closes it and expires on its own, so
if a later query says `connection refused`, hand them the same command again rather
than debugging it. `uia read-prod-db --shell` is the human-driven equivalent, but it
picks its own port, so the raw command above is what this skill uses.

There is no password anywhere in this, which is what the tooling wants: `compare.py`
refuses a DSN carrying one, in the userinfo and in the query string alike. Never ask
for, type, or echo a password -- this skill runs inside the hooks it is checking, so
anything typed here lands in the transcripts and stored rows the comparison then reads.

**development.** A local Postgres, no tunnel. Read `DATABASE_NAME`, `DATABASE_USER`,
`DATABASE_HOST` and `DATABASE_PORT` from `ai-gateway-data/.env` and build a
passwordless DSN from those. Do not read or copy `DATABASE_PASSWORD`. Do not assume
names; they differ between machines.

`compare.py` starts psql from an environment stripped of every `PG*` variable, so an
inherited `PGHOST`, `PGSSLMODE` or `PGSERVICE` cannot send it somewhere the DSN did
not name. A loopback tunnel is exempt from `sslmode=verify-full`; anything else is not.

Production rows are customer data. Keep them in the run: do not write them to disk
beyond the temporary files this skill uses, and keep the excerpts in the report to the
few characters a finding needs to be actionable.

## 3. Run the scan

```bash
WORK=$(mktemp -d)                       # not /tmp directly: the scan quotes transcripts
trap 'rm -rf "$WORK"' EXIT              # and there is no reason to leave them behind

python3 .claude/skills/identify-drift/scan_local.py \
  --tools <tools> --days <n> --out "$WORK/local.json"

export IDENTIFY_DRIFT_DSN="postgres://reporting_ro@127.0.0.1:15433/gateway_staging"
                                                   # never on the command line:
                                                   # arguments are visible in ps
python3 .claude/skills/identify-drift/compare.py \
  --local "$WORK/local.json" \
  --email "<email>" --environment staging \
  --out "$WORK/report.json"                        # not a shell redirect: that
                                                   # would use the umask
```

The psql it runs is checked first: whoever can write that binary, the file a symlink
points at, or any directory above either, can change what is handed the database
connection. On a managed Mac the only psql usually sits in a package-manager prefix
the admin group can write, so the check refuses and the run stops. That is the check
working, but it is not a question worth interrupting a scan for, so settle it in the
command rather than mid-run: `--psql` names a binary in a directory nobody else can
write, and `--allow-shared-psql` accepts the shared one and prints on stderr which
path was accepted. Say which one is being used and why when reporting.

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

A user record is only counted as a prompt when the person actually sent it. Claude
Code files everything under the user role -- injected reminders, slash-command
expansions, command output, task notifications -- and marks the real submissions with
`promptSource`. Only `typed` and `queued` are prompts. A file that marks nothing is an
older format and all of its prompts are kept, since filtering on a field it never
writes would read as total loss.

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
| prompts | `prompts.prompt`, a JSON object with `user_prompt` and `assistant_prompt`. One row is a whole turn: `user_prompt` joins the prompts queued during it with a blank line, and `assistant_prompt` is `{content, tool_use}` where `content` joins the turn's replies the same way |
| tool calls | `prompt_analytics.tool_name`, and `parameters->>'tool_use_id'` where present, plus `assistant_prompt`'s own `tool_use[].tool_use_id` |
| sessions | `prompt_analytics.thread_id` |
| the user | `gateway_users.email`, matched case-insensitively |

**The unit is the turn.** The hook uploads once per turn, at its end, carrying that
turn's prompt, replies and tool calls together. So a turn that never arrived is missing
all three, and reporting them separately says one fault three times while burying the
one that matters. Findings come in two kinds: turns the database never received, and
pieces missing from turns it did.

**Nothing is judged before it has had a chance to upload.** Each session carries a
watermark, the newest stored row it has. Local records after their session's watermark
may simply not have finished, so they are held back and counted in
`not_finished_yet` rather than reported. Without this the session running the scan
reports itself as loss, every time. The audit checks stop at the same mark: that log
holds its last hundred entries, which on a busy machine is the turn running right now.

**What is compared.** Tokens, user prompts, assistant messages, tool calls, sessions.
Prompts match on a sha256 of the whitespace-normalised text, computed the same way on
both sides, so no prompt text crosses the wire. Because a row holds a turn rather than a
message, both sides are split on their newline joins first and matched segment by
segment; a record counts as stored only when every segment it splits into is. Tool calls
match on `tool_use_id` when both sides carry one, and by count when they do not. Both
stored sources of an id are read: the pre-tool hook writes a row per call, the stop hook
sends the turn's whole list, and the second is the larger.

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

**Only the sessions the database has are compared, and a session it does not have is
never a finding.** A tool runs whether or not anyone installed the integration,
configuration moves between environments, and a machine can hold months of transcripts
the gateway was never told about, so an absent session says nothing about drift: it
may never have been instrumented, may have run against another environment, or may
predate the install. Chasing those produces noise and no bugs.

What is worth reporting is a session the database does hold that is missing pieces of
itself -- a prompt, a reply, or a tool call that should be inside a turn it did
receive. So the stored sessions are the whole scope, and every local record outside
them is dropped before anything is compared. The count of what was dropped appears in
the report's `sessions_not_in_db`, so the narrowing is visible without being alarming.

When the stored rows for a tool name no session at all, nothing is in scope and the
report says so in one line rather than comparing against a window it cannot place.

**The second finding's count is an upper bound.** A turn is grouped locally by the
prompt that started it, but the hook ends a turn whenever the assistant yields, so one
local turn can span several stored rows. When one of those rows is missing and another
is not, the turn reads as received and its missing half is counted as pieces rather
than as the turn it was. Treat a large count there as "at most this many", and check a
few against the stored rows before believing all of it.

**Tokens are only compared when the two sides cover the same work.** The stored totals
are the whole window's, so once anything has been held back -- a turn that never
arrived, a turn still running, a session the database does not have -- the sums are of
different things and the difference is arithmetic, not drift. Measured properly they
reconcile; measured across a gap they reported the same missing turns a second time, as
a 67% token loss.

Some findings are structural, not faults. Expect them, say so once, and do not
investigate them:

| Finding | Why it is expected |
|---|---|
| cursor: tool calls reconciled by count | its transcripts carry no ids, so identity matching is impossible |
| codex: token totals not reconciled | it reports a running total per turn, not a delta per message |
| augment: no transcript to compare | it keeps none, so only the upload direction is checkable |
| any tool: could not be checked for this window | an aggregate hit the row cap. Re-run over fewer days |
| any tool: audit log is full | it holds a hundred entries, so absence from it is not evidence |
| any tool: sessions absent from the database | out of scope by design, and not reported at all |
| any tool: records after a session's watermark | the turn may not have ended yet. Held back, counted in `not_finished_yet` |

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
one was scanned. Report the findings as they come: they are already grouped by cause,
so do not split one back into a bullet per category, and do not restate the same cause
in another form. If `not_finished_yet` or `sessions_not_in_db` is non-zero, say so in
one line after the blocks, because the reader should know what was left out.

If nothing is wrong, the whole report is the header plus `No issues found.` Do not pad
it with what you checked.

Do not recommend fixes unless asked. This skill reports; the ticket decides.
