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

**Environment** — `development`, `staging`, or `production`.

**Window** — how many days back. **Maximum 14.** Refuse a larger number and ask again;
scanning further is slow and the audit log will not reach that far anyway.

**Tools** — any combination of `claude-code`, `cursor`, `copilot`, `codex`, `augment`.
Offer multi-select.

**Email** — whose activity to check. If `~/.unbound/config.json` holds an `email`,
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

**development** — a local Postgres. Read the database name, user, host and port from
`ai-gateway-data/.env` (`DATABASE_NAME`, `DATABASE_USER`, `DATABASE_HOST`,
`DATABASE_PORT`) and build a passwordless DSN from those. Do not read or copy
`DATABASE_PASSWORD`. Do not assume names; they differ between machines.

**staging / production** — ask the operator to open their usual read-only tunnel and
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

## 4. What the comparison means

The audit log keeps only its last hundred entries. `scan_local.py` records the window
it still covers, and the transcript-versus-audit check runs only inside it. Outside
that window a missing audit entry has aged out; it is not evidence.

Direction tells you where to look:

| Gap | Meaning |
|---|---|
| in transcript, not in audit log | the hook never saw it — a capture bug |
| in audit log, not in the database | the upload lost it — ingest or network |
| in the database, not locally | duplicate, or attributed to the wrong user |

A token difference under 5% is not reported. Above it, the usual cause is work billed
to no turn: subagent messages outside the turn window, or turns that never uploaded.

---

## 5. Report

Header first, then the points. Nothing else.

```
Identify drift — <environment>
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
