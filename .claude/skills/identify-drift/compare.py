#!/usr/bin/env python3
"""Compare what a tool recorded locally against what we persisted, and say where a
loss happened rather than only that one did.

Three sources, so a gap has a direction:

  transcript -> audit   the hook never saw it          (a hook bug)
  audit      -> database the upload lost it            (an ingest or network bug)
  database only          we hold something local never had (a duplicate, or wrong attribution)

The audit log keeps only its last hundred entries, so it is compared only inside the
window it still covers. Outside that window a missing audit entry has aged out and
is not evidence of anything.
"""

import argparse
import hashlib
import json
import os
import grp
import pwd
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime
from urllib.parse import parse_qsl, unquote, urlsplit
from collections import Counter, defaultdict

# The database's own name for each tool, and the label the hook stamps on a payload.
APP_LABEL = {"claude-code": "claude-code", "cursor": "cursor", "copilot": "copilot",
             "codex": "codex", "augment": "augment_code"}


# Long enough for a fourteen-day window on a busy account, short enough that a
# pathological one fails with an answer instead of hanging.
STATEMENT_TIMEOUT_MS = 120000

# The widest window either half of the skill will look at.
MAX_DAYS = 14

# The connection options a DSN may carry, and the libpq variable each becomes.
# Anything outside this map is refused rather than dropped, so a TLS setting cannot
# go missing without the operator hearing about it. "password" is absent on purpose.
LIBPQ_OPTIONS = {
    "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY", "sslcrl": "PGSSLCRL", "passfile": "PGPASSFILE",
    "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME",
}

# psql's own environment, which the PG* strip does not cover.
PSQL_VARIABLES = {"PSQLRC", "PSQL_HISTORY", "PSQL_PAGER", "PAGER", "PSQL_EDITOR",
                  "EDITOR", "VISUAL"}

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", None, ""}

# The libpq modes that permit a plaintext session.
UNENCRYPTED_SSLMODES = {"disable", "allow", "prefer"}

# require encrypts but accepts any certificate, so it stops eavesdropping and not
# impersonation. verify-full is the default; the weaker encrypted modes are available
# to an operator who asks for one by name.
DEFAULT_SSLMODE = "verify-full"


def _connection_env(dsn):
    """Split a DSN into libpq environment variables.

    A connection string passed as an argument is readable by every account on the
    machine through the process list, so a password in one leaks the moment a query
    runs. The environment is not world-readable, so the parts travel there instead
    and psql is invoked with no connection details in its arguments at all.
    """
    parts = urlsplit(dsn)
    if parts.scheme not in ("postgres", "postgresql"):
        sys.exit("dsn must be a postgres:// or postgresql:// URL")
    # Keys folded because libpq spells them lower case, and folding the recognised
    # ones is what routes a weak sslmode into the check below rather than past it.
    options = {k.lower(): v for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    if "sslmode" in options:
        options["sslmode"] = options["sslmode"].lower()
    if parts.password or "password" in options:
        # No route into this tool carries a password, including the environment. The
        # command that would set one is itself captured by the hooks this compares,
        # so the secret would land in the transcripts, the audit log and the stored
        # prompts. libpq reads a password file that stays out of both.
        sys.exit("the dsn carries a password: remove it and let libpq read one from "
                 "~/.pgpass, or name a file with ?passfile=, either of which this "
                 "never reads")
    unknown = sorted(set(options) - set(LIBPQ_OPTIONS))
    if unknown:
        # Silently dropping a connection option is how a verify-full DSN ends up
        # negotiating an unverified one.
        sys.exit("unsupported connection option(s): %s" % ", ".join(unknown))
    # Start from an environment with no libpq state at all. Inheriting it lets the
    # destination and the policy come from different places: a hostless DSN would
    # take PGHOST from the environment and still be judged local, and an inherited
    # PGSSLMODE or PGSERVICE would outlive every check below.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("PG") and k not in PSQL_VARIABLES}
    # A read-only report is never worth holding a connection open for minutes. This
    # is the server-side bound; the subprocess timeout is only the outer backstop.
    env["PGOPTIONS"] = "-c statement_timeout=%d" % STATEMENT_TIMEOUT_MS
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = unquote(parts.username)
    database = parts.path.lstrip("/")
    if database:
        env["PGDATABASE"] = database
    for key, value in options.items():
        # A path is not a secret, so passfile travels; the password it points at is
        # read by libpq and never enters this process.
        env[LIBPQ_OPTIONS[key]] = value
    if parts.hostname not in LOCAL_HOSTS:
        # libpq defaults to prefer, which accepts an unverified or plaintext session.
        # A tunnel terminates on the loopback and is exempt; anything else must
        # encrypt, whether by omission or by asking for a weaker mode outright.
        mode = options.get("sslmode", DEFAULT_SSLMODE)
        if mode in UNENCRYPTED_SSLMODES:
            sys.exit("sslmode=%s would send customer data over an unencrypted or "
                     "unverified connection to %s; use require or stronger"
                     % (mode, parts.hostname))
        env["PGSSLMODE"] = mode
    return env


def _scrub(text, dsn):
    """Never echo the connection back: psql quotes it in several of its errors. A
    password cannot reach here any more, but the host, user and database still name
    infrastructure that does not belong in a report or a terminal someone screenshots."""
    out = (text or "").replace(dsn, "<dsn>")
    parts = urlsplit(dsn)
    for piece in (parts.password and unquote(parts.password), parts.hostname,
                  parts.username, parts.path.lstrip("/")):
        if piece and len(piece) > 2:
            out = out.replace(piece, "<redacted>")
    return out


def _group_members(gid):
    """Everyone in a group. gr_mem lists only the secondary members, so on a system
    where a shared group is somebody's primary one it reads as empty."""
    try:
        members = set(grp.getgrgid(gid).gr_mem)
    except KeyError:
        return None
    try:
        members |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == gid}
    except Exception:
        return None
    return members


def _ancestors(path):
    """Every directory a path passes through. Writing any one of them swaps what the
    step below it resolves to."""
    out, current = [], os.path.dirname(os.path.abspath(path))
    while True:
        out.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            return out
        current = parent


def _writable_by_others(path, follow=True):
    """Whether anyone but this account and root can write it. Works for a file or a
    directory: writing either one changes what gets run. follow=False asks about the
    link itself, since a link somebody else owns can be repointed after it is checked
    even when what it currently names is sound."""
    try:
        info = os.stat(path) if follow else os.lstat(path)
    except OSError:
        return True
    # The owner can rewrite it whatever the mode says, so a 0755 path belonging to
    # another account is not safe just because the group and world bits are clear.
    if info.st_uid not in (os.getuid(), 0):
        return True
    if stat.S_ISLNK(info.st_mode):
        # A symlink's permission bits mean nothing: Linux creates every one of them
        # 0777 and the kernel ignores them. Who owns it, and the directory holding it,
        # are what decide whether it can be repointed, and both are checked already.
        return False
    if stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX:
        # A sticky directory lets anyone create entries but only the owner of an entry
        # may replace or remove it, which is the whole concern here. /tmp is 1777.
        return False
    if info.st_mode & stat.S_IWOTH:
        return True
    if not info.st_mode & stat.S_IWGRP:
        return False
    members = _group_members(info.st_gid)
    # A group this cannot enumerate is not one to vouch for.
    if members is None:
        return True
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        return True
    return bool(members - {owner, "root"})


def _psql_binary(explicit=None):
    """An absolute psql, resolved once. Whoever can write the directory it sits in can
    replace it, and it is handed the connection and asked for the numbers this reports
    as fact, so a directory other accounts can write is not a place to take it from."""
    if explicit:
        if not os.path.isabs(explicit) or not os.access(explicit, os.X_OK):
            sys.exit("--psql must be an absolute path to an executable")
        found = explicit
    else:
        found = shutil.which("psql")
        if not found or not os.path.isabs(found):
            sys.exit("psql not found on PATH")
    # Every step that could be swapped: the name itself as a link, the real file behind
    # it, and every directory either passes through. Checking one level catches
    # replacing the binary and misses editing it in place, swapping a directory above
    # it, or repointing a link somebody else owns.
    real = os.path.realpath(found)
    suspect = [(found, False), (real, True)]
    suspect += [(d, True) for d in _ancestors(found) + _ancestors(real)]
    for path, follow in suspect:
        if not _writable_by_others(path, follow):
            continue
        if ACCEPT_SHARED_PSQL:
            # Named and accepted by a person, which is a different thing from a check
            # that was never run. The path is still reported so it appears in the log.
            sys.stderr.write("accepting a psql under %s, which other accounts can "
                             "write\n" % path)
            break
        sys.exit("%s is writable by accounts other than yours, so the psql this would "
                 "run could be changed. Point --psql at one they cannot, or pass "
                 "--allow-shared-psql as well to accept that risk." % path)
    # The resolved path, not the name it was found under: running the name again would
    # re-follow a link that could have been repointed since it was checked.
    return real


def _sql_literal(value):
    """A value as a dollar-quoted SQL literal.

    Dollar quoting needs no escaping at all: everything between the tags is taken
    verbatim, so a quote, a backslash or a newline in the value cannot end it. The
    only thing it cannot hold is its own tag, and the tag is chosen so the value does
    not contain it. This replaces carrying values through psql variables, which meant
    a value or a path crossing psql's parser and then a shell, where a backquote or an
    apostrophe silently produced an empty binding rather than an error.
    """
    text = str(value)
    tag, index = "drift", 0
    while "$%s$" % tag in text:
        index += 1
        tag = "drift%d" % index
    return "$%s$%s$%s$" % (tag, text, tag)


def psql(dsn, sql, params=None):
    """One query, JSON out. Read-only by construction: the role this connects with
    has no write grant, so a mistake here cannot change anything.

    Values are substituted as dollar-quoted literals, so nothing the caller supplies
    is parsed as SQL, and nothing of it reaches this process's arguments, where every
    local account could read it.
    """
    # One left-to-right pass, so a value that happens to contain another marker is
    # not rewritten by a later substitution. Replacing them one name at a time let an
    # email holding :'label' be edited inside its own finished literal.
    def _bind(match):
        name = match.group(1)
        if name not in (params or {}):
            sys.exit("query refers to :'%s', which was never given a value" % name)
        return _sql_literal((params or {})[name])

    sql = re.sub(r":'([a-z_]+)'", _bind, sql)
    # -X: a startup file can \set over the query, redirect output with \o, or run a
    # shell command with \!, none of which the PG* strip covers.
    command = [_psql_binary(PSQL), "-At", "-X", "-v", "ON_ERROR_STOP=1"]
    # Fed on stdin, not through -c: an argument is readable by every account on the
    # machine for as long as the query runs.
    # The alias is deliberately unlikely: json_agg(alias) resolves to a *column* of
    # that name when one exists, which silently returns scalars instead of objects.
    statement = ("SELECT coalesce(json_agg(_drift_row), '[]') FROM (%s) _drift_row;"
                 % sql.rstrip().rstrip(";"))
    result = subprocess.run(command, input=statement, capture_output=True, text=True,
                            timeout=180, env=_connection_env(dsn))
    if result.returncode != 0:
        error = _scrub(result.stderr, dsn).strip()
        if "statement timeout" in error.lower():
            # The row cap bounds what comes back, not what the server does to produce
            # it: a GROUP BY computes every group before any LIMIT applies. Narrowing
            # the window is the only thing that shrinks the work.
            sys.exit("the database gave up on this window after %ds. Re-run over "
                     "fewer days, or one tool at a time."
                     % (STATEMENT_TIMEOUT_MS // 1000))
        sys.exit("psql failed: %s" % error[:500])
    return json.loads(result.stdout.strip() or "[]")


# What one query may return. Past this the window is too broad to compare item by
# item, and the report says so rather than comparing a truncated set and calling the
# remainder missing.
ROW_CAP = 50000


def _capped(rows):
    """Rows plus whether the cap swallowed any. A silent truncation would turn every
    unreturned row into a false 'absent from the database'."""
    return rows[:ROW_CAP], len(rows) > ROW_CAP


def fetch_db(dsn, email, app_label, days, since=None, until=None):
    """What we hold for this user and tool, aggregated in the database and bounded.

    Values are counts, sums, digests and ids. Selecting the rows themselves would pull
    the window across: one ordinary account's stored prompts come to fourteen megabytes
    and a single row can be two hundred kilobytes.

    Prompts come back as a multiset of digests, not a set, so a prompt sent twice and
    stored once is still visible as a loss. Tool calls come back as ids where the row
    carries one, because equal counts of different calls are not a match.
    """
    params = {"email": email, "label": app_label, "days": int(days), "cap": ROW_CAP + 1}
    # An explicit interval when one is given, so the audit direction can ask about the
    # hours its log still covers instead of the whole window. Comparing a few audited
    # hours against fourteen stored days lets an older row cancel a recent loss.
    if since:
        params["since"] = since
        bounds = ["gm.request_initialized_at >= :'since'::timestamptz"]
    else:
        bounds = ["gm.request_initialized_at >= now() - (:'days' || ' days')::interval"]
    if until:
        params["until"] = until
        bounds.append("gm.request_initialized_at <= :'until'::timestamptz")
    where = """
        FROM gateway_metrics gm
        JOIN applications app ON app.id = gm.application_id
        JOIN gateway_users u ON u.id = app.owner_user_id
        WHERE lower(u.email) = lower(:'email')
          AND gm.app_label = :'label'
          AND %s
    """ % "\n          AND ".join(bounds)
    # The same trim, collapse and fold _norm applies, then a digest, so the two sides
    # are comparable without carrying the text across. Whole text, no prefix: distinct
    # prompts sharing an opening would otherwise reconcile against each other.
    norm = (r"encode(sha256(convert_to("
            r"lower(btrim(regexp_replace(%s, '\s+', ' ', 'g'))), 'UTF8')), 'hex')")

    totals = psql(dsn, """
        SELECT count(*) AS metrics_rows,
               coalesce(sum(gm.input_token_size), 0) AS input_tokens,
               coalesce(sum(gm.output_token_size), 0) AS output_tokens
        %s
    """ % where, params)

    threads = psql(dsn, """
        SELECT DISTINCT pa.thread_id
        FROM prompt_analytics pa
        WHERE pa.thread_id IS NOT NULL AND pa.gateway_metrics_id IN (SELECT gm.id %s)
        LIMIT :'cap'
    """ % where, params)

    tools = psql(dsn, """
        SELECT pa.tool_name, count(*) AS n,
               count(*) FILTER (WHERE pa.parameters ? 'tool_use_id') AS with_id
        FROM prompt_analytics pa
        WHERE pa.tool_name IS NOT NULL AND pa.gateway_metrics_id IN (SELECT gm.id %s)
        GROUP BY pa.tool_name
        LIMIT :'cap'
    """ % where, params)

    call_ids = psql(dsn, """
        SELECT DISTINCT pa.parameters->>'tool_use_id' AS call_id
        FROM prompt_analytics pa
        WHERE pa.parameters ? 'tool_use_id'
          AND pa.gateway_metrics_id IN (SELECT gm.id %s)
        LIMIT :'cap'
    """ % where, params)

    digests = psql(dsn, """
        SELECT role, h, count(*) AS n FROM (
          SELECT 'user' AS role, %s AS h
          FROM prompts p WHERE p.gateway_metrics_id IN (SELECT gm.id %s)
          UNION ALL
          SELECT 'assistant', %s
          FROM prompts p WHERE p.gateway_metrics_id IN (SELECT gm.id %s)
        ) x WHERE h IS NOT NULL
        GROUP BY role, h
        LIMIT :'cap'
    """ % (norm % "p.prompt->>'user_prompt'", where,
           norm % "p.prompt->>'assistant_prompt'", where), params)

    threads, threads_capped = _capped(threads)
    tools, tools_capped = _capped(tools)
    call_ids, ids_capped = _capped(call_ids)
    digests, digests_capped = _capped(digests)

    row = totals[0] if totals else {}
    tool_counts = {r["tool_name"]: int(r["n"]) for r in tools}
    with_id = sum(int(r["with_id"]) for r in tools)
    stored_calls = sum(tool_counts.values())
    return {
        "metrics_rows": int(row.get("metrics_rows") or 0),
        "input_tokens": int(row.get("input_tokens") or 0),
        "output_tokens": int(row.get("output_tokens") or 0),
        "threads": {r["thread_id"] for r in threads},
        "tool_counts": tool_counts,
        "call_ids": {r["call_id"] for r in call_ids if r["call_id"]},
        # Whether ids cover enough of the stored rows to reconcile by identity. Below
        # this the rows predate the id being recorded and only counts are available.
        "ids_are_representative": bool(stored_calls) and with_id >= stored_calls * ID_COVERAGE,
        "rows_with_call_id": with_id,
        "user_digests": Counter({r["h"]: int(r["n"]) for r in digests
                                 if r["role"] == "user"}),
        "assistant_digests": Counter({r["h"]: int(r["n"]) for r in digests
                                      if r["role"] == "assistant"}),
        "truncated": [what for flag, what in
                      ((threads_capped, "sessions"), (tools_capped, "tool names"),
                       (ids_capped, "tool call ids"), (digests_capped, "prompts"))
                      if flag],
    }


REDACT = False
PSQL = None
ACCEPT_SHARED_PSQL = False


def _parse(value):
    """ISO timestamps compare correctly only as datetimes; offsets can differ."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _excerpt(text):
    """What a finding shows of a prompt. Enough to find it again, and on production
    that is somebody's data, so --redact replaces it with a digest instead."""
    if REDACT:
        return "sha256:%s (%d chars)" % (
            hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:12], len(text or ""))
    return repr((text or "")[:60])


def _digest(text):
    """The same value the query computes, so the two sides compare without the text
    ever leaving the database."""
    return hashlib.sha256(_norm(text).encode("utf-8")).hexdigest()


def _ident(value):
    """An identifier the operator can search for, or a stable stand-in for it. Session
    and call ids name a person's project and turn, so production gets the stand-in."""
    if not value:
        return "(none)"
    if REDACT:
        return "id:%s" % hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return value


def _norm(text):
    """Compare prompts on their shape, not their bytes: the gateway may redact or clip.
    Whitespace and case only. Truncating here would make two prompts sharing a prefix
    interchangeable, which is a real collision in stored data, not a hypothetical."""
    return " ".join((text or "").split()).lower()


# Below this share of records carrying an id, matching on identity would skip more
# than it checked, so counting is the honest method.
ID_COVERAGE = 0.9


def _ids_are_usable(records):
    """Whether these records carry ids often enough to match on them."""
    if not records:
        return True
    return sum(1 for r in records if r.get("call_id")) >= len(records) * ID_COVERAGE


def _cannot_check(what, where, why):
    """A capped aggregate is not evidence of absence. Comparing against one turns every
    row the cap left out into a loss that never happened, so the check says it could
    not run instead of listing them."""
    return {
        "title": "%s could not be checked for this window" % what,
        "where": where,
        "evidence": "the stored %s hit the %d row cap" % (why, ROW_CAP),
        "why": "Comparing against a capped set would report the rows it left out as "
               "losses. Re-run over fewer days.",
    }


def compare(tool, local, db, days, db_audit=None):
    """Return a list of findings. Each is one problem, with its evidence."""
    findings = []
    transcript = local["transcript"]
    audit = local["audit"]
    win_start = local.get("audit_window_start")
    win_end = local.get("audit_window_end")

    by_kind = defaultdict(list)
    for record in transcript:
        by_kind[record["kind"]].append(record)

    audit_by_kind = defaultdict(list)
    for record in audit:
        audit_by_kind[record["kind"]].append(record)

    # A database holding essentially nothing for a window the machine was busy in is
    # one fact, not one finding per category. Saying it four times buries whatever
    # else is wrong, and the usual cause is mundane: this machine uploads somewhere
    # else, so the environment picked was the wrong one.
    turns = len(by_kind["user_prompt"]) or len(audit_by_kind["user_prompt"])
    local_activity = (turns + len(by_kind["tool_call"])
                      + len(audit_by_kind["tool_call"]))
    stored = db["metrics_rows"]
    # Judged on coverage, not on strict emptiness: a handful of rows against a thousand
    # turns is the same fact as none. Real partial loss keeps coverage high -- the
    # queued-prompt bug uploaded almost every turn and dropped a prompt inside them --
    # so this only catches the case where the window is simply not there.
    RATIO_FLOOR = 20
    negligible = ((stored == 0 and local_activity > 0)
                  or (turns >= RATIO_FLOOR and stored <= turns * 0.05))
    if negligible:
        return [{
            "title": "This database holds almost no record of the window",
            "where": "%s -> gateway_metrics (app_label %s)" % (tool, APP_LABEL[tool]),
            "evidence": "%d local turn(s) and %d tool call(s) over %d days, against %d "
                        "stored row(s)" % (turns, len(by_kind["tool_call"]), days, stored),
            "why": "Either the machine uploads to a different environment than the one "
                   "chosen, or the email does not own the application these rows are "
                   "filed under. Confirm both before reading this as data loss.",
        }]

    # ---- sessions ------------------------------------------------------
    local_sessions = set(local["sessions_transcript"]) | set(local["sessions_audit"])
    if "sessions" in db["truncated"] and local_sessions:
        findings.append(_cannot_check("Sessions", "%s -> prompt_analytics.thread_id"
                                      % tool, "sessions"))
        missing_sessions = []
    else:
        missing_sessions = sorted(s for s in local_sessions
                                  if s and s not in db["threads"])
    if missing_sessions and db["threads"]:
        findings.append({
            "title": "Sessions present locally are absent from the database",
            "where": "%s -> prompt_analytics.thread_id" % tool,
            "evidence": "%d of %d local sessions have no row. First: %s"
                        % (len(missing_sessions), len(local_sessions),
                           ", ".join(_ident(s) for s in missing_sessions[:3])),
            "why": "Either the hook never fired for these sessions, or every upload "
                   "for them failed. Check the audit log for one of the ids.",
        })

    # ---- prompts -------------------------------------------------------
    prompts_capped = "prompts" in db["truncated"]
    if prompts_capped and (by_kind["user_prompt"] or by_kind["assistant_message"]):
        findings.append(_cannot_check("Prompts", "%s transcripts -> prompts" % tool,
                                      "prompts"))
    for kind, stored, label, column in (
            ("user_prompt", db["user_digests"], "user prompts", "user_prompt"),
            ("assistant_message", db["assistant_digests"], "assistant messages",
             "assistant_prompt")):
        if prompts_capped:
            continue
        # A multiset: the same prompt sent three times and stored once is two losses,
        # which comparing sets would report as none.
        local_counts = Counter(_digest(r["text"]) for r in by_kind[kind] if r.get("text"))
        shortfall = local_counts - stored
        missing_texts = [r["text"] for r in by_kind[kind]
                         if r.get("text") and shortfall.get(_digest(r["text"]))]
        if shortfall and db["metrics_rows"]:
            missing = missing_texts or ["(text unavailable)"]
            findings.append({
                "title": "%s recorded locally are absent from the database"
                         % label.capitalize(),
                "where": "%s transcripts -> prompts.%s" % (tool, column),
                "evidence": "%d of %d missing. First: %s"
                            % (sum(shortfall.values()), sum(local_counts.values()),
                               _excerpt(missing[0])),
                "why": "The hook either did not capture these, or captured them into a "
                       "turn that was never uploaded.",
            })

    # ---- tool calls ----------------------------------------------------
    local_tools = Counter(r.get("tool") for r in by_kind["tool_call"] if r.get("tool"))
    # Ids are only usable when both sides carry them: matching on identity skips any
    # record without one, so a source that records no ids would be compared against
    # nothing and report nothing. Cursor transcripts carry none at all, which is why
    # this is a gate rather than an assumption. A truncated id set is unusable too,
    # because the ids it did not return would make present calls look absent.
    by_identity = (db["ids_are_representative"]
                   and _ids_are_usable(by_kind["tool_call"])
                   and "tool call ids" not in db["truncated"])
    if by_identity:
        # Identity, not arithmetic: five stored calls and five local calls can be ten
        # different calls, which counting alone reports as agreement.
        unidentified = [r for r in by_kind["tool_call"] if not r.get("call_id")]
        if unidentified:
            findings.append({
                "title": "Some local tool calls carry no id and were not matched",
                "where": "%s transcripts" % tool,
                "evidence": "%d of %d local call(s) have no id"
                            % (len(unidentified), len(by_kind["tool_call"])),
                "why": "Identity matching skips a record without an id, so these were "
                       "not compared either way.",
            })
        absent = [r for r in by_kind["tool_call"]
                  if r.get("call_id") and r["call_id"] not in db["call_ids"]]
        if absent and db["metrics_rows"]:
            findings.append({
                "title": "Tool calls made locally are absent from the database",
                "where": "%s transcripts -> prompt_analytics.parameters->>'tool_use_id'"
                         % tool,
                "evidence": "%d of %d call(s) have no stored row. First: %s (%s)"
                            % (len(absent),
                               len([r for r in by_kind["tool_call"] if r.get("call_id")]),
                               _ident(absent[0]["call_id"]), absent[0].get("tool")),
                "why": "A PreToolUse that failed to upload, or a tool the hook does not "
                       "handle.",
            })
    else:
        if local_tools and db["metrics_rows"]:
            # Otherwise an all-clear here would read as "every call is accounted for",
            # when counting cannot tell one call from another of the same name.
            findings.append({
                "title": "Tool calls could only be reconciled by count",
                "where": "%s -> prompt_analytics.parameters->>'tool_use_id'" % tool,
                "evidence": "%d of %d stored row(s) carry a tool_use_id"
                            % (db["rows_with_call_id"], sum(db["tool_counts"].values())),
                "why": "A lost call is invisible here whenever another call of the same "
                       "name was stored in its place. Findings below are counts, and a "
                       "clean result is not proof that every call arrived.",
            })
        if "tool names" in db["truncated"]:
            if local_tools:
                findings.append(_cannot_check(
                    "Tool calls", "%s transcripts -> prompt_analytics.tool_name" % tool,
                    "tool names"))
            short = {}
        else:
            short = {name: local_tools[name] - db["tool_counts"].get(name, 0)
                     for name in local_tools
                     if local_tools[name] > db["tool_counts"].get(name, 0)}
        if short and db["metrics_rows"]:
            worst = sorted(short.items(), key=lambda kv: -kv[1])[:3]
            findings.append({
                "title": "Tool calls made locally are under-recorded (by count)",
                "where": "%s transcripts -> prompt_analytics.tool_name" % tool,
                "evidence": "; ".join("%s local %d vs stored %d"
                                      % (n, local_tools[n], db["tool_counts"].get(n, 0))
                                      for n, _ in worst),
                "why": "Too few records on one side or the other carry a tool_use_id "
                       "to match calls individually, so this counts them instead: "
                       "equal counts of different calls would read as agreement.",
            })

    # ---- tokens --------------------------------------------------------
    local_in = sum(r.get("input", 0) for r in by_kind["usage"])
    local_out = sum(r.get("output", 0) for r in by_kind["usage"])
    if not by_kind["usage"] and by_kind["usage_total"] and db["metrics_rows"]:
        # A running per-turn total cannot be added up the way per-message deltas can,
        # and a session that began before the window carries usage from outside it.
        # Said out loud, because a check that quietly does not run reads as a pass.
        findings.append({
            "title": "Token totals were not reconciled for this tool",
            "where": "%s transcripts -> gateway_metrics" % tool,
            "evidence": "%d running-total record(s), no per-message usage"
                        % len(by_kind["usage_total"]),
            "why": "This tool reports a cumulative total per turn rather than a delta "
                   "per message, so the two sides are not comparable here. The prompt "
                   "and tool-call checks above still apply.",
        })
    for name, local_value, db_value in (("input", local_in, db["input_tokens"]),
                                        ("output", local_out, db["output_tokens"])):
        if db_value and local_value:
            drift = abs(local_value - db_value) / float(local_value)
            if drift > 0.05:
                findings.append({
                    "title": "%s tokens do not reconcile" % name.capitalize(),
                    "where": "%s transcripts -> gateway_metrics.%s_token_size"
                             % (tool, name),
                    "evidence": "local %s vs stored %s (%.0f%% apart)"
                                % (f"{local_value:,}", f"{db_value:,}", drift * 100),
                    "why": "Work billed to no turn: subagent or sidechain messages "
                           "the turn window excluded, or turns never uploaded.",
                })

    # ---- localise ------------------------------------------------------
    # Only meaningful while the log has spare room. At its cap it has rotated, so a
    # call missing from it may simply have been trimmed, and every busy session would
    # otherwise report a hook that is working fine as one that is dropping calls.
    saturated = local.get("audit_entries", 0) >= local.get("audit_limit", 100)
    if saturated:
        findings.append({
            "title": "Cannot attribute the loss: the audit log is full",
            "where": local["audit_log"],
            "evidence": "%d entries, which is its cap of %d"
                        % (local.get("audit_entries", 0), local.get("audit_limit", 100)),
            "why": "The log keeps only its most recent entries, so absence from it is "
                   "not evidence the hook missed anything. Re-run over a shorter window, "
                   "or on a quieter machine, to place the loss.",
        })
    elif win_start and win_end:
        start, end = _parse(win_start), _parse(win_end)

        def in_window(record):
            when = _parse(record.get("at"))
            return bool(when and start and end and start <= when <= end)

        # transcript -> audit: the hook did not see it.
        audit_calls = {r.get("call_id") for r in audit_by_kind["tool_call"]}
        unseen = [r for r in by_kind["tool_call"]
                  if in_window(r) and r.get("call_id")
                  and r["call_id"] not in audit_calls]
        if unseen:
            findings.append({
                "title": "The hook never saw some tool calls it should have",
                "where": "%s transcripts -> %s" % (tool, local["audit_log"]),
                "evidence": "%d call(s) inside the audit window are absent from it. "
                            "First: %s (%s)"
                            % (len(unseen), _ident(unseen[0].get("call_id")),
                               unseen[0].get("tool")),
                "why": "The loss is upstream of the upload: the hook did not fire, or "
                       "returned before logging. Not a network problem.",
            })

        # audit -> database: the hook saw it and the upload lost it. This is the only
        # direction that separates an ingest failure from a capture bug, and for a tool
        # whose audit log is its only local record it is the only check there is.
        # The database side of this direction covers the audit log's own interval.
        # Against the whole window an older stored row cancels a recent lost one.
        dba = db_audit or db
        logged = [r for r in audit_by_kind["tool_call"] if in_window(r)]
        audit_by_identity = (dba["ids_are_representative"]
                             and "tool call ids" not in dba["truncated"]
                             and _ids_are_usable(logged))
        if not audit_by_identity and logged:
            # The two directions can use different methods: a tool may stamp ids in its
            # transcript and not in the hook log. Saying so keeps a clean audit result
            # from reading as strongly as a clean transcript one.
            findings.append({
                "title": "The upload direction could only be reconciled by count",
                "where": local["audit_log"],
                "evidence": "%d of %d logged call(s) carry an id"
                            % (sum(1 for r in logged if r.get("call_id")), len(logged)),
                "why": "A lost call is invisible here whenever another call of the same "
                       "name was stored in its place.",
            })
        if audit_by_identity:
            dropped = [r for r in logged
                       if r.get("call_id") and r["call_id"] not in dba["call_ids"]]
            if dropped:
                findings.append({
                    "title": "The hook logged tool calls the database never received",
                    "where": "%s -> prompt_analytics.parameters->>'tool_use_id'"
                             % local["audit_log"],
                    "evidence": "%d of %d logged call(s) have no stored row. First: "
                                "%s (%s)"
                                % (len(dropped),
                                   len([r for r in logged if r.get("call_id")]),
                                   _ident(dropped[0]["call_id"]),
                                   dropped[0].get("tool")),
                    "why": "The hook saw these and the upload did not land them, so the "
                           "loss is the ingest path or the network, not the capture.",
                })
        elif "tool names" in dba["truncated"]:
            findings.append({
                "title": "Upload losses could not be checked for this window",
                "where": local["audit_log"],
                "evidence": "the stored tool names for the audit interval hit the "
                            "%d row cap" % ROW_CAP,
                "why": "Counting against a capped aggregate would report the rows the "
                       "cap left out as losses. Re-run over fewer days.",
            })
        else:
            counts = Counter(r.get("tool") for r in logged if r.get("tool"))
            dropped = {name: counts[name] - dba["tool_counts"].get(name, 0)
                       for name in counts
                       if counts[name] > dba["tool_counts"].get(name, 0)}
            if dropped:
                worst = sorted(dropped.items(), key=lambda kv: -kv[1])[:3]
                findings.append({
                    "title": "The hook logged tool calls the database never received "
                             "(by count)",
                    "where": "%s -> prompt_analytics.tool_name" % local["audit_log"],
                    "evidence": "; ".join("%s logged %d vs stored %d"
                                          % (n, counts[n], dba["tool_counts"].get(n, 0))
                                          for n, _ in worst),
                    "why": "Too few records on one side or the other carry a "
                           "tool_use_id to match calls individually, so this counts "
                           "them instead.",
                })

        logged_prompts = Counter(_digest(r["text"]) for r in audit_by_kind["user_prompt"]
                                 if in_window(r) and r.get("text"))
        # A capped digest set is not evidence of absence: the prompts it left out
        # would each read as one the upload lost.
        prompts_capped = "prompts" in dba["truncated"]
        dropped_prompts = Counter() if prompts_capped else (
            logged_prompts - dba["user_digests"])
        if prompts_capped and logged_prompts:
            findings.append({
                "title": "Prompt uploads could not be checked for this window",
                "where": local["audit_log"],
                "evidence": "the stored prompts for the audit interval hit the %d row "
                            "cap" % ROW_CAP,
                "why": "Comparing against a capped set would report the prompts it left "
                       "out as losses. Re-run over fewer days.",
            })
        first = next((r["text"] for r in audit_by_kind["user_prompt"]
                      if in_window(r) and r.get("text")
                      and dropped_prompts.get(_digest(r["text"]))), "(text unavailable)")
        if dropped_prompts and dba["metrics_rows"]:
            findings.append({
                "title": "The hook logged prompts the database never received",
                "where": "%s -> prompts.user_prompt" % local["audit_log"],
                "evidence": "%d of %d missing. First: %s"
                            % (sum(dropped_prompts.values()),
                               sum(logged_prompts.values()), _excerpt(first)),
                "why": "Captured and then lost on the way up, so look at the upload "
                       "rather than the hook.",
            })
    elif not local["audit_log_present"]:
        findings.append({
            "title": "No hook audit log on this machine",
            "where": local["audit_log"],
            "evidence": "file absent",
            "why": "The hook has never run for this tool here, so a local-vs-database "
                   "gap cannot be attributed. Install or re-run the setup first.",
        })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", required=True, help="scan_local.py output, or - for stdin")
    ap.add_argument("--dsn", help="prefer IDENTIFY_DRIFT_DSN: an argument is visible "
                                  "to every account on the machine through ps. No "
                                  "password in either; libpq reads one from ~/.pgpass")
    ap.add_argument("--email", required=True)
    ap.add_argument("--environment", required=True,
                    choices=("development", "staging", "production"))
    ap.add_argument("--out", help="write the report here, owner-only. A shell "
                                  "redirect would use the umask instead")
    ap.add_argument("--psql", help="an absolute path to a psql to use instead of the "
                                   "one on PATH. Checked the same way, so it names a "
                                   "better binary rather than skipping the question")
    ap.add_argument("--allow-shared-psql", action="store_true",
                    help="run a psql that other local accounts can change. They could "
                         "make it report anything")
    ap.add_argument("--redact", action="store_true",
                    help="show a digest instead of prompt text; use on production")
    args = ap.parse_args()

    # Read from the environment by default. Passing it as an argument puts any
    # password in this process's own command line, which is exactly the exposure the
    # libpq handoff below avoids for psql.
    dsn = os.environ.get("IDENTIFY_DRIFT_DSN") or args.dsn
    if not dsn:
        sys.exit("set IDENTIFY_DRIFT_DSN or pass --dsn, with no password in either")
    _connection_env(dsn)

    global REDACT, PSQL, ACCEPT_SHARED_PSQL
    PSQL = args.psql
    ACCEPT_SHARED_PSQL = args.allow_shared_psql
    # Staging carries customer data too, so development is the only environment that
    # shows prompt text and a mistyped one cannot silently opt out of redaction.
    REDACT = args.redact or args.environment != "development"

    local_all = json.load(sys.stdin if args.local == "-" else open(args.local))
    try:
        days = int(local_all["days"])
    except (KeyError, TypeError, ValueError):
        sys.exit("the scan file has no usable day count; re-run scan_local.py")
    # The window is bounded here as well as in the scanner, so the file that reaches
    # this cannot widen the query beyond what the scan was allowed to cover.
    if not 1 <= days <= MAX_DAYS:
        sys.exit("the scan file covers %d days; the limit is %d" % (days, MAX_DAYS))

    report = {"environment": args.environment, "email": args.email,
              "days": days, "since": local_all["since"], "tools": {}}
    for tool, local in local_all["tools"].items():
        db = fetch_db(dsn, args.email, APP_LABEL[tool], days)
        # A second, narrower aggregate covering exactly what the audit log still holds.
        # The upload direction is reconciled against this, not against the whole window.
        db_audit = None
        if local.get("audit_window_start"):
            db_audit = fetch_db(dsn, args.email, APP_LABEL[tool], days,
                                since=local["audit_window_start"],
                                until=local.get("audit_window_end"))
        findings = compare(tool, local, db, days, db_audit)
        truncated = sorted(set(db["truncated"])
                           | set(db_audit["truncated"] if db_audit else []))
        if truncated:
            # Said out loud rather than left to look like a clean run: past the cap the
            # unreturned rows would each read as a loss that never happened.
            findings.insert(0, {
                "title": "Window too broad to compare exhaustively",
                "where": "%s -> %s" % (tool, ", ".join(truncated)),
                "evidence": "more than %d distinct %s in %d days"
                            % (ROW_CAP, " and ".join(truncated), days),
                "why": "Findings below cover only what was returned. Re-run over fewer "
                       "days for a complete comparison.",
            })
        report["tools"][tool] = {
            "findings": findings,
            "counts": {
                "local_sessions": len(local["sessions_transcript"]),
                "db_metrics_rows": db["metrics_rows"],
                "db_threads": len(db["threads"]),
                "db_tool_kinds": len(db["tool_counts"]),
                "db_tool_calls": sum(db["tool_counts"].values()),
                "db_prompts": sum(db["user_digests"].values())
                              + sum(db["assistant_digests"].values()),
                # What the run actually did, not what the stored rows alone allow:
                # identity needs ids on both sides.
                "tool_calls_matched_by": (
                    "tool_use_id"
                    if (db["ids_are_representative"]
                        and "tool call ids" not in db["truncated"]
                        and _ids_are_usable([r for r in local["transcript"]
                                             if r.get("kind") == "tool_call"]))
                    else "count"),
                "truncated": truncated,
            },
        }
    if args.out:
        # Same handling as the scan file: findings quote prompt excerpts, session ids
        # and tool names, and O_NOFOLLOW keeps a planted symlink from redirecting the
        # truncate onto another file.
        try:
            fd = os.open(args.out,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        except OSError as error:
            sys.exit("cannot write %s: %s" % (args.out, error.strerror))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    else:
        json.dump(report, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
