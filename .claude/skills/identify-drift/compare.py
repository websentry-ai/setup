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
import json
import os
import hashlib
import os
import subprocess
import sys
from datetime import datetime
from urllib.parse import unquote, urlsplit
from collections import Counter, defaultdict

# The database's own name for each tool, and the label the hook stamps on a payload.
APP_LABEL = {"claude-code": "claude-code", "cursor": "cursor", "copilot": "copilot",
             "codex": "codex", "augment": "augment_code"}


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
    env = dict(os.environ)
    env.pop("PGPASSWORD", None)
    if parts.hostname:
        env["PGHOST"] = parts.hostname
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = unquote(parts.password)
    database = parts.path.lstrip("/")
    if database:
        env["PGDATABASE"] = database
    return env


def _scrub(text, dsn):
    """Never echo the connection back: psql quotes it in several of its errors."""
    out = (text or "").replace(dsn, "<dsn>")
    parts = urlsplit(dsn)
    if parts.password:
        out = out.replace(unquote(parts.password), "<redacted>")
    return out


def psql(dsn, sql, params=None):
    """One query, JSON out. Read-only by construction: the role this connects with
    has no write grant, so a mistake here cannot change anything.

    Values are bound through psql variables and referenced as :'name', which applies
    literal quoting on psql's side. Nothing the caller supplies is pasted into SQL.
    """
    command = ["psql", "-At", "-v", "ON_ERROR_STOP=1"]
    for name, value in (params or {}).items():
        command += ["-v", "%s=%s" % (name, value)]
    # Fed on stdin, not through -c: psql only expands :'name' in what it reads as
    # input, so -c would send the placeholder to the server verbatim.
    # The alias is deliberately unlikely: json_agg(alias) resolves to a *column* of
    # that name when one exists, which silently returns scalars instead of objects.
    statement = ("SELECT coalesce(json_agg(_drift_row), '[]') FROM (%s) _drift_row;"
                 % sql.rstrip().rstrip(";"))
    result = subprocess.run(command, input=statement, capture_output=True, text=True,
                            timeout=180, env=_connection_env(dsn))
    if result.returncode != 0:
        sys.exit("psql failed: %s" % _scrub(result.stderr, dsn).strip()[:500])
    return json.loads(result.stdout.strip() or "[]")


def fetch_db(dsn, email, app_label, days):
    """What we hold for this user and tool, aggregated in the database.

    Every value here is a count, a sum, or a short normalised string. Selecting the
    rows themselves and folding them in Python would pull the whole window across:
    one ordinary account's stored prompts come to fourteen megabytes, and a single
    row can be two hundred kilobytes, so a busy fortnight would be far larger than
    anything worth holding in one JSON value.
    """
    params = {"email": email, "label": app_label, "days": int(days)}
    where = """
        FROM gateway_metrics gm
        JOIN applications app ON app.id = gm.application_id
        JOIN gateway_users u ON u.id = app.owner_user_id
        WHERE lower(u.email) = lower(:'email')
          AND gm.app_label = :'label'
          AND gm.request_initialized_at >= now() - (:'days' || ' days')::interval
    """

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
    """ % where, params)

    tools = psql(dsn, """
        SELECT pa.tool_name, count(*) AS n
        FROM prompt_analytics pa
        WHERE pa.tool_name IS NOT NULL AND pa.gateway_metrics_id IN (SELECT gm.id %s)
        GROUP BY pa.tool_name
    """ % where, params)

    # Normalised here so the two sides are compared the same way; _norm does the
    # identical trim, collapse, truncate and fold in Python.
    texts = psql(dsn, """
        SELECT DISTINCT role, t FROM (
          SELECT 'user' AS role,
                 left(lower(btrim(regexp_replace(p.prompt->>'user_prompt',
                                                 '\s+', ' ', 'g'))), 200) AS t
          FROM prompts p
          WHERE p.gateway_metrics_id IN (SELECT gm.id %s)
          UNION ALL
          SELECT 'assistant',
                 left(lower(btrim(regexp_replace(p.prompt->>'assistant_prompt',
                                                 '\s+', ' ', 'g'))), 200)
          FROM prompts p
          WHERE p.gateway_metrics_id IN (SELECT gm.id %s)
        ) x WHERE t IS NOT NULL AND t <> ''
    """ % (where, where), params)

    row = totals[0] if totals else {}
    return {
        "metrics_rows": int(row.get("metrics_rows") or 0),
        "input_tokens": int(row.get("input_tokens") or 0),
        "output_tokens": int(row.get("output_tokens") or 0),
        "threads": {r["thread_id"] for r in threads},
        "tool_counts": {r["tool_name"]: int(r["n"]) for r in tools},
        "user_texts": {r["t"] for r in texts if r["role"] == "user"},
        "assistant_texts": {r["t"] for r in texts if r["role"] == "assistant"},
    }


REDACT = False


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


def _norm(text):
    """Compare prompts on their shape, not their bytes: the gateway may redact or clip."""
    return " ".join((text or "").split())[:200].lower()


def compare(tool, local, db, days):
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
    missing_sessions = sorted(s for s in local_sessions if s and s not in db["threads"])
    if missing_sessions and db["threads"]:
        findings.append({
            "title": "Sessions present locally are absent from the database",
            "where": "%s -> prompt_analytics.thread_id" % tool,
            "evidence": "%d of %d local sessions have no row. First: %s"
                        % (len(missing_sessions), len(local_sessions),
                           ", ".join(missing_sessions[:3])),
            "why": "Either the hook never fired for these sessions, or every upload "
                   "for them failed. Check the audit log for one of the ids.",
        })

    # ---- prompts -------------------------------------------------------
    for kind, stored_texts, label in (
            ("user_prompt", db["user_texts"], "user prompts"),
            ("assistant_message", db["assistant_texts"], "assistant messages")):
        local_texts = {_norm(r.get("text")) for r in by_kind[kind] if r.get("text")}
        missing = sorted(t for t in local_texts if t and t not in stored_texts)
        if missing and db["metrics_rows"]:
            findings.append({
                "title": "%s recorded locally are absent from the database"
                         % label.capitalize(),
                "where": "%s transcripts -> prompts.%s"
                         % (tool, "user_prompt" if kind == "user_prompt"
                            else "assistant_prompt"),
                "evidence": "%d of %d missing. First: %s"
                            % (len(missing), len(local_texts), _excerpt(missing[0])),
                "why": "The hook either did not capture these, or captured them into a "
                       "turn that was never uploaded.",
            })

    # ---- tool calls ----------------------------------------------------
    local_tools = Counter(r.get("tool") for r in by_kind["tool_call"] if r.get("tool"))
    short = {name: local_tools[name] - db["tool_counts"].get(name, 0)
             for name in local_tools
             if local_tools[name] > db["tool_counts"].get(name, 0)}
    if short and db["metrics_rows"]:
        worst = sorted(short.items(), key=lambda kv: -kv[1])[:3]
        findings.append({
            "title": "Tool calls made locally are under-recorded",
            "where": "%s transcripts -> prompt_analytics.tool_name" % tool,
            "evidence": "; ".join("%s local %d vs stored %d"
                                  % (n, local_tools[n], db["tool_counts"].get(n, 0))
                                  for n, _ in worst),
            "why": "A PreToolUse that failed to upload, or a tool the hook does not "
                   "handle. Compare one call_id against the audit log.",
        })

    # ---- tokens --------------------------------------------------------
    local_in = sum(r.get("input", 0) for r in by_kind["usage"])
    local_out = sum(r.get("output", 0) for r in by_kind["usage"])
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
                            % (len(unseen), unseen[0].get("call_id"), unseen[0].get("tool")),
                "why": "The loss is upstream of the upload: the hook did not fire, or "
                       "returned before logging. Not a network problem.",
            })

        # audit -> database: the hook saw it and the upload lost it. This is the only
        # direction that separates an ingest failure from a capture bug, and for a tool
        # whose audit log is its only local record it is the only check there is.
        logged = Counter(r.get("tool") for r in audit_by_kind["tool_call"]
                         if in_window(r) and r.get("tool"))
        dropped = {name: logged[name] - db["tool_counts"].get(name, 0)
                   for name in logged
                   if logged[name] > db["tool_counts"].get(name, 0)}
        if dropped:
            worst = sorted(dropped.items(), key=lambda kv: -kv[1])[:3]
            findings.append({
                "title": "The hook logged tool calls the database never received",
                "where": "%s -> prompt_analytics.tool_name" % local["audit_log"],
                "evidence": "; ".join("%s logged %d vs stored %d"
                                      % (n, logged[n], db["tool_counts"].get(n, 0))
                                      for n, _ in worst),
                "why": "The hook saw these and the upload did not land them, so the loss "
                       "is the ingest path or the network, not the capture.",
            })

        logged_prompts = {_norm(r.get("text")) for r in audit_by_kind["user_prompt"]
                          if in_window(r) and r.get("text")}
        dropped_prompts = sorted(t for t in logged_prompts
                                 if t and t not in db["user_texts"])
        if dropped_prompts and db["metrics_rows"]:
            findings.append({
                "title": "The hook logged prompts the database never received",
                "where": "%s -> prompts.user_prompt" % local["audit_log"],
                "evidence": "%d of %d missing. First: %s"
                            % (len(dropped_prompts), len(logged_prompts),
                               _excerpt(dropped_prompts[0])),
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
                                  "to every account on the machine through ps")
    ap.add_argument("--email", required=True)
    ap.add_argument("--environment", required=True)
    ap.add_argument("--redact", action="store_true",
                    help="show a digest instead of prompt text; use on production")
    args = ap.parse_args()

    # Read from the environment by default. Passing it as an argument puts any
    # password in this process's own command line, which is exactly the exposure the
    # libpq handoff below avoids for psql.
    dsn = os.environ.get("IDENTIFY_DRIFT_DSN") or args.dsn
    if not dsn:
        sys.exit("set IDENTIFY_DRIFT_DSN, or pass --dsn if it carries no password")
    if args.dsn and urlsplit(args.dsn).password:
        sys.exit("--dsn carries a password and would be visible in ps; "
                 "put it in IDENTIFY_DRIFT_DSN instead")

    global REDACT
    REDACT = args.redact or args.environment.lower() == "production"

    local_all = json.load(sys.stdin if args.local == "-" else open(args.local))
    days = local_all["days"]

    report = {"environment": args.environment, "email": args.email,
              "days": days, "since": local_all["since"], "tools": {}}
    for tool, local in local_all["tools"].items():
        db = fetch_db(dsn, args.email, APP_LABEL[tool], days)
        report["tools"][tool] = {
            "findings": compare(tool, local, db, days),
            "counts": {
                "local_sessions": len(local["sessions_transcript"]),
                "db_metrics_rows": db["metrics_rows"],
                "db_threads": len(db["threads"]),
                "db_tool_kinds": len(db["tool_counts"]),
                "db_prompt_texts": len(db["user_texts"]) + len(db["assistant_texts"]),
            },
        }
    json.dump(report, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
