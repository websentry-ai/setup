"""
The live hook's per-turn token usage on the shared sample transcripts, and what the
backfill uploader sends for each session's subagents.

tests/fixtures/claude_code_usage is mirrored in ai-gateway-data, whose backfill parser is
held to the same expected.json, reading the subagents from uploads.json, so the two ways a
Claude Code turn reaches us count it the same. Regenerate after an intended change with:

    python -m tests.claude_code.hooks.test_shared_usage_fixtures --write

then copy the directory into ai-gateway-data's tests/fixtures/claude_code_usage.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from tests.conftest import tool_module

unbound = tool_module("claude-code/hooks")
uploaders = (tool_module("claude-code/hooks/mdm", "setup"), tool_module("claude-code/hooks", "setup"))
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "claude_code_usage"
FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _is_prompt(entry):
    message = entry.get("message") or {}
    content = message.get("content")
    if entry.get("type") != "user" or entry.get("isSidechain") or message.get("role") != "user":
        return False
    if isinstance(content, str):
        return bool(content.strip())
    return isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") == "text" for b in content)


def _turns(main):
    """(prompt timestamp, end timestamp, last line index) per turn: a turn ends with its last line."""
    starts = [i for i, e in enumerate(main) if _is_prompt(e)]
    turns = []
    for n, start in enumerate(starts):
        last = (starts[n + 1] if n + 1 < len(starts) else len(main)) - 1
        turns.append((main[start]["timestamp"], main[last]["timestamp"], last))
    return turns


def _upto(ts):
    return lambda e: unbound._ts_lt(e.get("timestamp"), ts) or e.get("timestamp") == ts


def hook_usage(case_dir):
    """The usage the hook sends at each turn's Stop, reading the files as they stood then."""
    transcript = next(case_dir.glob("*.jsonl"))
    session_dir = case_dir / transcript.stem
    main = _lines(transcript)
    results, previous_end = [], None
    for prompt_ts, end_ts, last in _turns(main):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / transcript.name
            copy.write_text("".join(json.dumps(e) + "\n" for e in main[:last + 1]), encoding="utf-8")
            for agent in session_dir.rglob("*.jsonl") if session_dir.exists() else ():
                target = Path(tmp) / transcript.stem / agent.relative_to(session_dir)
                target.parent.mkdir(parents=True, exist_ok=True)
                kept = [e for e in _lines(agent) if _upto(end_ts)(e)]
                target.write_text("".join(json.dumps(e) + "\n" for e in kept), encoding="utf-8")
            data = unbound.parse_transcript_file(str(copy), user_prompt_timestamp=prompt_ts,
                                                 subagent_floor=previous_end, subagent_ceiling=end_ts)
        usage = data.get("usage") or {}
        results.append({"prompt": prompt_ts, "end": end_ts, "usage": {k: int(usage.get(k) or 0) for k in FIELDS}})
        previous_end = end_ts
    return results


def _case_dirs():
    return [d for d in sorted((FIXTURES / "cases").iterdir()) if d.is_dir()]


def all_cases():
    return {d.name: hook_usage(d) for d in _case_dirs()}


def all_uploads(uploader=uploaders[0]):
    """The subagent records the uploader bundles with each session."""
    return {d.name: uploader._backfill_subagent_usage(next(d.glob("*.jsonl"))) for d in _case_dirs()}


def manifest():
    """sha256 of every fixture file, so a copy elsewhere can prove it is the same set."""
    files = sorted(p for p in FIXTURES.rglob("*") if p.is_file() and p.name != "MANIFEST")
    return "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(FIXTURES).as_posix()}\n"
                   for p in files)


class TestHookMatchesSharedFixtures(unittest.TestCase):
    def test_each_turn_matches_the_expected_usage(self):
        expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
        self.assertEqual(all_cases(), expected)

    def test_both_uploaders_send_the_recorded_subagent_usage(self):
        recorded = json.loads((FIXTURES / "uploads.json").read_text(encoding="utf-8"))
        for uploader in uploaders:
            with self.subTest(uploader.__name__):
                self.assertEqual(all_uploads(uploader), recorded)

    def test_manifest_lists_every_fixture(self):
        self.assertEqual((FIXTURES / "MANIFEST").read_text(encoding="utf-8"), manifest())


if __name__ == "__main__" and "--write" in sys.argv:
    (FIXTURES / "expected.json").write_text(json.dumps(all_cases(), indent=2) + "\n", encoding="utf-8")
    (FIXTURES / "uploads.json").write_text(json.dumps(all_uploads(), indent=2) + "\n", encoding="utf-8")
    (FIXTURES / "MANIFEST").write_text(manifest(), encoding="utf-8")
    print("wrote expected.json, uploads.json and MANIFEST")
