"""The skill content hash the hook emits must byte-match what the discovery
backend computes for the same SKILL.md, or a reported hash never resolves to a
discovered body and the whole feature is inert.

The backend recipe is fixed (ai-gateway-data ``AIToolsService._compute_content_hash``):

    sha256(f"{file_name}:{content}")            # file_name is "SKILL.md"

where ``content`` is read exactly as the on-device scanner reads it
(coding-discovery-tool ``read_file_content`` / cowork ``_read_file_content``):

    file <= 50 KiB : Path.read_text("utf-8", errors="replace")   # folds CRLF -> LF
    file  > 50 KiB : open(rb).read(50 KiB).decode("utf-8", errors="replace")

The expected hashes below are computed from those literal bytes, independently
of the hook's own implementation, so a drift in either the recipe, the newline
handling, or the truncation boundary fails the test rather than passing on
matching-but-wrong logic. Every sibling hook is held to the same contract.
"""

import hashlib

import pytest

from tests.conftest import tool_module

TOOLS = ["claude-code/hooks", "copilot/hooks", "codex/hooks", "augment/hooks", "cursor"]

CAP = 50 * 1024


def _hash(module, path):
    return module._skill_content_hash(str(path))


def _expected(content_bytes):
    """The digest the backend would store for a SKILL.md whose scanner-read
    content decodes to ``content_bytes`` (already newline-folded / truncated)."""
    return hashlib.sha256(b"SKILL.md:" + content_bytes).hexdigest()


@pytest.fixture(params=TOOLS)
def hook(request):
    return tool_module(request.param)


def test_plain_ascii_matches_the_backend_recipe(hook, tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"# Deploy\nrun it\n")
    assert _hash(hook, skill) == _expected(b"# Deploy\nrun it\n")


def test_windows_crlf_is_folded_like_the_scanner(hook, tmp_path):
    """The scanner reads small files with read_text, which folds CRLF to LF.
    A Windows-authored SKILL.md must hash identically to its LF twin, or every
    Windows device mismatches its own discovered body."""
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"line one\r\nline two\r\n")
    assert _hash(hook, skill) == _expected(b"line one\nline two\n")


def test_multibyte_utf8_is_preserved(hook, tmp_path):
    skill = tmp_path / "SKILL.md"
    body = "café ☕ 日本語\n".encode("utf-8")
    skill.write_bytes(body)
    assert _hash(hook, skill) == _expected(body)


def test_a_lone_cr_is_also_folded(hook, tmp_path):
    """Universal-newline reading folds a bare CR too, so an old-Mac line ending
    must not fork the hash."""
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"a\rb\n")
    assert _hash(hook, skill) == _expected(b"a\nb\n")


def test_over_cap_file_is_byte_truncated_like_the_scanner(hook, tmp_path):
    """Above 50 KiB the scanner reads the first 50 KiB of bytes and decodes,
    with no newline folding. The hook must truncate at the same boundary."""
    skill = tmp_path / "SKILL.md"
    raw = b"x" * (CAP + 5000)
    skill.write_bytes(raw)
    assert _hash(hook, skill) == _expected(raw[:CAP])


def test_exactly_at_cap_reads_whole_file(hook, tmp_path):
    """A file exactly at the cap is not over it, so the whole thing is read."""
    skill = tmp_path / "SKILL.md"
    raw = b"y" * CAP
    skill.write_bytes(raw)
    assert _hash(hook, skill) == _expected(raw)


def test_over_cap_crlf_is_not_folded(hook, tmp_path):
    """The fold happens only on the small-file read_text path. Above the cap the
    scanner reads raw bytes, so CRLF must survive — this locks the branch so a
    future 'always fold' shortcut cannot pass."""
    skill = tmp_path / "SKILL.md"
    raw = b"a\r\n" * ((CAP // 3) + 1000)  # > cap, CRLF throughout
    skill.write_bytes(raw)
    assert _hash(hook, skill) == _expected(raw[:CAP])


def test_prefix_is_the_file_name_not_a_constant(hook, tmp_path):
    """The recipe prefixes the file name; for a skill that is always SKILL.md.
    A run's hash must equal SKILL.md-prefixed content, never bare content."""
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"body\n")
    assert _hash(hook, skill) != hashlib.sha256(b"body\n").hexdigest()
    assert _hash(hook, skill) == _expected(b"body\n")


def test_missing_or_unreadable_file_is_none(hook, tmp_path):
    assert _hash(hook, tmp_path / "does-not-exist" / "SKILL.md") is None
    assert hook._skill_content_hash(None) is None


def test_all_siblings_agree_on_the_same_body(tmp_path):
    """One SKILL.md, one digest — every hook computes the identical hash, so a
    skill shared across agents resolves to one discovered body."""
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"---\nname: docx\n---\nDo the thing.\n")
    digests = {tool_module(t)._skill_content_hash(str(skill)) for t in TOOLS}
    assert len(digests) == 1
    assert None not in digests


# ---------------------------------------------------------------------------
# Wiring: the hash is not just computable, it is emitted onto the skill entry
# every reporting path builds — one per sibling.
# ---------------------------------------------------------------------------

def _skill_file(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_bytes(b"emitted body\n")
    return skill, _expected(b"emitted body\n")


def test_augment_skill_entry_carries_the_hash(tmp_path):
    augment = tool_module("augment/hooks")
    skill, expected = _skill_file(tmp_path)
    entry = augment._skill_entry("docx", str(skill), "sess", "stamp")
    assert entry["content_hash"] == expected


def test_codex_prompt_emission_carries_the_hash(tmp_path, monkeypatch):
    codex = tool_module("codex/hooks")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(codex, "_resolve_skill_path", lambda name, cwd: str(skill))
    entries = codex._skill_tool_uses_from_prompt("$docx please", None, "sess", "stamp")
    assert entries and entries[0]["content_hash"] == expected


def test_copilot_prompt_emission_carries_the_hash(tmp_path, monkeypatch):
    copilot = tool_module("copilot/hooks")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(copilot, "_resolve_skill_path", lambda name, cwd: str(skill))
    entries = copilot._skill_tool_uses_from_prompt("/docx please", None, "sess", "stamp")
    assert entries and entries[0]["content_hash"] == expected


def test_copilot_invoked_event_emission_carries_the_hash(tmp_path, monkeypatch):
    """The primary Copilot path is the `skill.invoked` event, not the prompt
    fallback — it must carry the hash too."""
    copilot = tool_module("copilot/hooks")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(copilot, "_resolve_skill_path", lambda name, cwd: str(skill))
    entries = copilot._skill_tool_uses_from_events([{"data": {"name": "docx"}}], None)
    assert entries and entries[0]["content_hash"] == expected


def test_claude_code_posttooluse_emission_carries_the_hash(tmp_path, monkeypatch):
    unbound = tool_module("claude-code/hooks")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(unbound, "_resolve_skill_path", lambda name, cwd: str(skill))
    events = [
        {"event": {"hook_event_name": "UserPromptSubmit", "session_id": "s",
                   "prompt": "run the docx skill"}},
        {"event": {"hook_event_name": "PostToolUse", "session_id": "s",
                   "tool_name": "Skill", "tool_input": {"skill": "docx"},
                   "tool_response": {}}},
    ]
    exchange = unbound.build_llm_exchange(events, stop_assistant_message="done")
    uses = [u for m in exchange["messages"] if m["role"] == "assistant"
            for u in m.get("tool_use", [])]
    skill_uses = [u for u in uses if u.get("skill_name") == "docx"]
    assert skill_uses and skill_uses[0]["content_hash"] == expected


def test_claude_code_typed_slash_skill_carries_the_hash(tmp_path, monkeypatch):
    """A typed `/skill` never reaches the Skill tool; it is recovered from the
    prompt and emitted separately, and must carry the hash on that path too."""
    unbound = tool_module("claude-code/hooks")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(unbound, "_resolve_skill_path", lambda name, cwd: str(skill))
    events = [{"event": {"hook_event_name": "UserPromptSubmit", "session_id": "s",
                         "prompt": "/docx do it"}}]
    exchange = unbound.build_llm_exchange(events, stop_assistant_message="done")
    uses = [u for m in exchange["messages"] if m["role"] == "assistant"
            for u in m.get("tool_use", [])]
    skill_uses = [u for u in uses if u.get("skill_name") == "docx"]
    assert skill_uses and skill_uses[0]["content_hash"] == expected


def test_cursor_before_read_file_carries_the_hash(tmp_path, monkeypatch):
    """Cursor loads a skill by reading its SKILL.md, so the beforeReadFile entry
    is its skill invocation — it must carry the hash like the others."""
    cursor = tool_module("cursor")
    skill, expected = _skill_file(tmp_path)
    monkeypatch.setattr(cursor, "_skill_name_from_path", lambda file_path, cwd=None: "docx")
    events = [
        {"event": {"hook_event_name": "beforeSubmitPrompt", "prompt": "read docx"}},
        {"event": {"hook_event_name": "beforeReadFile", "file_path": str(skill), "content": ""}},
        {"event": {"hook_event_name": "afterAgentResponse", "text": "done"}},
    ]
    exchange = cursor.build_llm_exchange(events)
    uses = [u for m in exchange["messages"] if m["role"] == "assistant"
            for u in m.get("tool_use", [])]
    skill_uses = [u for u in uses if u.get("skill_name") == "docx"]
    assert skill_uses and skill_uses[0]["content_hash"] == expected
