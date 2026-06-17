"""
Tests for read-equivalent tool (Grep/Glob/LS) path forwarding in
claude-code/hooks/unbound.py (WEB-4871).

Covers:
  - _derive_read_equivalent_path  (file_path the gateway evaluates)
  - extract_command_for_pretool   (LS command / approval-key, regression on others)

These pin the W1/W2/W3 review fixes: the no-`path` (whole-cwd-scan) case must
forward the cwd rather than nothing, LS must be path-specific, and Grep's regex
pattern must never be forwarded as a path.
"""

import unittest

import unbound


def _event(tool_name, tool_input, cwd=None):
    e = {"tool_name": tool_name, "tool_input": tool_input}
    if cwd is not None:
        e["cwd"] = cwd
    return e


class TestDeriveReadEquivalentPath(unittest.TestCase):
    def d(self, tool_name, tool_input, cwd=None):
        return unbound._derive_read_equivalent_path(
            tool_name, tool_input, {"cwd": cwd} if cwd is not None else {}
        )

    # Explicit path always wins
    def test_grep_explicit_path(self):
        self.assertEqual(self.d("Grep", {"pattern": "X", "path": "/a/b"}), "/a/b")

    def test_ls_explicit_path(self):
        self.assertEqual(self.d("LS", {"path": "/etc"}), "/etc")

    def test_glob_explicit_path_beats_pattern(self):
        self.assertEqual(self.d("Glob", {"pattern": "**/*.env", "path": "/p"}), "/p")

    # W2: no path -> fall back to cwd (whole-tree scan must not be path-less)
    def test_grep_no_path_falls_back_to_cwd(self):
        self.assertEqual(self.d("Grep", {"pattern": "AWS_SECRET"}, cwd="/repo"), "/repo")

    def test_ls_no_path_falls_back_to_cwd(self):
        self.assertEqual(self.d("LS", {}, cwd="/repo"), "/repo")

    # W3: Glob keeps the path-like pattern as a fallback (filename/glob policies)
    def test_glob_pattern_used_when_no_path(self):
        self.assertEqual(self.d("Glob", {"pattern": "**/*.pem"}, cwd="/repo"), "**/*.pem")

    def test_glob_no_path_no_pattern_falls_back_to_cwd(self):
        self.assertEqual(self.d("Glob", {}, cwd="/repo"), "/repo")

    # Grep's regex pattern is NEVER forwarded as a path
    def test_grep_pattern_never_used_as_path(self):
        self.assertEqual(self.d("Grep", {"pattern": "SECRET_KEY.*="}, cwd="/repo"), "/repo")

    # Non-breaking edge: nothing available -> None (caller forwards no file_path)
    def test_no_path_no_cwd_returns_none(self):
        self.assertIsNone(self.d("Grep", {"pattern": "X"}))
        self.assertIsNone(self.d("LS", {}))
        self.assertIsNone(self.d("Glob", {}))


class TestExtractCommandForPretool(unittest.TestCase):
    # W1: LS command is path-specific (no "LS:LS" approval-key collapse)
    def test_ls_with_path(self):
        self.assertEqual(
            unbound.extract_command_for_pretool(_event("LS", {"path": "/srv"})), "/srv"
        )

    def test_ls_no_path_uses_cwd(self):
        self.assertEqual(
            unbound.extract_command_for_pretool(_event("LS", {}, cwd="/repo")), "/repo"
        )

    def test_ls_no_path_no_cwd_falls_back_to_tool_name(self):
        self.assertEqual(unbound.extract_command_for_pretool(_event("LS", {})), "LS")

    # Regression: unchanged behavior for the other tools
    def test_grep_returns_pattern(self):
        self.assertEqual(
            unbound.extract_command_for_pretool(_event("Grep", {"pattern": "X"})), "X"
        )

    def test_glob_returns_pattern(self):
        self.assertEqual(
            unbound.extract_command_for_pretool(_event("Glob", {"pattern": "**/*.py"})),
            "**/*.py",
        )

    def test_read_returns_file_path(self):
        self.assertEqual(
            unbound.extract_command_for_pretool(
                _event("Read", {"file_path": "/x/y"})
            ),
            "/x/y",
        )


if __name__ == "__main__":
    unittest.main()
