from __future__ import annotations

import json

import pytest

from hushspec.adapters.anthropic import (
    create_secure_tool_handler,
    map_claude_tool_to_action,
)
from hushspec.adapters.openai import map_openai_tool_call, create_openai_guard
from hushspec.adapters.mcp import map_mcp_tool_call, extract_domain, create_mcp_guard
from hushspec.adapters.crewai import secure_tool
from hushspec.canonical import canonical_json_value
from hushspec.evaluate import Decision
from hushspec.middleware import HushGuard, HushSpecDenied



# Shared policies


DENY_POLICY = """\
hushspec: "0.1.0"
name: deny-policy
rules:
  tool_access:
    block:
      - dangerous_tool
    allow:
      - safe_tool
    default: block
  shell_commands:
    forbidden_patterns:
      - "rm -rf"
  egress:
    allow:
      - api.example.com
    default: block
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
"""

ALLOW_ALL_POLICY = """\
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    default: allow
  egress:
    default: allow
"""



# OpenAI adapter



def canonical_size(value) -> int:
    """``args_size`` as core spec 3.7 defines it: UTF-8 bytes of the JCS text."""
    return len(canonical_json_value(value).encode("utf-8"))


class TestMapOpenAIToolCall:
    def test_maps_function_name_and_string_args(self):
        action = map_openai_tool_call("get_weather", '{"location":"NYC"}')
        assert action.type == "tool_call"
        assert action.target == "get_weather"
        assert action.args_size == len('{"location":"NYC"}')

    def test_maps_function_name_and_dict_args(self):
        args = {"location": "NYC", "units": "celsius"}
        action = map_openai_tool_call("get_weather", args)
        assert action.type == "tool_call"
        assert action.target == "get_weather"
        assert action.args_size == canonical_size(args)
        # The spaced-out form json.dumps writes is the wrong unit.
        assert action.args_size < len(json.dumps(args))

    def test_measures_a_string_payload_in_its_canonical_form(self):
        raw_args = '{"key":   "value"}'  # note extra spaces
        action = map_openai_tool_call("fn", raw_args)
        assert action.args_size == canonical_size({"key": "value"})
        assert action.args_size == len('{"key":"value"}')

    def test_measures_non_ascii_arguments_in_utf_8_bytes(self):
        # Core spec 3.7: bytes of the UTF-8 encoding, not characters and not
        # the escaped form. JCS leaves a non-ASCII character unescaped, so the
        # byte count exceeds the character count.
        args = {"city": "S\u00e3o Paulo", "lock": "\U0001f512"}
        action = map_openai_tool_call("locate", args)
        canonical = canonical_json_value(args)
        assert action.args_size == len(canonical.encode("utf-8"))
        assert action.args_size == len(canonical) + 4

    def test_measures_escaped_characters_as_the_bytes_jcs_writes(self):
        # The arguments arrive with a quote, a newline and a tab escaped. JCS
        # keeps the two-character escapes for the quote and the newline and
        # rewrites \u0009 as \t, so the count is of the escapes the canonical
        # form writes, never of the ones the caller happened to send.
        raw_args = '{"note": "a \\"b\\" \\n c", "tab": "\\u0009"}'
        action = map_openai_tool_call("note", raw_args)
        assert action.args_size == canonical_size(json.loads(raw_args))
        assert action.args_size == len('{"note":"a \\"b\\" \\n c","tab":"\\t"}')

    def test_handles_empty_dict_args(self):
        action = map_openai_tool_call("noop", {})
        assert action.type == "tool_call"
        assert action.target == "noop"
        assert action.args_size == 2  # '{}'

    def test_handles_empty_string_args(self):
        action = map_openai_tool_call("noop", "{}")
        assert action.type == "tool_call"
        assert action.args_size == 2


class TestCreateOpenAIGuard:
    def test_evaluates_allowed_tool_calls(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        handler = create_openai_guard(guard)
        result = handler("safe_tool", "{}")
        assert result.decision == Decision.ALLOW

    def test_evaluates_denied_tool_calls(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        handler = create_openai_guard(guard)
        result = handler("dangerous_tool", "{}")
        assert result.decision == Decision.DENY



# MCP adapter



class TestMapMCPToolCall:
    def test_maps_read_file_to_file_read(self):
        action = map_mcp_tool_call("read_file", {"path": "/etc/hosts"})
        assert action.type == "file_read"
        assert action.target == "/etc/hosts"

    def test_maps_write_file_to_file_write(self):
        action = map_mcp_tool_call(
            "write_file", {"path": "/tmp/out.txt", "content": "hello"}
        )
        assert action.type == "file_write"
        assert action.target == "/tmp/out.txt"
        assert action.content == "hello"

    def test_maps_list_directory_to_file_read(self):
        action = map_mcp_tool_call("list_directory", {"path": "/src"})
        assert action.type == "file_read"
        assert action.target == "/src"

    def test_maps_run_command_to_shell_command(self):
        action = map_mcp_tool_call("run_command", {"command": "ls -la"})
        assert action.type == "shell_command"
        assert action.target == "ls -la"

    def test_maps_execute_to_shell_command(self):
        action = map_mcp_tool_call("execute", {"command": "echo hi"})
        assert action.type == "shell_command"
        assert action.target == "echo hi"

    def test_maps_fetch_to_egress(self):
        action = map_mcp_tool_call(
            "fetch", {"url": "https://api.example.com/data"}
        )
        assert action.type == "egress"
        assert action.target == "api.example.com"

    def test_maps_http_request_to_egress(self):
        action = map_mcp_tool_call(
            "http_request", {"url": "https://evil.com/steal"}
        )
        assert action.type == "egress"
        assert action.target == "evil.com"

    def test_maps_unknown_tools_to_tool_call(self):
        args = {"query": "test"}
        action = map_mcp_tool_call("custom_search", args)
        assert action.type == "tool_call"
        assert action.target == "custom_search"
        assert action.args_size == canonical_size(args)

    def test_measures_non_ascii_and_escaped_arguments_in_utf_8_bytes(self):
        # Core spec 3.7: bytes of the UTF-8 encoding of the canonical JSON.
        # The accented character is one character and two bytes; the quote is
        # one character and two bytes once JCS has escaped it.
        args = {"query": 'caf\u00e9 "au lait"'}
        action = map_mcp_tool_call("custom_search", args)
        canonical = canonical_json_value(args)
        assert action.args_size == len(canonical.encode("utf-8"))
        assert action.args_size == len('{"query":"caf\u00e9 \\"au lait\\""}'.encode("utf-8"))

    def test_maps_unknown_tools_without_args(self):
        action = map_mcp_tool_call("ping")
        assert action.type == "tool_call"
        assert action.target == "ping"
        assert action.args_size is None

    def test_an_empty_arguments_object_is_two_bytes_not_no_measurement(self):
        # An MCP call carrying `"arguments": {}` did carry arguments, and `{}`
        # is two bytes of canonical JSON. Reporting no size instead would let
        # it past a `max_args_size` of 1 that the TypeScript and Go adapters
        # deny, so one limit would bound three different payloads.
        action = map_mcp_tool_call("custom_search", {})
        assert action.type == "tool_call"
        assert action.args_size == 2
        assert action.args_size == canonical_size({})

    def test_missing_path_in_read_file(self):
        action = map_mcp_tool_call("read_file", {})
        assert action.type == "file_read"
        assert action.target == ""

    def test_missing_command_in_run_command(self):
        action = map_mcp_tool_call("run_command", {})
        assert action.type == "shell_command"
        assert action.target == ""


class TestExtractDomain:
    def test_extracts_hostname_from_https(self):
        assert extract_domain("https://api.example.com/path") == "api.example.com"

    def test_extracts_hostname_from_http(self):
        assert extract_domain("http://localhost:3000") == "localhost"

    def test_extracts_hostname_with_port(self):
        assert extract_domain("https://sub.domain.org:8443/api") == "sub.domain.org"

    def test_returns_bare_string_for_invalid_url(self):
        assert extract_domain("not-a-url") == "not-a-url"

    def test_returns_empty_string_for_empty_input(self):
        assert extract_domain("") == ""


class TestCreateMCPGuard:
    def test_evaluates_file_read_through_guard(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        mcp_guard = create_mcp_guard(guard)
        result = mcp_guard("read_file", {"path": "/home/user/.ssh/id_rsa"})
        assert result.decision == Decision.DENY

    def test_allows_permitted_egress(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        mcp_guard = create_mcp_guard(guard)
        result = mcp_guard("fetch", {"url": "https://api.example.com/data"})
        assert result.decision == Decision.ALLOW

    def test_denies_forbidden_egress(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        mcp_guard = create_mcp_guard(guard)
        result = mcp_guard("http_request", {"url": "https://evil.com/steal"})
        assert result.decision == Decision.DENY

    def test_denies_forbidden_shell_commands(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        mcp_guard = create_mcp_guard(guard)
        result = mcp_guard("run_command", {"command": "rm -rf /"})
        assert result.decision == Decision.DENY

    def test_evaluates_unknown_tools_against_tool_access(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        mcp_guard = create_mcp_guard(guard)
        result = mcp_guard("safe_tool", {"data": "test"})
        assert result.decision == Decision.ALLOW

    def test_allows_all_with_permissive_policy(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)
        mcp_guard = create_mcp_guard(guard)
        assert mcp_guard("read_file", {"path": "/any/path"}).decision == Decision.ALLOW
        assert (
            mcp_guard("fetch", {"url": "https://any.domain.com"}).decision
            == Decision.ALLOW
        )
        assert (
            mcp_guard("run_command", {"command": "anything"}).decision
            == Decision.ALLOW
        )



# CrewAI adapter



class TestSecureTool:
    def test_allows_permitted_tool(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        @secure_tool(guard, tool_name="safe_tool")
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) == 10

    def test_denies_blocked_tool(self):
        guard = HushGuard.from_yaml(DENY_POLICY)

        @secure_tool(guard, tool_name="dangerous_tool")
        def my_tool(x: int) -> int:
            return x * 2

        with pytest.raises(HushSpecDenied):
            my_tool(5)

    def test_uses_function_name_as_default(self):
        guard = HushGuard.from_yaml(DENY_POLICY)

        @secure_tool(guard)
        def safe_tool(x: int) -> int:
            return x * 2

        # safe_tool is in the allow list
        assert safe_tool(5) == 10

    def test_preserves_function_name(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        @secure_tool(guard)
        def my_function():
            pass

        assert my_function.__name__ == "my_function"

    def test_preserves_docstring(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        @secure_tool(guard)
        def my_function():
            """My docstring."""
            pass

        assert my_function.__doc__ == "My docstring."

    def test_preserves_wrapped_reference(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        def original():
            pass

        wrapped = secure_tool(guard)(original)
        assert wrapped.__wrapped__ is original  # type: ignore[attr-defined]

    def test_custom_action_type(self):
        guard = HushGuard.from_yaml(DENY_POLICY)

        @secure_tool(guard, tool_name="rm -rf /", action_type="shell_command")
        def dangerous():
            return "should not run"

        with pytest.raises(HushSpecDenied):
            dangerous()



# Anthropic adapter



class _ToolUseBlock:
    """An SDK-shaped block: attributes, not keys."""

    def __init__(self, name: str, input: dict) -> None:
        self.type = "tool_use"
        self.id = "toolu_01ABC"
        self.name = name
        self.input = input


def _block(name: str, tool_input: dict | None = None) -> dict:
    return {
        "type": "tool_use",
        "id": "toolu_01ABC",
        "name": name,
        "input": tool_input if tool_input is not None else {},
    }


class TestMapClaudeToolToAction:
    def test_maps_bash_to_shell_command(self):
        action = map_claude_tool_to_action(_block("bash", {"command": "rm -rf /"}))
        assert action.type == "shell_command"
        assert action.target == "rm -rf /"

    def test_maps_dated_tool_versions(self):
        action = map_claude_tool_to_action(_block("bash_20250124", {"command": "ls"}))
        assert action.type == "shell_command"
        assert action.target == "ls"

    def test_maps_editor_view_to_file_read(self):
        action = map_claude_tool_to_action(
            _block(
                "text_editor_20250429",
                {"command": "view", "path": "/home/dev/.ssh/id_rsa"},
            )
        )
        assert action.type == "file_read"
        assert action.target == "/home/dev/.ssh/id_rsa"

    def test_maps_editor_str_replace_to_file_write_with_content(self):
        action = map_claude_tool_to_action(
            _block(
                "str_replace_editor",
                {
                    "command": "str_replace",
                    "path": "/app/config.py",
                    "old_str": "a",
                    "new_str": "SECRET = 'x'",
                },
            )
        )
        assert action.type == "file_write"
        assert action.target == "/app/config.py"
        assert action.content == "SECRET = 'x'"

    def test_maps_editor_create_to_file_write_with_file_text(self):
        action = map_claude_tool_to_action(
            _block(
                "str_replace_based_edit_tool",
                {"command": "create", "path": "/app/new.py", "file_text": "print(1)"},
            )
        )
        assert action.type == "file_write"
        assert action.content == "print(1)"

    def test_maps_computer_to_computer_use(self):
        action = map_claude_tool_to_action(_block("computer", {"action": "screenshot"}))
        assert action.type == "computer_use"
        assert action.target == "screenshot"

    def test_maps_web_fetch_to_egress_on_the_host(self):
        action = map_claude_tool_to_action(
            _block("web_fetch", {"url": "https://evil.example.com/a/b?c=d"})
        )
        assert action.type == "egress"
        assert action.target == "evil.example.com"

    def test_maps_fetch_to_egress(self):
        action = map_claude_tool_to_action(
            _block("fetch", {"url": "http://api.example.com/v1"})
        )
        assert action.type == "egress"
        assert action.target == "api.example.com"

    def test_unparseable_url_is_still_evaluated(self):
        action = map_claude_tool_to_action(_block("web_fetch", {"url": "not a url"}))
        assert action.type == "egress"
        assert action.target == "not a url"

    def test_maps_mcp_tools_to_their_inner_name(self):
        action = map_claude_tool_to_action(
            _block("mcp__github__create_issue", {"title": "x"})
        )
        assert action.type == "tool_call"
        assert action.target == "create_issue"
        assert action.args_size == canonical_size({"title": "x"})

    def test_maps_an_unknown_tool_to_a_tool_call(self):
        args = {"query": "select 1"}
        action = map_claude_tool_to_action(_block("run_query", args))
        assert action.type == "tool_call"
        assert action.target == "run_query"
        assert action.args_size == canonical_size(args)

    def test_reads_sdk_objects_structurally(self):
        action = map_claude_tool_to_action(_ToolUseBlock("bash", {"command": "whoami"}))
        assert action.type == "shell_command"
        assert action.target == "whoami"

    def test_a_block_with_no_input_is_still_mapped(self):
        action = map_claude_tool_to_action({"name": "bash"})
        assert action.type == "shell_command"
        assert action.target == ""

    def test_a_nameless_block_is_an_opaque_tool_call(self):
        action = map_claude_tool_to_action({})
        assert action.type == "tool_call"
        assert action.target == ""


class TestCreateSecureToolHandler:
    def test_runs_an_allowed_tool(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        calls: list[dict] = []
        handler = create_secure_tool_handler(
            guard, lambda block: calls.append(block) or "ok"
        )

        assert handler(_block("safe_tool", {})) == "ok"
        assert len(calls) == 1

    def test_a_denied_tool_never_runs(self):
        guard = HushGuard.from_yaml(DENY_POLICY)
        calls: list[dict] = []
        handler = create_secure_tool_handler(guard, lambda block: calls.append(block))

        with pytest.raises(HushSpecDenied):
            handler(_block("bash", {"command": "rm -rf /tmp"}))
        assert calls == []

    def test_passes_extra_arguments_through(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)
        handler = create_secure_tool_handler(
            guard, lambda block, suffix: f"{block['name']}{suffix}"
        )

        assert handler(_block("anything", {}), "!") == "anything!"
