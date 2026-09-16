from __future__ import annotations

import json

import pytest

from hushspec.adapters.openai import map_openai_tool_call, create_openai_guard
from hushspec.adapters.mcp import map_mcp_tool_call, extract_domain, create_mcp_guard
from hushspec.adapters.crewai import secure_tool
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
        assert action.args_size == len(json.dumps(args))

    def test_preserves_exact_string_length(self):
        raw_args = '{"key":   "value"}'  # note extra spaces
        action = map_openai_tool_call("fn", raw_args)
        assert action.args_size == len(raw_args)

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
        action = map_mcp_tool_call("custom_search", {"query": "test"})
        assert action.type == "tool_call"
        assert action.target == "custom_search"
        assert action.args_size is not None
        assert action.args_size > 0

    def test_maps_unknown_tools_without_args(self):
        action = map_mcp_tool_call("ping")
        assert action.type == "tool_call"
        assert action.target == "ping"
        assert action.args_size is None

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
