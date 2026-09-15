from hushspec.adapters.anthropic import (
    create_secure_tool_handler,
    map_claude_tool_to_action,
)
from hushspec.adapters.langchain import hush_tool
from hushspec.adapters.openai import map_openai_tool_call, create_openai_guard
from hushspec.adapters.mcp import map_mcp_tool_call, extract_domain, create_mcp_guard
from hushspec.adapters.crewai import secure_tool

__all__ = [
    "map_claude_tool_to_action",
    "create_secure_tool_handler",
    "hush_tool",
    "map_openai_tool_call",
    "create_openai_guard",
    "map_mcp_tool_call",
    "extract_domain",
    "create_mcp_guard",
    "secure_tool",
]
