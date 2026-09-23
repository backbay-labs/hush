from hushspec import HushGuard, HushSpecDenied, EvaluationAction
from hushspec.adapters import hush_tool, secure_tool
import sys

guard = HushGuard.from_file(sys.argv[1] if len(sys.argv) > 1 else "policy.yaml")
dispatches = []


@hush_tool(guard, tool_name="deploy")
def deploy():
    dispatches.append("deploy")


@secure_tool(guard, tool_name="write_file")
def write_file(content: str):
    dispatches.append(content)


@hush_tool(guard, action_type="file_read",
           action_mapper=lambda args, kwargs: EvaluationAction(type="file_read", target=args[0]))
def read_file(path: str):
    dispatches.append(path)


for operation in (deploy, lambda: write_file("synthetic"), lambda: read_file("/workspace/.env")):
    try:
        operation()
    except HushSpecDenied:
        pass
    else:
        raise AssertionError("Denied tool reached its body")
assert dispatches == []
try:
    invalid = hush_tool(guard, action_type="file_read")(lambda path: dispatches.append(path))
    invalid("/workspace/file.txt")
except ValueError as error:
    assert "action_mapper" in str(error)
else:
    raise AssertionError("Missing action mapper was accepted")
assert dispatches == []
guard.close()
print("PASS: Python LangChain/CrewAI decorators block before dispatch and require explicit effect mapping")
