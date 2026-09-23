"""Deterministic coding actor. Its only host-side effect route is MCP stdio."""
import argparse
import http.client
import json
import subprocess
import sys
from urllib.parse import urlparse

parser = argparse.ArgumentParser()
parser.add_argument("--origin", required=True)
parser.add_argument("--protected-path", required=True)
args = parser.parse_args()
request_id = 0


def request(method, params):
    global request_id
    request_id += 1
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        # Deliberately untrusted identity claim. The host never selects a handle from it.
        "io.modelcontextprotocol/serverInfo": {"name": "repo", "version": "trusted"},
    }
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}), flush=True)
    line = sys.stdin.buffer.readline(524289)
    if not line or len(line) > 524288 or not line.endswith(b"\n"):
        raise RuntimeError("missing or oversized host response")
    reply = json.loads(line)
    if reply.get("id") != request_id or "error" in reply:
        raise RuntimeError("host protocol failure")
    return reply["result"]


def call(name, arguments):
    return request("tools/call", {"name": name, "arguments": arguments})["structuredContent"]


probes = {}
try:
    with open(args.protected_path, "r", encoding="utf8") as stream:
        stream.read()
    probes["direct_read_denied"] = False
except OSError:
    probes["direct_read_denied"] = True
try:
    with open(args.protected_path, "w", encoding="utf8") as stream:
        stream.write("bypass")
    probes["direct_write_denied"] = False
except OSError:
    probes["direct_write_denied"] = True
url = urlparse(args.origin)
try:
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=1)
    connection.request("GET", "/direct-bypass")
    connection.getresponse().read()
    probes["direct_network_denied"] = False
except OSError:
    probes["direct_network_denied"] = True
finally:
    connection.close()
shell = subprocess.run(["/bin/sh", "-c", 'printf bypass > "$1"', "probe", args.protected_path],
                       capture_output=True, timeout=2, check=False)
probes["shell_host_write_denied"] = shell.returncode != 0

listed = request("tools/list", {})
assert "repo.patch_file" in [tool["name"] for tool in listed["tools"]]
read = call("repo.read_file", {"path": "note.txt"})
assert read["status"] == "completed"
before = read["value"]["structuredContent"]["content"]
after = before.replace("41", "42") + "// review-me\n"
patch = call("repo.patch_file", {"path": "note.txt", "before": before, "after": after})
assert patch["status"] == "completed"
assert call("network.fetch", {"url": args.origin + "/ok"})["status"] == "completed"
assert call("network.fetch", {"url": args.origin + "/redirect"})["status"] == "error"
for name, arguments in [
    ("repo.read_file", {"path": "secret.txt"}),
    ("other.read_file", {"path": "note.txt"}),
    ("repo.read_file", {"path": "../secret.txt"}),
    ("network.fetch", {"url": args.origin + "/outside"}),
    ("shell_exec", {"command": "cat /workspace/secret.txt"}),
]:
    assert call(name, arguments)["status"] == "blocked"
for name in ["symlink", "hardlink"]:
    assert call("repo.read_file", {"path": name})["status"] == "error"
assert all(probes.values())
print(json.dumps({"probes": probes, "workflow_completed": True, "requests": request_id}), file=sys.stderr, flush=True)
