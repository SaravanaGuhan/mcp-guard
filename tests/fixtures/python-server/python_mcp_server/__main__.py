"""Deliberately vulnerable Python MCP server fixture.

A real stdio JSON-RPC server, so the dynamic engine can actually launch it and
the ephemeral-venv path is exercised end to end.

Planted vulnerabilities, and nothing else:
  1. subprocess with shell=True on a request-derived value  (command injection)
  2. open() on a request-derived path                       (path traversal)
"""
import json
import subprocess
import sys


def handle_run_tool(params):
    # PLANTED 1: request value -> shell
    cmd = params["arguments"]["cmd"]
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout or result.stderr


def handle_read_resource(params):
    # PLANTED 2: request value -> open()
    uri = params["uri"].replace("file://", "")
    with open(uri, "r", encoding="utf-8") as fh:
        return fh.read()


def handle_safe_tool(params):
    # Safe: fixed argv, no shell. Must NOT be reported.
    return subprocess.run(["git", "status"], capture_output=True,
                          text=True).stdout


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "resources": {}},
                    "serverInfo": {"name": "python-server", "version": "1.0.0"}}})
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                    {"name": "run", "description": "run a shell command",
                     "inputSchema": {"type": "object",
                                     "properties": {"cmd": {"type": "string"}},
                                     "required": ["cmd"]}}]}})
            elif method == "tools/call" and params.get("name") == "run":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text",
                                 "text": handle_run_tool(params)}]}})
            elif method == "resources/read":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "contents": [{"uri": params.get("uri", ""),
                                  "text": handle_read_resource(params)}]}})
            elif method == "resources/list":
                send({"jsonrpc": "2.0", "id": mid,
                      "result": {"resources": []}})
            elif method and method.startswith("notifications/"):
                continue
            else:
                send({"jsonrpc": "2.0", "id": mid,
                      "error": {"code": -32601, "message": "Method not found"}})
        except Exception as exc:
            send({"jsonrpc": "2.0", "id": mid,
                  "error": {"code": -32603, "message": str(exc)}})


if __name__ == "__main__":
    main()
