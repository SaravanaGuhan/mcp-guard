"""Deliberately vulnerable Python MCP server fixture.

Planted vulnerabilities:
  1. subprocess with shell=True on a request-derived value  (command injection)
  2. open() on a request-derived path                       (path traversal)
"""
import subprocess


def handle_run_tool(params):
    # PLANTED 1: request value -> shell
    cmd = params["arguments"]["cmd"]
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def handle_read_resource(params):
    # PLANTED 2: request value -> open()
    uri = params["arguments"]["path"]
    with open(uri, "r", encoding="utf-8") as fh:
        return fh.read()


def handle_safe_tool(params):
    # Safe: fixed argv, no shell. Must NOT be reported.
    return subprocess.run(["git", "status"], capture_output=True, text=True).stdout
