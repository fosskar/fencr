import json
import os
import sys


def readable(path):
    try:
        os.listdir(path)
        return True
    except OSError:
        return False


for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    if request["method"] == "initialize":
        result = {
            "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
            "serverInfo": {"name": "local", "version": "1"},
        }
    elif request["method"] == "tools/list":
        result = {"tools": [{"name": "probe", "inputSchema": {"type": "object"}}]}
    elif request["method"] == "tools/call":
        probe = {
            "pid": os.getpid(),
            "uid": os.getuid(),
            "gateway": readable("/run/credentials/fencr-mcp-gateway.service"),
            "tokens": readable("/var/lib/fencr-mcp"),
        }
        result = {"content": [{"type": "text", "text": "probe " + json.dumps(probe)}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
