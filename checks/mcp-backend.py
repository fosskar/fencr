import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer backend-test-token":
            self.send_response(401)
            self.end_headers()
            return
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if "id" not in request:
            self.send_response(202)
            self.end_headers()
            return
        if request["method"] == "initialize":
            result = {
                "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                "serverInfo": {"name": "test", "version": "1"},
            }
        elif request["method"] == "tools/list":
            result = {"tools": [
                {"name": name, "inputSchema": {"type": "object"}}
                for name in ["read", "write", "hidden"]
            ]}
        elif request["method"] == "tools/call":
            result = {"content": [{"type": "text", "text": "called " + request["params"]["name"] + " " + json.dumps(request["params"].get("arguments", {}))}]}
        else:
            self.send_response(400)
            self.end_headers()
            return
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("127.0.0.1", 8766), Handler).serve_forever()
