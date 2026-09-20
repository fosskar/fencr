import asyncio
import contextlib
import json
import os
import socket
import time
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import anyio
import httpx
import uvicorn
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient

import gateway


class Backend:
    def __init__(self):
        self.calls = []

    async def list_tools(self, cursor=None):
        names = ["read", "write"] if cursor is None else ["hidden"]
        return types.ListToolsResult(
            tools=[types.Tool(name=name, inputSchema={"type": "object"}) for name in names],
            nextCursor="second" if cursor is None else None,
        )

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return types.CallToolResult(content=[types.TextContent(type="text", text="done")])


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        for name in ["agent", "reader", "backend"]:
            (directory / name).write_text("Bearer " + name + "-secret" if name != "backend" else "backend-secret")
        environment = patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)})
        environment.start()
        self.addCleanup(environment.stop)
        self.config = {
            "port": 8764,
            "servers": {"calendar": {
                "url": "http://127.0.0.1:8765/mcp/",
                "token_credential": "backend",
                "approval_tools": ["write"], "hidden_tools": ["hidden"],
            }},
            "principals": {
                "agent": {"token_credential": "agent", "allow": ["calendar.*"]},
                "reader": {"token_credential": "reader", "allow": ["calendar.read"]},
            },
            "approval_mode": "host", "approval_command": [], "approval_timeout": 1,
        }
        self.backend = Backend()
        self.opened = 0

        @contextlib.asynccontextmanager
        async def downstream(_):
            self.opened += 1
            # the transport and the client session are anyio context managers,
            # so entering one binds a cancel scope to the entering task. a stub
            # without one cannot catch a session entered in a request task and
            # then held past it
            async with anyio.create_task_group():
                yield self.backend

        patched = patch.object(gateway, "downstream", downstream)
        patched.start()
        self.addCleanup(patched.stop)

    def client(self):
        return TestClient(gateway.create_app(self.config))

    def headers(self, principal="agent", session=None):
        headers = {"Authorization": f"Bearer {principal}-secret", "Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
            headers["MCP-Protocol-Version"] = "2025-03-26"
        return headers

    def initialize(self, client, principal="agent"):
        response = client.post("/mcp/", headers=self.headers(principal), json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        })
        self.assertEqual(response.status_code, 200, response.text)
        session = response.headers["mcp-session-id"]
        response = client.post("/mcp/", headers=self.headers(principal, session), json={
            "jsonrpc": "2.0", "method": "notifications/initialized",
        })
        self.assertEqual(response.status_code, 202, response.text)
        return session

    def request(self, client, session, method, params=None, principal="agent"):
        response = client.post("/mcp/", headers=self.headers(principal, session), json={
            "jsonrpc": "2.0", "id": 2, "method": method, "params": params or {},
        })
        self.assertEqual(response.status_code, 200, response.text)
        for value in ["agent-secret", "reader-secret", "backend-secret"]:
            self.assertNotIn(value, response.text)
        return response.json()["result"]

    def test_listing_and_invocation_are_scoped(self):
        with self.client() as client:
            agent = self.initialize(client)
            reader = self.initialize(client, "reader")
            tools = self.request(client, agent, "tools/list")["tools"]
            self.assertEqual([tool["name"] for tool in tools], ["calendar__read", "calendar__write"])
            tools = self.request(client, reader, "tools/list", principal="reader")["tools"]
            self.assertEqual([tool["name"] for tool in tools], ["calendar__read"])
            for name in ["calendar__write", "calendar__hidden", "other__read"]:
                result = self.request(client, reader, "tools/call", {"name": name}, "reader")
                self.assertTrue(result["isError"])
            self.assertEqual(self.backend.calls, [])
            self.request(client, reader, "tools/call", {"name": "calendar__read"}, "reader")
            self.assertEqual(self.backend.calls, [("read", {})])

    def test_one_session_per_principal_is_reused(self):
        with self.client() as client:
            agent = self.initialize(client)
            reader = self.initialize(client, "reader")
            self.request(client, agent, "tools/call", {"name": "calendar__read"})
            self.request(client, agent, "tools/call", {"name": "calendar__read"})
            # the handshake costs more than the call, so the second one reuses
            # the session the first opened
            self.assertEqual(self.opened, 1)
            self.request(client, reader, "tools/call", {"name": "calendar__read"}, "reader")
            # and a second principal opens its own: a session must never carry
            # one sandbox's state to another
            self.assertEqual(self.opened, 2)
            self.assertEqual(self.backend.calls, [("read", {})] * 3)

    def test_a_dead_session_is_retried_on_a_fresh_one(self):
        with self.client() as client:
            agent = self.initialize(client)
            self.request(client, agent, "tools/call", {"name": "calendar__read"})
            self.assertEqual(self.opened, 1)
            # a backend may go away between two calls with nothing noticing
            failures = [True]
            original = self.backend.call_tool

            async def once(name, arguments):
                if failures.pop() if failures else False:
                    raise RuntimeError("the backend went away")
                return await original(name, arguments)

            self.backend.call_tool = once
            result = self.request(client, agent, "tools/call", {"name": "calendar__read"})
            self.assertFalse(result["isError"], result)
            self.assertEqual(self.opened, 2)

    # the backend may have acted before the failure; one approval is one
    # invocation, so an approved call is never sent twice
    def test_an_approved_call_is_not_retried(self):
        self.config["approval_command"] = [sys.executable, "-c", "raise SystemExit(0)"]
        with self.client() as client:
            agent = self.initialize(client)
            original = self.backend.call_tool

            async def acted_then_died(name, arguments):
                await original(name, arguments)
                raise RuntimeError("the response never arrived")

            self.backend.call_tool = acted_then_died
            result = self.request(client, agent, "tools/call", {"name": "calendar__write"})
            self.assertTrue(result["isError"], result)
            self.assertEqual(self.backend.calls, [("write", {})])

    def test_empty_allow_denies_every_tool(self):
        self.config["principals"]["reader"]["allow"] = []
        with self.client() as client:
            session = self.initialize(client, "reader")
            self.assertEqual(self.request(client, session, "tools/list", principal="reader")["tools"], [])
            result = self.request(client, session, "tools/call", {"name": "calendar__read"}, "reader")
            self.assertTrue(result["isError"])
            self.assertEqual(self.backend.calls, [])

    def test_session_cannot_cross_principals(self):
        with self.client() as client:
            session = self.initialize(client)
            for method in ["GET", "DELETE", "POST"]:
                response = client.request(method, "/mcp/", headers=self.headers("reader", session))
                self.assertEqual(response.status_code, 404, response.text)
            self.request(client, session, "tools/list")
            response = client.post("/mcp/", headers=self.headers("unknown"), json={})
            self.assertEqual(response.status_code, 401)
            response = client.post("/mcp/", headers=[("Authorization", "Bearer agent-secret"), ("Authorization", "Bearer reader-secret")], json={})
            self.assertEqual(response.status_code, 401)

    def test_duplicate_principal_tokens_refused(self):
        Path(self.directory.name, "reader").write_text("Bearer agent-secret")
        with self.assertRaises(RuntimeError):
            gateway.create_app(self.config)

    def test_approval_denial_timeout_error_and_missing_command(self):
        for command in [[], ["/does/not/exist"], [sys.executable, "-c", "raise SystemExit(1)"],
                        [sys.executable, "-c", "import time; time.sleep(60)"]]:
            with self.subTest(command=command):
                self.config["approval_command"] = command
                self.config["approval_timeout"] = 0.1
                with self.client() as client:
                    session = self.initialize(client)
                    result = self.request(client, session, "tools/call", {
                        "name": "calendar__write", "arguments": {"approve": True},
                    })
                    self.assertTrue(result["isError"])
                    self.assertEqual(self.backend.calls, [])

    # one live client: the http stack, the session and its initialize, which
    # every elicitation test needs before it can call a tool
    @contextlib.asynccontextmanager
    async def session(self, url, callback=None, principal="agent"):
        async with (
            httpx.AsyncClient(headers=self.headers(principal), trust_env=False) as http,
            streamable_http_client(url, http_client=http) as (read, write, session_id),
            ClientSession(read, write, elicitation_callback=callback) as session,
        ):
            await session.initialize()
            yield session, session_id

    @contextlib.contextmanager
    def live_gateway(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            server = uvicorn.Server(uvicorn.Config(
                gateway.create_app(self.config), log_level="error", timeout_graceful_shutdown=1,
            ))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]})
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started and thread.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(server.started, "gateway failed to start")
                yield f"http://127.0.0.1:{listener.getsockname()[1]}/mcp/"
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "gateway failed to stop")

    def test_client_elicitation_over_http(self):
        arguments = {"summary": "untrusted\ntext", "nested": {"x": [1, 2]}}
        for action in ["accept", "decline", "cancel", "timeout", "error", "unsupported"]:
            with self.subTest(action=action):
                self.backend.calls.clear()
                self.config["approval_mode"] = "client"
                self.config["approval_timeout"] = 0.1 if action == "timeout" else 2
                prompts = []

                async def callback(context, params):
                    prompts.append(params.message)
                    if action == "timeout":
                        await asyncio.sleep(0.3)
                        return types.ElicitResult(action="accept")
                    if action == "error":
                        return types.ErrorData(code=-32603, message="elicitation failed")
                    return types.ElicitResult(action=action)

                async def run(url):
                    callbacks = None if action == "unsupported" else callback
                    async with self.session(url, callbacks) as (session, _):
                        result = await session.call_tool("calendar__write", arguments)
                        self.assertEqual(result.isError, action != "accept", result)

                with self.live_gateway() as url:
                    asyncio.run(run(url))
                if action == "unsupported":
                    self.assertEqual(prompts, [])
                else:
                    self.assertEqual(len(prompts), 1)
                    self.assertEqual(json.loads(prompts[0].removeprefix("Approve this tool call? ")), {
                        "principal": "agent", "server": "calendar", "tool": "write", "arguments": arguments,
                    })
                self.assertEqual(self.backend.calls, [("write", arguments)] if action == "accept" else [])

    def test_legacy_form_capability_and_url_only_client(self):
        for capability, supported in [({}, True), ({"form": {}}, True), ({"url": {}}, False)]:
            with self.subTest(capability=capability):
                session = SimpleNamespace(
                    client_params=SimpleNamespace(capabilities=types.ClientCapabilities(elicitation=capability)),
                    elicit_form=AsyncMock(return_value=types.ElicitResult(action="accept")),
                )
                context = SimpleNamespace(session=session, request_id=7)
                if supported:
                    asyncio.run(gateway.approve_client(context, 1, {"tool": "write"}))
                    self.assertEqual(session.elicit_form.await_args.kwargs["related_request_id"], 7)
                else:
                    with self.assertRaises(PermissionError):
                        asyncio.run(gateway.approve_client(context, 1, {"tool": "write"}))
                    session.elicit_form.assert_not_awaited()

    def test_client_prompts_do_not_replace_authorization_or_host_approval(self):
        for mode, principal in [("client", "reader"), ("host", "agent")]:
            with self.subTest(mode=mode, principal=principal):
                self.config["approval_mode"] = mode
                prompts = []

                async def callback(context, params):
                    prompts.append(params.message)
                    return types.ElicitResult(action="accept")

                async def run(url):
                    async with self.session(url, callback, principal) as (session, _):
                        result = await session.call_tool("calendar__write", {})
                        self.assertTrue(result.isError)

                with self.live_gateway() as url:
                    asyncio.run(run(url))
                self.assertEqual(prompts, [])
                self.assertEqual(self.backend.calls, [])

    def test_other_principal_cannot_answer_elicitation(self):
        self.config["approval_mode"] = "client"
        prompts = []

        async def run(url):
            async def callback(context, params):
                prompts.append(params.message)
                response = await http.post(url, headers=self.headers("reader", session_id()), json={
                    "jsonrpc": "2.0", "id": context.request_id, "result": {"action": "accept"},
                })
                self.assertEqual(response.status_code, 404)
                return types.ElicitResult(action="decline")

            async with self.session(url, callback) as (session, session_id):
                result = await session.call_tool("calendar__write", {})
                self.assertTrue(result.isError)

        with self.live_gateway() as url:
            asyncio.run(run(url))
        self.assertEqual(len(prompts), 1)
        self.assertEqual(self.backend.calls, [])

    def test_host_approval_receives_exact_invocation(self):
        decision = str(Path(self.directory.name, "decision.json"))
        self.config["approval_command"] = [sys.executable, "-c",
            "import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())", decision]
        arguments = {"summary": "untrusted\ntext", "nested": {"x": [1, 2]}}
        with self.client() as client:
            session = self.initialize(client)
            result = self.request(client, session, "tools/call", {"name": "calendar__write", "arguments": arguments})
            self.assertFalse(result["isError"])
        self.assertEqual(json.loads(Path(decision).read_text()), {
            "principal": "agent", "server": "calendar", "tool": "write", "arguments": arguments,
        })
        self.assertEqual(self.backend.calls, [("write", arguments)])


class TransportTest(unittest.TestCase):
    def test_real_backend_transport_keeps_token_host_side(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                seen.append(self.headers.get("Authorization"))
                if seen[-1] != "Bearer backend-secret":
                    self.send_response(401)
                    self.end_headers()
                    return
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "id" not in request:
                    self.send_response(202)
                    self.end_headers()
                    return
                if request["method"] == "initialize":
                    result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "backend", "version": "1"}}
                elif request["method"] == "tools/list":
                    result = {"tools": []}
                else:
                    result = {"content": [{"type": "text", "text": "done"}]}
                body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "backend").write_text("backend-secret")
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                async def run():
                    async with gateway.downstream({"url": f"http://127.0.0.1:{server.server_port}/mcp/", "token_credential": "backend"}) as session:
                        result = await session.call_tool("read", {})
                        self.assertEqual(result.content[0].text, "done")
                with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": directory}):
                    asyncio.run(run())
                self.assertTrue(seen)
                self.assertEqual(set(seen), {"Bearer backend-secret"})
            finally:
                server.shutdown()
                thread.join()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
