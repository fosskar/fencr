# adapted from nixfiles/packages/mcp-gateway; see LICENSE
from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import os
import signal
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount


def secret(name: str) -> str:
    value = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / name).read_text().strip()
    if not value:
        raise RuntimeError(f"credential is empty: {name}")
    return value


def matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


@contextlib.asynccontextmanager
async def downstream(server: dict[str, Any]):
    async with (
        httpx.AsyncClient(
            timeout=httpx.Timeout(30, read=300),
            headers={"Authorization": f"Bearer {secret(server['token_credential'])}"},
            follow_redirects=False,
            trust_env=False,
        ) as http_client,
        streamable_http_client(server["url"], http_client=http_client) as (
            read, write, _,
        ),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


# the handshake costs more than the call it carries: a fresh session per
# tool call spends about 100ms on the transport, the initialize and the
# teardown before the backend sees anything. reuse one inside a window
IDLE_WINDOW = 30


class Sessions:
    """One downstream session per principal per backend.

    Keyed by principal, so a session never carries one vm's state to
    another. Opened on first use, so a backend that is down cannot keep the
    gateway from starting — every mcp-enabled vm's egress unit requires it.
    Dropped when idle past the window, so a restarted backend heals without
    any reconnect logic of its own.
    """

    def __init__(self, window: float = IDLE_WINDOW):
        self.window = window
        self.entries: dict[tuple[str, str], tuple[Any, float, contextlib.AsyncExitStack]] = {}
        self.locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def discard(self, key) -> None:
        entry = self.entries.pop(key, None)
        if entry is None:
            return
        # a session that already died cannot be closed cleanly, and saying so
        # adds nothing: the entry is gone either way
        with contextlib.suppress(Exception):
            await entry[2].aclose()

    async def acquire(self, key, server: dict[str, Any]):
        lock = self.locks.get(key)
        if lock is None:
            lock = self.locks[key] = asyncio.Lock()
        async with lock:
            entry = self.entries.get(key)
            if entry is not None and time.monotonic() - entry[1] < self.window:
                self.entries[key] = (entry[0], time.monotonic(), entry[2])
                return entry[0]
            await self.discard(key)
            stack = contextlib.AsyncExitStack()
            session = await stack.enter_async_context(downstream(server))
            self.entries[key] = (session, time.monotonic(), stack)
            return session

    async def call(self, key, server: dict[str, Any], action):
        """Run action against the session, once more on a fresh one if it fails.

        A session can die between two calls without anything noticing, so the
        first failure is retried rather than reported.
        """
        for last in (False, True):
            session = await self.acquire(key, server)
            try:
                return await action(session)
            except Exception:
                await self.discard(key)
                if last:
                    raise

    async def aclose(self) -> None:
        for key in list(self.entries):
            await self.discard(key)


async def approve(command: list[str], timeout: float, request: dict[str, Any]) -> None:
    if not command:
        raise PermissionError("no host approval command configured")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            env={"PATH": os.defpath},
            start_new_session=True,
        )
    except OSError as error:
        raise PermissionError("host approval command unavailable") from error
    try:
        async with asyncio.timeout(timeout):
            await process.communicate(json.dumps(request, sort_keys=True).encode())
        if process.returncode != 0:
            raise PermissionError("host approval refused")
    except TimeoutError as error:
        raise PermissionError("host approval timed out") from error
    finally:
        # an approval helper must not leave a pending decision alive after timeout
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


async def approve_client(context, timeout, request):
    params = context.session.client_params
    capability = params.capabilities.elicitation if params else None
    # legacy clients advertise form elicitation as an empty capability object
    if capability is None or (capability.form is None and capability.url is not None):
        raise PermissionError("client does not support form elicitation")
    try:
        async with asyncio.timeout(timeout):
            result = await context.session.elicit_form(
                "Approve this tool call? " + json.dumps(request, sort_keys=True),
                {"type": "object", "properties": {}},
                related_request_id=context.request_id,
            )
    except TimeoutError as error:
        raise PermissionError("client approval timed out") from error
    if result.action != "accept":
        raise PermissionError("client approval refused")


def create_server(name, principal, config, sessions):
    servers = config["servers"]
    approval_mode = config["approval_mode"]
    approval_command = config["approval_command"]
    approval_timeout = config["approval_timeout"]
    gateway = Server("fencr-mcp-gateway")

    def permitted(server_name, tool_name):
        return (
            not matches(tool_name, servers[server_name].get("hidden_tools", []))
            and matches(f"{server_name}.{tool_name}", principal["allow"])
        )

    @gateway.list_tools()
    async def list_tools() -> list[types.Tool]:
        tools = []
        for server_name, server in servers.items():
            async def listing(session, server_name=server_name):
                found = []
                cursor = None
                while True:
                    result = await session.list_tools(cursor=cursor)
                    found.extend(
                        tool.model_copy(update={"name": f"{server_name}__{tool.name}"})
                        for tool in result.tools
                        if permitted(server_name, tool.name)
                    )
                    cursor = result.nextCursor
                    if cursor is None:
                        return found

            tools.extend(await sessions.call((name, server_name), server, listing))
        return tools

    @gateway.call_tool()
    async def call_tool(tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
        server_name, separator, tool_name = tool.partition("__")
        if (
            not separator or server_name not in servers or not tool_name
            or not permitted(server_name, tool_name)
        ):
            raise ValueError("unknown MCP gateway tool")
        server = servers[server_name]
        if matches(tool_name, server["approval_tools"]):
            request = {
                "principal": name, "server": server_name,
                "tool": tool_name, "arguments": arguments,
            }
            if approval_mode == "client":
                await approve_client(gateway.request_context, approval_timeout, request)
            else:
                await approve(approval_command, approval_timeout, request)
        return await sessions.call(
            (name, server_name), server, lambda session: session.call_tool(tool_name, arguments)
        )

    return gateway


def create_app(config):
    if config["approval_mode"] not in ("host", "client"):
        raise ValueError("unknown approval mode")
    tokens = {}
    sessions = Sessions()
    for name, principal in config["principals"].items():
        token = secret(principal["token_credential"])
        if not token.startswith("Bearer ") or token.encode() in tokens:
            raise RuntimeError("gateway principals need distinct bearer credentials")
        tokens[token.encode()] = StreamableHTTPSessionManager(
            app=create_server(name, principal, config, sessions),
            # elicitation requests must reach the client before the tool call completes
            json_response=config["approval_mode"] == "host",
            session_idle_timeout=1800,
        )

    async def handle(scope, receive, send):
        authorization = [value for key, value in scope["headers"] if key == b"authorization"]
        manager = tokens.get(authorization[0]) if len(authorization) == 1 else None
        if manager is None:
            await PlainTextResponse("Unauthorized", status_code=401)(scope, receive, send)
            return
        # each principal owns a separate transport registry, including GET and DELETE
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_):
        async with contextlib.AsyncExitStack() as stack:
            stack.push_async_callback(sessions.aclose)
            for manager in tokens.values():
                await stack.enter_async_context(manager.run())
            yield

    return Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)


def main():
    config = json.loads(Path(os.environ["MCP_GATEWAY_CONFIG"]).read_text())
    uvicorn.run(create_app(config), host="127.0.0.1", port=config["port"], access_log=False)


if __name__ == "__main__":
    main()
