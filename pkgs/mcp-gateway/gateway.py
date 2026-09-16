# adapted from nixfiles/packages/mcp-gateway; see LICENSE
from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import os
import signal
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


def create_server(name, principal, servers, approval_command, approval_timeout):
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
            async with downstream(server) as session:
                cursor = None
                while True:
                    result = await session.list_tools(cursor=cursor)
                    tools.extend(
                        tool.model_copy(update={"name": f"{server_name}__{tool.name}"})
                        for tool in result.tools
                        if permitted(server_name, tool.name)
                    )
                    cursor = result.nextCursor
                    if cursor is None:
                        break
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
            await approve(approval_command, approval_timeout, {
                "principal": name, "server": server_name,
                "tool": tool_name, "arguments": arguments,
            })
        async with downstream(server) as session:
            return await session.call_tool(tool_name, arguments)

    return gateway


def create_app(config):
    tokens = {}
    managers = []
    for name, principal in config["principals"].items():
        token = secret(principal["token_credential"])
        if not token.startswith("Bearer ") or token.encode() in tokens:
            raise RuntimeError("gateway principals need distinct bearer credentials")
        manager = StreamableHTTPSessionManager(
            app=create_server(name, principal, config["servers"],
                              config["approval_command"], config["approval_timeout"]),
            json_response=True,
            session_idle_timeout=1800,
        )
        managers.append(manager)
        tokens[token.encode()] = manager

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
            for manager in managers:
                await stack.enter_async_context(manager.run())
            yield

    return Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)


def main():
    config = json.loads(Path(os.environ["MCP_GATEWAY_CONFIG"]).read_text())
    uvicorn.run(create_app(config), host="127.0.0.1", port=config["port"], access_log=False)


if __name__ == "__main__":
    main()
