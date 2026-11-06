"""MCP stdio test: launches the real server as a subprocess, lists the tools and drives the
whole find -> plan -> confirm -> freed flow over the protocol."""

from __future__ import annotations

import re
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

from conftest import Factory, port_is_free, wait_until  # noqa: E402

EXPECTED_TOOLS = {
    "list_listening",
    "whats_on_port",
    "find_free_port",
    "kill_port",
    "process_tree",
    "check_port_reachable",
}


def params() -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "ports_mcp"])


@pytest.mark.anyio
async def test_full_flow_over_stdio(spawn: Factory) -> None:
    s = spawn.http_server()
    async with stdio_client(params()) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "ports"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(t.description and len(t.description) > 80 for t in tools)

        res = await session.call_tool("whats_on_port", {"port": s.port})
        assert not res.is_error and "Python http.server" in res.content[0].text

        res = await session.call_tool("check_port_reachable", {"host": "127.0.0.1", "port": s.port})
        assert res.content[0].text.startswith("REACHABLE")

        res = await session.call_tool("kill_port", {"port": s.port})
        plan = res.content[0].text
        assert not res.is_error and "nothing has been killed yet" in plan
        assert not port_is_free(s.port)
        token = re.search(r"Token: ([0-9a-f]+)", plan)
        assert token

        res = await session.call_tool("kill_port", {"port": s.port, "confirm_token": token.group(1)})
        assert not res.is_error and "is now free" in res.content[0].text
        assert wait_until(lambda: port_is_free(s.port))

        res = await session.call_tool("check_port_reachable", {"host": "127.0.0.1", "port": s.port})
        assert res.content[0].text.startswith("UNREACHABLE")


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(spawn: Factory) -> None:
    s = spawn.http_server()
    async with stdio_client(params()) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("whats_on_port", {"port": 99999})
        assert res.is_error and "between 1 and 65535" in res.content[0].text
        res = await session.call_tool("kill_port", {"port": s.port, "confirm_token": "nope"})
        assert res.is_error and "Call kill_port" in res.content[0].text
        assert not port_is_free(s.port)
        res = await session.call_tool("process_tree", {"pid": 2**22 + 99})
        assert res.is_error and "No process with PID" in res.content[0].text
        res = await session.call_tool("find_free_port", {"start": 5000, "end": 4000})
        assert res.is_error and "greater than" in res.content[0].text


@pytest.mark.anyio
async def test_listing_over_stdio(spawn: Factory) -> None:
    s = spawn.http_server()
    async with stdio_client(params()) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("list_listening", {"process_name": "http.server"})
        assert f"127.0.0.1:{s.port}" in res.content[0].text


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
