"""find_free_port and check_port_reachable against real sockets."""

from __future__ import annotations

import socket

import pytest

from ports_mcp import server
from ports_mcp.procs import PortsError


def _listen(n: int) -> list[socket.socket]:
    """Occupy n CONSECUTIVE ports (retrying until the OS gives a free run)."""
    for _ in range(200):
        first = socket.socket()
        first.bind(("127.0.0.1", 0))
        base = first.getsockname()[1]
        socks = [first]
        try:
            for i in range(1, n):
                s = socket.socket()
                socks.append(s)
                s.bind(("127.0.0.1", base + i))
            for s in socks:
                s.listen()
            return socks
        except OSError:
            for s in socks:
                s.close()
    raise RuntimeError("could not reserve consecutive ports")


def _first_port(text: str) -> int:
    return int(text.split(": ")[1].split(".")[0].split(",")[0])


def test_find_free_port_skips_occupied_ports() -> None:
    socks = _listen(3)
    try:
        base = socks[0].getsockname()[1]
        assert _first_port(server.find_free_port(base, base + 10)) == base + 3
        assert server.find_free_port(base, base + 10, count=3).count(",") == 2
    finally:
        for s in socks:
            s.close()


def test_find_free_port_errors_when_range_is_full() -> None:
    socks = _listen(3)
    try:
        base = socks[0].getsockname()[1]
        with pytest.raises(PortsError, match="No free port"):
            server.find_free_port(base, base + 2)
    finally:
        for s in socks:
            s.close()


def test_find_free_port_validates() -> None:
    with pytest.raises(PortsError, match="greater"):
        server.find_free_port(9000, 8000)
    with pytest.raises(PortsError, match="count"):
        server.find_free_port(8000, 9000, count=0)


def test_reachable_and_refused() -> None:
    (s,) = _listen(1)
    port = s.getsockname()[1]
    try:
        assert server.check_port_reachable("127.0.0.1", port).startswith("REACHABLE")
    finally:
        s.close()
    refused = server.check_port_reachable("127.0.0.1", port)
    assert refused.startswith("UNREACHABLE") and "refused" in refused


def test_unresolvable_host() -> None:
    text = server.check_port_reachable("no-such-host.invalid", 80, timeout=5)
    assert text.startswith("UNREACHABLE") and "resolve" in text


def test_timeout_is_reported_without_hanging() -> None:
    # A listener that never accept()s with a full backlog: Linux drops further SYNs (timeout),
    # Windows/macOS may refuse instead. Either way the call must return within the timeout.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(0)
    port = s.getsockname()[1]
    fillers = []
    try:
        for _ in range(8):
            c = socket.socket()
            c.setblocking(False)
            c.connect_ex(("127.0.0.1", port))
            fillers.append(c)
        text = server.check_port_reachable("127.0.0.1", port, timeout=0.5)
        assert text.startswith(("UNREACHABLE", "REACHABLE"))
    finally:
        for c in fillers:
            c.close()
        s.close()


def test_reachable_validates_arguments() -> None:
    with pytest.raises(PortsError, match="timeout"):
        server.check_port_reachable("127.0.0.1", 80, timeout=0)
    with pytest.raises(PortsError, match="host"):
        server.check_port_reachable("  ", 80)
