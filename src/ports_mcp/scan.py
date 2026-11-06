"""Socket discovery: who is listening on which port.

``psutil.net_connections`` is the cross-platform source. Its limits differ per OS and the
caller must be told about them rather than shown a silently incomplete list:

* Linux, not root: other users' sockets are listed but their PID is None.
* macOS, not root: the call raises AccessDenied. We fall back to asking each process we are
  allowed to inspect; sockets of processes we cannot inspect are then missing, and the scan
  result says how many processes were unreadable.
* Windows: works unprivileged, but details of system services may be denied later.
"""

from __future__ import annotations

import socket
import sys
from dataclasses import dataclass, field
from typing import Any

import psutil


@dataclass(frozen=True)
class Listener:
    proto: str  # "tcp" | "udp"
    address: str
    port: int
    pid: int | None  # None: the OS did not reveal the owner (needs elevation)


@dataclass
class ScanResult:
    listeners: list[Listener] = field(default_factory=list)
    # Human-readable limitations of this scan (hidden owners, unreadable processes).
    notes: list[str] = field(default_factory=list)

    @property
    def hidden_owner_count(self) -> int:
        return sum(1 for ln in self.listeners if ln.pid is None)


def _windows_unnamed_listener(c: Any) -> bool:
    """Some Windows 11 builds report sockets created inside restricted job/sandbox contexts
    with TCP state 0 (psutil: 'NONE') instead of LISTEN, and netstat omits them, but they do
    accept connections. A TCP socket with no remote end and state NONE is a listener."""
    return sys.platform == "win32" and c.status == psutil.CONN_NONE and not c.raddr


def _as_listener(c: Any, pid: int | None) -> Listener | None:
    if not c.laddr:
        return None
    if c.type == socket.SOCK_STREAM:
        if c.status != psutil.CONN_LISTEN and not _windows_unnamed_listener(c):
            return None
        proto = "tcp"
    elif c.type == socket.SOCK_DGRAM:
        if c.raddr:  # a connected UDP socket is a client, not a server
            return None
        proto = "udp"
    else:
        return None
    return Listener(proto, str(c.laddr.ip), int(c.laddr.port), pid)


def scan(proto: str = "tcp") -> ScanResult:
    """List listening sockets. ``proto`` is "tcp", "udp" or "all"."""
    if proto not in ("tcp", "udp", "all"):
        raise ValueError(f"protocol must be 'tcp', 'udp' or 'all', not {proto!r}")
    result = ScanResult()
    found: set[Listener] = set()
    try:
        conns: list[Any] = list(psutil.net_connections(kind="inet"))
        for c in conns:
            ln = _as_listener(c, c.pid)
            if ln is not None:
                found.add(ln)
    except psutil.AccessDenied:
        unreadable = 0
        for p in psutil.process_iter():
            try:
                pconns: list[Any] = list(p.net_connections(kind="inet"))
                for c in pconns:
                    ln = _as_listener(c, p.pid)
                    if ln is not None:
                        found.add(ln)
            except psutil.AccessDenied:
                unreadable += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        result.notes.append(
            "The OS only lets root list all sockets, so each process was inspected "
            f"individually; {unreadable} process(es) could not be read and any ports they "
            "hold are NOT in this list. Run the server with sudo for a complete view."
        )
    result.listeners = sorted(
        (ln for ln in found if proto == "all" or ln.proto == proto),
        key=lambda ln: (ln.port, ln.proto, ln.address, ln.pid or 0),
    )
    hidden = result.hidden_owner_count
    if hidden:
        result.notes.append(
            f"{hidden} listener(s) belong to processes the OS will not identify without "
            "elevation (Administrator on Windows, sudo on Linux/macOS)."
        )
    return result


def listeners_on_port(port: int, proto: str = "tcp") -> ScanResult:
    r = scan(proto)
    r.listeners = [ln for ln in r.listeners if ln.port == port]
    return r


def probe_hidden_listener(port: int) -> bool:
    """True if a TCP connect to localhost:port succeeds. Used to catch a listener the scan
    could not see (unreadable owner)."""
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            continue
    return False


def bind_probe(port: int, host: str = "127.0.0.1") -> str | None:
    """Try to bind ``host:port``. None if it works, otherwise the OS error text.

    SO_REUSEADDR is deliberately not set: on Windows it would let us "bind" a port that is
    already in use.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
    except OSError as e:
        return str(e)
    finally:
        s.close()
    return None
