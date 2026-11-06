"""Shared helpers: real listener subprocesses on OS-assigned ports."""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path

import psutil
import pytest

from ports_mcp.scan import bind_probe, listeners_on_port

LISTEN_AND_REPORT = """
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(5)
{extra}
print(s.getsockname()[1], {report}, flush=True)
time.sleep(600)
"""

# Parent listens and owns a child process (no socket) that sleeps.
TREE_PARENT = LISTEN_AND_REPORT.format(
    extra=(
        "import subprocess\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])"
    ),
    report="child.pid",
)

# Ignores SIGTERM. (Windows has no SIGTERM handler concept: terminate is a hard kill there.)
STUBBORN = LISTEN_AND_REPORT.format(
    extra="import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)",
    report="0",
)


class Spawned:
    def __init__(self, proc: subprocess.Popen[str], port: int, extra: int = 0) -> None:
        self.proc = proc
        self.port = port
        self.extra = extra


def owned_by(pid: int | None, spawned: Spawned) -> bool:
    """True if ``pid`` is the spawned process or one of its descendants (on Windows a venv
    python.exe is a launcher whose child is the real interpreter)."""
    if pid is None:
        return False
    if pid == spawned.proc.pid:
        return True
    try:
        return pid in [c.pid for c in psutil.Process(spawned.proc.pid).children(recursive=True)]
    except psutil.NoSuchProcess:
        return False


def port_is_free(port: int) -> bool:
    return not listeners_on_port(port).listeners and bind_probe(port) is None


def wait_until(pred, timeout: float = 10.0) -> bool:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


class Factory:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.procs: list[subprocess.Popen[str]] = []

    def _start(self, args: list[str]) -> subprocess.Popen[str]:
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        self.procs.append(p)
        return p

    def script(self, source: str, name: str = "listener.py") -> Spawned:
        path = self.tmp / f"{len(self.procs)}_{name}"
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        p = self._start([sys.executable, "-u", str(path)])
        assert p.stdout is not None
        parts = p.stdout.readline().split()
        assert parts, "listener script did not report a port"
        return Spawned(p, int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)

    def http_server(self) -> Spawned:
        """The real thing: python -m http.server on an OS-assigned port."""
        p = self._start([sys.executable, "-u", "-m", "http.server", "0", "--bind", "127.0.0.1"])
        assert p.stdout is not None
        line = p.stdout.readline()  # "Serving HTTP on 127.0.0.1 port 54321 (...)"
        port = int(line.split(" port ")[1].split()[0])
        return Spawned(p, port)

    def cleanup(self) -> None:
        for p in self.procs:
            try:
                for c in psutil.Process(p.pid).children(recursive=True):
                    c.kill()
            except psutil.NoSuchProcess:
                pass
            p.kill()
            p.wait(timeout=10)
            if p.stdout:
                p.stdout.close()


@pytest.fixture
def spawn(tmp_path: Path) -> Iterator[Factory]:
    f = Factory(tmp_path)
    yield f
    f.cleanup()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
