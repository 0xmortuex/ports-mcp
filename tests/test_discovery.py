"""Discovery tests against REAL listening processes on OS-assigned ports."""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys

import psutil
import pytest

from conftest import Factory, owned_by
from ports_mcp import server
from ports_mcp.procs import PortsError, ProcInfo, exposure, hint_for, proc_info
from ports_mcp.scan import listeners_on_port, scan


def test_real_http_server_is_discovered(spawn: Factory) -> None:
    s = spawn.http_server()
    lns = listeners_on_port(s.port).listeners
    assert lns, "the listener must be found"
    assert all(ln.proto == "tcp" and ln.address == "127.0.0.1" for ln in lns)
    assert any(owned_by(ln.pid, s) for ln in lns)


def test_whats_on_port_reports_process_details(spawn: Factory) -> None:
    s = spawn.http_server()
    text = server.whats_on_port(s.port)
    assert f"port {s.port}" in text
    assert "http.server" in text  # command line
    assert "Python http.server" in text  # framework hint
    assert "loopback only" in text
    assert "kill_port: allowed" in text
    assert "cwd:" in text


def test_exposed_vs_loopback_flagged() -> None:
    # In-process sockets: one on every interface, one on loopback only.
    a = socket.socket()
    b = socket.socket()
    try:
        a.bind(("0.0.0.0", 0))
        a.listen()
        b.bind(("127.0.0.1", 0))
        b.listen()
        text = server.list_listening()
        wide, local = a.getsockname()[1], b.getsockname()[1]
        line_wide = next(x for x in text.splitlines() if f"0.0.0.0:{wide}" in x)
        line_local = next(x for x in text.splitlines() if f"127.0.0.1:{local}" in x)
        assert "EXPOSED" in line_wide
        assert "loopback only" in line_local
        assert str(wide) in text.split("EXPOSED to the network")[1].splitlines()[0]
    finally:
        a.close()
        b.close()


def test_exposure_classification() -> None:
    assert exposure("0.0.0.0") == "all"
    assert exposure("::") == "all"
    assert exposure("127.0.0.1") == "loopback"
    assert exposure("::1") == "loopback"
    assert exposure("::ffff:127.0.0.1") == "loopback"
    assert exposure("192.168.1.5") == "interface"
    assert exposure("fe80::1%eth0") == "interface"


def test_list_listening_filters(spawn: Factory) -> None:
    s = spawn.http_server()
    other = spawn.http_server()
    only = server.list_listening(port_min=s.port, port_max=s.port)
    assert f":{s.port}" in only and f":{other.port}" not in only
    by_name = server.list_listening(process_name="http.server")
    assert f":{s.port}" in by_name and f":{other.port}" in by_name
    assert "0 process(es)" in server.list_listening(process_name="no-such-process-xyz")
    with pytest.raises(PortsError, match="greater than"):
        server.list_listening(port_min=10, port_max=5)
    with pytest.raises(ValueError, match="protocol"):
        server.list_listening(protocol="sctp")


def test_udp_listener_visible_only_with_udp_protocol() -> None:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", 0))
        port = u.getsockname()[1]
        assert f"127.0.0.1:{port}" not in server.list_listening(port_min=port, port_max=port)
        both = server.list_listening(port_min=port, port_max=port, protocol="udp")
        assert f"udp  127.0.0.1:{port}" in both
        assert any(ln.port == port for ln in scan("all").listeners)
    finally:
        u.close()


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_real_node_server_gets_node_hint(spawn: Factory, tmp_path) -> None:  # type: ignore[no-untyped-def]
    js = tmp_path / "srv.js"
    js.write_text(
        "const s=require('http').createServer((q,r)=>r.end('ok'));"
        "s.listen(0,'127.0.0.1',()=>{console.log(s.address().port)});",
        encoding="utf-8",
    )
    p = subprocess.Popen(
        [shutil.which("node") or "node", str(js)], stdout=subprocess.PIPE, text=True
    )
    spawn.procs.append(p)
    assert p.stdout is not None
    port = int(p.stdout.readline())
    text = server.whats_on_port(port)
    assert "Node.js process" in text and "srv.js" in text


def test_nothing_listening_on_port() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    text = server.whats_on_port(port)
    assert "Nothing is listening" in text and "free to use" in text


def test_invalid_port_rejected() -> None:
    with pytest.raises(PortsError, match="between 1 and 65535"):
        server.whats_on_port(70000)


def test_process_tree_shows_parent_child_and_listener(spawn: Factory) -> None:
    from conftest import TREE_PARENT

    s = spawn.script(TREE_PARENT)
    pid = next(ln.pid for ln in listeners_on_port(s.port).listeners if ln.pid)
    text = server.process_tree(pid)
    assert "<== target" in text
    assert f"tcp/127.0.0.1:{s.port}" in text
    assert str(s.extra) in text  # the child the script started
    with pytest.raises(PortsError, match="No process"):
        server.process_tree(2**22 + 12345)


def test_access_denied_is_reported_not_hidden() -> None:
    # Real OS behavior: pick any process whose details we are denied (system services on
    # Windows, other users' processes on Linux/macOS). Skip if this account can see all.
    denied = None
    for p in psutil.process_iter():
        info = proc_info(p.pid)
        if info is not None and info.denied and p.pid not in (0,):
            denied = info
            break
    if denied is None:
        pytest.skip("this account can read every process")
    assert denied.denied  # recorded, not silently dropped
    text = server.process_tree(denied.pid)
    assert "elevation needed" in text or "NOTE: the OS denied" in text


@pytest.mark.parametrize(
    ("argv", "name", "expected"),
    [
        (["node", r"C:\p\node_modules\vite\bin\vite.js"], "node.exe", "Vite"),
        (["node", "/p/node_modules/.bin/next", "dev"], "node", "Next.js"),
        (["python", "-m", "uvicorn", "app:app", "--reload"], "python", "uvicorn"),
        (["python", "manage.py", "runserver"], "python3", "Django"),
        (["python", "-m", "flask", "run"], "python", "Flask"),
        (["/usr/bin/docker-proxy", "-proto", "tcp"], "docker-proxy", "Docker port proxy"),
        (["redis-server", "*:6379"], "redis-server", "Redis"),
        (["node", "server.js"], "node", "Node.js process"),
    ],
)
def test_framework_hints(argv: list[str], name: str, expected: str) -> None:
    info = ProcInfo(1234, name, argv, None, None, None, None)
    h = hint_for(info)
    assert h is not None and expected in h.label


def test_project_folder_named_vite_is_not_vite() -> None:
    info = ProcInfo(1, "node", ["node", r"C:\work\vite-demo\server.js"], None, None, None, None)
    h = hint_for(info)
    assert h is not None and h.label == "Node.js process"


def test_own_interpreter_is_a_python_process() -> None:
    info = proc_info(psutil.Process().pid)
    assert info is not None and info.cmdline and sys.version_info >= (3, 10)
    assert hint_for(info) is not None


def test_thread_name_does_not_hide_the_runtime() -> None:
    # Linux reports the main thread's name ("MainThread" for Node, the test runner for
    # Python) instead of the executable name, so the hint must fall back to argv[0].
    node = ProcInfo(1, "MainThread", ["/usr/local/bin/node", "/srv/app.js"], None, None, None, None)
    py = ProcInfo(2, "pytest", ["/opt/python/bin/python3.12", "-m", "pytest"], None, None, None, None)
    h_node, h_py = hint_for(node), hint_for(py)
    assert h_node is not None and h_node.label == "Node.js process"
    assert h_py is not None and h_py.label == "Python process"
