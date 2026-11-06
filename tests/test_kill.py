"""The two-step kill, exercised against REAL processes: nothing is mocked except the clock
used to test token expiry."""

from __future__ import annotations

import re
import socket
import sys
import textwrap

import psutil
import pytest

from conftest import STUBBORN, TREE_PARENT, Factory, Spawned, port_is_free, wait_until
from ports_mcp import killer, server
from ports_mcp.procs import PortsError, ProcInfo
from ports_mcp.scan import listeners_on_port, scan

TOKEN = re.compile(r"Token: ([0-9a-f]+)")


def plan_token(text: str) -> str:
    m = TOKEN.search(text)
    assert m, text
    return m.group(1)


def gone(pid: int) -> bool:
    return not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE


def listener_pids(s: Spawned) -> list[int]:
    return [ln.pid for ln in listeners_on_port(s.port).listeners if ln.pid is not None]


def test_plan_alone_kills_nothing_then_token_frees_the_port(spawn: Factory) -> None:
    s = spawn.http_server()
    pids = listener_pids(s)
    plan = server.kill_port(s.port)
    assert "nothing has been killed yet" in plan
    assert "Python http.server" in plan and f"PID {pids[0]}" in plan
    assert "127.0.0.1" in plan
    # The plan must not have touched anything.
    assert not port_is_free(s.port)
    assert all(psutil.pid_exists(p) for p in pids)

    result = server.kill_port(s.port, confirm_token=plan_token(plan))
    assert f"port {s.port} is now free" in result
    assert wait_until(lambda: port_is_free(s.port))
    assert wait_until(lambda: all(gone(p) for p in pids))


def test_token_is_single_use(spawn: Factory) -> None:
    s = spawn.http_server()
    token = plan_token(server.kill_port(s.port))
    server.kill_port(s.port, confirm_token=token)
    with pytest.raises(PortsError, match="Unknown, expired or already-used"):
        server.kill_port(s.port, confirm_token=token)


def test_process_tree_is_killed_with_its_root(spawn: Factory) -> None:
    s = spawn.script(TREE_PARENT)
    root = listener_pids(s)[0]
    kids = [c.pid for c in psutil.Process(root).children(recursive=True)]
    assert s.extra in kids
    plan = server.kill_port(s.port)
    assert "plus child" in plan and f"PID {s.extra}" in plan
    server.kill_port(s.port, confirm_token=plan_token(plan))
    assert wait_until(lambda: all(gone(p) for p in [root, *kids]))
    assert wait_until(lambda: port_is_free(s.port))


def test_process_that_ignores_sigterm_is_force_killed(spawn: Factory) -> None:
    s = spawn.script(STUBBORN)
    pid = listener_pids(s)[0]
    token = plan_token(server.kill_port(s.port))
    result = server.kill_port(s.port, confirm_token=token, grace_seconds=1.0)
    assert wait_until(lambda: gone(pid))
    assert wait_until(lambda: port_is_free(s.port))
    if sys.platform != "win32":
        # POSIX: SIGTERM was ignored, so the tool had to escalate to SIGKILL.
        assert "Force-killed after 1 s" in result
    else:
        # Windows has no catchable SIGTERM: terminate is already a hard kill.
        assert "Force-killed" not in result


def test_wrong_port_token_is_rejected_and_invalidated(spawn: Factory) -> None:
    a = spawn.http_server()
    b = spawn.http_server()
    token = plan_token(server.kill_port(a.port))
    with pytest.raises(PortsError, match=f"issued for port {a.port}, not port {b.port}"):
        server.kill_port(b.port, confirm_token=token)
    # Nothing died, and the rejected token no longer works even for its own port.
    assert not port_is_free(a.port) and not port_is_free(b.port)
    with pytest.raises(PortsError, match="Unknown, expired or already-used"):
        server.kill_port(a.port, confirm_token=token)
    assert not port_is_free(a.port)


def test_unknown_token_is_rejected(spawn: Factory) -> None:
    s = spawn.http_server()
    with pytest.raises(PortsError, match="Unknown, expired or already-used"):
        server.kill_port(s.port, confirm_token="deadbeef0000")
    assert not port_is_free(s.port)


def test_expired_token_is_rejected(spawn: Factory) -> None:
    s = spawn.http_server()
    now = [1000.0]
    store = killer.PlanStore(ttl=60.0, clock=lambda: now[0])
    _, text = killer.make_plan(s.port, "tcp", False, store)
    token = plan_token(text)
    now[0] += 61.0
    with pytest.raises(PortsError, match="token expired"):
        store.redeem(token, s.port)
    assert not port_is_free(s.port)

    # An unexpired token on the same store still works, to prove the clock is what mattered.
    _, text2 = killer.make_plan(s.port, "tcp", False, store)
    plan = store.redeem(plan_token(text2), s.port)
    now[0] += 59.0
    killer.execute(plan, 2.0)
    assert wait_until(lambda: port_is_free(s.port))


def test_token_checked_at_redeem_time_when_plan_still_stored(spawn: Factory) -> None:
    """Expiry is enforced on redeem even if purge has not run (plan still in the dict)."""
    s = spawn.http_server()
    now = [0.0]
    store = killer.PlanStore(ttl=10.0, clock=lambda: now[0])
    _, text = killer.make_plan(s.port, "tcp", False, store)
    now[0] = 10.0
    with pytest.raises(PortsError, match="expired"):
        store.redeem(plan_token(text), s.port)


def test_plan_for_a_stale_process_identity_aborts_without_killing(spawn: Factory) -> None:
    """If the PID now belongs to a different process (PID reuse), nothing is killed."""
    s = spawn.http_server()
    store = killer.PlanStore()
    plan, _ = killer.make_plan(s.port, "tcp", False, store)
    pid = next(iter(plan.created_times))
    plan.created_times[pid] = (plan.created_times[pid] or 0.0) - 1000.0
    with pytest.raises(PortsError, match="PID was reused"):
        killer.execute(plan, 1.0)
    assert not port_is_free(s.port)


def test_nothing_listening_is_an_error() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(PortsError, match="Nothing is listening"):
        server.kill_port(port)


def test_udp_port_can_be_planned_and_killed(spawn: Factory) -> None:
    src = """
    import socket, time
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1], 0, flush=True)
    time.sleep(600)
    """
    s = spawn.script(textwrap.dedent(src))
    assert listeners_on_port(s.port, "udp").listeners
    token = plan_token(server.kill_port(s.port, protocol="udp"))
    server.kill_port(s.port, confirm_token=token, protocol="udp")
    assert wait_until(lambda: not listeners_on_port(s.port, "udp").listeners)


# -- refusals ---------------------------------------------------------------------------


def test_own_process_is_refused() -> None:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        with pytest.raises(PortsError, match="(?s)REFUSED.*ports-mcp server process itself"):
            server.kill_port(port)
        with pytest.raises(PortsError, match="cannot be overridden with force"):
            server.kill_port(port, force=True)
    finally:
        sock.close()


def test_an_ancestor_of_the_server_is_refused(spawn: Factory) -> None:
    """The listener below is the PARENT of a process running the planning code, so killing
    it would kill the caller."""
    child_code = textwrap.dedent(
        """
        import sys
        from ports_mcp import server
        try:
            server.kill_port(int(sys.argv[1]), force=True)
            print("NOT-REFUSED")
        except Exception as e:
            print("REFUSED", e)
        """
    )
    parent = f"""
    import socket, subprocess, sys
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    out = subprocess.run([sys.executable, "-c", {child_code!r}, str(port)],
                         capture_output=True, text=True).stdout
    print(port, 0, flush=True)
    print(out.replace("\\n", " | "), flush=True)
    import time; time.sleep(600)
    """
    sp = spawn.script(textwrap.dedent(parent))
    assert sp.proc.stdout is not None
    line = sp.proc.stdout.readline()
    assert line.startswith("REFUSED"), line
    assert "ancestor of the ports-mcp server" in line
    assert not port_is_free(sp.port)


@pytest.mark.parametrize("pid", [0, 1, 4])
def test_pids_0_1_4_have_hard_refusals(pid: int) -> None:
    assert killer.hard_reasons(pid, {})


def test_real_pid_4_listener_is_refused_even_with_force() -> None:
    pid4 = [ln for ln in scan("tcp").listeners if ln.pid == 4]
    if not pid4:
        pytest.skip("no listener owned by PID 4 on this machine (Windows http.sys / SMB)")
    port = pid4[0].port
    with pytest.raises(PortsError, match="Windows kernel"):
        server.kill_port(port, force=True)


def test_real_system_service_needs_force_and_still_needs_confirmation() -> None:
    from ports_mcp.procs import hint_for, proc_info

    protected = {*killer.HARD_PIDS}
    candidate = None
    for ln in scan("tcp").listeners:
        if ln.pid is None or ln.pid in protected:
            continue
        info = proc_info(ln.pid)
        if info and killer.soft_reasons(info, hint_for(info)):
            candidate = ln
            break
    if candidate is None:
        pytest.skip("no operating-system service is listening on this machine")
    with pytest.raises(PortsError, match="REFUSED without force"):
        server.kill_port(candidate.port)
    # With force a plan (and token) is issued, but we deliberately never redeem it.
    plan = server.kill_port(candidate.port, force=True)
    assert "FORCED over these warnings" in plan and "Token:" in plan


def test_soft_reasons_recognise_services() -> None:
    svc = ProcInfo(900, "svchost.exe", [], None, "NT AUTHORITY\\SYSTEM", None, None)
    reasons = killer.soft_reasons(svc, None)
    assert any("operating-system service" in r for r in reasons)
    assert any("service account" in r for r in reasons)
    dev = ProcInfo(901, "node.exe", ["node", "vite"], None, "me", None, None)
    assert killer.soft_reasons(dev, None) == []
    hidden = ProcInfo(902, None, None, None, None, None, None, denied=["name", "username"])
    assert killer.soft_reasons(hidden, None)


def test_kill_arguments_are_validated() -> None:
    with pytest.raises(PortsError, match="between 1 and 65535"):
        server.kill_port(0)
    with pytest.raises(PortsError, match="must be 'tcp' or 'udp'"):
        server.kill_port(8080, protocol="all")

