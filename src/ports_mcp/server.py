"""ports-mcp: an MCP server that answers "what is using port 3000?" and frees it safely."""

from __future__ import annotations

import functools
import socket
import time
from collections.abc import Callable
from typing import Any, TypeVar

import psutil
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import killer
from .procs import (
    PortsError,
    ProcInfo,
    ancestors,
    children_recursive,
    exposure,
    exposure_text,
    hint_for,
    proc_info,
    protected_pids,
)
from .scan import Listener, ScanResult, bind_probe, probe_hidden_listener, scan

mcp = MCPServer(
    "ports",
    instructions=(
        "Find out what is using a TCP/UDP port and free it, on Windows, macOS and Linux. "
        "Start with whats_on_port(port) for a single port or list_listening() for the whole "
        "machine; process_tree(pid) shows what a process started. find_free_port picks an "
        "unused port and check_port_reachable tests a TCP connect. To free a port call "
        "kill_port(port) FIRST: it kills nothing and returns a plan plus a confirm_token. Show "
        "the plan to the user, and only after they agree call kill_port(port, "
        "confirm_token=...). Never invent a token. Processes the OS hides from an "
        "unelevated server are reported as such, not skipped."
    ),
)

# Pending kill plans live for the lifetime of the server process.
_plans = killer.PlanStore()

F = TypeVar("F", bound=Callable[..., Any])

# MCPServer only forwards a ToolError's message to the client; anything else arrives as a
# bare "Error executing tool X". These are failures the agent can act on, so their text is
# kept. Anything not listed is a genuine bug and stays hidden from the client.
_EXPECTED = (PortsError, ValueError, psutil.AccessDenied, psutil.NoSuchProcess)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except psutil.AccessDenied as e:
            raise ToolError(
                f"Access denied by the OS ({e}). Run the ports-mcp server elevated "
                "(Administrator on Windows, sudo on Linux/macOS) to inspect this process."
            ) from e
        except _EXPECTED as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


def _check_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise PortsError(f"port must be between 1 and 65535, got {port}")


def _short(s: str, n: int = 300) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def _proc_header(info: ProcInfo) -> str:
    h = hint_for(info)
    bits = [f"{info.display_name}  PID {info.pid}"]
    if h:
        bits.append(f"[{h.label}]")
    if info.username:
        bits.append(f"user {info.username}")
    return "  ".join(bits)


def _proc_details(info: ProcInfo, indent: str = "  ") -> list[str]:
    out = []
    out.append(
        f"{indent}cmd: {_short(info.command)}"
        if info.command
        else f"{indent}cmd: <unavailable: access denied, elevation needed>"
    )
    out.append(
        f"{indent}cwd: {info.cwd}"
        if info.cwd
        else f"{indent}cwd: <unavailable: access denied, elevation needed>"
    )
    return out


def _socket_line(ln: Listener, indent: str = "  ") -> str:
    return f"{indent}{ln.proto}  {ln.address}:{ln.port}".ljust(len(indent) + 34) + exposure_text(
        ln.address
    )


def _notes(res: ScanResult) -> list[str]:
    return [f"NOTE: {n}" for n in res.notes]


@tool
def list_listening(
    port_min: int = 1,
    port_max: int = 65535,
    process_name: str | None = None,
    protocol: str = "tcp",
) -> str:
    """List what is listening on this machine, grouped by process.

    Each process shows its PID, name, user, command line, working directory, an inferred
    framework (Vite, Next.js, uvicorn, Flask, docker-proxy, ...) and every port it holds with
    the address it is bound to. Sockets bound to 0.0.0.0 or :: are flagged EXPOSED (reachable
    from the network); 127.0.0.1 / ::1 are loopback only.

    Filters: port_min/port_max (inclusive), process_name (case-insensitive substring of the
    process name or its command line, e.g. "node" or "uvicorn"), protocol "tcp" (default),
    "udp" or "all". Listeners whose owner the OS hides without elevation are listed under
    "unidentified process" rather than dropped.
    """
    if port_min > port_max:
        raise PortsError(f"port_min ({port_min}) is greater than port_max ({port_max})")
    res = scan(protocol)
    socks = [ln for ln in res.listeners if port_min <= ln.port <= port_max]

    groups: dict[int | None, list[Listener]] = {}
    for ln in socks:
        groups.setdefault(ln.pid, []).append(ln)

    rows: list[tuple[int, ProcInfo | None, list[Listener]]] = []
    needle = process_name.lower() if process_name else None
    for pid, lns in groups.items():
        info = proc_info(pid) if pid is not None else None
        if pid is not None and info is None:
            continue  # exited during the scan
        if needle:
            if info is None:
                continue  # cannot match a name we are not allowed to see
            hay = ((info.name or "") + " " + (info.command or "")).lower()
            if needle not in hay:
                continue
        rows.append((min(ln.port for ln in lns), info, lns))
    rows.sort(key=lambda r: r[0])

    flt = [f"protocol={protocol}"]
    if (port_min, port_max) != (1, 65535):
        flt.append(f"ports {port_min}-{port_max}")
    if process_name:
        flt.append(f"process~{process_name!r}")
    nports = len({(ln.proto, ln.port) for _, _, lns in rows for ln in lns})
    exposed = sorted(
        {ln.port for _, _, lns in rows for ln in lns if exposure(ln.address) == "all"}
    )
    out = [f"{len(rows)} process(es) listening on {nports} port(s) ({', '.join(flt)})"]
    if exposed:
        out.append(
            f"EXPOSED to the network (0.0.0.0/::): {', '.join(map(str, exposed[:40]))}"
            + (" ..." if len(exposed) > 40 else "")
        )
    for _, info, lns in rows:
        out.append("")
        if info is None:
            out.append("unidentified process  (owner hidden by the OS: elevation needed)")
        else:
            out.append(_proc_header(info))
            out.extend(_proc_details(info))
        out.extend(_socket_line(ln) for ln in lns)
    if res.notes:
        out.append("")
        out.extend(_notes(res))
    return "\n".join(out)


@tool
def whats_on_port(port: int, protocol: str = "tcp") -> str:
    """Answer "what is using port N?" in detail.

    Returns every listener on the port: PID, process name, user, full command line, working
    directory, the inferred framework, the address it is bound to (and whether that exposes it
    to the network), the process's parent and children, and whether kill_port would refuse it
    (system process, your own MCP client). If nothing is listening it says so, and also checks
    whether the port can be bound, which catches OS-reserved ports (Windows excluded ranges)
    and listeners hidden by missing privileges.
    """
    _check_port(port)
    res = scan(protocol)
    here = [ln for ln in res.listeners if ln.port == port]
    if not here:
        out = [f"Nothing is listening on {protocol} port {port}."]
        if protocol != "udp":
            if probe_hidden_listener(port):
                out.append(
                    "BUT a TCP connect to localhost succeeds, so a listener exists that this "
                    "process cannot identify (elevation needed)."
                )
            err = bind_probe(port)
            if err:
                out.append(
                    f"Binding 127.0.0.1:{port} fails ({err}): the port is unavailable even "
                    "though nothing is listening (reserved by the OS, or held by a process "
                    "this user cannot see)."
                )
            else:
                out.append(f"Binding 127.0.0.1:{port} works, so it is free to use.")
        out.extend(_notes(res))
        return "\n".join(out)

    by_pid: dict[int | None, list[Listener]] = {}
    for ln in here:
        by_pid.setdefault(ln.pid, []).append(ln)
    out = [f"{len(by_pid)} process(es) listening on {protocol} port {port}:"]
    protected = protected_pids()
    for pid, lns in by_pid.items():
        out.append("")
        if pid is None:
            out.append("unidentified process (owner hidden by the OS: elevation needed)")
            out.extend(_socket_line(ln) for ln in lns)
            continue
        info = proc_info(pid)
        if info is None:
            out.append(f"PID {pid} exited during the scan")
            continue
        h = hint_for(info)
        out.append(_proc_header(info))
        out.extend(_proc_details(info))
        out.extend(_socket_line(ln) for ln in lns)
        if info.create_time:
            out.append(f"  running for {time.time() - info.create_time:.0f} s")
        parents = ancestors(pid)
        if parents:
            p = parents[0]
            out.append(f"  parent: {p.display_name} PID {p.pid}")
        kids = children_recursive(pid)
        if kids:
            out.append(f"  children: {', '.join(f'{k.display_name} ({k.pid})' for k in kids[:10])}")
        if h and h.advice:
            out.append(f"  note: {h.advice}")
        hard = killer.hard_reasons(pid, protected)
        soft = killer.soft_reasons(info, h)
        if hard:
            out.append(f"  kill_port: REFUSES always ({hard[0]})")
        elif soft:
            out.append(f"  kill_port: refuses without force ({soft[0]})")
        else:
            out.append("  kill_port: allowed, via a plan and confirm_token")
    out.extend(_notes(res))
    return "\n".join(out)


@tool
def find_free_port(
    start: int = 3000, end: int = 3999, count: int = 1, host: str = "127.0.0.1"
) -> str:
    """Find unused TCP port(s) in start..end (inclusive), lowest first.

    A port counts as free only if nothing is listening on it AND the OS lets us bind it on
    `host`, so ports reserved by the OS (Windows excluded ranges) are skipped. `count`
    returns that many ports. Use host "0.0.0.0" to require that the port is free on every
    interface.
    """
    _check_port(start)
    _check_port(end)
    if start > end:
        raise PortsError(f"start ({start}) is greater than end ({end})")
    if not 1 <= count <= 100:
        raise PortsError("count must be between 1 and 100")
    busy = {ln.port for ln in scan("tcp").listeners}
    free: list[int] = []
    skipped = 0
    for p in range(start, end + 1):
        if p in busy:
            continue
        if bind_probe(p, host) is not None:
            skipped += 1
            continue
        free.append(p)
        if len(free) == count:
            break
    if not free:
        raise PortsError(
            f"No free port in {start}-{end} on {host} ({len(busy)} listening, {skipped} "
            "reserved or unbindable). Widen the range."
        )
    msg = f"Free TCP port(s) on {host}: {', '.join(map(str, free))}"
    if len(free) < count:
        msg += f" (only {len(free)} of the {count} requested exist in {start}-{end})"
    return msg + ". Another program can still grab it before you do."


@tool
def kill_port(
    port: int,
    confirm_token: str | None = None,
    protocol: str = "tcp",
    force: bool = False,
    grace_seconds: float = 5.0,
) -> str:
    """Free a port by stopping the process on it. TWO STEPS, never kills on the first call.

    Step 1: call kill_port(port). Nothing is killed. You get a plan naming every process (and
    its child processes) that would be stopped, what each one is (dev server such as
    vite/next/uvicorn, docker-proxy, database...), and a single-use confirm_token valid for 60
    seconds. Show the plan to the user.
    Step 2: after the user agrees, call kill_port(port, confirm_token=<token>). Processes get
    a graceful terminate, then a force-kill after grace_seconds; the tool then verifies the
    port is actually free and reports anything that survived.

    Always refused, even with force: PID 0, 1 and 4, this server, and its ancestors (your MCP
    client). Refused unless force=True on step 1: operating-system services (svchost, systemd,
    SYSTEM-account processes, ...). The token only works for the port it was issued for.
    """
    _check_port(port)
    if confirm_token is None:
        _, text = killer.make_plan(port, protocol, force, _plans)
        return text
    if grace_seconds < 0 or grace_seconds > 60:
        raise PortsError("grace_seconds must be between 0 and 60")
    plan = _plans.redeem(confirm_token, port)
    return killer.execute(plan, grace_seconds)


def _render_tree(root: ProcInfo, target_pid: int, ports: dict[int, list[str]], limit: int) -> list[str]:
    kids_of: dict[int, list[ProcInfo]] = {}
    for d in children_recursive(root.pid):
        if d.ppid is not None:
            kids_of.setdefault(d.ppid, []).append(d)
    lines: list[str] = []

    def walk(info: ProcInfo, depth: int) -> None:
        if len(lines) >= limit:
            return
        mark = "  <== target" if info.pid == target_pid else ""
        port_s = f"  listening: {', '.join(ports[info.pid])}" if info.pid in ports else ""
        cmd = f"  {_short(info.command, 100)}" if info.command else ""
        lines.append(f"{'    ' * depth}{info.display_name} ({info.pid}){port_s}{mark}{cmd}")
        for k in sorted(kids_of.get(info.pid, []), key=lambda i: i.pid):
            walk(k, depth + 1)

    walk(root, 0)
    return lines


@tool
def process_tree(pid: int) -> str:
    """Show a process's ancestors (who started it) and all its descendants, as a tree.

    Each node lists name, PID and a shortened command line, and marks processes that are
    listening on a port. Use it before killing: killing a child can be undone by its parent
    restarting it (npm, nodemon, a reloader, a service manager).
    """
    info = proc_info(pid)
    if info is None:
        raise PortsError(f"No process with PID {pid} (it may have exited).")
    ports: dict[int, list[str]] = {}
    for ln in scan("all").listeners:
        if ln.pid is not None:
            ports.setdefault(ln.pid, []).append(f"{ln.proto}/{ln.address}:{ln.port}")
    chain = list(reversed(ancestors(pid)))
    lines = [f"Process tree around PID {pid}:"]
    for depth, a in enumerate(chain):
        lines.append(f"{'    ' * depth}{a.display_name} ({a.pid})")
    base = len(chain)
    sub = _render_tree(info, pid, ports, 200)
    lines.extend("    " * base + s for s in sub)
    if len(sub) >= 200:
        lines.append("... truncated at 200 processes")
    if info.denied:
        lines.append(
            f"NOTE: the OS denied {', '.join(info.denied)} for this process (elevation needed)."
        )
    return "\n".join(lines)


@tool
def check_port_reachable(host: str, port: int, timeout: float = 3.0) -> str:
    """Try a TCP connect to host:port and report REACHABLE or UNREACHABLE with the reason.

    Distinguishes "connection refused" (host is up, nothing listening), "timed out" (firewall
    drop or host down) and DNS failures. Works for localhost and remote hosts alike. It only
    connects and disconnects; no data is sent. Timeout is in seconds (0.1 to 30).
    """
    _check_port(port)
    if not 0.1 <= timeout <= 30:
        raise PortsError("timeout must be between 0.1 and 30 seconds")
    if not host.strip():
        raise PortsError("host must not be empty")
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except socket.gaierror as e:
        return f"UNREACHABLE: could not resolve host {host!r} ({e}). Check the spelling or DNS."
    except TimeoutError:
        return (
            f"UNREACHABLE: {host}:{port} did not answer within {timeout:g} s. A firewall is "
            "probably dropping packets, or the host is down."
        )
    except ConnectionRefusedError:
        return (
            f"UNREACHABLE: {host}:{port} refused the connection. The host is up but nothing "
            "is listening on that port; use whats_on_port to check locally."
        )
    except OSError as e:
        return f"UNREACHABLE: {host}:{port} failed to connect ({e})."
    ms = (time.monotonic() - start) * 1000
    return f"REACHABLE: {host}:{port} accepted a TCP connection in {ms:.0f} ms."


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
