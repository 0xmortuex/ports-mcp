"""The safe, two-step kill.

Step 1 (``make_plan``) resolves the port to processes, walks their trees, applies every
safety rule and, only if nothing blocks it, stores a *plan* under a random single-use token.
Step 2 (``execute``) redeems the token for the same port, re-checks that the world still
looks like the plan, then terminates gracefully and force-kills what survives.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import psutil

from .procs import (
    Hint,
    PortsError,
    ProcInfo,
    ancestors,
    children_recursive,
    exposure_text,
    hint_for,
    proc_info,
    protected_pids,
)
from .scan import Listener, listeners_on_port, probe_hidden_listener

# PIDs that are never killable, with or without force.
HARD_PIDS: dict[int, str] = {
    0: "PID 0 is the idle/kernel pseudo-process",
    1: "PID 1 is the init system (systemd/launchd): killing it takes the machine down",
    4: (
        "PID 4 is the Windows kernel ('System'). It owns ports through http.sys and SMB; "
        "stop the service that uses it instead (for example `iisreset /stop`, "
        "`net stop http`, or stop the SQL Reporting / IIS / World Wide Web service)"
    ),
}

# Names (lowercase, without .exe) of operating-system services. Killable only with force.
SYSTEM_NAMES = frozenset(
    """system registry smss csrss wininit services lsass lsm svchost winlogon spoolsv
    fontdrvhost dwm wslservice systemd systemd-resolved systemd-networkd init launchd
    sshd dbus-daemon cupsd avahi-daemon rpcbind mdnsresponder rapportd controlcenter
    configd networkd""".split()
)

_SERVICE_ACCOUNTS = ("nt authority\\system", "nt authority\\local service", "nt authority\\network service")

DEFAULT_TTL = 60.0


def _stem(name: str | None) -> str:
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


def hard_reasons(pid: int, protected: dict[int, str]) -> list[str]:
    """Reasons this PID may never be killed (not even with force)."""
    out = []
    if pid in HARD_PIDS:
        out.append(HARD_PIDS[pid])
    if pid in protected:
        out.append(protected[pid])
    return out


def soft_reasons(info: ProcInfo, hint: Hint | None) -> list[str]:
    """Reasons to refuse unless force=True: it looks like part of the operating system."""
    out = []
    stem = _stem(info.name)
    if stem in SYSTEM_NAMES:
        out.append(f"'{info.display_name}' is an operating-system service")
        if stem == "controlcenter":
            out.append(
                "on macOS this is the AirPlay Receiver; turn it off in System Settings > "
                "General > AirDrop & Handoff instead"
            )
    if info.username and info.username.lower() in _SERVICE_ACCOUNTS:
        out.append(f"it runs as the Windows service account {info.username}")
    if hint and hint.kind == "infrastructure":
        out.append(f"it is {hint.label} infrastructure")
    if "name" in info.denied or "username" in info.denied:
        out.append(
            "the OS hides its identity from this process (access denied), which usually "
            "means it belongs to the system or another user"
        )
    return out


# -- plan -------------------------------------------------------------------------------


@dataclass
class Target:
    info: ProcInfo
    hint: Hint | None
    sockets: list[Listener]
    descendants: list[ProcInfo]
    parent: ProcInfo | None


@dataclass
class Plan:
    token: str
    port: int
    proto: str
    force: bool
    targets: list[Target]
    expires_at: float  # on the store's clock
    created_times: dict[int, float | None] = field(default_factory=dict)

    @property
    def root_pids(self) -> set[int]:
        return {t.info.pid for t in self.targets}


class PlanStore:
    """Holds pending plans. Tokens are single use and expire."""

    def __init__(
        self, ttl: float = DEFAULT_TTL, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.ttl = ttl
        self._clock = clock
        self._plans: dict[str, Plan] = {}

    def add(self, plan: Plan) -> None:
        self._purge()
        self._plans[plan.token] = plan

    def now(self) -> float:
        return self._clock()

    def _purge(self) -> None:
        now = self._clock()
        for tok in [t for t, p in self._plans.items() if p.expires_at <= now]:
            del self._plans[tok]

    def redeem(self, token: str, port: int) -> Plan:
        """Return and consume the plan, or raise PortsError saying exactly why not."""
        plan = self._plans.pop(token, None)
        if plan is None:
            raise PortsError(
                "Unknown, expired or already-used confirm_token. Tokens are single use and "
                f"valid for {self.ttl:g} s. Call kill_port(port={port}) without a token to "
                "get a fresh plan."
            )
        if plan.expires_at <= self._clock():
            raise PortsError(
                f"The confirm_token expired (plans are valid for {self.ttl:g} s) and has "
                f"been discarded. Call kill_port(port={port}) again for a new plan."
            )
        if plan.port != port:
            raise PortsError(
                f"This confirm_token was issued for port {plan.port}, not port {port}. It has "
                "been invalidated. Review the plan for the port you mean and request a new "
                "token."
            )
        return plan


def _describe(info: ProcInfo, hint: Hint | None) -> str:
    bits = [f"PID {info.pid} {info.display_name}"]
    if hint:
        bits.append(f"[{hint.label}]")
    if info.username:
        bits.append(f"user {info.username}")
    return " ".join(bits)


def _build_targets(port: int, proto: str) -> tuple[list[Target], list[str]]:
    res = listeners_on_port(port, proto)
    if not res.listeners:
        # Only claim a hidden listener when this specific port probes as occupied. Unrelated
        # hidden sockets elsewhere on the machine (res.notes) say nothing about this port.
        if probe_hidden_listener(port):
            raise PortsError(
                f"Something may be using port {port} but this process cannot see which. "
                + " ".join(res.notes)
                + " Run the ports-mcp server elevated (Administrator / sudo), then retry."
            )
        raise PortsError(f"Nothing is listening on {proto} port {port}; there is nothing to kill.")
    hidden = [ln for ln in res.listeners if ln.pid is None]
    if hidden:
        raise PortsError(
            f"{proto} port {port} is held by a process whose PID the OS hides from this "
            "user, so it cannot be inspected or killed. Run the ports-mcp server elevated "
            "(Administrator / sudo) to manage it."
        )
    by_pid: dict[int, list[Listener]] = {}
    for ln in res.listeners:
        assert ln.pid is not None
        by_pid.setdefault(ln.pid, []).append(ln)
    targets = []
    for pid, socks in sorted(by_pid.items()):
        info = proc_info(pid)
        if info is None:
            continue  # exited between the scan and now
        parents = ancestors(pid)
        targets.append(
            Target(info, hint_for(info), socks, children_recursive(pid), parents[0] if parents else None)
        )
    if not targets:
        raise PortsError(f"The process on port {port} exited just now; nothing to kill.")
    return targets, res.notes


def make_plan(port: int, proto: str, force: bool, store: PlanStore) -> tuple[Plan, str]:
    """Build and register a plan; returns it with the text to show the agent."""
    if proto not in ("tcp", "udp"):
        raise PortsError("protocol must be 'tcp' or 'udp' for kill_port")
    targets, _ = _build_targets(port, proto)
    protected = protected_pids()

    hard: list[str] = []
    soft: list[str] = []
    for t in targets:
        for pid, info in [(t.info.pid, t.info)] + [(d.pid, d) for d in t.descendants]:
            for r in hard_reasons(pid, protected):
                hard.append(f"PID {pid} ({info.display_name}): {r}")
        for r in soft_reasons(t.info, t.hint):
            soft.append(f"PID {t.info.pid} ({t.info.display_name}): {r}")
    if hard:
        raise PortsError(
            f"REFUSED. {proto} port {port} cannot be freed by killing its process:\n  "
            + "\n  ".join(hard)
            + "\nThis refusal cannot be overridden with force."
        )
    if soft and not force:
        raise PortsError(
            f"REFUSED without force. {proto} port {port} is held by what looks like part of "
            "the operating system:\n  "
            + "\n  ".join(soft)
            + "\nKilling it may break the machine. If you are sure, call "
            f"kill_port(port={port}, force=True) to get a plan; you will still have to confirm it."
        )

    plan = Plan(
        token=secrets.token_hex(6),
        port=port,
        proto=proto,
        force=force,
        targets=targets,
        expires_at=store.now() + store.ttl,
    )
    lines = [
        f"KILL PLAN for {proto} port {port} (nothing has been killed yet)",
        f"Token: {plan.token} (single use, valid {store.ttl:g} s)",
        "",
    ]
    total = 0
    for t in targets:
        total += 1 + len(t.descendants)
        plan.created_times[t.info.pid] = t.info.create_time
        lines.append(f"Will stop {_describe(t.info, t.hint)}")
        for s in t.sockets:
            lines.append(f"    holds {s.address}:{s.port} ({exposure_text(s.address)})")
        if t.info.command:
            lines.append(f"    command: {t.info.command[:300]}")
        if t.info.cwd:
            lines.append(f"    cwd: {t.info.cwd}")
        for d in t.descendants:
            lines.append(f"    plus child {_describe(d, hint_for(d))}")
        if t.hint and t.hint.advice:
            lines.append(f"    NOTE: {t.hint.advice}")
        if t.hint and t.hint.kind == "datastore":
            lines.append(
                "    NOTE: this is a database/cache; killing it can lose unsaved data. "
                "Prefer its own shutdown command."
            )
        p = t.parent
        if p is not None:
            if p.command and p.command == t.info.command:
                note = "same command line: a launcher shim that exits with its child"
            else:
                note = "NOT killed; if it restarts the child, stop the parent instead"
            lines.append(f"    parent: {_describe(p, hint_for(p))} ({note})")
    if soft:
        lines.append("FORCED over these warnings:")
        lines.extend(f"    {s}" for s in soft)
    lines += [
        "",
        f"{total} process(es) in total. Method: graceful terminate, wait for exit, then "
        "force-kill whatever survives. On Windows there is no graceful step: terminate is "
        "immediate.",
        f'To go ahead call: kill_port(port={port}, confirm_token="{plan.token}")',
    ]
    store.add(plan)
    return plan, "\n".join(lines)


# -- execution --------------------------------------------------------------------------


def _alive(p: psutil.Process) -> bool:
    try:
        return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _wait_gone(procs: list[psutil.Process], timeout: float) -> list[psutil.Process]:
    """Wait up to ``timeout`` seconds; return the processes still alive."""
    deadline = time.monotonic() + timeout
    alive = [p for p in procs if _alive(p)]
    while alive and time.monotonic() < deadline:
        time.sleep(0.05)
        alive = [p for p in alive if _alive(p)]
    return alive


def execute(plan: Plan, grace: float) -> str:
    """Carry out a redeemed plan. Raises PortsError if the port is not freed."""
    # 1. The world must still match the plan.
    res = listeners_on_port(plan.port, plan.proto)
    now_pids = {ln.pid for ln in res.listeners}
    unexpected = now_pids - plan.root_pids - {None}
    if unexpected or None in now_pids:
        raise PortsError(
            f"ABORTED, nothing was killed: port {plan.port} is now held by different "
            f"process(es) {sorted(p for p in now_pids if p is not None)} than the plan "
            "covered. Request a new plan and review it."
        )
    protected = protected_pids()

    # 2. Snapshot current trees, verify identity (PID reuse) and re-run the hard rules.
    victims: list[psutil.Process] = []
    names: dict[int, str] = {}
    extra_children = 0
    planned_desc = {d.pid for t in plan.targets for d in t.descendants}
    for t in plan.targets:
        pid = t.info.pid
        if pid not in now_pids:
            continue  # already exited by itself
        info = proc_info(pid)
        if info is None:
            continue
        if info.create_time != plan.created_times.get(pid):
            raise PortsError(
                f"ABORTED, nothing was killed: PID {pid} is no longer the process that was "
                "planned (the PID was reused). Request a new plan."
            )
        group = [info] + children_recursive(pid)
        for g in group:
            reasons = hard_reasons(g.pid, protected)
            if reasons:
                raise PortsError(
                    f"ABORTED, nothing was killed: PID {g.pid} ({g.display_name}) is now in the "
                    f"process tree and is protected: {reasons[0]}."
                )
            if g.pid != pid and g.pid not in planned_desc:
                extra_children += 1
            try:
                victims.append(psutil.Process(g.pid))
                names[g.pid] = g.display_name
            except psutil.NoSuchProcess:
                continue

    # 3. Graceful terminate (root first so a supervisor cannot respawn its children).
    denied: list[str] = []
    for p in victims:
        try:
            p.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            denied.append(f"PID {p.pid} ({names[p.pid]})")
    survivors = _wait_gone(victims, grace)
    # 4. Force-kill what ignored the polite request.
    forced: list[str] = []
    for p in survivors:
        try:
            p.kill()
            forced.append(f"PID {p.pid} ({names[p.pid]})")
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            if f"PID {p.pid} ({names[p.pid]})" not in denied:
                denied.append(f"PID {p.pid} ({names[p.pid]})")
    stuck = _wait_gone(survivors, 5.0)

    # 5. The only success criterion: is the port actually free?
    deadline = time.monotonic() + 5.0
    holders = listeners_on_port(plan.port, plan.proto).listeners
    while holders and time.monotonic() < deadline:
        time.sleep(0.1)
        holders = listeners_on_port(plan.port, plan.proto).listeners

    report = [
        f"Stopped {len(victims) - len(stuck)} of {len(victims)} process(es) on "
        f"{plan.proto} port {plan.port}.",
    ]
    if forced:
        report.append(
            "Force-killed after "
            f"{grace:g} s (ignored the graceful request): " + ", ".join(forced)
        )
    if extra_children:
        report.append(f"{extra_children} child process(es) appeared after the plan and were stopped too.")
    problems = []
    if denied:
        problems.append(
            "Access denied (elevation needed): " + ", ".join(denied)
        )
    if stuck:
        problems.append("Still running: " + ", ".join(f"PID {p.pid}" for p in stuck))
    if holders:
        problems.append(
            f"Port {plan.port} is STILL in use by PID(s) "
            f"{sorted({h.pid for h in holders if h.pid is not None})}. A supervisor or "
            "parent probably restarted it; look at process_tree and stop that instead."
        )
    if problems:
        raise PortsError("\n".join(report + problems))
    report.append(f"Verified: {plan.proto} port {plan.port} is now free.")
    return "\n".join(report)
