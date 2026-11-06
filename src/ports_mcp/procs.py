"""Process inspection: info, trees, framework hints, exposure. Thin layer over psutil.

Nothing here hides a failure. When the OS refuses to tell us something (psutil.AccessDenied)
the field is left None and its name is recorded in ``ProcInfo.denied`` so the caller can say
"elevation needed" instead of pretending the process has no command line.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

import psutil


class PortsError(Exception):
    """An expected, user-actionable failure. The message is shown to the agent verbatim."""


@dataclass
class ProcInfo:
    pid: int
    name: str | None
    cmdline: list[str] | None
    cwd: str | None
    username: str | None
    create_time: float | None
    ppid: int | None
    denied: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.name if self.name else "<name hidden>"

    @property
    def command(self) -> str | None:
        if not self.cmdline:
            return None
        return " ".join(self.cmdline)


def proc_info(pid: int) -> ProcInfo | None:
    """Collect what the OS lets us see about ``pid``. None if the process is gone."""
    try:
        p = psutil.Process(pid)
        info = ProcInfo(pid, None, None, None, None, None, None)
        with p.oneshot():
            for attr in ("name", "cmdline", "cwd", "username", "create_time", "ppid"):
                try:
                    setattr(info, attr, getattr(p, attr)())
                except psutil.AccessDenied:
                    info.denied.append(attr)
        # psutil returns [] / "" (not AccessDenied) for some protected processes.
        if info.cmdline == []:
            info.cmdline = None
            info.denied.append("cmdline")
        if info.cwd == "":
            info.cwd = None
            info.denied.append("cwd")
        return info
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def children_recursive(pid: int) -> list[ProcInfo]:
    """All descendants of ``pid``. Empty if the process is gone."""
    try:
        kids = psutil.Process(pid).children(recursive=True)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return []
    out: list[ProcInfo] = []
    for k in kids:
        i = proc_info(k.pid)
        if i is not None:
            out.append(i)
    return out


def ancestors(pid: int) -> list[ProcInfo]:
    """Parents of ``pid`` from the immediate parent up to the root."""
    try:
        parents = psutil.Process(pid).parents()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return []
    out: list[ProcInfo] = []
    for q in parents:
        i = proc_info(q.pid)
        if i is not None:
            out.append(i)
    return out


def protected_pids() -> dict[int, str]:
    """PIDs this server must never signal, with the reason."""
    out: dict[int, str] = {os.getpid(): "this is the ports-mcp server process itself"}
    for q in psutil.Process().parents():
        out[q.pid] = (
            "it is an ancestor of the ports-mcp server (probably your MCP client or "
            "terminal); killing it would shut this server down"
        )
    return out


# -- exposure ---------------------------------------------------------------------------


def exposure(address: str) -> str:
    """'all' (0.0.0.0 / ::), 'loopback' (127.x / ::1) or 'interface' (one specific NIC)."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "interface"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "all"
    if ip.is_loopback:
        return "loopback"
    return "interface"


def exposure_text(address: str) -> str:
    e = exposure(address)
    if e == "all":
        return "EXPOSED: all interfaces, reachable from the network"
    if e == "loopback":
        return "loopback only"
    return f"bound to one interface ({address}), reachable from that network"


# -- framework hints --------------------------------------------------------------------


@dataclass(frozen=True)
class Hint:
    label: str
    kind: str  # dev-server | datastore | container | infrastructure | runtime
    advice: str | None = None


# (label, kind, any-of tokens, all-of tokens, advice). Tokens come from _tokens().
_Rule = tuple[str, str, frozenset[str], frozenset[str], str | None]


def _r(label: str, kind: str, any_of: str, all_of: str = "", advice: str | None = None) -> _Rule:
    return (label, kind, frozenset(any_of.split()), frozenset(all_of.split()), advice)


_RULES: list[_Rule] = [
    _r("Vite dev server", "dev-server", "vite"),
    _r("Next.js", "dev-server", "next next-server next-router-worker"),
    _r("webpack dev server", "dev-server", "webpack-dev-server webpack webpack-cli"),
    _r("Nuxt", "dev-server", "nuxt nuxi"),
    _r("Astro", "dev-server", "astro"),
    _r("Angular CLI", "dev-server", "ng", all_of="serve"),
    _r("Parcel", "dev-server", "parcel"),
    _r("Storybook", "dev-server", "storybook start-storybook"),
    _r("Create React App", "dev-server", "react-scripts"),
    _r("Remix", "dev-server", "remix"),
    _r("Expo / Metro bundler", "dev-server", "expo metro"),
    _r("uvicorn (ASGI)", "dev-server", "uvicorn"),
    _r("gunicorn (WSGI)", "dev-server", "gunicorn"),
    _r("hypercorn (ASGI)", "dev-server", "hypercorn"),
    _r("daphne (ASGI)", "dev-server", "daphne"),
    _r("FastAPI CLI", "dev-server", "fastapi"),
    _r("Flask", "dev-server", "flask"),
    _r("Django runserver", "dev-server", "manage", all_of="runserver"),
    _r("Streamlit", "dev-server", "streamlit"),
    _r("Jupyter", "dev-server", "jupyter jupyter-lab jupyter-notebook jupyterlab"),
    _r("Python http.server", "dev-server", "http.server"),
    _r("Rails / Puma", "dev-server", "rails puma unicorn"),
    _r("Jekyll", "dev-server", "jekyll"),
    _r("Hugo", "dev-server", "hugo"),
    _r("PHP", "dev-server", "php php-cgi php-fpm"),
    _r(
        "Docker port proxy",
        "container",
        "docker-proxy",
        advice=(
            "this only forwards a published container port. Killing it leaves the container "
            "running with the port unpublished; use `docker ps` and `docker stop <container>` "
            "instead"
        ),
    ),
    _r(
        "Docker Desktop / WSL port forwarder",
        "infrastructure",
        "com.docker.backend vpnkit wslrelay wslservice",
        advice="killing it breaks port forwarding for every container or WSL distro",
    ),
    _r("PostgreSQL", "datastore", "postgres"),
    _r("Redis", "datastore", "redis-server"),
    _r("MySQL / MariaDB", "datastore", "mysqld mariadbd"),
    _r("MongoDB", "datastore", "mongod"),
    _r("Memcached", "datastore", "memcached"),
    _r("Elasticsearch", "datastore", "elasticsearch"),
]

_GENERIC_RUNTIMES = {
    "node": "Node.js process",
    "deno": "Deno process",
    "bun": "Bun process",
    "ruby": "Ruby process",
    "java": "Java process",
    "dotnet": ".NET process",
}

_EXT = re.compile(r"\.(js|mjs|cjs|py|pyw|cmd|exe|bat|ps1|rb|php)$")


def _tokens(info: ProcInfo) -> set[str]:
    """Lowercased basenames of argv (and package names under node_modules), so a project
    directory called 'vite-demo' does not look like Vite."""
    toks: set[str] = set()
    args = list(info.cmdline or [])
    if info.name:
        args.append(info.name)
    for a in args:
        norm = a.replace("\\", "/").lower()
        base = _EXT.sub("", norm.rsplit("/", 1)[-1])
        toks.add(base)
        if "." in base:
            toks.update(part for part in base.split(".") if part)
        m = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)", norm)
        if m:
            toks.add(m.group(1))
    return toks


def hint_for(info: ProcInfo) -> Hint | None:
    """Infer what kind of server this is from its command line and name."""
    toks = _tokens(info)
    for label, kind, any_of, all_of, advice in _RULES:
        if toks & any_of and all_of <= toks:
            return Hint(label, kind, advice)
    stem = _EXT.sub("", (info.name or "").lower())
    if stem.startswith("python"):
        return Hint("Python process", "runtime")
    if stem in _GENERIC_RUNTIMES:
        return Hint(_GENERIC_RUNTIMES[stem], "runtime")
    return None
