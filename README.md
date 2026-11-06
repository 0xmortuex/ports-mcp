# ports-mcp

**Ask your AI agent "what is using port 3000?" and have it free the port safely, on Windows, macOS and Linux.**

<!-- mcp-name: io.github.0xmortuex/ports-mcp -->

ports-mcp is an [MCP](https://modelcontextprotocol.io) server built on [psutil](https://github.com/giampaolo/psutil), so the same six tools work on every OS. It lists listeners, explains what a process is (Vite, Next.js, uvicorn, Flask, docker-proxy, a database...), shows process trees, finds free ports, tests TCP reachability, and frees a port through a **two-step confirmed kill** that refuses to touch anything that would hurt.

## Install

Claude Code:

```bash
claude mcp add ports -- uvx ports-mcp
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ports": { "command": "uvx", "args": ["ports-mcp"] }
  }
}
```

Needs [uv](https://docs.astral.sh/uv/) and Python 3.10+. Without uv: `pip install ports-mcp` and use the `ports-mcp` command.

## Try asking

- "What is using port 3000?"
- "Show me everything listening on this machine that is exposed to the network."
- "List my node and uvicorn dev servers with their working directories."
- "Free port 5173." (you get a plan first and confirm it)
- "Find me 3 free ports between 8000 and 8100."
- "Show the process tree of PID 4312. Who started it?"
- "Is localhost:8080 reachable?"

## Tools

| Tool | What it does |
|------|--------------|
| `list_listening` | Everything listening, grouped by process: PID, name, user, command line, cwd, inferred framework, bound address. Sockets on `0.0.0.0` / `::` are flagged **EXPOSED**, `127.0.0.1` / `::1` are loopback only. Filter by port range, process name, protocol (`tcp`, `udp`, `all`). |
| `whats_on_port` | Full detail for one port, plus parent/children and whether `kill_port` would allow it. If nothing is listening it tells you whether the port is bindable, which catches OS-reserved ports and hidden listeners. |
| `find_free_port` | Lowest unused port(s) in a range that the OS will really let you bind. |
| `kill_port` | Two-step, confirmed kill (below). |
| `process_tree` | Ancestors and all descendants of a PID, marking which ones listen on a port. |
| `check_port_reachable` | TCP connect with a timeout; tells refused vs timed out vs DNS failure. |

## The kill is two steps

```
> kill_port(port=5173)
KILL PLAN for tcp port 5173 (nothing has been killed yet)
Token: 2c19fba46833 (single use, valid 60 s)

Will stop PID 13664 node.exe [Vite dev server] user me
    holds 127.0.0.1:5173 (loopback only)
    command: node C:\proj\node_modules\vite\bin\vite.js
    plus child PID 13702 esbuild.exe
    parent: PID 13650 npm.exe (NOT killed; if it restarts the child, stop the parent instead)
To go ahead call: kill_port(port=5173, confirm_token="2c19fba46833")

> kill_port(port=5173, confirm_token="2c19fba46833")
Stopped 2 of 2 process(es) on tcp port 5173.
Verified: tcp port 5173 is now free.
```

- The first call never kills. It returns the plan and a random token.
- The token is single use, expires after 60 s, and only works for the port it was issued for. A wrong-port attempt also invalidates it.
- On the second call the world is re-checked: if a different process now holds the port, or a PID was reused, nothing is killed.
- Processes get a graceful terminate, then a force-kill after `grace_seconds` (default 5). The tool then checks that the port is really free and says so, or reports what survived (for example a parent that respawned it).

**Always refused, even with `force`:** PID 0, 1 and 4, the ports-mcp process itself, and its ancestors (your MCP client and terminal).
**Refused unless `force=True` on the planning call:** operating-system services (svchost, systemd, launchd, SYSTEM-account processes, Docker Desktop's backend, processes whose identity the OS hides). Even then you still get a plan and must confirm it.

## Permissions and what you will not see

ports-mcp runs as you. Some processes are invisible without elevation, and it says so rather than hiding them:

- **Windows:** system services show up, but their command line and working directory may read "access denied, elevation needed".
- **Linux:** sockets owned by other users are listed as "unidentified process"; run with `sudo` to see owners.
- **macOS:** listing every socket needs root. Without it ports-mcp inspects each process it may read and warns how many it could not, so a port can be held by something it cannot see (`whats_on_port` also probes with a connect and a bind to catch that).

## Security

- `kill_port` terminates processes the current user can terminate. The plan/token flow exists so a model cannot do it in one careless call; show the plan to a human.
- The token is `secrets.token_hex`, kept only in server memory, never written to disk.
- `check_port_reachable` makes an outbound TCP connection to whatever host you give it (no data is sent). Do not expose this server to untrusted callers: it can probe your network.
- Command lines can contain secrets (tokens in arguments). `list_listening` and `whats_on_port` print them, truncated to 300 characters, to the connected model.
- On Windows `terminate` is an immediate hard kill; there is no graceful stop for non-console programs.

## Development

```bash
uv sync --extra test
uv run pytest            # starts real listener processes on random ports
uv run ruff check src tests
uv run mypy --strict src
```

Companion tutorial that builds a minimal version from scratch: [ports-mcp-the-hard-way](https://github.com/0xmortuex/ports-mcp-the-hard-way).

MIT licensed.
