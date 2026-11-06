# Changelog

## 0.1.0

First release.

- Tools: `list_listening`, `whats_on_port`, `find_free_port`, `kill_port`, `process_tree`,
  `check_port_reachable`. Cross-platform through psutil (Windows, macOS, Linux).
- Framework hints from the command line: Vite, Next.js, webpack, Nuxt, Astro, uvicorn, gunicorn,
  Flask, Django, Streamlit, Jupyter, http.server, Rails/Puma, docker-proxy, common databases.
- `kill_port` is two-step with a single-use, expiring, port-bound confirm token; graceful
  terminate then force-kill; verifies the port is free afterwards.
- Hard refusals: PID 0/1/4, the server itself, its ancestors. Soft refusals (need `force`):
  operating-system services and Docker Desktop infrastructure.
- Access-denied details are reported as "elevation needed", never dropped silently.
