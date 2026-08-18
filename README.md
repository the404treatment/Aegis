# AEGIS

SOC detection-engineering console with an agent ingest platform.

```bash
npm run build     # src/ -> ui/index.html
npm test          # 62 assertions
npm run serve     # build + server on http://127.0.0.1:8787
```

Open `ui/index.html` directly for the console with no backend, or run the
server for live agent data and shared ticketing.

- `CLAUDE.md` — architecture, conventions, hard rules (read this first)
- `deploy/README-deploy.md` — server + agent deployment
- `splunk/aegis_hec_setup.md` — HEC config and starting searches

## Security posture

The agent is read-only by design: it reads event logs and reports host facts.
No command channel, no download path, no exec. Read `agents/aegis-agent.ps1`
before deploying it anywhere. The server binds `127.0.0.1` and has no TLS —
terminate TLS in front of it. See `CLAUDE.md` and `deploy/` for detail.
