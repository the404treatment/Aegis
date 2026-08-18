# AEGIS

SOC detection-engineering console with an incident-response platform.

```bash
npm run build     # src/ -> ui/index.html
npm test          # build + full suite (UI, server, end-to-end HTTP)
npm run serve     # build + server on http://127.0.0.1:8787
```

No dependencies to install — the console is vanilla JS and the server is
Node's standard library only.

**Offline** (open `ui/index.html` directly, no backend): ATT&CK coverage
matrix, hunt map, detection studio, artifact triage, offline response
playbooks, IOC extraction, and in-browser ingest of Chainsaw / Suricata /
Zeek / PCAP exports.

**With the server:** live agent telemetry, event search, shared tickets,
case files with SHA-256 hashed evidence, signed formal reports, a
tamper-evident audit chain, and team chat. Named accounts with roles are
opt-in — without them the shared analyst token works exactly as before.

- `CLAUDE.md` — architecture, conventions, hard rules (read this first)
- `deploy/README-deploy.md` — server + agent deployment
- `splunk/aegis_hec_setup.md` — HEC config and starting searches
- `NEXT_STEPS.md` — priority-ordered roadmap

## Security posture

The agent is read-only by design: it reads event logs and reports host facts.
No command channel, no download path, no exec. Read `agents/aegis-agent.ps1`
before deploying it anywhere. The server binds `127.0.0.1` and has no TLS —
terminate TLS in front of it. See `CLAUDE.md` and `deploy/` for detail.
