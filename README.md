# AEGIS

[![test](https://github.com/the404treatment/Aegis/actions/workflows/test.yml/badge.svg)](https://github.com/the404treatment/Aegis/actions/workflows/test.yml)

A SOC console your team works an incident in together — detection engineering,
live agent telemetry, shared cases, and a signed record of who did what.

**[Try it in the browser →](https://the404treatment.github.io/Aegis/)** — no install,
no signup, nothing to configure. The console is fully functional offline, so the
hosted build is the real app rather than a demo.

<p align="center">
  <img src="assets/matrix.png" alt="ATT&CK coverage matrix showing telemetry coverage per technique" width="860">
</p>

<table>
  <tr>
    <td><img src="assets/huntmap.png" alt="Hunt map showing an intrusion traced across zones"></td>
    <td><img src="assets/studio.png" alt="Detection studio with staged techniques on the kill chain"></td>
  </tr>
  <tr>
    <td align="center"><sub>Hunt map — the intrusion traced across your estate</sub></td>
    <td align="center"><sub>Detection studio — staged techniques, mapped to the kill chain</sub></td>
  </tr>
</table>

## Install

One line. It installs to your home directory, registers a service that survives
a reboot, and waits until the server actually answers before saying it worked.

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/the404treatment/Aegis/main/install.sh | sh
```

**Windows** (PowerShell, no admin needed)

```powershell
irm https://raw.githubusercontent.com/the404treatment/Aegis/main/install.ps1 | iex
```

No `sudo`, no admin, no package manager. [Node.js 18+](https://nodejs.org) is the
only prerequisite and the installer checks for it rather than silently pulling in
someone else's install script. Re-running upgrades in place and keeps your tokens,
so enrolled agents keep working.

Prefer to look before you run it? Clone the repo and double-click **`start.cmd`**
(Windows) or run **`./start.sh`** (Linux/macOS) — same result.

Then open the console. It asks you to create the first account, which becomes the
lead and can add everyone else.

## Get telemetry flowing

Find the machines on your network and push the agent to them:

```bash
node discover.mjs --json targets.json                    # scan
node deploy-agents.mjs --targets targets.json            # review the plan
node deploy-agents.mjs --targets targets.json --confirm  # deploy
```

Deployment is dry-run by default, only touches hosts you list, and never handles
your password — Windows and ssh prompt for that themselves.
**[Full step-by-step guide →](INSTALL.md)**

## Working an incident together

Accounts are on by default, because a case file nobody can be attributed to is
worth very little afterwards.

- **Presence** — the top bar shows who else is connected, live.
- **Activity feed** — what everyone has been doing, newest first, read straight
  out of the audit chain.
- **Team chat** — delivered over the SSE stream the console already holds open.
- **Cases** — evidence stored content-addressed by SHA-256, formal reports frozen
  and signed against a snapshot hash.
- **Audit** — every action hash-chained. Edit the record on disk and the console
  refuses to trust it and says so.

The shared analyst token still works as a break-glass and automation credential.
Set `"requireLogin": false` in `server/config.json` for a single-analyst lab.

## Air-gapped networks

Nothing in AEGIS downloads at run time, phones home, checks a licence, or contacts
a CDN — so an enclave with no route out behaves identically. For a machine with no
Node either, build a bundle that carries its own runtime:

```bash
npm run bundle -- --target linux-x64     # or win-x64, darwin-arm64
```

That produces `dist/aegis-airgap-<target>.tar.gz` containing AEGIS, a pinned Node
runtime verified against the SHA-256 checksums published beside it, and a launcher.
Copy it across, extract, run. Verified on a machine with no Node installed at all.

## Everything else

```bash
npm start         # start the server
npm run setup     # regenerate config + rebuild (keeps your tokens)
npm run demo      # seed a realistic incident so you can explore with data
npm test          # build + full suite (UI, server, end-to-end HTTP)
```

**Offline** (open `ui/index.html` directly, no backend): ATT&CK coverage matrix,
hunt map, detection studio, artifact triage, response playbooks, IOC extraction,
and in-browser ingest of Chainsaw / Suricata / Zeek / PCAP exports.

**With the server:** live agent telemetry, event search, shared tickets, cases with
hashed evidence, signed formal reports, the audit chain, presence, activity and chat.

**AI Analyst** (optional, the only part that talks to the internet): set
`ANTHROPIC_API_KEY` in the server's environment and restart. The **server** holds
the key and makes the call, so it is never sent to a browser and never ends up in
the published `ui/index.html`.

- `INSTALL.md` — step-by-step: server, agents, firewall, verification
- `CLAUDE.md` — architecture, conventions, hard rules (read this first)
- `deploy/README-deploy.md` — server + agent deployment
- `splunk/aegis_hec_setup.md` — HEC config and starting searches
- `NEXT_STEPS.md` — priority-ordered roadmap

## Security posture

The agent is read-only by design: it reads event logs and reports host facts. No
command channel, no download path, no exec — there is **no remote-exec channel, by
design**. Read `agents/aegis-agent.ps1` before deploying it anywhere.

The server speaks plain HTTP: terminate TLS in front of it (there is a ready-made
`deploy/Caddyfile`) before it crosses a network you do not trust. Rotate the
enrollment token after rollout with `node setup.mjs --rotate`.
