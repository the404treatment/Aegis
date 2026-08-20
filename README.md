# AEGIS

[![test](https://github.com/the404treatment/Aegis/actions/workflows/test.yml/badge.svg)](https://github.com/the404treatment/Aegis/actions/workflows/test.yml)

A SOC console your team works an incident in together - detection engineering,
live agent telemetry, shared cases, and a signed record of who did what.

**[Try it in the browser →](https://the404treatment.github.io/Aegis/)** - no install,
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
    <td align="center"><sub>Hunt map - the intrusion traced across your estate</sub></td>
    <td align="center"><sub>Detection studio - staged techniques, mapped to the kill chain</sub></td>
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
(Windows) or run **`./start.sh`** (Linux/macOS) - same result.

Prefer Docker, or installing on a NAS or a Proxmox host? A full step-by-step
walkthrough for all of these, including Docker's Proxmox-specific options, is
in **[INSTALL.md](INSTALL.md)**.

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
your password - Windows and ssh prompt for that themselves.
**[Full step-by-step guide →](INSTALL.md)**

## What you see first

A **live dashboard**, not a reference chart. Threat level for the last hour,
malicious events as they land, which hosts are noisiest, which ATT&CK techniques
have actually been *observed*, and which agents have gone quiet.

You choose the cards - a triage shift and a detection-engineering afternoon want
different first screens, so the layout is yours and is remembered per browser.

Reference material (the full ATT&CK matrix, the log-source catalogue, the
technique library) is still there, one click away. It just no longer sits in
front of someone walking up to a screen mid-incident.

## A local AI that speaks first

Optional, entirely local, no API key:

```bash
npm run ai:setup
```

It finds an inference server already on the host - **Ollama**, LM Studio,
llama.cpp, Jan, vLLM or TGI - pulls a model from **Hugging Face** if you have
none, and wires it in. Models are GGUF; the default is Llama 3.2 3B at Q4, which
runs on a laptop with no GPU.

The point is that **it doesn't wait to be asked.** It reads telemetry as it
lands and posts an assessment unprompted:

> **UNPROMPTED · 41 EVENTS · DC01**
> Password-spray burst against DC01 - 40 failed logons (4625) inside a minute
> from one source, then a success. Treat as likely compromise. Next: pull 4624
> for that account and check the source IP against your VPN pool.

You can ask it things directly too. Nothing leaves the machine.
**[Setup guide →](LOCAL-AI.md)**

## Working an incident together

Accounts are on by default, because a case file nobody can be attributed to is
worth very little afterwards.

- **Presence** - the top bar shows who else is connected, live.
- **Activity feed** - what everyone has been doing, newest first, read straight
  out of the audit chain.
- **Team chat** - delivered over the SSE stream the console already holds open.
- **Cases** - evidence stored content-addressed by SHA-256, formal reports frozen
  and signed against a snapshot hash.
- **Audit** - every action hash-chained. Edit the record on disk and the console
  refuses to trust it and says so.

The shared analyst token still works as a break-glass and automation credential.
Set `"requireLogin": false` in `server/config.json` for a single-analyst lab.

## Air-gapped networks

Nothing in AEGIS downloads at run time, phones home, checks a licence, or contacts
a CDN - so an enclave with no route out behaves identically. For a machine with no
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
hunt map, detection studio, response playbooks, IOC extraction, and in-browser
ingest of Chainsaw / Suricata / Zeek / PCAP exports.

**With the server:** live agent telemetry, event search, shared tickets, cases with
hashed evidence, signed formal reports, the audit chain, presence, activity and chat.

**AI** (optional): `npm run ai:setup` on the server. Every AI feature runs on
that machine - there is no hosted API and no key anywhere. Nothing leaves the
host.

- `INSTALL.md` - step-by-step: server, agents, firewall, verification
- `docs/RUNBOOK.md` - **when something breaks**: every failure, with the fix
- `LOCAL-AI.md` - the local companion: setup, model choice, air-gapped use
- `docs/DEFENDING-AEGIS.md` - attacks on AEGIS itself, with the detections
- `CLAUDE.md` - architecture, conventions, hard rules (read this first)
- `deploy/README-deploy.md` - server + agent deployment
- `splunk/aegis_hec_setup.md` - HEC config and starting searches
- `NEXT_STEPS.md` - priority-ordered roadmap

## Security posture

The agent is read-only by design: it reads event logs and reports host facts. No
command channel, no download path, no exec - there is **no remote-exec channel, by
design**. Read `agents/aegis-agent.ps1` before deploying it anywhere.

The server speaks plain HTTP: terminate TLS in front of it (there is a ready-made
`deploy/Caddyfile`) before it crosses a network you do not trust.

**AEGIS is itself a target** - it holds the incident record. Everything about a
stock install is public because this repo is public, so stop matching the docs:

```bash
node harden.mjs --name svc-telemetry --port 9443 --rotate
```

That renames the service, moves the port, rotates the tokens and re-registers
the service. It is a delaying tactic, not a control - its real value is that
once you are not on `aegis`:8787, anything probing for `aegis` on 8787 is not
you, which is a detection you could not write before.
**[The full threat model, with detections →](docs/DEFENDING-AEGIS.md)**
