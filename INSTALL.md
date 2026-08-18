# Installing AEGIS

Two things get installed:

1. **The server** — one machine on your network. Hosts the console and receives
   agent data.
2. **The agent** — each workstation or server you want telemetry from. Read-only;
   it reports in, and takes no commands back.

You only need Node.js 18 or newer. There is nothing to `npm install` — AEGIS has
no dependencies.

---

## Part 1 — The server

### Windows

1. Install **Node.js LTS** from <https://nodejs.org> if you don't have it.
2. Download or clone AEGIS.
3. **Double-click `start.cmd`.**

That's it. On first run it generates your tokens, builds the console, then starts
the server and opens it in your browser.

### Linux / macOS

```bash
git clone https://github.com/the404treatment/Aegis.git
cd Aegis
./start.sh
```

### What first run prints

Keep this — you need the two tokens:

```
  Open the console   http://127.0.0.1:8787
  Agents report to   http://192.168.1.17:8787

  Analyst token   Q9Nae8I5X3mIDFB0gu2qMFhuGX2moNlY
  Enrollment      IX1fj-IZBmOJDOCBfvOEV558VJG0Xyvz
```

- **Analyst token** — signs the console in to the server.
- **Enrollment token** — lets an agent join. Shared by every agent.

Both are printed again every time the server starts, and live in
`server/config.json`.

> **The "Agents report to" address is the one that matters.** If your machine has
> VPN or VM adapters, setup picks the real network one and labels the rest
> `(virtual — probably not this one)`. If agents can't connect, try another
> address from that list.

### Open the firewall

The server binds to every interface, but the OS still blocks the port. **Agents
cannot connect until you do this.**

**Windows** — in an *Administrator* PowerShell:

```powershell
New-NetFirewallRule -DisplayName "AEGIS 8787" -Direction Inbound `
  -Protocol TCP -LocalPort 8787 -Action Allow -Profile Domain,Private
```

`Domain,Private` deliberately — this should not be reachable from a public network.

**Linux**

```bash
sudo ufw allow 8787/tcp                                   # ufw
sudo firewall-cmd --add-port=8787/tcp --permanent && sudo firewall-cmd --reload   # firewalld
```

### Connect the console

Open <http://127.0.0.1:8787>, click the **connection indicator** in the top bar,
and paste the server URL and **analyst token**.

---

## Part 2 — The agents

### Windows endpoint

Copy `agents/aegis-agent.ps1` to the machine, then in an **Administrator**
PowerShell (it needs elevation to read the Security log and protect its key):

```powershell
# try one cycle first to confirm it works
.\aegis-agent.ps1 -Server http://192.168.1.17:8787 -EnrollmentToken <enrollment-token> -Once

# then install it as a scheduled task that runs every 5 minutes
.\aegis-agent.ps1 -Server http://192.168.1.17:8787 -EnrollmentToken <enrollment-token> -Install
```

Replace the address with your **"Agents report to"** URL.

### Linux / macOS endpoint

```bash
sudo ./aegis-agent.py --server http://192.168.1.17:8787 --token <enrollment-token> --once
```

For continuous collection use the systemd unit and timer in `deploy/`.

### Rolling out to many machines

GPO, Intune, SCCM and Ansible all work — the agent is a single script with no
dependencies. See `deploy/README-deploy.md`, which also covers code-signing the
PowerShell agent so you can run under `AllSigned` rather than
`-ExecutionPolicy Bypass`.

---

## Part 3 — Check it's working

1. In the console, open **Network Map**. Enrolled hosts appear automatically.
2. Open **Event Search** and run `severity:malicious`, or just press Search to see
   everything.
3. On the server, `server/data/events.ndjson` grows as telemetry lands.

Nothing showing up? In order of likelihood:

| Symptom | Cause |
|---|---|
| Agent: connection timed out | Firewall rule missing, or wrong "Agents report to" address |
| Agent: `must run as Administrator` | Re-open PowerShell as admin |
| Agent: 401 / bad enrollment token | Token mismatch — copy it again from the server output |
| Console shows "needs a server" | Console isn't connected — paste the **analyst** token, not the enrollment one |
| Server: `Port 8787 is already in use` | AEGIS is already running, or something else has the port |

---

## Part 4 — Before you rely on it

The defaults are tuned for *getting running*, not for a hostile network. Three
things to fix before this is more than a lab:

1. **Turn on TLS.** The server speaks plain HTTP by design — tokens and telemetry
   cross the network in the clear. Put a TLS reverse proxy in front of it; there
   is a ready-made `deploy/Caddyfile`.
2. **Turn on accounts.** By default one shared analyst token is the only
   credential and nothing is attributable to a person. Set `"requireLogin": true`
   in `server/config.json` and create accounts — the analyst token keeps working
   as a break-glass credential, so this can't lock you out. See the "Enabling
   named accounts" section of `deploy/README-deploy.md`.
3. **Rotate the enrollment token after rollout.** It's only needed at first
   contact; enrolled agents hold their own keys and keep working.
   ```bash
   node setup.mjs --rotate    # regenerates both tokens
   ```

---

## Reference

| Command | Does |
|---|---|
| `npm run setup` | Regenerate config and rebuild (keeps existing tokens) |
| `node setup.mjs --local` | Bind to this machine only — no agents |
| `node setup.mjs --port 9000` | Use a different port |
| `node setup.mjs --rotate` | Issue new tokens (every agent must re-enrol) |
| `npm start` | Start the server |
| `npm test` | Run the full test suite |

Config lives in `server/config.json`; data in `server/data/`. Back up both — the
data directory holds tickets, cases, evidence and the audit chain.
