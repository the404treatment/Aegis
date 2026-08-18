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

### The one-liner

Installs to your home directory, registers a service that starts on boot, and
waits until the server answers before claiming success. No admin, no `sudo`.

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/the404treatment/Aegis/main/install.sh | sh
```

**Windows** (PowerShell)

```powershell
irm https://raw.githubusercontent.com/the404treatment/Aegis/main/install.ps1 | iex
```

Re-run it any time to upgrade — your tokens and data are kept, so enrolled agents
keep working.

### Or clone it and look first

Piping a script into a shell is convenient, not virtuous. To read it first:

**Windows** — clone the repo, then **double-click `start.cmd`**
**Linux / macOS**

```bash
git clone https://github.com/the404treatment/Aegis.git
cd Aegis
./start.sh
```

Same result: first run generates your tokens, builds the console, starts the
server and opens it.

### Create the first account

The console asks for one on first run. That account becomes the **lead** and can
add everyone else from the console. There is nothing to configure and no way to
lock yourself out — the offer only appears while the server has no accounts, and
disappears the moment it has one.

Accounts are on by default because every ticket, case and evidence upload is
recorded against the person who did it. For a single-analyst lab where a shared
token is enough, set `"requireLogin": false` in `server/config.json`.

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

### The quick way: scan, review, push

```bash
node discover.mjs --json targets.json        # 1. what's on this network?
node deploy-agents.mjs --targets targets.json          # 2. show me the plan
node deploy-agents.mjs --targets targets.json --confirm # 3. do it
```

**Step 1** is a connect scan of your own subnets. It checks a handful of admin
ports (445, 5985, 3389, 22), does reverse DNS, and works out which hosts could
take a push and which need doing by hand:

```
  address          name                      os        open           deploy via
  10.10.5.42       wks-042.corp.local        windows   SMB,WinRM      winrm
  10.10.9.5        web01.corp.local          linux     SSH            ssh
  10.10.1.99       printer.corp.local        unknown   SMB            manual
```

**Step 2** prints the plan and changes nothing. Open `targets.json` and delete
anything that shouldn't get an agent — the scan suggests, you decide.

**Step 3** does the install: PowerShell remoting for Windows, `scp`+`ssh` for
Linux. You'll be prompted for credentials by Windows or ssh themselves; AEGIS
never sees, stores or transmits your password.

> **Scan only what you're responsible for.** A sweep across every host looks
> exactly like the reconnaissance AEGIS is built to detect, and it will light up
> an IDS — correctly. On a corporate network, tell whoever runs it first.

Hosts with no WinRM or SSH still need the manual route below, or your existing
tooling (GPO, Intune, SCCM, Ansible all work — it's a single script with no
dependencies).

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

## Running it on an isolated or air-gapped network

AEGIS is a good fit for a lab, a VM network or an enclave with no internet,
because there is nothing to download at run time — no package install, no CDN,
no telemetry, no licence check. Once the files are on the box it is entirely
self-contained.

**Inside a VM network or isolated segment**, nothing special is needed:

1. Copy the AEGIS folder to the server VM (shared folder, ISO, scp — anything).
2. `start.cmd` / `./start.sh`.
3. Point agents at the address it prints. Guest VMs on the same virtual switch
   reach it exactly like physical hosts.

If the VM has several adapters (NAT plus host-only is the usual setup), setup
lists them all — pick the one on the same network as the machines you want
telemetry from. NAT addresses are usually **not** it.

**With no internet and no Node on the far side**, build a bundle that carries its
own runtime. On a machine that *does* have internet:

```bash
npm run bundle -- --target linux-x64      # or win-x64, darwin-arm64, linux-arm64
```

That writes `dist/aegis-airgap-<target>.tar.gz` — AEGIS, a prebuilt console, a
pinned Node runtime, and a launcher. The Node download is checked against the
SHA-256 published beside it on nodejs.org and the bundler refuses to package a
mismatch. Copy it across on whatever media your enclave allows:

```bash
shasum -a 256 -c aegis-airgap-linux-x64.tar.gz.sha256   # verify after transfer
tar -xzf aegis-airgap-linux-x64.tar.gz
cd aegis-airgap-linux-x64
./run.sh                                                 # Windows: run.cmd
```

No secrets travel in the bundle — tokens are generated on first run on the far
side. Verified end-to-end on a machine with no Node installed at all.

To check nothing is quietly reaching out, pull the network and use it — everything
except the AI Analyst (which calls the Anthropic API by design, and is off unless
you give it a key) works exactly the same.

## Turning on the AI Analyst

Optional, and the only part of AEGIS that talks to the internet. The **server**
holds the key and makes the call, so it is never sent to a browser and never
ends up in the published `ui/index.html`.

Get a key from <https://console.anthropic.com>, then either set it in the
environment before starting the server:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # Windows: $env:ANTHROPIC_API_KEY="sk-ant-..."
```

or put it in `server/config.json` (which is gitignored):

```json
"ai": { "enabled": true, "apiKey": "sk-ant-...", "model": "claude-opus-5" }
```

The env var wins if both are set. Restart the server — the banner then reads
`AI analyst  claude-opus-5` instead of `disabled`. Leave it unset and the AI tab
says so plainly; nothing else is affected.

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
2. **Give everyone their own account.** Accounts are on by default and the first
   one is created from the login screen, so this is likely already done — but a
   team sharing one login is the same as no accounts at all. Add one per person
   from the console; the analyst token stays as break-glass. See the "Enabling
   named accounts" section of `deploy/README-deploy.md`.
3. **Stop matching the published defaults.** Everything about a stock install —
   service name, port, paths, endpoints — is in a public repo. One command
   changes all of it and rotates the tokens:
   ```bash
   node harden.mjs --name svc-telemetry --port 9443 --rotate
   ```
   Then read `docs/DEFENDING-AEGIS.md`, which is the point of doing it: once
   you're not on `aegis`:8787, anything probing for `aegis` on 8787 is not you.
   It covers the five attack stages against AEGIS itself with the detection
   commands for each.

---

## Reference

| Command | Does |
|---|---|
| `npm run discover` | Scan the network for hosts that could take an agent |
| `npm run deploy:agents -- --targets targets.json` | Show the deployment plan (add `--confirm` to run it) |
| `npm run demo` | Seed a realistic incident so you can see the console with data in it |
| `npm run setup` | Regenerate config and rebuild (keeps existing tokens) |
| `node setup.mjs --local` | Bind to this machine only — no agents |
| `node setup.mjs --port 9000` | Use a different port |
| `node setup.mjs --rotate` | Issue new tokens (every agent must re-enrol) |
| `npm start` | Start the server |
| `npm test` | Run the full test suite |
| `npm run bundle -- --target linux-x64` | Build a self-contained air-gap bundle |
| `npm run ai:setup` | Set up the local AI companion (optional — see LOCAL-AI.md) |
| `npm run ai:check` | Report what local model servers AEGIS can find |
| `node harden.mjs --show` | Show the service name and port this deployment uses |
| `node harden.mjs --name X --port N --rotate` | Stop matching the published defaults |

Config lives in `server/config.json`; data in `server/data/`. Back up both — the
data directory holds tickets, cases, evidence and the audit chain.
