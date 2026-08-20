# Installing AEGIS

This guide assumes no prior familiarity with the project. Every step says what
to type or click, and why it matters, in order.

Two things get installed, usually on two different kinds of machine:

1. **The server** - one machine on your network. Hosts the console and
   receives telemetry from the agents. Install this first.
2. **The agent** - each workstation or server you want visibility into. It is
   read-only: it reports what it sees and takes no commands back. Install
   this second, once the server is running.

There are no other dependencies to install. AEGIS does not use `npm install`,
does not download packages at run time, and does not phone home.

---

## Before you start

Pick the machine that will run the server - a spare desktop, a VM, or a
small home-lab box are all fine. Confirm the following on that machine:

| You need | Why |
|---|---|
| One of: [Node.js 18 or newer](https://nodejs.org), **or** Docker Engine 20.10+ with the Compose plugin | These are the only two ways to run the server. Pick one - you do not need both. |
| Network access from this machine to the workstations you want telemetry from | Agents push data to the server; the server never reaches out to them. |
| A few minutes of admin/root access | Only needed once, to open a firewall port. Nothing after that needs elevated rights. |

If you are not sure which install path to pick: the **native install** (Part
2, Option A or B) is simplest on a Windows or macOS desktop you already use
day to day. **Docker** (Part 2, Option C) is simplest on a Linux server, a
NAS, or a Proxmox host, because it keeps AEGIS and everything it needs inside
one container instead of on the bare system.

---

## Part 1 - Get the code onto your machine

Every step from here on assumes you are working inside the folder this
step creates.

### Step 1 - Download the repository

**If you have Git installed** (check by running `git --version`; if that
prints a version number, you have it):

```bash
git clone https://github.com/the404treatment/Aegis.git
cd Aegis
```

*Why:* `git clone` copies the full project, with history, to a new `Aegis`
folder and `cd Aegis` moves your terminal into it, since every command below
needs to run from there.

**If you do not have Git**, download it without the command line instead:

1. Open <https://github.com/the404treatment/Aegis> in a browser.
2. Click the green **Code** button, then **Download ZIP**.
3. Extract the ZIP file anywhere you like (right-click → *Extract All* on
   Windows, double-click on macOS).
4. Open a terminal (PowerShell on Windows, Terminal on macOS/Linux) and move
   into the extracted folder, for example:
   ```powershell
   cd C:\Users\you\Downloads\Aegis-main
   ```

*Why:* this gets you the identical set of files as `git clone`, just without
needing Git installed. The only difference is you will not get automatic
`git pull` upgrades later - re-downloading the ZIP does the same job.

---

## Part 2 - Install and start the server

Choose **one** of the three options below. All three end at the same place:
a running server printing two tokens you will need in Part 4.

### Option A - the one-line installer (fastest)

Installs to your home directory, registers a service that restarts on boot,
and waits until the server actually answers before saying it worked. Skips
Part 1 entirely - you do not need to have downloaded anything first.

**Linux / macOS** - open a terminal and run:
```bash
curl -fsSL https://raw.githubusercontent.com/the404treatment/Aegis/main/install.sh | sh
```

**Windows** - open PowerShell (no admin needed) and run:
```powershell
irm https://raw.githubusercontent.com/the404treatment/Aegis/main/install.ps1 | iex
```

*Why:* this downloads the project and runs its own first-time setup in one
step. It is the fastest path if you trust piping a script into a shell; if
you would rather read the script before it touches your machine, use Option
B instead, which is the exact same result achieved by hand.

Re-running either command later upgrades AEGIS in place and keeps your
existing tokens and data, so already-enrolled agents keep working.

### Option B - run it yourself after cloning (see-before-you-run)

Requires Part 1 to be done first (you should be sitting inside the `Aegis`
folder). Requires [Node.js 18 or newer](https://nodejs.org) to be installed.

**Step 1 - Check your Node version:**
```bash
node --version
```
*Why:* AEGIS needs Node 18+. If this command is not found, install Node
from the link above and come back to this step.

**Step 2 - Start AEGIS:**

- **Windows:** double-click **`start.cmd`** in the `Aegis` folder.
- **Linux / macOS:**
  ```bash
  ./start.sh
  ```

*Why:* on first run this script generates your server config and two
security tokens, builds the console into a single `ui/index.html` file, and
starts the server. On every run after that, it just rebuilds (in case you
changed anything) and starts. When it finishes, it opens the console in your
browser automatically.

Continue to **Part 3** once you see `Starting AEGIS. Press Ctrl-C to stop.`
in the terminal.

### Option C - Docker (recommended for servers, NAS devices, and Proxmox)

Runs AEGIS inside a container instead of directly on the host OS. Useful
when you want the server isolated from everything else on that machine, or
when the host is something you would rather not install Node.js onto
directly (a NAS, a shared Linux box, a Proxmox host).

**Prerequisites:** Docker Engine 20.10 or newer, with the Compose plugin
(the modern `docker compose` command - check with `docker compose version`;
if that fails but `docker-compose version` works, you have the older
standalone tool and can substitute `docker-compose` for `docker compose`
below).

- **Windows / macOS:** install [Docker Desktop](https://www.docker.com/products/docker-desktop/), which includes Compose and, on Windows, sets up WSL2 for you if it is not already present.
- **Linux:** install [Docker Engine](https://docs.docker.com/engine/install/) for your distribution, then the [Compose plugin](https://docs.docker.com/compose/install/linux/).
- **Proxmox:** see the dedicated subsection below - Docker does not run directly on the Proxmox host itself.
- **Synology, QNAP, Unraid, or any other Docker-capable NAS:** any host running Docker Engine 20.10+ with Compose v2 works identically to the Linux steps below. Your NAS's own container-management app can usually import a `docker-compose.yml` directly - point it at `deploy/docker-compose.yml` from the steps below rather than retyping the settings by hand.

**Step 1 - Get the code.** Complete Part 1 above (either `git clone` or the
ZIP download). Docker needs the actual project files on disk to build from;
it does not fetch them for you.

**Step 2 - Run the setup script:**
```bash
node docker-setup.mjs
```
*Why one command:* the several steps a Docker install otherwise needs -
creating `deploy/config.json`, generating two real tokens, setting the
container-internal paths correctly, deciding whether other machines should
be able to reach it, and running `docker compose up -d` - are easy to get
half-right by hand, and a half-right Docker config tends to fail silently
(the container starts, but nothing can connect to it) rather than with a
clear error. This script does all of it in the right order and tells you
what it did at each step.

If you are at an interactive terminal, it asks one question - whether other
machines on your network should be able to reach this server (answer yes if
your agents will run on different machines; no for a single-machine lab, or
if you plan to put a reverse proxy in front). Skip the question entirely
with `node docker-setup.mjs --lan` or `node docker-setup.mjs --local`.

When it finishes, it prints the same "Open the console" address and tokens
a native install prints. Continue to **Part 3**.

<details>
<summary><strong>Prefer to do it by hand? Expand for the manual steps.</strong></summary>

**Step 1 - Move into the deploy folder:**
```bash
cd deploy
```
*Why:* the Docker files live here, and the config file you create next
needs to sit alongside them.

**Step 2 - Create your config file:**
```bash
cp ../server/config.example.json config.json
```
*Why:* the example file is a template with placeholder tokens and paths
meant for a native install. Docker will not create this file for you
automatically, and if it does not exist *before* the next steps, Docker
silently mounts an empty folder in its place instead of failing with a
clear error - so this has to happen first.

**Step 3 - Edit `config.json`** and make three changes:

1. Change `"host": "127.0.0.1"` to `"host": "0.0.0.0"`.
   *Why:* inside a container, `127.0.0.1` means "only reachable from inside
   this container." Docker's port forwarding cannot deliver outside traffic
   to an address like that - the server has to listen on `0.0.0.0` (all
   interfaces) for the container's published port to work at all.

2. Change `"dataDir": "./data"` to `"dataDir": "/app/server/data"`, and
   `"uiDir": "../ui"` to `"uiDir": "/app/ui"`.
   *Why:* these two paths are relative to the folder the process starts in,
   which is different inside the container than on a native install. Left
   as the example's values, the server tries to create its data folder
   outside the one path Docker actually persists, on a filesystem the
   container deliberately makes read-only - it will fail to start.

3. Replace both `CHANGE-ME-generate-with-openssl-rand-base64-24` values with
   real random tokens. Generate two with whichever of these you have
   available:
   ```bash
   openssl rand -base64 24
   ```
   or, in Windows PowerShell:
   ```powershell
   [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Maximum 256 }))
   ```
   Run either command twice - once for `enrollmentToken`, once for
   `analystToken` - and paste each result in.
   *Why:* these are the passwords that let agents and analysts talk to your
   server. The placeholder values are public (they are in this repository),
   so leaving them in place means anyone who has ever read this file could
   reach your server.

**Step 4 - Build and start the container:**
```bash
docker compose up -d
```
*Why:* `-d` runs it in the background. The first run also builds the image,
which takes a minute or two; every run after that reuses the cached build
and starts in seconds.

**Step 5 - Confirm it is running:**
```bash
docker compose logs -f aegis
```
*Why:* you should see the same startup banner a native install prints,
including the "Open the console" address. Press `Ctrl-C` to stop watching
the logs - this does not stop the container.

**Step 6 - Open the console.** By default the container only publishes to
`127.0.0.1`, so browse to `http://127.0.0.1:8787` **from the Docker host
itself**. If agents will run on other machines, create a `deploy/.env` file
containing `AEGIS_BIND=0.0.0.0`, then run `docker compose up -d` again.
*Why a separate file rather than editing `docker-compose.yml` directly:*
`.env` overrides the compose file's defaults without you having to edit
tracked YAML, and it is exactly what `docker-setup.mjs` above writes for
you when you answer "yes" to the network question - so the two paths stay
equivalent. The narrower binding is the safer default for a first run;
widening it is a deliberate choice you make once ready, and you should also
complete the firewall step (Part 5) and, before relying on this in
production, put TLS in front (Part 12).

</details>

**Managing the container afterwards:**

| Command | Does |
|---|---|
| `docker compose logs -f aegis` | Watch the live server output |
| `docker compose down` | Stop and remove the container (your data in `./data` and `config.json` are untouched) |
| `git pull && node docker-setup.mjs` | Upgrade: pull the latest code, rebuild, and restart, keeping your tokens and network choice |

Continue to **Part 3**.

#### Docker on Proxmox VE

Proxmox itself does not run Docker containers - the Proxmox host runs its
own hypervisor stack (LXC and QEMU/KVM), and the Proxmox project
specifically advises against installing Docker directly onto the Proxmox
host OS, since it can interfere with Proxmox's own container and networking
management. You have three supported options, in order of what most
deployments should use:

**Option 1 - Docker inside a VM (most compatible, easiest to reason about).**
Create a small Linux VM (Debian or Ubuntu, 1 vCPU and 1-2 GB of RAM is
plenty), install Docker Engine inside it exactly as you would on any other
Linux box, and follow the Linux steps above unchanged. This gives you full
Docker compatibility with no Proxmox-specific caveats, at the cost of the
normal overhead of a VM.

**Option 2 - skip Docker and install AEGIS natively inside an LXC container
(lowest overhead).** Since AEGIS has no dependencies beyond Node.js, an
unprivileged Debian or Ubuntu LXC container with Node 18+ installed can run
Option B above directly - no Docker involved at all. This is the leanest
option on Proxmox and avoids the Docker-in-LXC questions below entirely.

**Option 3 - Docker inside an LXC container**, for deployments that
specifically want the Docker workflow. This needs nesting enabled on the
container, which Docker requires and which is off by default for security
reasons. From the Proxmox host shell (not inside the container):
```bash
pct set <CTID> --features nesting=1,keyctl=1
pct reboot <CTID>
```
Replace `<CTID>` with your container's ID (visible in the Proxmox web UI).
Then install Docker inside the container as you would on a normal Debian or
Ubuntu host, and follow the Linux steps above. This works well on recent
Proxmox VE (7 and later) with unprivileged containers; if your policies
require a privileged container instead, the same `nesting=1,keyctl=1`
features apply, with the usual privileged-container trade-off of a larger
attack surface against the Proxmox host if the container itself is
compromised.

If you are not sure which to pick: **Option 2** gets you running fastest and
with the least to maintain, since AEGIS was built with exactly that
"nothing extra to install" goal in mind. Reach for Docker (Option 1 or 3)
only if you have a standing reason to prefer it, such as an existing
container-registry workflow.

---

## Part 3 - Sign in

Open the console in a browser (Part 2 tells you the exact address for
whichever install option you used). Accounts are on by default, so it asks
you to sign in, and it comes with two ready-made logins so you are not stuck
at a blank form:

| Role      | Sign in as | Password   | Can do                                   |
|-----------|------------|------------|------------------------------------------|
| **Admin** | `admin`    | `admin123` | Everything, incl. manage users, close tickets |
| **User**  | `user`     | `user123`  | Hunt, log observations, raise tickets    |

Pick a role on the login screen and confirm the password. That is the whole
sign-in.

> **Change these before this touches a network.** The defaults are for a
> local box. In **Admin -> Accounts** you can reset their passwords (which
> retires the default) and add named accounts per person - every ticket,
> case, and evidence upload is recorded against whoever did it, which is the
> point of accounts.

*Prefer named accounts from the start?* Set `"seedDefaultAccounts": false` in
`server/config.json` (or `deploy/config.json` for Docker) before first run,
and the console will instead ask you to create the first account, which
becomes the lead. Set `"requireLogin": false` to turn accounts off entirely
for a single-analyst lab.

---

## Part 4 - Save your tokens

When the server first starts, it prints a numbered walkthrough - open the
console, deploy an agent, watch it appear - ending with the two tokens:

```
   NEXT STEPS

   1. Open the console:  http://127.0.0.1:8787
      Sign in with a ready-made account:
        admin  / admin123   (lead)
        user   / user123    (analyst)

   2. Deploy an agent on a machine you want telemetry from:
        Windows :  powershell -ExecutionPolicy Bypass -File agents\aegis-agent.ps1 -Server http://192.168.1.17:8787 -EnrollmentToken IX1fj-... -Install
        Linux   :  sudo python3 agents/aegis-agent.py --server http://192.168.1.17:8787 --token IX1fj-... --once

   3. Watch hosts appear on the Network Map and the ATT&CK Matrix
      light up as their telemetry lands.

   analyst token (automation / break-glass) : Q9Nae8I5X3mIDFB0gu2qMFhuGX2moNlY
```

Copy both tokens somewhere safe.

- **Analyst token** - signs the console in to the server. You will paste
  this once, in Part 6.
- **Enrollment token** - lets an agent join. Every agent you install in
  Part 8 needs it.

*Why keep these:* both are also stored in `server/config.json` (or
`deploy/config.json` under Docker) and are printed again every time the
server starts, so you have not lost them if you close this window - but
having them handy now saves you a trip back to the server later.

> **The "Agents report to" address is the one that matters for agents.** If
> the server machine has VPN or virtual-machine network adapters, it picks
> the real network address automatically and labels the rest
> `(virtual - probably not this one)`. If an agent cannot connect later, try
> a different address from that list.

---

## Part 5 - Open the firewall

The server listens on every network interface, but the operating system
still blocks the port from outside traffic by default. **Agents cannot
reach the server until this step is done.**

**You may not need to do anything.** Many Linux distributions - Kali, Arch,
most minimal server images and containers - ship with **no active host
firewall at all**, in which case the port is already reachable and there is
nothing to open. `npm run setup` detects which firewall tool this machine
actually has and prints only the command that applies to it, including
telling you when the answer is "none, go test it".

Check before installing anything. From another machine on the network:
```bash
curl -s http://YOUR-SERVER-IP:8787/api/health
```
If that returns JSON, the port is open and you can skip the rest of this
section entirely.

**Windows** - open PowerShell **as Administrator** and run:
```powershell
New-NetFirewallRule -DisplayName "AEGIS 8787" -Direction Inbound `
  -Protocol TCP -LocalPort 8787 -Action Allow -Profile Domain,Private
```
*Why `Domain,Private` and not `Public`:* this deliberately excludes public
networks (coffee-shop Wi-Fi, hotel networks) so the port is not reachable
outside your own trusted network segments.

**Linux** - run only the one matching the firewall you actually have. Check
first with `command -v ufw firewall-cmd nft iptables`:

| If you have | Run |
|---|---|
| `ufw` | `sudo ufw allow 8787/tcp` |
| `firewall-cmd` | `sudo firewall-cmd --add-port=8787/tcp --permanent && sudo firewall-cmd --reload` |
| `nft` | `sudo nft add rule inet filter input tcp dport 8787 accept` |
| `iptables` | `sudo iptables -I INPUT -p tcp --dport 8787 -j ACCEPT` |
| none of them | nothing to do - the port is already reachable |

*Why this matters:* installing a firewall you were not previously running,
purely to open a port in it, leaves the machine more locked down than it was
before and does not help you. The `nft` and `iptables` rules above apply
immediately but do not survive a reboot; making them permanent differs per
distribution.

**Docker installs:** if you are running Docker on Linux, the same commands
above apply to the Docker *host's* firewall - Docker's own iptables rules
handle traffic reaching the container once it arrives at the host.

---

## Part 6 - Connect the console

Open the console in a browser (the "Open the console" address from Part 4),
click the **connection indicator** in the top bar, and paste in:

1. The **server URL** (the "Agents report to" address, if you are
   connecting from a different machine than the server itself).
2. The **analyst token** from Part 4.

*Why:* the console can run entirely offline with no server at all - this
step is what tells it to also show live telemetry from a specific server
rather than only local, browser-stored data.

---

## Part 7 - Deploy agents

### The quick way: scan, review, push

Run these from inside the AEGIS folder on the server machine, or any machine
with network access to your workstations. **Parts 2 to 6 above must be done
first** - these need the enrollment token that `npm run setup` generates, and
will stop and tell you so if it does not exist yet.

```bash
node discover.mjs --json targets.json                    # 1. what's on this network?
node deploy-agents.mjs --targets targets.json            # 2. show me the plan
node deploy-agents.mjs --targets targets.json --confirm  # 3. do it
```

Note that this pushes agents to *other* machines. To get telemetry from the
server machine itself, install an agent on it directly using the one-machine
steps further down.

**Step 1** scans your own subnets for a handful of admin ports (445, 5985,
3389, 22), does reverse DNS, and works out which hosts can take a
push-install and which need doing by hand:

```
  address          name                      os        open           deploy via
  10.10.5.42       wks-042.corp.local        windows   SMB,WinRM      winrm
  10.10.9.5        web01.corp.local          linux     SSH            ssh
  10.10.1.99       printer.corp.local        unknown   SMB            manual
```

*Why:* this is a read-only reconnaissance pass over your own network,
identical in spirit to what a security scanner would do. It writes its
findings to `targets.json` rather than acting on anything.

**Step 2** prints the plan and changes nothing. Open `targets.json` in a
text editor and delete any host that should not get an agent.
*Why a separate review step:* the scan suggests candidates; you decide.
Nothing is installed until Step 3, and Step 3 only touches what is still
listed in the file.

**Step 3** performs the install: PowerShell remoting for Windows hosts,
`scp` + `ssh` for Linux hosts. Windows or ssh will prompt you for
credentials directly - AEGIS never sees, stores, or transmits your
password.

> **Scan only what you are responsible for.** A network sweep looks exactly
> like the reconnaissance AEGIS itself is built to detect, and it will
> correctly trigger an IDS on a network that has one. On a corporate
> network, tell whoever runs it before you scan.

Hosts with no WinRM or SSH still need the manual route below, or your
existing tooling - GPO, Intune, SCCM, and Ansible all work unmodified, since
the agent is a single script with no dependencies. See
`deploy/README-deploy.md` for ready-made examples of each.

### Windows endpoint, one machine at a time

**Step 1 - Copy `agents/aegis-agent.ps1`** to the target machine.
*Why:* the agent is a single self-contained script; nothing else from the
repository needs to travel with it.

**Step 2 - Open an Administrator PowerShell** on that machine.
*Why:* it needs elevation to read the Windows Security event log and to
protect its own credential file from other users on the machine.

**Step 3 - Run it once to confirm it works:**
```powershell
.\aegis-agent.ps1 -Server http://192.168.1.17:8787 -EnrollmentToken <enrollment-token> -Once
```
Replace the address with your own **"Agents report to"** URL from Part 4,
and `<enrollment-token>` with the token from the same place.

**Step 4 - Install it to run continuously:**
```powershell
.\aegis-agent.ps1 -Server http://192.168.1.17:8787 -EnrollmentToken <enrollment-token> -Install
```
*Why two separate runs:* `-Once` proves connectivity and the token work
before you commit to a scheduled task; `-Install` then registers that same
command to run automatically every five minutes.

### Linux / macOS endpoint, one machine at a time

```bash
sudo python3 agents/aegis-agent.py --server http://192.168.1.17:8787 --token <enrollment-token> --once
```
*Why `python3 ...` and not `./aegis-agent.py`:* if you downloaded the ZIP
rather than using `git clone`, the executable bit is not preserved, and
`sudo ./aegis-agent.py` then fails with `command not found` - which reads
like the file is missing even though it is right there. Naming the
interpreter works either way. (To use the `./` form, run
`chmod +x agents/aegis-agent.py` first.)

*Why `sudo`:* reading system logs requires it, mirroring the Windows
elevation requirement above. For continuous collection rather than a single
run, install the systemd service and timer unit files provided in
`deploy/`.

### Rolling out to many machines at once

GPO, Intune, SCCM, and Ansible all work unchanged, since the agent is a
single script with no dependencies to stage alongside it. Worked examples
for each are in `deploy/README-deploy.md`, which also covers code-signing
the PowerShell agent so it can run under an `AllSigned` execution policy
instead of `-ExecutionPolicy Bypass`.

**Installing under a different name**, so an intruder who gets onto an
endpoint cannot spot the agent by searching for "AEGIS": add
`-Name svc-telemetry` (the scheduled task and its `ProgramData` folder both
take that name), or `--agent-name svc-telemetry` on the assisted deployer
from Step 1 above. Uninstall later using that same name. Full step-by-step,
including the Linux equivalent: `docs/RUNBOOK.md`, section 7.

---

## Part 8 - Confirm it is working

1. In the console, open **Network Map**. Enrolled hosts should appear
   automatically within a few minutes.
2. Open **Event Search** and either run `severity:malicious` or just press
   Search with nothing typed, to see everything that has arrived so far.
3. On the server, `server/data/events.ndjson` (or `deploy/data/events.ndjson`
   under Docker) should be growing as telemetry lands.

### If nothing is showing up

In order of how often each one turns out to be the cause:

| Symptom | Likely cause |
|---|---|
| Agent: connection timed out | Firewall rule missing (Part 5), or the wrong "Agents report to" address was used |
| Agent: `must run as Administrator` | Re-open PowerShell as Administrator and try again |
| Agent: 401 / bad enrollment token | The token does not match - copy it again from the server's own output |
| Console shows "needs a server" | The console is not connected yet - redo Part 6 and make sure you pasted the **analyst** token, not the enrollment one |
| Server: `Port 8787 is already in use` | AEGIS is already running elsewhere, or something else on the machine has that port |
| Docker: container starts but nothing can connect | `"host"` in `config.json` is still `127.0.0.1` - see Part 2, Option C, Step 4 |

For anything not covered here, `docs/RUNBOOK.md` is a symptom-indexed guide
to every known failure mode and its fix.

---

## Running it on an isolated or air-gapped network

AEGIS is a good fit for a lab, a VM network, or an enclave with no internet
access, because nothing about it downloads at run time - no package
install, no CDN asset, no telemetry, no licence check. Once the files are on
the box, it is entirely self-contained.

**Inside a VM network or isolated segment**, nothing special is needed
beyond the steps already above:

1. Copy the AEGIS folder onto the server VM by whatever means your network
   allows (shared folder, ISO, `scp`).
2. Run `start.cmd` / `./start.sh` as in Part 2, Option B.
3. Point agents at the address it prints. Guest VMs on the same virtual
   switch reach it exactly as physical hosts would.

**With no internet and no Node.js on the far side**, build a self-contained
bundle on a machine that *does* have internet access:

```bash
npm run bundle -- --target linux-x64      # or win-x64, darwin-arm64, linux-arm64
```

This writes `dist/aegis-airgap-<target>.tar.gz`, containing AEGIS, a
pre-built console, a pinned Node.js runtime, and a launcher. The Node
download is checked against the SHA-256 checksum published by nodejs.org,
and the bundler refuses to package a mismatch. Carry it across on whatever
media your enclave allows, then on the target machine:

```bash
shasum -a 256 -c aegis-airgap-linux-x64.tar.gz.sha256   # verify after transfer
tar -xzf aegis-airgap-linux-x64.tar.gz
cd aegis-airgap-linux-x64
./run.sh                                                 # Windows: run.cmd
```

No secrets travel inside the bundle - tokens are generated fresh on first
run on the receiving side.

---

## Turning on the local AI (optional)

Entirely local - there is no hosted API and no key anywhere in AEGIS.
Install a local inference server on the AEGIS host first (Ollama is the
simplest option), then, **from inside the AEGIS folder on that same host**
(this writes into that install's `server/config.json`, the same as `npm
start` needs to run from there), run:

```bash
npm run ai:setup
```

Running it from anywhere else fails immediately with npm's own `ENOENT:
Could not read package.json` - that means "wrong folder," not "broken."

*Why this order:* the setup script looks for an inference server already
running on the machine, downloads a model for it if none is present, writes
the configuration, and verifies the whole path with a real test question -
so it needs something to find before it can wire anything in.

You get two features from this: the **AI Analyst** tab for questions you
type, and the **Companion**, which reads telemetry as it lands and comments
on anything suspicious without being asked. Full guide, including model
choice and air-gapped setup: **[LOCAL-AI.md](LOCAL-AI.md)**.

---

## Before you rely on this

The defaults above are tuned for *getting running quickly*, not for a
hostile network. Do these three things before treating AEGIS as more than a
lab setup:

**1. Turn on TLS.** The server speaks plain HTTP by design - tokens and
telemetry cross the network in the clear otherwise. Put a TLS reverse proxy
in front of it; a ready-made `deploy/Caddyfile` is included for this.

**2. Give everyone their own account.** Accounts are on by default and the
first one was created from the login screen in Part 3, so this is likely
already partly done - but a whole team sharing one login is functionally the
same as having no accounts at all. Add one person at a time from the
console; the analyst token remains available as a break-glass credential.
See "Enabling named accounts" in `deploy/README-deploy.md`.

**3. Stop matching the published defaults.** The service name, port, file
paths, and API endpoints of a stock install are all public, because this
repository is public. One command changes all of it and rotates both
tokens at once:
```bash
node harden.mjs --name svc-telemetry --port 9443 --rotate
```
Then read `docs/DEFENDING-AEGIS.md`, which is the actual point of doing
this: once you are no longer reachable as `aegis` on port `8787`, anything
still probing for exactly that combination is not you - which is a
detection you could not write before changing the defaults. That document
covers the five realistic attack stages against AEGIS itself, with the
detection commands for each.

---

## Command reference

| Command | Does |
|---|---|
| `npm run discover` | Scan the network for hosts that could take an agent |
| `npm run deploy:agents -- --targets targets.json` | Show the deployment plan (add `--confirm` to run it) |
| `npm run demo` | Seed a realistic incident so you can explore the console with data in it |
| `npm run setup` | Regenerate config and rebuild (keeps existing tokens) |
| `node setup.mjs --local` | Bind to this machine only - no agents |
| `node setup.mjs --port 9000` | Use a different port |
| `node setup.mjs --rotate` | Issue new tokens (every agent must re-enrol) |
| `npm start` | Start the server (native install) |
| `npm test` | Run the full test suite |
| `npm run bundle -- --target linux-x64` | Build a self-contained air-gap bundle |
| `npm run ai:setup` | Set up the local AI companion (optional - see LOCAL-AI.md) |
| `npm run ai:check` | Report what local model servers AEGIS can find |
| `node harden.mjs --show` | Show the service name and port this deployment currently uses |
| `node harden.mjs --name X --port N --rotate` | Stop matching the published defaults |
| `node docker-setup.mjs` | Set up and start the server (Docker install) - config, tokens, and `docker compose up -d` in one step |
| `node docker-setup.mjs --lan` / `--local` | Same, without the network-exposure prompt |
| `node docker-setup.mjs --rotate` | Issue new tokens (every agent must re-enrol) |
| `docker compose logs -f aegis` | Watch the live server output (Docker install), run from `deploy/` |
| `docker compose down` | Stop the container without deleting its data |
| `git pull && node docker-setup.mjs` | Upgrade a Docker install to the latest code |

Config lives in `server/config.json` (native) or `deploy/config.json`
(Docker); data lives in `server/data/` or `deploy/data/` respectively. Back
up both - the data directory holds tickets, cases, evidence, and the audit
chain.
