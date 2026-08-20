# AEGIS runbook

For whoever runs the server. Analysts have the guided tour in the app (`?`);
this is the other half - every failure this thing can have, what it looks like,
and how to fix it.

Each entry is the same shape: **Symptom → What it means → Check → Fix**. Run the
checks in order; they are cheapest-first.

> **Two things before anything else.**
> 1. `server/config.json` holds your tokens and `server/data/` holds every
>    ticket, case, evidence file and the audit chain. **Back both up.** Almost
>    everything below is recoverable; losing `server/data/` is not.
> 2. Nothing here needs the internet. If a fix tells you to download something,
>    you are reading the wrong document.

---

## Index

| Symptom | Section |
|---|---|
| Won't start at all | [1.1](#11-the-server-will-not-start) |
| `Port 8787 is already in use` | [1.2](#12-port-already-in-use) |
| Died after a reboot | [1.3](#13-it-does-not-come-back-after-a-reboot) |
| Windows: script "cannot be loaded" | [1.4](#14-windows-blocks-the-scripts) |
| Console says "needs a server" | [2.1](#21-the-console-will-not-connect) |
| Login screen won't take my password | [2.2](#22-nobody-can-sign-in) |
| **Locked out entirely** | [2.3](#23-locked-out-no-lead-account-works) |
| Console connects but nothing updates | [2.4](#24-connected-but-nothing-is-live) |
| Agent won't enrol | [3.1](#31-an-agent-will-not-enrol) |
| `hostname required` on enrol | [3.2](#32-hostname-required-when-the-agent-has-one) |
| Agent enrolled but sends nothing | [3.3](#33-enrolled-but-no-events-arrive) |
| An agent went quiet | [3.4](#34-an-agent-has-gone-quiet) |
| Duplicate hosts on the map | [3.5](#35-the-same-host-appears-twice) |
| **Audit chain does not verify** | [4.1](#41-the-audit-chain-does-not-verify) |
| Evidence file missing | [4.2](#42-evidence-is-missing-or-will-not-open) |
| Disk filling up | [4.3](#43-the-disk-is-filling-up) |
| Console slow with lots of events | [4.4](#44-the-console-has-got-slow) |
| No local model / AI greyed out | [5.1](#51-the-ai-is-greyed-out) |
| AI answers are slow or time out | [5.2](#52-the-model-is-too-slow-or-times-out) |
| Companion never says anything | [5.3](#53-the-companion-never-speaks) |
| Upgrade broke something | [6.1](#61-an-upgrade-broke-something) |
| Suspected compromise of AEGIS | [6.2](#62-you-think-aegis-itself-has-been-attacked) |
| Someone left the team | [6.3](#63-offboarding-someone) |
| **Stop an attacker finding/killing the server** | [7](#7-making-the-server-harder-to-find-and-kill) |
| **Rename the agents so they can't be spotted** | [7a-agents](#7a-agents-rename-the-agents-too) |

---

## 1. Starting up

### 1.1 The server will not start

**Check** - run it in the foreground so you can see the error:

```bash
node server/aegis-server.mjs --config ./server/config.json
```

| What it prints | Fix |
|---|---|
| `SyntaxError` / `Unexpected token` in config.json | The config is malformed. See below. |
| `Cannot find module` | Incomplete checkout. Re-run the installer, or `git pull`. |
| Nothing, exits silently | Node is too old. `node -v` must be ≥ 18. |
| `EACCES` | You asked for a port under 1024. Use one above it. |

**Fix a broken config** - it is only JSON, and losing it costs you your tokens
(every agent re-enrols), so try repairing before regenerating:

```bash
node -e "JSON.parse(require('fs').readFileSync('server/config.json','utf8'))"   # points at the bad line
```

Beyond repair? `node setup.mjs` writes a fresh one, keeping any tokens it can
still read. If it cannot, every agent must be re-enrolled with the new token.

### 1.2 Port already in use

The server tells you this deliberately rather than dying with a stack trace.
Usually it is **already running**.

```bash
# Linux/macOS
ss -ltnp 'sport = :8787'          # or: lsof -i :8787
# Windows
Get-NetTCPConnection -LocalPort 8787 | Select-Object OwningProcess
Get-Process -Id (Get-NetTCPConnection -LocalPort 8787).OwningProcess
```

If it is AEGIS, you are done - open the console. If it is something else, move
AEGIS: `node harden.mjs --port 9443` (and see [3.1](#31-an-agent-will-not-enrol),
because agents hold the old address).

### 1.3 It does not come back after a reboot

**Linux** - the usual cause is lingering. Without it a *user* service stops when
you log out, which for a telemetry collector is exactly wrong:

```bash
systemctl --user status aegis          # or your renamed service
loginctl show-user "$(id -un)" | grep Linger
sudo loginctl enable-linger "$(id -un)"    # the fix
systemctl --user enable --now aegis
```

**macOS**

```bash
launchctl list | grep aegis
launchctl load ~/Library/LaunchAgents/com.aegis.server.plist
```

**Windows** - the task is per-user and only fires at *logon*, so a rebooted
server sitting at the login screen has not started it:

```powershell
Get-ScheduledTask -TaskName 'AEGIS Server' | Select-Object State
Start-ScheduledTask -TaskName 'AEGIS Server'
```

For a machine that must run headless, change the trigger to *At startup* and set
the task to run whether the user is logged on or not. That needs a stored
credential - a decision to make deliberately, not by default.

### 1.4 Windows blocks the scripts

> `... cannot be loaded because running scripts is disabled on this system`

```powershell
Get-ExecutionPolicy -List
# per-process, no permanent change:
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

For a fleet, code-sign the agent instead of loosening policy - see
`deploy/README-deploy.md`.

---

## 2. The console

### 2.1 The console will not connect

Work outwards from the server.

```bash
# 1. Is it alive at all, from the server itself?
curl -fsS http://127.0.0.1:8787/api/health && echo OK

# 2. Is it listening on the network, not just loopback?
#    "127.0.0.1:8787" here is the bug - agents and other machines cannot reach it.
ss -ltn | grep 8787
```

If it is bound to loopback, `node setup.mjs` (without `--local`) rebinds it to
all interfaces.

```bash
# 3. From the analyst's machine
curl -fsS http://<server-ip>:8787/api/health
```

Fails from there but works locally → **firewall**. This is the single most
common cause:

```powershell
New-NetFirewallRule -DisplayName "AEGIS 8787" -Direction Inbound `
  -Protocol TCP -LocalPort 8787 -Action Allow -Profile Domain,Private
```

On Linux, find out what you are actually running before opening anything -
`sudo ufw allow` is useless advice on a host with no ufw, and installing one
to open a port in it leaves the machine more restricted than it started:

```bash
command -v ufw firewall-cmd nft iptables
```

| Reported | Run |
|---|---|
| `ufw` | `sudo ufw allow 8787/tcp` |
| `firewall-cmd` | `sudo firewall-cmd --add-port=8787/tcp --permanent && sudo firewall-cmd --reload` |
| `nft` | `sudo nft add rule inet filter input tcp dport 8787 accept` |
| `iptables` | `sudo iptables -I INPUT -p tcp --dport 8787 -j ACCEPT` |
| nothing | no host firewall is installed - the block is elsewhere (see below) |

If nothing is reported, stop looking at the host firewall: check that the
server is bound to `0.0.0.0` rather than `127.0.0.1` (`grep host server/config.json`),
and then look at anything between the two machines - hypervisor networking,
VLAN segmentation, or a cloud security group.

### 2.2 Nobody can sign in

```bash
curl -s http://127.0.0.1:8787/api/auth/mode
```

| Response | Meaning |
|---|---|
| `"needsSetup":true` | No accounts exist. The login screen offers to **create the first one**. Use it. |
| `"requireLogin":false` | Accounts are off; the console wants the **analyst token**, not a password. |
| `"accounts":N` with N ≥ 1 | Accounts exist - this is a wrong password, or a lockout. |

Five failed attempts locks that name briefly. Wait it out; the audit log records
every attempt:

```bash
grep auth.login.failed server/data/audit.ndjson | tail -20
```

### 2.3 Locked out, no lead account works

**This is why the analyst token exists.** It is break-glass and always works,
regardless of accounts.

```bash
grep analystToken server/config.json
```

Sign in via the connection indicator → *Use an analyst token*. Then open
**Admin** and reset the password. If the token itself is lost:

```bash
node harden.mjs --rotate     # new analyst + enrollment tokens, printed
```

Rotating means **every agent must re-enrol**. Named accounts are unaffected.

### 2.4 Connected but nothing is live

The badge says connected, but events, presence and chat never move - the SSE
stream is broken rather than the API.

```bash
# Should hang open and dribble keepalives. If it returns instantly, something
# in the middle is buffering it.
curl -N "http://127.0.0.1:8787/api/stream?token=<analyst-token>"
```

Almost always a **reverse proxy buffering the event stream**. AEGIS sends
`X-Accel-Buffering: no`; if yours ignores it:

- nginx: `proxy_buffering off;` and `proxy_read_timeout 3600s;`
- Apache: `SetEnv proxy-sendchunked 1`, disable `mod_deflate` on this path
- Caddy: works out of the box - see `deploy/Caddyfile`

Also check the browser console for a mixed-content block: an `https://` console
cannot open an `http://` stream.

---

## 3. Agents

### 3.1 An agent will not enrol

```powershell
# Run one cycle in the foreground and read the error
.\aegis-agent.ps1 -Server http://<server-ip>:8787 -EnrollmentToken <token> -Once
```

| Error | Cause |
|---|---|
| connection timed out | Firewall, or wrong address. Re-check [2.1](#21-the-console-will-not-connect). |
| `401 bad enrollment token` | Token mismatch - copy it again from the server banner. Rotated recently? |
| `must run as Administrator` | Elevation. The Security log is not readable without it. |
| `hostname required` | See [3.2](#32-hostname-required-when-the-agent-has-one). |

The address matters: use the **"Agents report to"** line the server printed, not
`127.0.0.1`. If the server has VPN or VM adapters, setup labels the virtual ones
- pick the one on the same network as your endpoints.

### 3.2 `hostname required` when the agent has one

The server constrains hostnames to letters, digits, dot, dash, underscore,
colon, slash, at and plus - deliberately, because hostnames get rendered into
the console and a quote or bracket in one is an injection attempt, not a name
(see `docs/DEFENDING-AEGIS.md`).

A machine whose name is entirely outside that set is rejected rather than
silently mangled.

```powershell
$env:COMPUTERNAME     # if this contains something exotic, that is why
```

Rename the host, or pass an explicit clean name to the agent.

### 3.3 Enrolled but no events arrive

It appears on the map, `eventCount` stays 0.

```bash
# Is anything landing at all?
tail -f server/data/events.ndjson
```

```powershell
# On the endpoint: is the agent actually running on a schedule?
Get-ScheduledTask -TaskName 'AEGIS Agent' | Select-Object State, LastRunTime, LastTaskResult
```

`LastTaskResult` non-zero → run it with `-Once` in the foreground and read the
error. Otherwise the usual cause is **the logs are empty because auditing is
off**. The console tells you which: Network Map → map menu → **Logging posture**
lists hosts missing Sysmon, 4104 and 5145.

Turn on what is missing (command-line auditing in particular - 4688 without
`CommandLine` is nearly useless), then wait one collection cycle.

### 3.4 An agent has gone quiet

Shown as `quiet` on the dashboard's Agent health card after `staleAfter`
seconds (default 180).

**Treat this as a finding, not a fault.** An endpoint that stops reporting is
either broken or being silenced, and the second is what you bought this for.
`docs/DEFENDING-AEGIS.md` §5 covers it. Rule out the boring causes first -
machine off, agent task disabled, network - then investigate.

The agent is built to make the boring causes rare: it runs from a scheduled
task that repeats on the interval and also refires at boot and at logon, so a
killed process or a reboot self-heals (§7b). A host that is still quiet after
that has had its **task** stopped, not just its process, which is the version
worth looking at.

**Confirming the agent is alive.** Its own scheduled runs are reported as
telemetry, flagged as collector self-activity. In Event Search, untick **Hide
agent activity** and you will see them, labelled `AEGIS`, one per interval per
host. A host producing those is reporting; a host absent from them is not. They
are hidden by default and excluded from the dashboard and the map so they are
not mistaken for activity on the host.

### 3.5 The same host appears twice

Re-enrolment matches on hostname, so a machine that was **renamed** enrols as a
new agent and the old record lingers.

Delete the stale one in the console (Network Map → node → remove), or:

```bash
curl -X DELETE http://127.0.0.1:8787/api/agents/<agent-id> \
  -H "Authorization: Bearer <analyst-token>"
```

Its events stay in the lake; only the agent record goes.

---

## 4. Data and integrity

### 4.1 The audit chain does not verify

**Stop and read this one properly.** The console shows a red banner on the
activity feed and Admin shows `BROKEN`.

```bash
curl -s http://127.0.0.1:8787/api/activity \
  -H "Authorization: Bearer <analyst-token>" | grep -o '"intact":[a-z]*'
```

It means `server/data/audit.ndjson` has been **edited, truncated or reordered
since it was written**. The chain covers the actor, action, target, timestamp
and the event body, so any of those changing breaks it.

There are only three explanations, in order of likelihood:

1. **Disk or process damage** - an unclean shutdown mid-write, or a full disk.
   Check `dmesg` / Event Viewer around the time it broke.
2. **Someone edited it by hand.** Restoring a backup *over* a live chain does
   this too.
3. **Someone is covering their tracks.** This is the case the feature exists for.

Do not "fix" it by deleting the file - that destroys the evidence and the record
in one move. Instead:

```bash
cp server/data/audit.ndjson /safe/place/audit-$(date +%F-%H%M).ndjson   # preserve it first
```

Then find where it breaks:

```bash
npm run verify:audit
```

That walks the chain row by row and reports the **first** bad row, which property
stopped matching, and the row's contents - so you can say *"someone changed this
account's role to lead at 00:42"* rather than *"the chain is broken"*:

```
  BROKEN at row 1 (seq 1, 2026-08-19T00:42:10.063Z)

    · its stored body no longer hashes to the recorded dataHash - the body was edited

    actorId    u_8YkXIu-F
    action     user.create
    data       {"name":"Sarah Okafor","role":"lead"}

  Rows 0–0 are still provably intact (1 of 6).
```

Everything **before** that row is still provably intact and can be relied on.
Treat anything from it onward as unverified until explained.

It also reads a backup, which is how you find out whether the copy you kept is
any better than the live one:

```bash
node verify-audit.mjs --file /backups/audit-2026-08-19.ndjson
```

Exit codes suit cron: `0` intact, `1` broken, `2` unreadable. Run it on a
schedule and alert on anything non-zero - see
`docs/DEFENDING-AEGIS.md` for the rest of that monitoring.

**Prevention:** ship `audit.ndjson` off the box as it is written - Splunk HEC,
or `rsyslog`. Someone who owns the server can edit the local copy; they cannot
edit the one that already left.

### 4.2 Evidence is missing or will not open

Evidence is **content-addressed**: the filename *is* the SHA-256 of the bytes.

```bash
cd server/data/evidence
for f in *; do
  [ "$(sha256sum "$f" | cut -d' ' -f1)" = "${f%%.*}" ] || echo "MISMATCH: $f"
done
```

Any mismatch means the file was swapped underneath the case - handle it as
[4.1](#41-the-audit-chain-does-not-verify). A file listed on a case but absent
from disk is a restore that missed the evidence directory: it is not in
`cases.json`, it is a separate tree.

### 4.3 The disk is filling up

`events.ndjson` is append-only and grows with telemetry. The server refuses to
append past `maxEventFileMB` (default 256) rather than filling the disk.

```bash
du -sh server/data/*
```

Rotate it - the file is the archive, the in-memory ring is what the console
reads, so rotating loses nothing the UI is using:

```bash
systemctl --user stop aegis
mv server/data/events.ndjson server/data/events-$(date +%F).ndjson
gzip server/data/events-*.ndjson
systemctl --user start aegis
```

For real retention, send events to Splunk (`splunk.enabled`) and treat AEGIS's
copy as a buffer.

### 4.4 The console has got slow

The console keeps the last 500 events client-side and the server 5000, so
slowness is usually **the map, not the data**: several hundred nodes with
animation on will do it.

- Fit/zoom out rather than rendering everything at 100%
- Hide zones you are not working in
- On the dashboard, drop cards you do not read

If it is genuinely the event volume, narrow with Event Search rather than
scrolling - that query runs server-side.

---

## 5. The local AI

Optional. Everything else works without it. Full setup: `LOCAL-AI.md`.

### 5.1 The AI is greyed out

```bash
npm run ai:check        # what AEGIS can find
```

Nothing found → no inference server is running on the **AEGIS host** (not your
laptop). Start Ollama/LM Studio/llama.cpp and re-run `npm run ai:setup`.

Started it *after* AEGIS? Nothing needs restarting - reconnect the console, or:

```bash
curl -s http://127.0.0.1:8787/api/llm/detect -H "Authorization: Bearer <analyst-token>"
```

### 5.2 The model is too slow or times out

> `the local model took too long - a first request loads the weights`

The **first** request after a cold start loads several GB and can take a minute.
That is normal once.

Every request slow → the model is too big for the RAM and is swapping:

```bash
npm run ai:setup -- --model hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
```

Rough guide: 3B/Q4 ≈ 4 GB, 7B/Q4 ≈ 8 GB, 14B/Q4 ≈ 12 GB. Exceed what you have
and it will technically work while being useless.

### 5.3 The Companion never speaks

It only wakes for **suspicious or malicious** events - a quiet estate means a
quiet companion, which is correct.

```bash
grep -c '"severity":"malicious"' server/data/events.ndjson
grep '"watch"' server/config.json          # must not be false
```

Both fine and still silent → check the server log for `[companion]` lines; a
model that errors is logged there rather than spamming the incident room.

---

## 6. Change and incident

### 6.1 An upgrade broke something

The installer is idempotent and keeps your data and tokens, so rolling back is
just checking out the previous commit:

```bash
cd ~/.aegis
git log --oneline -10
git checkout <last-good-sha>
npm run build
systemctl --user restart aegis
```

`server/data/` and `server/config.json` are untouched by this - they are
gitignored, which is exactly why.

Back on your feet? `git checkout main` and report what broke.

### 6.2 You think AEGIS itself has been attacked

`docs/DEFENDING-AEGIS.md` is the full playbook - five attack stages with
detections. Immediately:

1. **Preserve the record.** Copy `server/data/` somewhere the suspect does not
   control. Do this before anything else.
2. **Verify the chain** ([4.1](#41-the-audit-chain-does-not-verify)). Whether it
   still verifies changes everything that follows.
3. **Rotate and evict.** `node harden.mjs --rotate` kills the shared token;
   deleting an account kills its sessions immediately.
4. **Move.** `node harden.mjs --name <dull-name> --port <not-8787>`. Anything
   still probing the old name afterwards is not you - which is a detection you
   could not write before.

### 6.3 Offboarding someone

Admin → their row → **remove**. That revokes their live sessions in the same
action; there is no separate step and no window where the account is deleted but
the session still works.

Everything they did stays in the audit chain and the case files. You are
removing the account, not the record - and you should not be able to remove the
record.

---

## 7. Making the server harder to find and kill

An attacker who has moved onto the AEGIS host and understands what it is will
try to **stop it** - silence looks like calm, and a dead collector reports
nothing about what they do next.

Read this whole section before you act on it, because the framing matters. None
of the steps below stop someone with root/admin who is *looking* - the server
listens on a port, has a working directory, and has a service definition, and any
of those gives it away. What they do is:

- make it walk past a casual sweep of the process and service lists,
- make killing the process pointless, because it restarts,
- and make killing it **loud**, because the record already left the box and its
  silence is alarmed on.

That last pair is the actual protection. Hiding buys minutes; restart-plus-alarm
is what turns "they killed it" from a gap in your telemetry into a page. Do them
in that order of priority - the hiding is the least important part, even though
it is the part that was asked for.

### 7a. Stop it announcing itself - name

Everything about a stock install is public because the project is. One command
changes the **service name, the port, and the tokens** together:

```bash
node harden.mjs --name svc-telemetry --port 9443 --rotate
node harden.mjs --show          # confirm what you are now running as
```

That renames the systemd unit / launchd agent / Scheduled Task, so it no longer
reads `aegis` in a service listing. It also drives the **process name**: on the
next restart the process reports itself as `svc-telemetry` in `ps` / `top` /
Task Manager instead of `node .../aegis-server.mjs`, so someone grepping the
process list for `aegis` or `node` finds nothing useful.

Pick a name that belongs on that machine - `svc-telemetry`, `health-agent`,
`node-metrics`. A name that is obviously hiding (`totally-not-aegis`) is worse
than none.

To set only the process name without touching the service, put it in
`server/config.json` and restart:

```json
"procName": "svc-telemetry"
```

Confirm it took, on the box:

```bash
# Linux - the renamed process, no mention of aegis
ps -eo pid,comm,args | grep -i telemetry
# Windows PowerShell - the window/title, plus the owning command line
Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
  Select-Object ProcessId, CommandLine
```

> **The command line still shows the path.** `process.title` changes the process
> *name*, not the full argument list, and on Windows the `CommandLine` in WMI
> still shows `...aegis-server.mjs`. To hide that too, install AEGIS into a
> directory that does not say "aegis" either - `~/.local/svc-telemetry` rather
> than `~/.aegis`. `AEGIS_DIR=~/.local/svc-telemetry` on the installer does this
> from the start; moving an existing install means re-running the installer
> there and re-pointing the service. This is the point of diminishing returns -
> spend the effort on 7b and 7c instead.

### 7a-agents. Rename the agents too

The server is one host; the agents are on every endpoint, and an intruder who
lands on a workstation can find and kill an agent called **AEGIS Agent** just as
easily as one on the server. The agent installs under a name you choose.

**One endpoint, by hand** - on the machine, in an Administrator PowerShell:

```powershell
# Install under a dull name. The scheduled task AND the C:\ProgramData folder
# both take this name, so nothing on the box says "AEGIS".
.\aegis-agent.ps1 -Server http://<server>:<port> -EnrollmentToken <token> -Name svc-telemetry -Install
```

Confirm it is there and does not name AEGIS:

```powershell
Get-ScheduledTask -TaskName svc-telemetry        # your name, not "AEGIS Agent"
Get-ChildItem C:\ProgramData\svc-telemetry       # state folder, likewise
```

> **The name is how the agent finds itself again.** Whatever you install with,
> you must **uninstall and re-point with the same `-Name`** - it is how the
> agent locates its own task and folder. Write down what you used.
> ```powershell
> .\aegis-agent.ps1 -Server http://<server>:<port> -Name svc-telemetry -Uninstall
> ```
> Forgotten which name a box uses? List the tasks that run PowerShell against a
> ProgramData script and read it off:
> ```powershell
> Get-ScheduledTask | Where-Object { $_.Actions.Arguments -match 'ProgramData' } |
>   Select-Object TaskName
> ```

**A whole fleet at once** - the assisted deployer takes the name and passes it
through to every host it touches (Windows/WinRM only):

```bash
node deploy-agents.mjs --targets targets.json --agent-name svc-telemetry           # review the plan
node deploy-agents.mjs --targets targets.json --agent-name svc-telemetry --confirm # do it
```

Use the **same** `--agent-name` every time you touch that fleet, for the same
reason as above.

**Linux/macOS endpoints** - the Python agent does not install its own service;
it runs from a systemd unit and timer (`deploy/`). Renaming it is renaming those
unit files:

```bash
# copy the templates under a dull name, then
sudo systemctl daemon-reload
sudo systemctl enable --now svc-telemetry.timer
sudo systemctl disable --now aegis.timer        # remove the old one
```

The agent binary itself can be copied to any path and filename - it holds no
name of its own; only the unit that runs it does.

> ‼️ **Pick the name once, write it down, use it everywhere.** A fleet where
> every box has a different agent name is one you cannot uninstall or upgrade in
> bulk. Dull-but-consistent beats clever-but-forgotten.

### 7b. Make killing it pointless - restart

**The agents.** The Windows agent installs with three triggers, not one: it
repeats on the collection interval, and it also fires **at startup** and **at
logon**. Killing the PowerShell process does nothing, because the next
repetition runs within the interval; a reboot or a logoff does nothing, because
the startup and logon triggers re-arm it. It also carries a restart-on-failure
count, so a crashed cycle relaunches. An attacker therefore has to disable the
whole scheduled task, which is a louder and logged action, rather than wait for
a gap. Confirm on an endpoint:

```powershell
$t = Get-ScheduledTask -TaskName svc-telemetry
$t.Triggers.CimClass.CimClassName      # expect a repetition trigger plus BootTrigger and LogonTrigger
$t.Settings.RestartCount               # expect 3
```

The Linux agent runs from a systemd timer, which is itself the persistence: the
timer refires on schedule regardless of what happened to the last run. Add
`Restart=on-failure` to the service unit for the crashed-cycle case.

**The server.** The installers register it to restart on failure
(`Restart=on-failure` / `KeepAlive` / task restart count), so `kill <pid>` just
starts it again a few seconds later. Confirm yours does:

```bash
systemctl --user show svc-telemetry -p Restart          # want: on-failure
launchctl print gui/$(id -u)/com.svc-telemetry.server | grep -i keepalive
```
```powershell
(Get-ScheduledTask -TaskName 'svc-telemetry').Settings.RestartCount   # want: >= 1
```

To *stop* it, an attacker now has to disable the service, not kill the process -
and disabling a service is a louder, logged action you can alert on (7c, and
`docs/DEFENDING-AEGIS.md` §5).

Two things make this stronger:

- **Run it as a dedicated, low-privilege user** that owns nothing else. Then only
  that user or root can stop the service, which shrinks who can silence it to the
  people who could already do anything.
- **Do not leave `harden.mjs`, `setup.mjs` and the repo world-readable** next to
  a running install. They document exactly what the service is. `chmod 700` the
  install directory.

### 7c. Make killing it loud - the part that actually protects you

Hiding and restarting buy time. This is the control.

1. **Ship the audit chain off the box as it is written** - Splunk HEC
   (`splunk.enabled`) or `rsyslog` on `server/data/audit.ndjson`. Someone who
   owns the host can stop the service and edit the local record; they cannot edit
   the copy that already left. Without this, killing the server and wiping
   `server/data/` erases both the telemetry *and* the proof it existed.

2. **Alert on its silence, not its presence.** A collector that stops reporting
   is the signal. From another machine:

   ```bash
   # cron, every 5 min, on a DIFFERENT host - if AEGIS is the only thing
   # watching AEGIS, it cannot tell you it is gone.
   curl -fsS --max-time 10 http://<aegis-host>:9443/api/health >/dev/null \
     || notify-your-oncall "AEGIS health check failed"
   ```

   And alert on the agents going quiet in bulk - `docs/DEFENDING-AEGIS.md` §5 has
   the query. An attacker who silences the whole fleet at once is the loudest
   possible event, if you are listening for absence.

3. **Verify the record still verifies**, on a schedule, from off-box:

   ```bash
   # note the bare -- : npm keeps --quiet for itself otherwise
   node verify-audit.mjs --quiet || notify-your-oncall "AEGIS audit chain broken"
   ```

If you do only one thing in this section, do 7c.1 - get the audit log off the
box. Renaming the process is the part that was asked for; shipping the record
somewhere they do not control is the part that matters when they succeed.

---

## Quick reference

```bash
npm run verify:audit                      # is the record still trustworthy?
node harden.mjs --show                    # what am I running as?
node harden.mjs --rotate                  # new tokens (agents must re-enrol)
node setup.mjs                            # regenerate config + rebuild, keep tokens
npm run ai:check                          # what local models can AEGIS see?
npm test                                  # full suite - run after any local change
curl -s localhost:8787/api/health         # is it alive?
curl -s localhost:8787/api/auth/mode      # accounts on? any created?
```

| File | What it is | Back up? |
|---|---|---|
| `server/config.json` | Tokens, port, AI settings | **Yes** |
| `server/data/` | Tickets, cases, evidence, audit chain | **Yes - this is the irreplaceable one** |
| `server/service.json` | Local service name/port | Nice to have |
| `ui/index.html` | Build artifact | No - rebuilt by `npm run build` |
