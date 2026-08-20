# Defending AEGIS

AEGIS is a target. It holds the incident record - every ticket, every case, the
evidence, and the hash chain the formal report is signed against. An adversary
who reaches it can read your investigation into them, and if they get far enough,
edit it.

This is the threat model for the platform itself: what an attack on AEGIS looks
like at each stage, how to detect it, and what to run.

Everything here uses telemetry AEGIS already collects, or a shell command on the
server. Nothing needs a new product.

> **First, change the defaults.** Everything about a stock AEGIS install is
> public - service name, port, paths, endpoints - because this repo is public.
> ```bash
> node harden.mjs --show                                      # what am I running as?
> node harden.mjs --name svc-telemetry --port 9443 --rotate   # stop matching the docs
> ```
> This is a delaying tactic, not a control. Its real value is below: once you are
> not on `aegis`:8787, **anything probing for `aegis` on 8787 is not you**, and
> that is a high-signal alert you could not write before.

---

## Stage 1 - Discovery

*They are looking for the SOC platform.*

An attacker on the network sweeps for admin surfaces. AEGIS looks like a web app
on an odd port with an unauthenticated `/api/health` and `/api/auth/mode`.

**What it looks like**

- Connections to the AEGIS port from hosts that are not analyst workstations.
- `/api/health` or `/api/auth/mode` hit repeatedly with no login following.
- Requests to the *old* name or port after you have hardened.

**Detect**

```bash
# Who is talking to AEGIS, ranked. Analysts are a short list; anything else is a question.
ss -tn state established "( sport = :9443 )" | awk 'NR>1{split($4,a,":"); print a[1]}' | sort | uniq -c | sort -rn
```

```spl
* Splunk: unauthenticated probing - health checks with no session behind them
index=aegis sourcetype=aegis:access uri_path IN ("/api/health","/api/auth/mode")
| stats count dc(uri_path) as paths by src_ip
| where count > 20
| lookup analyst_workstations ip as src_ip OUTPUT hostname
| where isnull(hostname)
```

The high-signal one, only available once you have hardened:

```spl
* Anything asking for the published defaults is reading the docs, not working here
index=network (dest_port=8787 OR uri_path="/api/enroll") NOT src_ip IN (<your analysts>)
| stats count values(dest_ip) by src_ip
```

**Reduce the surface**

- Bind to the SOC VLAN only, not `0.0.0.0`.
- Put the TLS proxy in front (`deploy/Caddyfile`) and firewall the app port so
  only the proxy reaches it.

---

## Stage 2 - Credential attack

*They found it. Now they want in.*

Three ways in: an analyst account, the shared analyst token, or the enrollment
token. The first is guessable, the other two are stealable.

**What it looks like**

- Failed logins in bursts, or slowly against many names.
- A valid token used from an unexpected source.
- Enrollment from a host you did not deploy an agent to.

**Detect**

The audit chain records every failed login as `auth.login.failed` with the name
tried, so this needs nothing but AEGIS itself:

```bash
# Failed logins by account and hour - spray shows as many names, brute force as one
jq -r 'select(.action=="auth.login.failed") | [.timestamp[0:13], .actorId] | @tsv' \
  server/data/audit.ndjson | sort | uniq -c | sort -rn | head -20
```

```bash
# Enrollments - every one should match a deployment you did
jq -r 'select(.action=="agent.enroll") | [.timestamp, .data.hostname, .data.ip] | @tsv' \
  server/data/audit.ndjson
```

AEGIS locks an account after 5 failures in a window, so a **successful login
immediately after a run of failures** is the shape that matters:

```spl
index=aegis action IN ("auth.login.failed","auth.login")
| transaction actorId maxspan=10m
| search action="auth.login.failed" action="auth.login"
| where eventcount > 5
```

**Reduce the surface**

- Named accounts are on by default. Keep them on - a shared token is a
  credential nobody has to explain losing.
- Rotate the enrollment token once rollout is done: `node harden.mjs --rotate`.
  Enrolled agents hold their own keys and keep working.
- Put the console behind your normal SSO at the proxy if you have one.

---

## Stage 3 - They are inside

*A valid session, as somebody.*

**What it looks like**

- An account reading far more cases than that person works.
- Activity outside that person's hours.
- Two sessions for one account from different addresses.
- A role changed to `lead`.

**Detect**

The activity feed is the fast human check - open it and look for a name doing
something they don't do. For the query version:

```bash
# Who did what, per person, today
jq -r --arg d "$(date -u +%Y-%m-%d)" \
  'select(.timestamp|startswith($d)) | [.actorId, .action] | @tsv' \
  server/data/audit.ndjson | sort | uniq -c | sort -rn
```

```bash
# Privilege changes. There should be almost none, and you should know each one.
jq -r 'select(.action=="user.update" and .data.role=="lead")
       | [.timestamp, .actorId, .targetId] | @tsv' server/data/audit.ndjson
```

```spl
* Impossible travel / session sharing
index=aegis action=auth.login
| stats dc(src_ip) as ips values(src_ip) as srcs by actorId, date_hour
| where ips > 1
```

**Reduce the surface**

- Roles are least-privilege already: `analyst` cannot finalize a report or
  manage users. Do not hand out `lead` for convenience.
- Deleting an account kills its sessions immediately. Use that on offboarding.

---

## Stage 4 - Tampering with the record

*The most damaging move, and the one AEGIS is built to catch.*

An attacker who understands what AEGIS is will try to edit the investigation:
delete the ticket about them, change a severity, remove an evidence hash.

**This is detectable by construction.** The audit log is hash-chained and stores
each event body, so any retroactive edit - to a body, an actor, a timestamp, or
by deleting a row - breaks verification.

**Detect**

```bash
# The whole check. Run it on a schedule and alert on anything but true.
curl -s http://127.0.0.1:9443/api/activity -H "Authorization: Bearer $AEGIS_TOKEN" | jq .intact
```

The console does this for you: if the chain stops verifying, the activity feed
says so in red instead of quietly narrating an edited record.

```bash
# File-level tripwire, in case someone stops the service before editing
sha256sum server/data/audit.ndjson >> /var/log/aegis-audit-hashes.log
```

```bash
# Evidence is content-addressed: the filename IS the hash of the contents.
# Any mismatch means a file was swapped underneath the case.
cd server/data/evidence && for f in *; do
  [ "$(sha256sum "$f" | cut -d' ' -f1)" = "${f%%.*}" ] || echo "TAMPERED: $f"
done
```

**Reduce the surface**

- Ship `audit.ndjson` off the box as it is written - to Splunk via the HEC
  integration, or `rsyslog`. An attacker who owns the server can edit the local
  copy, but not the one that already left.
- Back up `server/data/` somewhere they do not also control.
- Freeze formal reports (`report.finalize`). A frozen report is signed against a
  snapshot hash and stops tracking the case, so later edits cannot rewrite it.

---

## Stage 5 - Turning it off

*If they cannot read it, they will stop it.*

Silence looks like calm. That is what makes this the dangerous one.

**What it looks like**

- The service stopped or the unit disabled.
- Agents stop reporting - all of them at once, or the ones on hosts they own.
- The port closes.

**Detect**

```bash
# systemd remembers. An unexpected stop is right here.
journalctl --user -u svc-telemetry --since "24 hours ago" | grep -Ei "stopped|failed|killed"
```

```bash
# Windows: task disabled or service stopped
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=141,142} |
  Where-Object { $_.Message -match 'telemetry' } | Select-Object TimeCreated, Id, Message
```

**The one that matters most - agents going quiet.** AEGIS marks an agent stale
after `staleAfter` seconds, but nothing shouts about it:

```spl
* Alert on absence, not presence. Silence is the signal.
| inputlookup aegis_expected_agents
| join type=left hostname [ search index=aegis earliest=-30m | stats latest(_time) as last by hostname ]
| where isnull(last) OR last < relative_time(now(), "-30m")
| table hostname last
```

Run that on a schedule. **An agent that stops reporting is either broken or
suppressed, and both are worth a person's attention.**

**Reduce the surface**

- The installers set `Restart=on-failure` / `KeepAlive` / task restart, so
  killing the process is not enough - it has to be disabled, which is louder.
- Externally monitor `/api/health`. If AEGIS is the only thing watching AEGIS,
  it cannot tell you it is gone.
- Make the process itself harder to spot and kill in the first place -
  renaming it, running it least-privilege, and getting the record off the box so
  killing it is loud rather than silent. `docs/RUNBOOK.md` §7 is the step-by-step.

---

## The short version

Run these on a schedule. Between them they cover every stage above.

| Check | Cadence | Alert when |
|---|---|---|
| `curl /api/activity \| jq .intact` | 15 min | anything but `true` |
| Evidence hash check (Stage 4) | daily | any output at all |
| Agents-gone-quiet search (Stage 5) | 30 min | any host listed |
| `auth.login.failed` by actor (Stage 2) | hourly | > 10 for one name |
| `user.update` role changes (Stage 3) | daily | any you cannot account for |
| Probes of the old name/port (Stage 1) | hourly | any, once hardened |

And the three things worth doing once:

1. `node harden.mjs --name <something-dull> --port <not-8787> --rotate`
2. Ship `audit.ndjson` off the box as it is written.
3. Monitor the agents' silence, not just their noise.
