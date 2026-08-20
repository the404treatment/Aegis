# Deploying AEGIS

## Server

**Docker (recommended)**
```bash
node docker-setup.mjs
```
Writes `deploy/config.json` with real tokens and the container-correct
paths, asks whether other machines should reach the server (or skip that
with `--lan` / `--local`), and runs `docker compose up -d`. Doing the same
by hand needs three easy-to-get-wrong edits to `config.json` - see
`INSTALL.md`'s Docker section for that manual path, and for the
Proxmox-specific options.

**systemd**
```bash
sudo useradd -r -s /usr/sbin/nologin aegis
sudo mkdir -p /opt/aegis && sudo cp -r server ui /opt/aegis/
sudo chown -R aegis:aegis /opt/aegis
sudo cp deploy/aegis-server.service /etc/systemd/system/
sudo systemctl enable --now aegis-server
```

Put TLS in front (see `Caddyfile`). Never expose port 8787 directly.

## Agents at scale

**GPO (Windows)** - Computer Configuration → Policies → Windows Settings →
Scripts → Startup:

```
powershell.exe -ExecutionPolicy Bypass -File \\dc01\netlogon\install-agent.ps1 -Server https://aegis.internal:8787 -Token <token>
```

**Intune** - package `install-agent.ps1` as a Win32 app, run as system.
Detection rule: file exists `%ProgramData%\AEGIS\agent.json`.

**Ansible (Linux)**
```yaml
- hosts: all
  become: yes
  tasks:
    - copy: src=agents/aegis-agent.py dest=/usr/local/bin/aegis-agent.py mode=0755
    - template: src=aegis-agent.service.j2 dest=/etc/systemd/system/aegis-agent.service
    - copy: src=deploy/aegis-agent.timer dest=/etc/systemd/system/aegis-agent.timer
    - systemd: name=aegis-agent.timer enabled=yes state=started daemon_reload=yes
```

## Sign the agent before wide deployment

Unsigned PowerShell running as SYSTEM on every host is exactly the pattern your
own detections should flag. Sign it:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath aegis-agent.ps1 -Certificate $cert -TimestampServer http://timestamp.digicert.com
```

Then set execution policy to `AllSigned` on the endpoints rather than using
`-ExecutionPolicy Bypass`.

## Enabling named accounts (optional)

By default the analyst token is the only console credential - one shared
secret, no user identity. That is unchanged and still supported.

To get per-user logins, roles and real attribution, set `requireLogin: true`
in `config.json` and restart. Nothing breaks when you do: **the analyst token
keeps working** as the break-glass and automation credential, so you cannot
lock yourself out, and scripts or integrations using it need no changes.

Create the first account with the analyst token:

```bash
curl -X POST http://127.0.0.1:8787/api/users \
  -H "Authorization: Bearer $ANALYST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"you","password":"a-real-password","role":"lead"}'
```

The server prints this command on startup when accounts are on and none exist.

Two roles:

| Role | Can |
|------|-----|
| `analyst` | search events, create tickets, comment, edit **their own** tickets |
| `lead` | all of the above, plus edit **any** ticket, remove agents, manage accounts |

Notes:

- Sessions are bearer tokens, not cookies - the console already authenticates
  that way, and `EventSource` (the live feed) cannot send custom headers.
- Sessions last 7 days. Changing or deleting an account revokes its live
  sessions immediately.
- Failed logins are rate-limited per IP and name: five attempts in fifteen
  minutes triggers a fifteen-minute lockout, which holds even for the correct
  password.
- Passwords are scrypt-hashed with a per-user salt. Accounts live in
  `data/users.json`, sessions in `data/sessions.json` - both inside `dataDir`,
  so back them up (and protect them) with the rest of it.
- There is still no TLS in the server itself. Put the reverse proxy in front
  **before** anyone types a password into it.

## Rotate the enrollment token after rollout

It is only needed at first contact. Once agents hold their own keys, change
`enrollmentToken` in config and restart - existing agents keep working.

## Upgrading agents

There is no auto-update on purpose (an update channel is an execution channel).
Re-run the installer; it reuses the existing agent identity because enrollment
is keyed on hostname.
