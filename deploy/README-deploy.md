# Deploying AEGIS

## Server

**Docker (recommended)**
```bash
cd deploy
cp ../server/config.example.json config.json   # edit tokens
docker compose up -d
```

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

**GPO (Windows)** — Computer Configuration → Policies → Windows Settings →
Scripts → Startup:

```
powershell.exe -ExecutionPolicy Bypass -File \\dc01\netlogon\install-agent.ps1 -Server https://aegis.internal:8787 -Token <token>
```

**Intune** — package `install-agent.ps1` as a Win32 app, run as system.
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

## Rotate the enrollment token after rollout

It is only needed at first contact. Once agents hold their own keys, change
`enrollmentToken` in config and restart — existing agents keep working.

## Upgrading agents

There is no auto-update on purpose (an update channel is an execution channel).
Re-run the installer; it reuses the existing agent identity because enrollment
is keyed on hostname.
