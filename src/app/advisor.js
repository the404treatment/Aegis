/* ================= RESPONSE ADVISOR ================= */
/* Offline, deterministic response advisor: turns ATT&CK technique IDs, an
   affected host, and any IOCs observed on it into phased, copy-pasteable
   containment / eradication / recovery / hardening guidance. 100% local -
   no network, no LLM. Ported from Skyhawk's response-advisor engine and
   rekeyed to AEGIS's own MITRE data (T()) and 15-tactic taxonomy instead of
   a second technique list. */

const RA_PLATFORMS={windows:"Windows · PowerShell",cmd:"Windows · cmd",linux:"Linux · bash",ad:"Active Directory · PowerShell",m365:"Microsoft 365 · PowerShell",network:"Network device",edr:"EDR console",manual:"Manual step"};
const RA_PHASES=[["triage","Preserve evidence first"],["contain","Contain now"],["eradicate","Eradicate"],["recover","Recover"],["block","Block the indicators"],["harden","Harden so it can't recur"]];
const raA=(text,platform,cmd,why)=>({text,platform:platform||"manual",cmd:cmd||"",why:why||""});

const RA_IPV4=/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const RA_NET_TYPES=new Set(['fw','router','switch','vpn']);

function raOsOf(n){
 const os=(n.os||'').toLowerCase();
 if(RA_NET_TYPES.has(n.type))return'network';
 if(/palo alto|fortinet|cisco|pfsense|mikrotik|juniper|ubiquiti|aruba|f5|citrix netscaler/.test(os))return'network';
 if(/windows/.test(os))return'windows';
 if(/linux|macos|unix|bsd|ubuntu|debian|rhel|rocky|alma|suse|fedora|mint|arch|opensuse/.test(os))return'linux';
 return'either';
}
function raParseHost(n){
 return{host:n.label||'the host',ip:n.ip||'',type:n.type||'host',os:raOsOf(n)};
}

/* ---- per-host containment (built dynamically so commands name the real host) ---- */
function raPreserveEvidence(h){
 const items=[];
 if(h.os==='windows'||h.os==='either')items.push(raA(
  `Capture volatile evidence from ${h.host} before you touch it`,"windows",
  `# Run as admin ON ${h.host}. Save output to removable/air-gapped media, not the host.\n`+
  `Get-Date -Format o > C:\\ir\\${h.host}-collected.txt\n`+
  `Get-NetTCPConnection | Sort-Object State | Format-Table -Auto | Out-File C:\\ir\\${h.host}-netstat.txt\n`+
  `Get-Process | Select-Object Id,ProcessName,Path,StartTime | Out-File C:\\ir\\${h.host}-procs.txt\n`+
  `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Out-File C:\\ir\\${h.host}-cmdlines.txt`,
  "Network isolation and process kills destroy live state. Capture connections and process trees first."));
 if(h.os==='linux'||h.os==='either')items.push(raA(
  `Capture volatile evidence from ${h.host} before you touch it`,"linux",
  `# Run as root ON ${h.host}. Write to mounted media, not local disk.\n`+
  `mkdir -p /ir && date -u > /ir/${h.host}-collected.txt\n`+
  `ss -tanp > /ir/${h.host}-sockets.txt\n`+
  `ps auxww > /ir/${h.host}-procs.txt`,
  "Sockets and process command lines disappear the moment you isolate or reboot."));
 return items;
}
function raIsolateHost(h,attackerIp){
 const items=[raA(`Network-contain ${h.host} in your EDR`,"edr","","One click in your EDR severs the host from the network but keeps the EDR link for investigation - cleaner than a firewall change.")];
 if(h.os==='windows'||h.os==='either')items.push(raA(
  `Firewall-isolate ${h.host}${h.ip?' ('+h.ip+')':''}, keeping only your admin subnet`,"windows",
  `# Run on ${h.host}. Replace 10.0.0.0/24 with your responder/management subnet.\n`+
  `Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block\n`+
  `New-NetFirewallRule -DisplayName "IR-Allow-Admin-In"  -Direction Inbound  -RemoteAddress 10.0.0.0/24 -Action Allow\n`+
  `New-NetFirewallRule -DisplayName "IR-Allow-Admin-Out" -Direction Outbound -RemoteAddress 10.0.0.0/24 -Action Allow`,
  "Default-deny both directions, then allow only your admin subnet."));
 if(h.os==='linux'||h.os==='either')items.push(raA(
  `Firewall-isolate ${h.host}${h.ip?' ('+h.ip+')':''}, keeping only your admin host`,"linux",
  `# Run on ${h.host}. Replace 10.0.0.10 with your responder host.\n`+
  `sudo iptables -I INPUT  -s 10.0.0.10 -j ACCEPT\n`+
  `sudo iptables -I OUTPUT -d 10.0.0.10 -j ACCEPT\n`+
  `sudo iptables -A INPUT  -j DROP\n`+
  `sudo iptables -A OUTPUT -j DROP`,
  "Accept your admin host first, then drop everything else in/out."));
 if(h.os==='network')items.push(raA(
  `Shut the compromised interface / pull the ACL on ${h.host}`,"network",
  `! Cisco IOS example - shut the affected port\nconf t\n interface <Gi0/x>\n  shutdown\nend\nwrite memory`,
  "Isolate at the port/ACL level and preserve its running-config + logs."));
 return items;
}
function raCutSessions(h,attackerIp){
 const ip=attackerIp||"<attacker-ip>";
 return[
  raA(`Kill the attacker's live SSH session(s) on ${h.host}`,"linux",
   `who\nss -tnp state established '( sport = :22 )'\n`+
   `sudo ss -K dst ${ip}\n`+
   `sudo pkill -KILL -t pts/1   # or terminate a specific login shell by TTY from 'who'\n`+
   `sudo passwd -l <username> && sudo pkill -KILL -u <username>`,
   "Isolation stops new connections but an interactive session already open can still act - terminate it explicitly."),
  raA(`Kill the attacker's live RDP/interactive session(s) on ${h.host}`,"windows",
   `query session\nlogoff <SESSIONID>\n`+
   `New-NetFirewallRule -DisplayName "IR-Block-RDP-${ip}" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress ${ip} -Action Block`,
   "An existing RDP/console session survives isolation until you log it off."),
 ];
}

/* ---- technique knowledge base (contain / eradicate / recover / harden) ---- */
const RA_TECH={
 T1190:{contain:[raA("Take the exploited app offline or put the WAF in block mode","manual","","Stop the bleeding at the entry point while you patch.")],
  eradicate:[raA("Find and remove webshells / attacker files dropped in the web root","linux",`sudo find /var/www -type f -mmin -1440 -printf '%TY-%Tm-%Td %TH:%TM  %p\\n' | sort\nsudo grep -RilnE "eval\\(|base64_decode\\(|system\\(|passthru\\(|assert\\(" /var/www`,"Web exploitation almost always drops a webshell for re-entry."),
   raA("Rotate every secret the app process could read","manual","","DB connection strings, API keys and signing keys must be assumed stolen.")],
  recover:[raA("Rebuild the host from a known-good image, then restore data","manual","","A host that ran attacker code shouldn't be trusted after cleanup on anything critical.")],
  harden:[raA("Patch to a fixed version and put it behind a WAF + MFA","manual","","Close the actual CVE and add compensating controls.")]},
 T1133:{contain:[raA("Disable the exposed remote-access service (RDP/VPN/Citrix) until fixed","manual","","External remote services are internet-reachable by definition.")],
  harden:[raA("Require MFA on all remote access and restrict source IPs","manual","","MFA + geo/allow-listing defeats valid-cred access over VPN/RDP.")]},
 T1078:{contain:[raA("Disable the compromised account(s) immediately","ad",`Disable-ADAccount -Identity <samAccountName>`,"Stop the account being used while you investigate blast radius."),
   raA("Revoke all active sessions / refresh tokens for the account","m365",`Revoke-MgUserSignInSession -UserId <user@domain>`,"Disabling the account doesn't kill sessions/tokens already issued.")],
  eradicate:[raA("Force a password reset and re-enable only after review","ad",`Set-ADAccountPassword -Identity <samAccountName> -Reset -NewPassword (Read-Host -AsSecureString "New password")\nSet-ADUser -Identity <samAccountName> -ChangePasswordAtLogon $true`,"Rotate the credential; require change at next logon.")],
  harden:[raA("Enforce MFA and alert on impossible-travel / new-device sign-ins","manual","","Stolen valid creds are stopped by MFA and anomaly detection.")]},
 T1566:{contain:[raA("Purge the phishing email from all mailboxes","m365",`New-ComplianceSearch -Name "IR-Phish" -ExchangeLocation All -ContentMatchQuery 'subject:"<subject>" AND from:<sender>'\nStart-ComplianceSearch -Identity "IR-Phish"\nNew-ComplianceSearchAction -SearchName "IR-Phish" -Purge -PurgeType HardDelete`,"Pull the lure from every inbox so no one else clicks it."),
   raA("Reset credentials + revoke sessions for anyone who interacted","m365",`Revoke-MgUserSignInSession -UserId <user@domain>`,"Treat clickers/credential-enterers as compromised until proven otherwise.")],
  harden:[raA("Block the sender/domain and enforce MFA","manual","","Stop repeat delivery and neuter any harvested passwords.")]},
 T1059:{eradicate:[raA("Kill the malicious process by name or PID","windows",`Get-Process -Name <procname> -ErrorAction SilentlyContinue | Stop-Process -Force`,"Terminate the live interpreter/payload before it does more.")],
  harden:[raA("Enable command-line + script logging so this is caught next time","windows",`reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f`,"Full command lines in event logs make the next intrusion obvious.")]},
 "T1059.001":{eradicate:[raA("Kill the PowerShell payload and grab its command line","windows",`Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" | Select-Object ProcessId,CommandLine\nStop-Process -Id <pid> -Force`,"Capture the (often encoded) command line for IOCs before killing it.")],
  harden:[raA("Turn on Script Block Logging and Constrained Language Mode","windows",`reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f`,"Logs every script block and limits what unsigned scripts can do.")]},
 T1053:{eradicate:[raA("Enumerate and remove the malicious scheduled task","windows",`Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) -or $_.TaskName -match '<suspect>' } | Format-Table TaskName,TaskPath,State\nUnregister-ScheduledTask -TaskName "<TaskName>" -Confirm:$false`,"Scheduled tasks are a top persistence spot.")],
  harden:[raA("Alert on task creation (Event ID 4698)","manual","","Security 4698 fires on every new task.")]},
 "T1053.005":{eradicate:[raA("Enumerate and remove the malicious scheduled task","windows",`Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) -or $_.TaskName -match '<suspect>' } | Format-Table TaskName,TaskPath,State\nUnregister-ScheduledTask -TaskName "<TaskName>" -Confirm:$false`,"Scheduled tasks are a top persistence spot.")],
  harden:[raA("Alert on task creation (Event ID 4698)","manual","","Security 4698 fires on every new task.")]},
 T1543:{eradicate:[raA("Find and delete the malicious Windows service","windows",`Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'C:\\\\Windows|Program Files' } | Select-Object Name,PathName,StartName\nStop-Service -Name "<svc>" -Force\nsc.exe delete "<svc>"`,"Services from odd paths are classic persistence.")],
  harden:[raA("Alert on service installs (Event ID 7045)","manual","","System 7045 logs every new service.")]},
 "T1543.003":{eradicate:[raA("Find and delete the malicious Windows service","windows",`Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'C:\\\\Windows|Program Files' } | Select-Object Name,PathName,StartName\nStop-Service -Name "<svc>" -Force\nsc.exe delete "<svc>"`,"Services from odd paths are classic persistence.")],
  harden:[raA("Alert on service installs (Event ID 7045)","manual","","System 7045 logs every new service.")]},
 T1547:{eradicate:[raA("Enumerate and clean autostart / Run keys","windows",`reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"\nreg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"\nreg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "<ValueName>" /f`,"Run/RunOnce keys and the Startup folder are the most common userland persistence.")]},
 T1055:{eradicate:[raA("Identify the injected host process and terminate it","windows",`Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Sort-Object Name\nStop-Process -Id <pid> -Force`,"Injected code lives inside a legit process - find the anomalous parent/child and kill it.")],
  recover:[raA("Reboot to clear memory-resident implants, then re-scan","manual","","Injection is often fileless; a reboot plus fresh EDR scan clears what killing the process may miss.")]},
 T1003:{contain:[raA("Assume every credential used on this host is stolen - plan a rotation","manual","","Credential dumping means cached/logged-on secrets are gone.")],
  eradicate:[raA("Force-reset every exposed user and privileged account","ad",`Set-ADAccountPassword -Identity <samAccountName> -Reset -NewPassword (Read-Host -AsSecureString "New password")\nSet-ADUser -Identity <samAccountName> -ChangePasswordAtLogon $true`,"Rotate all accounts that had sessions on the host, prioritising admins and service accounts."),
   raA("Rotate the local administrator password (all hosts, via LAPS)","windows",`Reset-LapsPassword -ComputerName <host>   # if LAPS is deployed`,"A dumped local admin hash enables lateral movement everywhere it's reused.")],
  recover:[raA("Reset the krbtgt account TWICE if a DC or domain admin was exposed","ad",`# Do TWICE with AD replication (10h+) between resets:\nSet-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(64,10)) -AsPlainText -Force)`,"Invalidates forged Kerberos (golden) tickets. Space the two resets by one replication cycle.")],
  harden:[raA("Enable LSA Protection (RunAsPPL) and Credential Guard","windows",`reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`,"Stops tools reading LSASS memory. Reboot to apply.")]},
 "T1003.001":{contain:[raA("Assume all credentials cached on this host are compromised","manual","","LSASS held plaintext/hashes/tickets for everyone logged on.")],
  eradicate:[raA("Force-reset accounts that had sessions on the host","ad",`Set-ADAccountPassword -Identity <samAccountName> -Reset -NewPassword (Read-Host -AsSecureString "New password")\nSet-ADUser -Identity <samAccountName> -ChangePasswordAtLogon $true`,"Prioritise domain admins and service accounts that logged on interactively."),
   raA("Block LSASS credential theft going forward with an ASR rule","windows",`Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled`,"Blocks credential stealing from lsass.exe directly.")],
  recover:[raA("Reset krbtgt TWICE if a DC/domain admin was exposed","ad",`# One replication cycle apart:\nSet-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(64,10)) -AsPlainText -Force)`,"Kills golden tickets forged from a stolen krbtgt hash.")],
  harden:[raA("Enable RunAsPPL + Credential Guard on all hosts","windows",`reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`,"Protects LSASS from user-mode credential dumpers. Reboot to apply.")]},
 T1110:{contain:[raA("Lock the targeted account(s) and block the source IP","ad",`Search-ADAccount -LockedOut | Format-Table Name,LastLogonDate\nDisable-ADAccount -Identity <samAccountName>`,"Stop the guessing against the account and cut the source.")],
  harden:[raA("Enforce lockout policy + MFA and alert on 4625 spikes","manual","","Lockout thresholds and MFA make spraying/brute force ineffective.")]},
 T1021:{contain:[raA("Cut RDP/SMB from the attacker and reset the pivoted account","windows",`New-NetFirewallRule -DisplayName "IR-Block-Lateral" -Direction Inbound -Protocol TCP -LocalPort 445,3389,5985 -RemoteAddress <attacker-ip> -Action Block`,"Kill the movement path (SMB/RDP/WinRM) from the compromised host and rotate the account used to move.")],
  harden:[raA("Segment the network and require MFA for admin protocols","manual","","Host firewalls / VLAN segmentation + MFA on RDP/WinRM stop the pivot repeating.")]},
 "T1021.001":{contain:[raA("Log off the attacker's RDP session and block 3389 from the source","windows",`query session\nlogoff <SESSIONID>\nNew-NetFirewallRule -DisplayName "IR-Block-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress <attacker-ip> -Action Block`,"End the live RDP session, then block the port from the attacker.")],
  harden:[raA("Restrict RDP to jump hosts + Network Level Authentication + MFA","manual","","Never expose RDP flat; broker it through MFA-gated jump hosts.")]},
 "T1021.002":{contain:[raA("Cut SMB from the attacker and audit admin-share access","windows",`New-NetFirewallRule -DisplayName "IR-Block-SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress <attacker-ip> -Action Block\nGet-SmbSession | Format-Table ClientComputerName,ClientUserName\nClose-SmbSession -Force`,"Block 445 from the source and close live SMB sessions.")],
  harden:[raA("Disable admin shares where unneeded and enforce SMB signing","manual","","Reduce C$/ADMIN$ exposure and require signing to blunt relay/lateral abuse.")]},
 T1570:{eradicate:[raA("Find and remove tools the attacker copied in","windows",`Get-ChildItem C:\\Users\\*\\AppData\\Local\\Temp,C:\\Windows\\Temp,C:\\ProgramData -Recurse -Include *.exe,*.dll,*.ps1 -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-2)} | Select-Object FullName,LastWriteTime`,"Staged tooling usually lands in Temp/ProgramData - hunt by recent write time.")]},
 T1105:{contain:[raA("Block the download source at the perimeter and DNS","manual","","Cut the channel the attacker pulls tools/payloads through.")],
  eradicate:[raA("Remove downloaded payloads and record their hashes","windows",`Get-FileHash <path-to-file> -Algorithm SHA256`,"Hash before deleting so the indicator can be swept fleet-wide.")]},
 T1071:{contain:[raA("Sinkhole/deny the C2 domains and IPs everywhere","manual","","Block at firewall egress, DNS and proxy so beacons can't reach home.")],
  harden:[raA("Force outbound web through an inspecting proxy; alert on beacons","manual","","Deny direct egress; jittered/periodic callbacks stand out through a proxy.")]},
 T1486:{contain:[raA("Isolate every encrypting host and protect the backups NOW","manual","","Ransomware spreads fast - segment first, and get backups offline/read-only."),
   raA("Identify the ransomware family and stop the spread mechanism","manual","","Knowing the family tells you the propagation method (SMB, GPO, PsExec) to cut.")],
  eradicate:[raA("Rebuild encrypted hosts from clean media; remove persistence","manual","","Do not just decrypt in place - the intrusion that delivered ransomware is still present.")],
  recover:[raA("Restore from verified clean backups, rebuilding tier-0 first","manual","","Validate backup integrity before restoring; bring DCs/identity back first."),
   raA("Rotate ALL credentials including krbtgt (twice) and service accounts","ad",`# See T1003 krbtgt guidance - reset twice, one replication cycle apart.`,"Ransomware crews almost always have domain admin - assume total credential compromise.")],
  harden:[raA("Segment, enforce MFA, and keep offline immutable backups","manual","","Immutable/offline backups + segmentation turn a domain-wide event into a contained one.")]},
 T1490:{contain:[raA("Confirm shadow-copy/backup deletion and protect what remains","windows",`vssadmin list shadows`,"Attackers delete VSS/backups before encrypting - check what's gone and lock down the rest immediately.")],
  recover:[raA("Restore from off-host backups the attacker couldn't reach","manual","","On-host shadow copies are usually destroyed; rely on offline/immutable copies.")]},
 T1489:{eradicate:[raA("Identify what stopped critical services and restart them cleanly","windows",`Get-WinEvent -FilterHashtable @{LogName='System';Id=7036} -MaxEvents 50 | Select-Object TimeCreated,Message\nStart-Service -Name <svc>`,"Attackers stop AV/DB/backup services before acting.")]},
 T1562:{contain:[raA("Re-enable the security tooling the attacker disabled","windows",`Set-MpPreference -DisableRealtimeMonitoring $false\nStart-Service WinDefend\nGet-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled`,"Turn defenses back on so you're not blind.")],
  harden:[raA("Enable Tamper Protection and alert when AV/EDR is disabled","manual","","Tamper Protection blocks the disable; alerting catches attempts.")]},
 "T1562.001":{contain:[raA("Re-enable the security tooling the attacker disabled","windows",`Set-MpPreference -DisableRealtimeMonitoring $false\nStart-Service WinDefend\nGet-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled`,"Turn defenses back on so you're not blind.")],
  harden:[raA("Enable Tamper Protection and alert when AV/EDR is disabled","manual","","Tamper Protection blocks the disable; alerting catches attempts.")]},
 T1136:{eradicate:[raA("Find and disable recently-created rogue accounts","ad",`Get-ADUser -Filter { whenCreated -gt (Get-Date).AddDays(-7) } -Properties whenCreated | Format-Table Name,whenCreated\nDisable-ADAccount -Identity <samAccountName>`,"Backdoor accounts are persistence - disable, don't delete, to preserve for evidence.")],
  harden:[raA("Alert on account creation (4720) and privileged group changes (4728/4732)","manual","","New-account and group-add events flag this technique early.")]},
 "T1136.001":{eradicate:[raA("Find and disable recently-created rogue accounts","ad",`Get-ADUser -Filter { whenCreated -gt (Get-Date).AddDays(-7) } -Properties whenCreated | Format-Table Name,whenCreated\nDisable-ADAccount -Identity <samAccountName>`,"Backdoor accounts are persistence - disable, don't delete, to preserve for evidence.")],
  harden:[raA("Alert on account creation (4720) and privileged group changes (4728/4732)","manual","","New-account and group-add events flag this technique early.")]},
 T1070:{contain:[raA("Check for cleared logs and switch to off-host logging now","windows",`Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 | Select-Object TimeCreated,Message`,"Event ID 1102 = audit log cleared. If logs were wiped, forward everything to a SIEM the attacker can't reach.")],
  harden:[raA("Ship logs off-host in real time and restrict who can clear them","manual","","Central logging defeats local log deletion.")]},
 "T1070.001":{contain:[raA("Check for cleared logs and switch to off-host logging now","windows",`Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 | Select-Object TimeCreated,Message`,"Event ID 1102 = audit log cleared. If logs were wiped, forward everything to a SIEM the attacker can't reach.")],
  harden:[raA("Ship logs off-host in real time and restrict who can clear them","manual","","Central logging defeats local log deletion.")]},
 T1552:{eradicate:[raA("Hunt for and purge credentials sitting in files/config","linux",`grep -RilnE "password|passwd|secret|api[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE KEY" /home /etc /var/www 2>/dev/null | head -50`,"Find plaintext secrets the attacker likely already grabbed, then rotate every one you find.")],
  harden:[raA("Move secrets into a vault and scan repos/configs in CI","manual","","A secrets manager + pre-commit/CI scanning stops credentials living in files.")]},
 T1098:{eradicate:[raA("Review and revert recent account/group changes and added keys","ad",`Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties whenChanged | Sort-Object whenChanged -Descending | Format-Table Name,whenChanged\nRemove-ADGroupMember -Identity "Domain Admins" -Members <samAccountName> -Confirm:$false`,"Attackers grant themselves persistence by adding accounts to privileged groups - audit and revert each.")],
  harden:[raA("Alert on group changes (4728/4732/4756) and new credential registration","manual","","Privileged-group additions and new MFA/keys should page someone.")]},
 T1036:{eradicate:[raA("Verify the suspect binary's real path, signature and hash","windows",`Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" | Select-Object ProcessId,ExecutablePath,CommandLine\nGet-AuthenticodeSignature <path-to-exe> | Select-Object Status,SignerCertificate\nGet-FileHash <path-to-exe> -Algorithm SHA256`,"Masquerading hides malware as a trusted name - confirm path, signature and hash.")],
  harden:[raA("Enable application control (WDAC/AppLocker) to block untrusted binaries","manual","","Signed-and-allowed-only execution defeats renamed/relocated malware.")]},
};

/* ---- tactic-level fallbacks: keyed by AEGIS's own tactic NAMES (T(id).tactic
   already resolves to one of these strings). AEGIS splits Defense Evasion into
   Stealth + Defense Impairment, so Skyhawk's single defense-evasion bucket is
   duplicated under both. Every technique without a specific RA_TECH entry
   still gets solid, phase-appropriate guidance from its tactic. ---- */
const RA_TACTIC_FALLBACK={
 "Reconnaissance":{contain:[raA("Confirm whether the recon led to access; scope what was exposed","manual","","Check perimeter/auth logs for follow-on activity from the same source.")],
  harden:[raA("Reduce external attack surface and remove leaked information","manual","","Tighten what's public, and rate-limit/alert on scanning.")]},
 "Resource Development":{contain:[raA("Block the attacker infrastructure and pre-position detections","manual","","If you've identified attacker domains/accounts/tooling being staged, block them and watch for their use.")],
  harden:[raA("Monitor for newly-registered look-alike domains and leaked credentials","manual","","Typosquat/brand monitoring and credential-leak alerting catch staging before it's used.")]},
 "Initial Access":{contain:[raA("Cut the entry vector and isolate the entry host","manual","","Disable the exploited service, block the sender, or pull the exposed account, then isolate the first host.")],
  eradicate:[raA("Remove the foothold the attacker established on entry","manual","","Webshell, dropped tool, added account or mail rule - find and remove whatever gave them a way back in.")],
  harden:[raA("Patch the entry point and require MFA on all external access","manual","","Close the specific vector and add MFA so a repeat attempt fails.")]},
 "Execution":{eradicate:[raA("Identify and kill the malicious process, capturing its command line","windows",`Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Sort-Object Name\nStop-Process -Id <pid> -Force`,"Grab the full command line (for IOCs) before terminating the payload.")],
  harden:[raA("Enable command-line + script logging and application control","windows",`reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`,"Full command-line auditing plus WDAC/AppLocker makes execution both visible and harder.")]},
 "Persistence":{eradicate:[raA("Sweep the host for persistence and remove the attacker's mechanism","windows",`Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location\nGet-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName,TaskPath`,"Persistence hides in run keys, services, tasks and WMI subscriptions - enumerate and remove what's attacker-owned.")],
  recover:[raA("If persistence can't be fully proven clean, rebuild the host","manual","","For anything critical, reimaging is safer than chasing every persistence artifact.")],
  harden:[raA("Baseline autoruns and alert on new persistence (4698/7045)","manual","","Alerting on service/task creation surfaces the next attempt fast.")]},
 "Privilege Escalation":{contain:[raA("Identify what the attacker escalated to and constrain that access","windows",`whoami /priv\nGet-LocalGroupMember -Group Administrators`,"Confirm which privileges/groups were gained so you know the blast radius.")],
  eradicate:[raA("Patch the escalation vector and remove attacker-added privileges","manual","","Close the exploited weakness and revoke any rights they granted themselves.")],
  harden:[raA("Enforce least privilege and keep hosts patched","manual","","Fewer local admins + timely patching removes most escalation paths.")]},
 "Stealth":{contain:[raA("Re-enable and verify security tooling; check for cleared logs","windows",`Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled\nGet-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5`,"Evasion works by blinding you - restore AV/EDR and confirm logs weren't wiped.")],
  eradicate:[raA("Remove the evasion artifacts (masqueraded files, hidden persistence)","manual","","Hunt renamed/hidden binaries and tampered config, then restore them.")],
  harden:[raA("Enable Tamper Protection and ship logs off-host in real time","manual","","Tamper Protection blocks defense-disabling; central logging defeats local log deletion.")]},
 "Defense Impairment":{contain:[raA("Re-enable and verify security tooling; check for cleared logs","windows",`Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled\nGet-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5`,"Evasion works by blinding you - restore AV/EDR and confirm logs weren't wiped.")],
  eradicate:[raA("Remove the evasion artifacts (masqueraded files, hidden persistence)","manual","","Hunt renamed/hidden binaries and tampered config, then restore them.")],
  harden:[raA("Enable Tamper Protection and ship logs off-host in real time","manual","","Tamper Protection blocks defense-disabling; central logging defeats local log deletion.")]},
 "Credential Access":{contain:[raA("Assume the targeted credentials are stolen and plan rotation","manual","","Scope which accounts/secrets were reachable from the affected host.")],
  eradicate:[raA("Force-reset the exposed credentials","ad",`Set-ADAccountPassword -Identity <samAccountName> -Reset -NewPassword (Read-Host -AsSecureString "New password")\nSet-ADUser -Identity <samAccountName> -ChangePasswordAtLogon $true`,"Rotate every credential the attacker could have captured.")],
  harden:[raA("Enforce MFA, LSA Protection and phishing-resistant auth","windows",`reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`,"MFA + protected LSASS + FIDO2 blunt most credential theft.")]},
 "Discovery":{contain:[raA("Treat discovery as a live intruder mapping your environment","manual","","Enumeration precedes lateral movement - hunt the same host/account for the next stage now.")],
  harden:[raA("Limit what low-privileged accounts can enumerate; alert on recon bursts","manual","","Restrict anonymous/LDAP enumeration and alert on rapid discovery from one host.")]},
 "Lateral Movement":{contain:[raA("Cut the lateral protocols from the source and reset the pivot account","windows",`New-NetFirewallRule -DisplayName "IR-Block-Lateral" -Direction Inbound -Protocol TCP -LocalPort 445,3389,5985 -RemoteAddress <attacker-ip> -Action Block`,"Block SMB/RDP/WinRM from the compromised host and rotate the account being used to move.")],
  eradicate:[raA("Remove tooling the attacker transferred to reached hosts","windows",`Get-ChildItem C:\\Windows\\Temp,C:\\ProgramData -Include *.exe,*.dll,*.ps1 -Recurse -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-2)`,"Sweep each reached host for staged binaries.")],
  harden:[raA("Segment the network and require MFA on admin protocols","manual","","Host-firewall/VLAN segmentation + MFA on RDP/WinRM stop the pivot repeating.")]},
 "Collection":{contain:[raA("Identify what data was staged and cut the collection","windows",`Get-ChildItem C:\\,D:\\ -Include *.zip,*.rar,*.7z,*.tar,*.gz -Recurse -ErrorAction SilentlyContinue | Where-Object Length -gt 10MB | Sort-Object LastWriteTime -Descending | Select-Object FullName,Length,LastWriteTime`,"Find staged/archived data so you know what's at risk, then remove it and cut access.")],
  harden:[raA("Apply least-privilege on sensitive repositories and deploy DLP","manual","","Restrict who can bulk-read sensitive stores and watch for mass collection.")]},
 "Command and Control":{contain:[raA("Block the C2 at the edge, DNS and proxy, then remove the implant","manual","","Deny the beacon's destinations everywhere and kill the implant process.")],
  harden:[raA("Force outbound through an inspecting proxy and alert on beaconing","manual","","Default-deny egress with proxy inspection makes periodic callbacks stand out.")]},
 "Exfiltration":{contain:[raA("Block the exfil destination, throttle egress, and size the loss","manual","","Cut the channel, then use proxy/DLP/netflow logs to determine what and how much left.")],
  harden:[raA("Egress-filter outbound traffic and deploy DLP","manual","","Default-deny egress + DLP detects and blocks bulk data leaving.")]},
 "Impact":{contain:[raA("Isolate affected hosts to stop the spread and protect backups","manual","","Destructive actions spread fast - segment immediately and get backups offline/read-only.")],
  eradicate:[raA("Remove the tool causing impact and the intrusion behind it","manual","","Don't just undo the damage - the access that delivered it is still present.")],
  recover:[raA("Restore from verified clean backups, rebuilding identity/tier-0 first","manual","","Validate backup integrity, bring DCs/identity back first, and rotate all credentials.")],
  harden:[raA("Keep offline immutable backups and segment the network","manual","","Immutable backups + segmentation turn a fleet-wide event into a contained one.")]},
};

/* ---- IOC blocking (dynamic from what's tracked on the host) ---- */
function raBlockIocs(iocs){
 const items=[];
 const ips=[...new Set(iocs.filter(x=>x.type==='ipv4').map(x=>x.value))];
 const domains=[...new Set(iocs.filter(x=>x.type==='domain').map(x=>x.value))];
 const urls=[...new Set(iocs.filter(x=>x.type==='url').map(x=>x.value))];
 const hashes=[...new Set(iocs.filter(x=>['md5','sha1','sha256'].includes(x.type)).map(x=>x.value))];
 if(ips.length){
  items.push(raA(`Block ${ips.length} malicious IP${ips.length>1?'s':''} outbound (host firewall)`,"windows",
   ips.map(ip=>`New-NetFirewallRule -DisplayName "IR-Block-${ip}" -Direction Outbound -Action Block -RemoteAddress ${ip}`).join("\n"),
   "Deny egress to the attacker infrastructure on Windows hosts."));
  items.push(raA(`Block the same IP${ips.length>1?'s':''} on Linux and at the edge`,"linux",
   ips.map(ip=>`sudo iptables -A OUTPUT -d ${ip} -j DROP`).join("\n")+`\n# Also add these to your perimeter firewall / proxy deny-list.`,
   "Once at the perimeter, every host is covered."));
 }
 if(domains.length)items.push(raA(`Sinkhole ${domains.length} C2 domain${domains.length>1?'s':''}`,"linux",
  domains.map(d=>`echo "0.0.0.0 ${d}" | sudo tee -a /etc/hosts`).join("\n")+`\n# Better: add these to your DNS/proxy block-list so it covers the whole estate.`,
  "A DNS/proxy block-list is the real fix; the hosts entry is a quick local stopgap."));
 if(urls.length)items.push(raA(`Block ${urls.length} malicious URL${urls.length>1?'s':''} at the proxy`,"manual",urls.join("\n"),"Add these exact URLs to your web-proxy deny-list."));
 if(hashes.length)items.push(raA(`Blocklist ${hashes.length} file hash${hashes.length>1?'es':''} in EDR and sweep for them`,"edr",hashes.join("\n"),"Add these hashes to your EDR custom-IOC/blocklist and run a fleet-wide search."));
 return items;
}

/**
 * Build a tailored response plan.
 * @param {object} opts { techniques:[T####,...], hosts:[{host,ip,type,os}], iocs:[{type,value}] }
 */
function buildAdvisory(opts){
 opts=opts||{};
 const techniques=opts.techniques||[];
 const hosts=opts.hosts||[];
 const iocs=opts.iocs||[];
 const attackerIp=(iocs.find(x=>x.type==='ipv4')||{}).value||'';

 const ids=new Set();
 techniques.forEach(id=>{ids.add(id);if(id.includes('.'))ids.add(id.split('.')[0]);});

 const buckets={triage:[],contain:[],eradicate:[],recover:[],block:[],harden:[]};

 if(hosts.length){
  hosts.forEach(h=>{
   raPreserveEvidence(h).forEach(it=>buckets.triage.push(it));
   raIsolateHost(h,attackerIp).forEach(it=>buckets.contain.push(it));
   raCutSessions(h,attackerIp).forEach(it=>buckets.contain.push(it));
  });
 }else{
  buckets.contain.push(raA("Isolate the affected host(s)","edr","","No host is attached to this yet - open it from the hunt map for host-specific commands."));
 }

 const applied=new Set();
 [...ids].forEach(id=>{
  const kb=RA_TECH[id];
  if(!kb||applied.has(id))return;
  applied.add(id);
  ['contain','eradicate','recover','harden'].forEach(ph=>(kb[ph]||[]).forEach(it=>buckets[ph].push(it)));
 });

 const tacticsUsed=[];
 techniques.forEach(id=>{
  if(RA_TECH[id]||RA_TECH[id.split('.')[0]])return;
  const tac=T(id).tactic;
  if(tac&&RA_TACTIC_FALLBACK[tac]&&tacticsUsed.indexOf(tac)<0)tacticsUsed.push(tac);
 });
 tacticsUsed.forEach(tac=>{
  const kb=RA_TACTIC_FALLBACK[tac];
  ['contain','eradicate','recover','harden'].forEach(ph=>(kb[ph]||[]).forEach(it=>buckets[ph].push(it)));
 });

 raBlockIocs(iocs).forEach(it=>buckets.block.push(it));

 if(!techniques.length)buckets.harden.push(raA("Stage an ATT&CK technique for targeted advice","manual","","Log an observation with an event ID (or stage a technique in the Studio) and re-open this advisor for technique-specific containment and eradication steps."));

 const subs=s=>String(s||'')
  .replace(/<attacker-ip>/g,attackerIp||'<attacker-ip>')
  .replace(/\{HOST\}/g,hosts[0]?hosts[0].host:'the host')
  .replace(/\{IP\}/g,(hosts[0]&&hosts[0].ip)||attackerIp||'<host-ip>');

 const sections=RA_PHASES.map(([key,label])=>{
  const seen=new Set();
  const items=buckets[key].filter(it=>{if(seen.has(it.text))return false;seen.add(it.text);return true;})
   .map(it=>({...it,text:subs(it.text),cmd:subs(it.cmd),platformLabel:RA_PLATFORMS[it.platform]||'Step'}));
  return{key,label,items};
 }).filter(s=>s.items.length);

 return{techniques,hosts:hosts.map(h=>({host:h.host,ip:h.ip,type:h.type})),attackerIp,sections};
}
function adviseTechnique(id){return buildAdvisory({techniques:[id],hosts:[],iocs:[]});}
function adviseNode(uid){
 const n=lsNodes.find(x=>x.uid===uid);
 if(!n)return buildAdvisory({techniques:[],hosts:[],iocs:[]});
 const techniques=[...new Set((n.obs||[]).map(o=>{
  const ev=LOGSRC.find(e=>e.id===o.evId);
  if(!ev||!ev.linked)return null;
  const evObj=ALL().find(x=>x.id===ev.linked);
  return(evObj&&evObj.mitre&&evObj.mitre[0])||null;
 }).filter(Boolean))];
 const iocs=(n.obs||[]).flatMap(o=>extractIocs(o.note||''));
 return buildAdvisory({techniques,hosts:[raParseHost(n)],iocs});
}

/* ---- UI: lazy veil, same pattern as openLiveSetup() ---- */
function openAdvisor(id,uid){
 const node=uid?lsNodes.find(x=>x.uid===uid):null;
 const adv=uid?adviseNode(uid):adviseTechnique(id);
 const label=node?node.label:(id?`${id} · ${esc(T(id).name)}`:'');
 let v=document.getElementById('ra-veil');
 if(!v){v=document.createElement('div');v.id='ra-veil';v.className='ls-quick-veil';document.body.appendChild(v);}
 v.innerHTML=`<div class="ls-det-sheet ra-sheet">
  <div class="ls-ne-grip" onclick="closeAdvisor()"></div>
  <div class="ls-det-head">Response playbook${label?` · ${esc(label)}`:''}</div>
  <div class="ls-det-sub">Deterministic, offline containment / eradication / recovery guidance. No network, no LLM - copy, paste, and adapt to your environment.</div>
  ${adv.sections.length?adv.sections.map(s=>`
   <div class="ra-phase">
    <div class="ra-phase-h">${esc(s.label)}</div>
    ${s.items.map(it=>`<div class="ra-item">
     <div class="ra-item-top"><span class="ra-item-plat">${esc(it.platformLabel)}</span><span class="ra-item-text">${esc(it.text)}</span></div>
     ${it.cmd?`<pre class="ra-cmd">${esc(it.cmd)}</pre>`:''}
     ${it.why?`<div class="ra-why">${esc(it.why)}</div>`:''}
    </div>`).join('')}
   </div>`).join(''):'<div class="ls-det-sub">Nothing to show yet.</div>'}
 </div>`;
 v.classList.add('open');v.onclick=(e)=>{if(e.target===v)closeAdvisor();};
}
function closeAdvisor(){const v=document.getElementById('ra-veil');if(v)v.classList.remove('open');}
