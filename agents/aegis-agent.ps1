<#
.SYNOPSIS
  AEGIS Windows agent. Enrolls with the AEGIS server, heartbeats, and ships a
  curated set of Security / Sysmon / PowerShell events.

.DESCRIPTION
  Deliberately read-only. It reads event logs and reports host facts. It does
  not accept commands from the server, does not download or execute anything,
  and has no persistence beyond the scheduled task you install yourself.

  Ships only the Event IDs in $EventFilter. That is a detection-relevant subset,
  not a full log pipeline. For volume collection use a Splunk Universal
  Forwarder alongside this — see README.

.PARAMETER Server
  Base URL of the AEGIS server, e.g. https://aegis.internal:8787

.PARAMETER EnrollmentToken
  Shared enrollment token from the server console.

.PARAMETER Once
  Run a single collection cycle and exit (for scheduled-task mode).

.EXAMPLE
  .\aegis-agent.ps1 -Server https://aegis.internal:8787 -EnrollmentToken 'xxxx'

.EXAMPLE
  # install as a scheduled task running every 5 minutes as SYSTEM
  .\aegis-agent.ps1 -Server https://aegis.internal:8787 -EnrollmentToken 'xxxx' -Install

.EXAMPLE
  # install under a dull name so an intruder scanning the task list finds no
  # "AEGIS" - the task AND the ProgramData folder take this name. Uninstall
  # with the same -Name. See docs/RUNBOOK.md section 7.
  .\aegis-agent.ps1 -Server https://x:8787 -EnrollmentToken 'xxxx' -Name svc-telemetry -Install
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [string]$EnrollmentToken,
  [switch]$Once,
  [switch]$Install,
  [switch]$Uninstall,
  [int]$IntervalSeconds = 300,
  [int]$LookbackMinutes = 10,
  # The identity the agent installs itself under: the scheduled-task name and
  # the ProgramData folder both derive from this. Default 'AEGIS' keeps every
  # existing install working. Set it to something dull so an intruder on the
  # endpoint who scans the task list for 'AEGIS' finds nothing - see
  # docs/RUNBOOK.md section 7. Whatever you install with, you must uninstall
  # with: the name is how the agent finds its own task and folder again.
  [string]$Name = 'AEGIS'
)

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
# Constrain the name to characters that are safe in a task name, a path and a
# filename all at once - same reasoning as the server's hostname handling.
$SafeName = ($Name -replace '[^A-Za-z0-9._-]', '')
if (-not $SafeName) { $SafeName = 'AEGIS' }
$TaskName = $SafeName
$StateDir = Join-Path $env:ProgramData $SafeName
$StateFile = Join-Path $StateDir 'agent.json'
$ScriptLeaf = ($SafeName.ToLower() + '-agent.ps1')

# The agent needs elevation for two reasons: its identity lives under
# ProgramData (ACL'd to SYSTEM/Administrators so a normal user cannot steal
# the agent key), and the Security log is unreadable without it. Without this
# check the first failure is a raw UnauthorizedAccessException from
# Set-Content, which tells the operator nothing useful.
function Test-Elevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}
if (-not (Test-Elevated)) {
  Write-Host ''
  Write-Host '  AEGIS agent must run as Administrator.' -ForegroundColor Yellow
  Write-Host ''
  Write-Host '  It needs elevation to read the Security event log and to store its'
  Write-Host '  agent key under ProgramData with restricted permissions.'
  Write-Host ''
  Write-Host '  Right-click PowerShell -> "Run as administrator", then re-run:'
  Write-Host ("    .\aegis-agent.ps1 -Server {0} -EnrollmentToken <token>" -f
    $(if ($Server) { $Server } else { '<server-url>' })) -ForegroundColor Cyan
  Write-Host ''
  exit 1
}
$LogFile = Join-Path $StateDir 'agent.log'

function Write-Log {
  param([string]$Msg, [string]$Level = 'INFO')
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'u'), $Level, $Msg
  Write-Verbose $line
  try {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    # keep the log from growing forever
    if ((Get-Item $LogFile -ErrorAction SilentlyContinue).Length -gt 5MB) {
      Set-Content -Path $LogFile -Value (Get-Content $LogFile -Tail 2000)
    }
  } catch { }
}

# ---------------------------------------------------------------- install
if ($Install) {
  if (-not $EnrollmentToken) { throw 'EnrollmentToken is required to install.' }
  $script = $MyInvocation.MyCommand.Path
  # The copied script keeps the chosen name too, so nothing on disk says "aegis"
  # if you renamed it.
  $dest = Join-Path $StateDir $ScriptLeaf
  New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
  Copy-Item $script $dest -Force
  # lock the directory down: SYSTEM + Administrators only
  icacls $StateDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

  $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$dest`" -Server `"$Server`" -EnrollmentToken `"$EnrollmentToken`" -Name `"$SafeName`" -Once"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Seconds $IntervalSeconds)
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
  Write-Host "Agent installed. Task '$TaskName' runs every $IntervalSeconds seconds as SYSTEM."
  Write-Host "State: $StateDir"
  if ($SafeName -ne 'AEGIS') { Write-Host "Renamed install - uninstall this one with:  -Uninstall -Name $SafeName" }
  exit 0
}
if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item $StateDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "Agent removed (task '$TaskName')."
  exit 0
}

# ---------------------------------------------------------------- state
function Get-State {
  if (Test-Path $StateFile) { try { return Get-Content $StateFile -Raw | ConvertFrom-Json } catch { } }
  return $null
}
function Save-State($obj) {
  if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
  $obj | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding UTF8
  try { icacls $StateFile /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null } catch { }
}

# ---------------------------------------------------------------- host facts
function Get-HostFacts {
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $roles = @()
  # DC detection: DomainRole 4 or 5
  if ($cs.DomainRole -in 4, 5) { $roles += 'domain_controller' }
  if ($os.Caption -match 'Server') { $roles += 'server' }
  if (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue) { $roles += 'iis' }
  if (Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue) { $roles += 'mssql' }
  if (Get-Service -Name 'vmms' -ErrorAction SilentlyContinue) { $roles += 'hypervisor' }

  $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -First 1 -ExpandProperty IPAddress)

  [pscustomobject]@{
    hostname = $env:COMPUTERNAME
    os       = $os.Caption.Trim()
    ip       = $ip
    roles    = $roles
    version  = $AgentVersion
  }
}

# ---------------------------------------------------------------- HTTP
function Invoke-Aegis {
  param([string]$Path, [hashtable]$Headers = @{}, $Body, [string]$Method = 'POST')
  $uri = ($Server.TrimEnd('/')) + $Path
  $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 8 -Compress } else { $null }
  $params = @{
    Uri = $uri; Method = $Method; Headers = $Headers
    ContentType = 'application/json'; TimeoutSec = 30; UseBasicParsing = $true
  }
  if ($json) { $params.Body = [System.Text.Encoding]::UTF8.GetBytes($json) }
  return Invoke-RestMethod @params
}

function Register-Agent {
  if (-not $EnrollmentToken) { throw 'No saved credentials and no -EnrollmentToken supplied.' }
  $facts = Get-HostFacts
  $body = @{
    enrollmentToken = $EnrollmentToken
    hostname = $facts.hostname; os = $facts.os; ip = $facts.ip
    roles = $facts.roles; version = $facts.version
  }
  $r = Invoke-Aegis -Path '/api/enroll' -Body $body
  $state = [pscustomobject]@{ agentId = $r.agentId; agentKey = $r.agentKey; server = $Server; lastEventTime = (Get-Date).AddMinutes(-$LookbackMinutes).ToString('o') }
  Save-State $state
  Write-Log "enrolled as $($r.agentId)"
  return $state
}

# ---------------------------------------------------------------- collection
# Detection-relevant subset. Add IDs here rather than shipping everything.
$EventFilter = @{
  'Security' = @(
    4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4702,
    4719, 4720, 4722, 4724, 4728, 4732, 4738, 4740, 4756, 4768, 4769, 4771,
    4776, 4778, 4779, 4964, 5140, 5145, 1102, 4657
  )
  'Microsoft-Windows-Sysmon/Operational' = @(1, 3, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 25)
  'Microsoft-Windows-PowerShell/Operational' = @(4103, 4104)
  'System' = @(7045, 7031, 7034, 1074, 6008, 104)
  'Microsoft-Windows-Windows Defender/Operational' = @(1116, 1117, 5001, 5010, 5012)
}

# IDs that are interesting enough to flag rather than file as info
$SuspiciousIds = @(1102, 4719, 4697, 7045, 4728, 4732, 4756, 4672, 4964, 25, 104, 1116, 1117, 5001, 5010, 5012)
$MaliciousHints = @('mimikatz', 'lsass', 'procdump', '-enc ', 'FromBase64String', 'DownloadString', 'IEX ', 'vssadmin delete', 'bcdedit', 'wevtutil cl')

# suspicious command-line / dropped-file-path patterns, used both for severity
# and for tagging a live ATT&CK technique on 4688 / Sysmon EID 1 (ported from
# Skyhawk's EV_SUSP_CMD / EV_SUSP_PATH)
$SuspiciousCmdlineRe = '-enc(odedcommand)?\b|frombase64string|downloadstring|iex\b|invoke-expression|-nop\b|-windowstyle\s+hidden|-noni\b|certutil.*(-urlcache|-decode)|bitsadmin|mshta|regsvr32.*http|rundll32.*(javascript|http)|nc\.exe|invoke-webrequest.*-outfile'
$SuspiciousPathRe = '\\temp\\|\\appdata\\|\\programdata\\|\\windows\\temp\\|\\users\\public\\|\\\$recycle'

# Event-ID -> ATT&CK technique. Reuses the exact mitre[0] values already
# curated in src/data/win-events.js for IDs AEGIS's own matrix maps (4624,
# 4625, 4688, 4698, 4720, 4732, 7045, 1102) rather than a second, potentially
# divergent table; IDs outside AEGIS's curated matrix (Sysmon 10, PowerShell
# 4104, System 104, Defender events, 4728/4756) use Skyhawk's own mapping
# since there's no AEGIS value to reuse.
function Get-EventTechnique {
  param([string]$Channel, [string]$Id, [hashtable]$Fields)
  $cmd = $Fields['CommandLine']
  switch ($Channel) {
    'Security' {
      switch ($Id) {
        '4624' { return 'T1078' }
        '4625' { return 'T1110' }
        '4688' {
          if ($cmd -and ($cmd -imatch $SuspiciousCmdlineRe)) { return 'T1059' }
          if ($cmd -and ($cmd -imatch $SuspiciousPathRe)) { return 'T1036' }
          return ''
        }
        '4698' { return 'T1053' }
        '4720' { return 'T1136' }
        { $_ -in '4728', '4732', '4756' } { return 'T1098' }
        '1102' { return 'T1070' }
      }
    }
    'System' { if ($Id -eq '104') { return 'T1070.001' } }
    'Microsoft-Windows-Sysmon/Operational' {
      switch ($Id) {
        '1' {
          if ($cmd -and ($cmd -imatch $SuspiciousCmdlineRe)) { return 'T1059' }
          if ($cmd -and ($cmd -imatch $SuspiciousPathRe)) { return 'T1036' }
          return ''
        }
        '10' { if ($Fields['TargetImage'] -and ($Fields['TargetImage'] -imatch 'lsass\.exe')) { return 'T1003.001' } }
      }
    }
    'Microsoft-Windows-PowerShell/Operational' { if ($Id -eq '4104') { return 'T1059.001' } }
    'Microsoft-Windows-Windows Defender/Operational' {
      if ($Id -in '1116', '1117') { return 'T1204' }
      if ($Id -in '5001', '5010', '5012') { return 'T1562.001' }
    }
  }
  return ''
}

function Get-NewEvents {
  param([datetime]$Since)
  $out = New-Object System.Collections.ArrayList
  foreach ($channel in $EventFilter.Keys) {
    $ids = $EventFilter[$channel]
    try {
      $filter = @{ LogName = $channel; StartTime = $Since; ID = $ids }
      $records = Get-WinEvent -FilterHashtable $filter -MaxEvents 400 -ErrorAction Stop
    } catch {
      # channel absent (no Sysmon, etc.) or nothing matched — both are normal
      continue
    }
    foreach ($r in $records) {
      $msg = ''
      try { $msg = ($r.Message -split "`n")[0].Trim() } catch { }
      $sev = 'info'
      if ($SuspiciousIds -contains $r.Id) { $sev = 'suspicious' }
      foreach ($hint in $MaliciousHints) {
        if ($r.Message -and $r.Message.ToLower().Contains($hint.ToLower())) { $sev = 'malicious'; break }
      }
      $fields = @{}
      try {
        # pull a few high-value fields when present
        $x = [xml]$r.ToXml()
        foreach ($d in $x.Event.EventData.Data) {
          if ($d.Name -in 'SubjectUserName','TargetUserName','NewProcessName','Image','CommandLine',
                          'ParentImage','IpAddress','LogonType','ServiceName','ImagePath','TargetFilename',
                          'DestinationIp','DestinationPort','ObjectName','TargetImage') {
            if ($d.'#text') { $fields[$d.Name] = ([string]$d.'#text').Substring(0, [Math]::Min(512, ([string]$d.'#text').Length)) }
          }
        }
      } catch { }
      [void]$out.Add(@{
        ts        = [long]([DateTimeOffset]$r.TimeCreated).ToUnixTimeMilliseconds()
        channel   = $channel
        eventId   = [string]$r.Id
        severity  = $sev
        message   = $msg.Substring(0, [Math]::Min(1000, $msg.Length))
        fields    = $fields
        technique = (Get-EventTechnique -Channel $channel -Id ([string]$r.Id) -Fields $fields)
      })
    }
  }
  return $out
}


# ---------------------------------------------------------------- discovery
function Get-LoggingPosture {
  <# What this host is actually configured to log. Drives the gap report so
     you find out Sysmon is missing before an incident, not during one. #>
  $sysmon = $null -ne (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
  $ps = $false
  try {
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction Stop
    $ps = ($k.EnableScriptBlockLogging -eq 1)
  } catch { }
  $cmd = $false
  try {
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction Stop
    $cmd = ($k.ProcessCreationIncludeCmdLine_Enabled -eq 1)
  } catch { }
  # detailed file share auditing (5145) is off by default
  $share = $false
  try {
    $out = auditpol /get /subcategory:"Detailed File Share" 2>$null
    $share = ($out -match 'Success')
  } catch { }
  @{ sysmon = $sysmon; psScriptBlock = $ps; cmdLineAudit = $cmd; shareAudit = $share }
}

function Get-Peers {
  <# Established connections to other hosts. This is real adjacency: it draws
     the links on the map from traffic that actually happened. #>
  $peers = @()
  try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction Stop |
      Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' }
    foreach ($c in $conns) {
      $peers += @{ ip = $c.RemoteAddress; port = $c.RemotePort; proto = 'tcp' }
    }
  } catch { }
  # de-duplicate on ip+port
  $peers | Group-Object { "$($_.ip):$($_.port)" } | ForEach-Object { $_.Group[0] } | Select-Object -First 200
}

function Get-Listening {
  try {
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
      Select-Object -ExpandProperty LocalPort -Unique | Select-Object -First 100
  } catch { @() }
}

function Send-Discovery {
  param($Hdr)
  $body = @{
    peers     = @(Get-Peers)
    listening = @(Get-Listening)
    logging   = Get-LoggingPosture
  }
  try { Invoke-Aegis -Path '/api/discovery' -Headers $Hdr -Body $body | Out-Null }
  catch { Write-Log "discovery failed: $($_.Exception.Message)" 'WARN' }
}

# ---------------------------------------------------------------- cycle
function Invoke-Cycle {
  $state = Get-State
  if (-not $state -or -not $state.agentKey) { $state = Register-Agent }
  $hdr = @{ 'X-Agent-Id' = $state.agentId; 'X-Agent-Key' = $state.agentKey }

  $facts = Get-HostFacts
  try {
    Invoke-Aegis -Path '/api/heartbeat' -Headers $hdr -Body @{ ip = $facts.ip; roles = $facts.roles } | Out-Null
  } catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
      Write-Log 'credentials rejected, re-enrolling' 'WARN'
      $state = Register-Agent
      $hdr = @{ 'X-Agent-Id' = $state.agentId; 'X-Agent-Key' = $state.agentKey }
    } else { throw }
  }

  Send-Discovery -Hdr $hdr

  $since = [datetime]::Parse($state.lastEventTime)
  if ((Get-Date) - $since -gt [TimeSpan]::FromHours(24)) { $since = (Get-Date).AddHours(-1) }  # cap catch-up
  $events = Get-NewEvents -Since $since

  if ($events.Count -gt 0) {
    # chunk so a busy DC does not post a 40MB body
    $chunk = 200
    for ($i = 0; $i -lt $events.Count; $i += $chunk) {
      $slice = $events[$i..([Math]::Min($i + $chunk - 1, $events.Count - 1))]
      Invoke-Aegis -Path '/api/events' -Headers $hdr -Body @{ events = $slice } | Out-Null
    }
    Write-Log "shipped $($events.Count) events"
  }
  $state.lastEventTime = (Get-Date).ToString('o')
  Save-State $state
}

# ---------------------------------------------------------------- main
try {
  if ($Once) { Invoke-Cycle; exit 0 }
  Write-Host "AEGIS agent running. Ctrl-C to stop. Interval ${IntervalSeconds}s."
  while ($true) {
    try { Invoke-Cycle } catch { Write-Log $_.Exception.Message 'ERROR' }
    Start-Sleep -Seconds $IntervalSeconds
  }
} catch {
  Write-Log $_.Exception.Message 'FATAL'
  throw
}
