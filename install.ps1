<#
  AEGIS one-line installer (Windows).

    irm https://raw.githubusercontent.com/the404treatment/Aegis/main/install.ps1 | iex

  Installs into %LOCALAPPDATA%\AEGIS, generates tokens, builds the console,
  registers a Scheduled Task that starts it at logon, and waits until the
  server actually answers before claiming success.

  Deliberate:
    - No admin rights. It installs per-user and registers a per-user task.
      An installer that demands elevation to run a log collector has already
      made your security posture worse.
    - Node is checked, not silently installed. Piping a script that downloads
      and runs another vendor's installer is how supply-chain incidents start.
    - Idempotent: re-running upgrades in place and keeps your tokens, so
      enrolled agents keep working.
#>
[CmdletBinding()]
param(
  [string]$Repo   = $(if ($env:AEGIS_REPO)   { $env:AEGIS_REPO }   else { 'https://github.com/the404treatment/Aegis' }),
  [string]$Branch = $(if ($env:AEGIS_BRANCH) { $env:AEGIS_BRANCH } else { 'main' }),
  [string]$Dir    = $(if ($env:AEGIS_DIR)    { $env:AEGIS_DIR }    else { Join-Path $env:LOCALAPPDATA 'AEGIS' }),
  [int]   $Port   = $(if ($env:AEGIS_PORT)   { [int]$env:AEGIS_PORT } else { 8787 })
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "  $m" -ForegroundColor White }
function Warn($m) { Write-Host "  $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host ""; Write-Host "  ERROR  $m" -ForegroundColor Red; Write-Host ""; exit 1 }

Write-Host ""
Write-Host "  AEGIS" -ForegroundColor White -NoNewline
Write-Host "  SOC detection console + incident platform" -ForegroundColor DarkGray
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray

# --- Node -------------------------------------------------------------------
$nodeSearchPaths = @("$env:ProgramFiles\nodejs\node.exe", "${env:ProgramFiles(x86)}\nodejs\node.exe", "$env:LOCALAPPDATA\Programs\nodejs\node.exe")
$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) {
  # A fresh install puts node on the PATH of *new* shells only, so look in the
  # standard locations before giving up on someone who just installed it.
  foreach ($p in $nodeSearchPaths) {
    if (Test-Path $p) { $env:PATH = (Split-Path $p) + ';' + $env:PATH; $node = Get-Command node; break }
  }
}
if (-not $node) {
  # Same posture as install.sh: install through the OS's own signed package
  # source, with explicit consent, or not at all - never a piped installer
  # from a third-party vendor. winget is Microsoft's own repository and ships
  # with Windows 10 1709+ / 11, so it is the direct equivalent of apt/brew/etc.
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) {
    Die @"
Node.js 18+ is required but was not found, and winget is not available to install it.
  Install Node from https://nodejs.org (LTS), then run this again.
  AEGIS itself has no dependencies - Node is the only thing it needs.
"@
  }
  Warn "Node.js is not installed."
  Write-Host "  It can be installed from Microsoft's own package repository with:" -ForegroundColor DarkGray
  Write-Host ""
  Write-Host "      winget install --id OpenJS.NodeJS.LTS -e" -ForegroundColor Cyan
  Write-Host ""
  $reply = ''
  try { $reply = Read-Host "  Run that now? [y/N]" } catch { }
  if ($reply -notmatch '^[Yy]') { Die "nothing installed. Run the command above, then re-run this installer." }
  Write-Host ""
  & winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
  if ($LASTEXITCODE -ne 0) { Die "that failed - run it by hand, then re-run this installer." }
  foreach ($p in $nodeSearchPaths) {
    if (Test-Path $p) { $env:PATH = (Split-Path $p) + ';' + $env:PATH; $node = Get-Command node; break }
  }
  if (-not $node) { Die "Node installed but is not on PATH yet. Open a new PowerShell window and re-run this." }
}
$major = [int](& node -p 'process.versions.node.split(".")[0]')
if ($major -lt 18) { Die "Node.js 18 or newer is required (found $(& node -v)). Upgrade and run this again." }
Step "node            $(& node -v)"

# --- fetch ------------------------------------------------------------------
$upgrade = $false
$git = Get-Command git -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $Dir '.git')) {
  $upgrade = $true
  Step "upgrading       $Dir"
  if (-not $git) { Die "$Dir is a git checkout but git is not installed." }
  & git -C $Dir fetch --quiet --depth 1 origin $Branch
  if ($LASTEXITCODE -ne 0) { Die "could not reach $Repo" }
  & git -C $Dir reset --quiet --hard "origin/$Branch"
  if ($LASTEXITCODE -ne 0) { Die "could not update $Dir - move it aside and re-run." }
}
elseif ($git) {
  Step "cloning         $Repo"
  & git clone --quiet --depth 1 --branch $Branch $Repo $Dir
  if ($LASTEXITCODE -ne 0) { Die "could not clone $Repo" }
}
else {
  # No git: fall back to the zip so a bare machine still works.
  Step "downloading     $Repo ($Branch)"
  $zip = Join-Path $env:TEMP "aegis-$Branch.zip"
  $tmp = Join-Path $env:TEMP "aegis-extract-$([guid]::NewGuid().ToString('N'))"
  Invoke-WebRequest -Uri "$Repo/archive/refs/heads/$Branch.zip" -OutFile $zip -UseBasicParsing
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
  if (-not $inner) { Die "the downloaded archive was empty" }
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  Copy-Item -Path (Join-Path $inner.FullName '*') -Destination $Dir -Recurse -Force
  Remove-Item $zip, $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- configure + build ------------------------------------------------------
# setup.mjs is idempotent: it keeps existing tokens unless --rotate is passed,
# so an upgrade never orphans the agents already reporting in.
Step "configuring     tokens + build"
Push-Location $Dir
try {
  & node setup.mjs --port $Port | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "setup failed - run 'node setup.mjs' in $Dir to see why" }
} finally { Pop-Location }

# --- scheduled task ---------------------------------------------------------
$taskName = 'AEGIS Server'
$service = $false
try {
  Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
  $action  = New-ScheduledTaskAction -Execute $node.Source `
              -Argument "`"$Dir\server\aegis-server.mjs`" --config `"$Dir\server\config.json`"" `
              -WorkingDirectory $Dir
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  # Stop-on-idle and the default execution time limit would both kill a server
  # that is doing its job by sitting still.
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  $settings.DisallowStartIfOnBatteries = $false
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'AEGIS SOC console and agent ingest server' | Out-Null
  Start-ScheduledTask -TaskName $taskName
  $service = $true
  Step "service         Scheduled Task (starts at logon)"
} catch {
  Warn "could not register a Scheduled Task: $($_.Exception.Message)"
  Warn "starting it in this session instead - it will not survive a reboot."
  Start-Process -FilePath $node.Source `
    -ArgumentList "`"$Dir\server\aegis-server.mjs`"", '--config', "`"$Dir\server\config.json`"" `
    -WorkingDirectory $Dir -WindowStyle Hidden
}

# --- wait for it to actually answer ----------------------------------------
Step "waiting         for the server to come up"
$up = $false
foreach ($i in 1..60) {
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $up = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $up) { Die "the server did not come up within 60s. Run 'node server\aegis-server.mjs --config server\config.json' in $Dir to see why." }

# --- done -------------------------------------------------------------------
$cfg = Get-Content (Join-Path $Dir 'server\config.json') -Raw | ConvertFrom-Json
$lan = & node -e "const os=require('os');for(const[n,a]of Object.entries(os.networkInterfaces())){if(/vmware|virtualbox|hyper-v|vethernet|docker|tailscale|zerotier|wg/i.test(n))continue;for(const x of a||[])if(x.family==='IPv4'&&!x.internal){console.log(x.address);process.exit(0)}}console.log('127.0.0.1')"

Write-Host ""
Write-Host "  AEGIS is running." -ForegroundColor Green
Write-Host ""
Write-Host "  Open the console    http://127.0.0.1:$Port"
Write-Host "  Agents report to    http://${lan}:$Port"
Write-Host ""
Write-Host "  The console will ask you to create the first account. It becomes the" -ForegroundColor DarkGray
Write-Host "  lead, and can add everyone else from there." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Let agents through the firewall (admin PowerShell, once):" -ForegroundColor DarkGray
Write-Host "    New-NetFirewallRule -DisplayName 'AEGIS $Port' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Domain,Private"
Write-Host ""
Write-Host "  Add this machine as an endpoint (admin PowerShell):" -ForegroundColor DarkGray
Write-Host "    $Dir\agents\aegis-agent.ps1 -Server http://${lan}:$Port -EnrollmentToken $($cfg.enrollmentToken) -Install"
Write-Host ""
if ($service) {
  Write-Host "  stop    Stop-ScheduledTask -TaskName '$taskName'" -ForegroundColor DarkGray
  Write-Host "  remove  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor DarkGray
  Write-Host ""
}
if ($upgrade) { Write-Host "  Upgraded in place - your tokens and data were kept." -ForegroundColor DarkGray; Write-Host "" }
