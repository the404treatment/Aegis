<#
  Windows agent installer. Two ways in:

    # From a checkout / unzipped download - finds the agent next to itself:
    powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
      -Server https://aegis.internal:8787 -Token <enrollment-token>

    # From a GPO startup script / Intune / RMM push, with the agent staged on
    # a share - point -Source at it:
    powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
      -Server https://x:8787 -Token <token> -Source \\fileserver\sw$\aegis-agent.ps1

  This wrapper exists for unattended pushes. If you already have the checkout
  in front of you, you can skip it entirely and run the agent directly:
    powershell -ExecutionPolicy Bypass -File ..\agents\aegis-agent.ps1 `
      -Server <url> -EnrollmentToken <token> -Install
#>
param(
  [Parameter(Mandatory)][string]$Server,
  [Parameter(Mandatory)][string]$Token,
  # Where to copy the agent from. Empty = auto-locate: look for
  # agents\aegis-agent.ps1 relative to this script (the checkout layout), so an
  # unzipped download Just Works with no path to know. Only set this for a
  # staged-share push where the agent is not sitting beside the repo.
  [string]$Source = "",
  [int]$IntervalSeconds = 300
)
$ErrorActionPreference = 'Stop'

# Resolve the agent source. In a checkout this script lives in deploy\ and the
# agent in agents\ - the single most common reason the old default failed was
# that it pointed at a corporate fileshare that does not exist on a laptop.
if (-not $Source) {
  $here = Split-Path -Parent $MyInvocation.MyCommand.Path
  $candidates = @(
    (Join-Path $here '..\agents\aegis-agent.ps1'),   # deploy\ -> ..\agents\
    (Join-Path $here 'aegis-agent.ps1'),             # same folder
    (Join-Path $here 'agents\aegis-agent.ps1')       # run from repo root
  )
  $Source = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $Source) {
    Write-Host ''
    Write-Host '  Could not find aegis-agent.ps1 automatically.' -ForegroundColor Yellow
    Write-Host '  Looked in:' -ForegroundColor Yellow
    $candidates | ForEach-Object { Write-Host ("    {0}" -f (Resolve-Path -LiteralPath $_ -ErrorAction SilentlyContinue).Path) -ForegroundColor DarkGray }
    Write-Host '  Pass -Source <path-to-aegis-agent.ps1> to point at it.' -ForegroundColor Cyan
    Write-Host ''
    exit 1
  }
}
if (-not (Test-Path $Source)) {
  Write-Host ("  Source not found: {0}" -f $Source) -ForegroundColor Yellow
  exit 1
}

$dest = Join-Path $env:ProgramData 'AEGIS'
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item $Source (Join-Path $dest 'aegis-agent.ps1') -Force

# Hand off to the agent's own installer. It self-elevates and re-launches with
# -ExecutionPolicy Bypass if this shell is not already elevated, so this wrapper
# does not have to duplicate that logic.
& (Join-Path $dest 'aegis-agent.ps1') -Server $Server -EnrollmentToken $Token -IntervalSeconds $IntervalSeconds -Install
Write-Host "AEGIS agent installed on $env:COMPUTERNAME"
