<#
  One-line Windows agent installer. Intended for GPO startup script, Intune,
  or an RMM push.

    powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
      -Server https://aegis.internal:8787 -Token <enrollment-token>

  Downloads nothing: point -Source at a share holding aegis-agent.ps1.
#>
param(
  [Parameter(Mandatory)][string]$Server,
  [Parameter(Mandatory)][string]$Token,
  [string]$Source = "\\fileserver\software$\aegis\aegis-agent.ps1",
  [int]$IntervalSeconds = 300
)
$ErrorActionPreference = 'Stop'
$dest = "$env:ProgramData\AEGIS"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item $Source "$dest\aegis-agent.ps1" -Force
& "$dest\aegis-agent.ps1" -Server $Server -EnrollmentToken $Token -IntervalSeconds $IntervalSeconds -Install
Write-Host "AEGIS agent installed on $env:COMPUTERNAME"
