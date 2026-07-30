#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigurationPath = "$env:ProgramFiles\MonitoringPlatform\app\appsettings.Production.json",
  [string]$ServiceName = 'MonitoringPlatform',
  [switch]$ConfirmDemotion
)

$ErrorActionPreference = 'Stop'
if (-not $ConfirmDemotion) { throw 'ConfirmDemotion is required.' }
$configuration = [IO.Path]::GetFullPath($ConfigurationPath)
if (-not (Test-Path -LiteralPath $configuration -PathType Leaf)) { throw "Configuration not found: $configuration" }
if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Fence local writes and configure passive role')) { return }
$backup = "$configuration.pre-demotion-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $configuration -Destination $backup -Force
try {
  Stop-Service -Name $ServiceName -Force
  $settings = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
  if (-not $settings.HighAvailability) { throw 'HighAvailability configuration is missing.' }
  $settings.HighAvailability.Enabled = $true
  $settings.HighAvailability.ConfiguredRole = 'passive'
  $temporary = "$configuration.tmp"
  $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
  Move-Item -LiteralPath $temporary -Destination $configuration -Force
  Start-Service -Name $ServiceName
}
catch {
  Copy-Item -LiteralPath $backup -Destination $configuration -Force
  Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
  throw
}
Write-Host "Node is passive. Wait at least one lease TTL before promoting another node. Configuration backup: $backup"
