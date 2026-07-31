#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$StandbyReplicaPath,
  [string]$ApplicationPath = "$env:ProgramFiles\MonitoringPlatform\app\MonitoringPlatform.Api.exe",
  [string]$ContentRoot = "$env:ProgramFiles\MonitoringPlatform\app"
)

$ErrorActionPreference = 'Stop'
$replica = [IO.Path]::GetFullPath($StandbyReplicaPath)
$application = [IO.Path]::GetFullPath($ApplicationPath)
$checkpointPath = Join-Path ([IO.Path]::GetFullPath($ContentRoot)) 'Data\ha-replication-checkpoint.json'
if (-not (Test-Path -LiteralPath $replica -PathType Leaf)) { throw "Standby replica not found: $replica" }
if (-not (Test-Path -LiteralPath $application -PathType Leaf)) { throw "Application not found: $application" }
if (-not (Test-Path -LiteralPath $checkpointPath -PathType Leaf)) { throw "Replication checkpoint not found: $checkpointPath" }

& $application --verify-sqlite $replica
if ($LASTEXITCODE -ne 0) { throw 'Standby replica failed SQLite integrity verification.' }
$checkpoint = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
if ([long]$checkpoint.sequence -lt 1 -or [long]$checkpoint.epoch -lt 1 -or [string]::IsNullOrWhiteSpace($checkpoint.hash)) { throw 'Replication checkpoint is incomplete.' }
[pscustomobject]@{
  ReplicaPath = $replica
  ReplicaBytes = (Get-Item -LiteralPath $replica).Length
  Sequence = [long]$checkpoint.sequence
  Epoch = [long]$checkpoint.epoch
  Hash = [string]$checkpoint.hash
  VerifiedAtUtc = [DateTimeOffset]::UtcNow
} | ConvertTo-Json -Depth 3
