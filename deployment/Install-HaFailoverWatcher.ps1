#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$NodeId,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$ClusterId,
  [Parameter(Mandatory = $true)][uri]$WitnessUrl,
  [Parameter(Mandatory = $true)][uri]$PrimaryReadyUrl,
  [Parameter(Mandatory = $true)][uri]$PromotedReadyUrl,
  [Parameter(Mandatory = $true)][string]$StandbyReplicaPath,
  [string]$ServiceName = 'MonitoringPlatform',
  [string]$TaskName = 'MonitoringPlatform-HaFailoverWatcher',
  [int]$FailureThreshold = 3,
  [int]$CheckSeconds = 5,
  [ValidateRange(5, 300)][int]$LeaseTtlSeconds = 60
)

$ErrorActionPreference = 'Stop'
if ($WitnessUrl.Scheme -ne 'https' -or $PrimaryReadyUrl.Scheme -ne 'https' -or $PromotedReadyUrl.Scheme -ne 'https') { throw 'WitnessUrl, PrimaryReadyUrl and PromotedReadyUrl must use HTTPS.' }
$watcher = Join-Path $PSScriptRoot 'Watch-HaFailover.ps1'
if (-not (Test-Path -LiteralPath $watcher -PathType Leaf)) { throw "Watcher script not found: $watcher" }
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw "Service not found: $ServiceName" }
if (-not $PSCmdlet.ShouldProcess($TaskName, 'install standby automatic failover watcher')) { return }
if (-not [Diagnostics.EventLog]::SourceExists('MonitoringPlatform')) { New-EventLog -LogName Application -Source 'MonitoringPlatform' }

$arguments = @('-NoProfile', '-File', ('"{0}"' -f $watcher), '-NodeId', $NodeId, '-ClusterId', $ClusterId,
  '-WitnessUrl', $WitnessUrl.AbsoluteUri, '-PrimaryReadyUrl', $PrimaryReadyUrl.AbsoluteUri, '-StandbyReplicaPath', ('"{0}"' -f [IO.Path]::GetFullPath($StandbyReplicaPath)),
  '-PromotedReadyUrl', $PromotedReadyUrl.AbsoluteUri, '-ServiceName', $ServiceName, '-FailureThreshold', $FailureThreshold, '-CheckSeconds', $CheckSeconds,
  '-LeaseTtlSeconds', $LeaseTtlSeconds) -join ' '
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed $TaskName. The watcher reads the witness token only from the protected service environment; it does not put the token into the task command line."
