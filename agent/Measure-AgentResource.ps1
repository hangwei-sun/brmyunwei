#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$ServiceName = 'MonitoringPlatformAgent',
  [int]$DurationSeconds = 180,
  [double]$MaxAverageCpuPercent = 0.2,
  [double]$MaxWorkingSetMB = 25
)

if ($DurationSeconds -lt 15) { throw 'DurationSeconds must be at least 15.' }
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if (-not $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) {
  throw "Service '$ServiceName' must be installed and running before measurement."
}

$first = Get-Process -Id $service.ProcessId
$cpuStart = $first.CPU
$at = Get-Date
Start-Sleep -Seconds $DurationSeconds
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
$last = Get-Process -Id $service.ProcessId
$elapsed = ((Get-Date) - $at).TotalSeconds
$logical = [Environment]::ProcessorCount
$cpuPercent = if ($elapsed -gt 0) { [math]::Round((($last.CPU - $cpuStart) / $elapsed / $logical) * 100, 3) } else { 0 }
$result = [pscustomobject]@{
  Service = $ServiceName
  ProcessId = $service.ProcessId
  DurationSeconds = [math]::Round($elapsed, 1)
  AverageCpuPercent = $cpuPercent
  WorkingSetMB = [math]::Round($last.WorkingSet64 / 1MB, 2)
  PrivateMemoryMB = [math]::Round($last.PrivateMemorySize64 / 1MB, 2)
  Handles = $last.Handles
  Threads = $last.Threads.Count
  Timestamp = Get-Date -Format o
}
$result | Format-List
if ($cpuPercent -gt $MaxAverageCpuPercent -or $result.WorkingSetMB -gt $MaxWorkingSetMB) {
  throw "Resource budget exceeded: CPU must be <= $MaxAverageCpuPercent% and working set <= $MaxWorkingSetMB MiB."
}
