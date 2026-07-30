#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param([string]$ServiceName = 'MonitoringPlatform')

$ErrorActionPreference = 'Stop'
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host "Service not found: $ServiceName"
    return
}
if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Stop and remove Windows service')) { return }
if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
& sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to delete the Windows service.' }
Write-Host 'Service removed. Monitoring data and application files were preserved.'
