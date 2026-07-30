#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Witness",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatformWitness",
    [string]$ServiceName = 'MonitoringPlatformWitness',
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

function Test-PathUnderRoot {
    param([string]$Path, [string]$Root)
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    return $resolvedPath.StartsWith($resolvedRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$DataRoot = [System.IO.Path]::GetFullPath($DataRoot)
if (-not (Test-PathUnderRoot -Path $InstallRoot -Root $env:ProgramFiles) -or -not (Test-PathUnderRoot -Path $DataRoot -Root $env:ProgramData)) {
    throw 'InstallRoot must remain under Program Files and DataRoot must remain under ProgramData.'
}
if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Stop and remove Witness Windows service')) { return }

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to delete Witness Windows service.' }
}
if ($RemoveData -and (Test-Path -LiteralPath $DataRoot)) {
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    Write-Host 'Witness service and persisted lease data were removed. Application files were retained.'
}
else {
    Write-Host 'Witness service was removed. Application files and persisted lease data were retained.'
}
