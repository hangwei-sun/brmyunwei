#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    [string]$DatabasePath = "$env:ProgramData\MonitoringPlatform\data\monitoring.db",
    [string]$ServiceName = 'MonitoringPlatform'
)

$ErrorActionPreference = 'Stop'
$backup = [System.IO.Path]::GetFullPath($BackupPath)
$database = [System.IO.Path]::GetFullPath($DatabasePath)
$checksumPath = "$backup.sha256"
if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "Backup not found: $backup" }
if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) { throw "Checksum not found: $checksumPath" }

$expected = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [string]::Equals($expected, $actual, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Backup checksum verification failed.'
}

$service = Get-Service -Name $ServiceName -ErrorAction Stop
if ($service.Status -ne 'Stopped') {
    throw "Stop service $ServiceName before restoring the database."
}
if (-not $PSCmdlet.ShouldProcess($database, "Restore verified backup $backup")) { return }

$databaseDirectory = Split-Path -Parent $database
New-Item -ItemType Directory -Path $databaseDirectory -Force | Out-Null
$rollbackPath = "$database.pre-restore-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
if (Test-Path -LiteralPath $database) {
    Move-Item -LiteralPath $database -Destination $rollbackPath
}
foreach ($suffix in @('-wal', '-shm')) {
    $sidecar = "$database$suffix"
    if (Test-Path -LiteralPath $sidecar) {
        Move-Item -LiteralPath $sidecar -Destination "$rollbackPath$suffix"
    }
}
Copy-Item -LiteralPath $backup -Destination $database
Write-Host "Database restored. Previous database preserved at: $rollbackPath"
Write-Host "Start $ServiceName and verify /api/health before deleting the rollback copy."
