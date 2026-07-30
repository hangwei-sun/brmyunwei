#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatform",
    [string]$ServiceName = 'MonitoringPlatform'
)

$ErrorActionPreference = 'Stop'
$package = [System.IO.Path]::GetFullPath($PackageRoot)
$sourceApp = Join-Path $package 'app'
$sourceConfig = Join-Path $package 'appsettings.Production.json'
if (-not (Test-Path -LiteralPath (Join-Path $sourceApp 'MonitoringPlatform.Api.exe') -PathType Leaf)) {
    throw 'The package does not contain app\MonitoringPlatform.Api.exe.'
}
if (-not (Test-Path -LiteralPath $sourceConfig -PathType Leaf)) {
    throw 'Create appsettings.Production.json from the supplied template before installation.'
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service $ServiceName already exists. Use the documented upgrade procedure."
}

$targetApp = Join-Path $InstallRoot 'app'
if (Test-Path -LiteralPath $targetApp) {
    throw "Install target already exists: $targetApp"
}
if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Install $ServiceName")) { return }

New-Item -ItemType Directory -Path $targetApp -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataRoot 'data') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataRoot 'keys') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataRoot 'backup') -Force | Out-Null
Copy-Item -Path (Join-Path $sourceApp '*') -Destination $targetApp -Recurse -Force
Copy-Item -LiteralPath $sourceConfig -Destination (Join-Path $targetApp 'appsettings.Production.json')

$serviceIdentity = "NT SERVICE\$ServiceName"
$exePath = Join-Path $targetApp 'MonitoringPlatform.Api.exe'
& sc.exe create $ServiceName "binPath= `"$exePath`"" 'start= delayed-auto' "obj= $serviceIdentity" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the Windows service.' }
& icacls.exe $InstallRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the application directory.' }
& icacls.exe $DataRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the data directory.' }
& sc.exe description $ServiceName '轻量化 Windows 机房运维监控中心' | Out-Null
& sc.exe failure $ServiceName 'reset=86400' 'actions=restart/60000/restart/300000' | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Start-Service -Name $ServiceName
Write-Host "Service installed and started: $ServiceName"
