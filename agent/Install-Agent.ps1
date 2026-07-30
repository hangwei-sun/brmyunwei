#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$AgentName,
    [Parameter(Mandatory = $true)]
    [Security.SecureString]$AgentKey,
    [Parameter(Mandatory = $true)]
    [uri]$PrimaryEndpoint,
    [uri]$SecondaryEndpoint,
    [string[]]$WatchedServices = @(),
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Agent",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatform\Agent",
    [string]$ServiceName = 'MonitoringPlatformAgent'
)

$ErrorActionPreference = 'Stop'
if ($PrimaryEndpoint.Scheme -ne 'https' -or ($SecondaryEndpoint -and $SecondaryEndpoint.Scheme -ne 'https')) {
    throw 'Agent endpoints must use HTTPS.'
}
if ($WatchedServices.Count -gt 32 -or $WatchedServices | Where-Object { $_.Length -gt 128 }) {
    throw 'WatchedServices accepts at most 32 service names, each up to 128 characters.'
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "Service already exists: $ServiceName" }
if (Test-Path -LiteralPath $InstallRoot) { throw "Install directory already exists: $InstallRoot" }

$sourceRoot = $PSScriptRoot
$sourceExe = Join-Path $sourceRoot 'MonitoringPlatform.Agent.exe'
$sourceConfig = "$sourceExe.config"
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf) -or -not (Test-Path -LiteralPath $sourceConfig -PathType Leaf)) {
    throw 'Run this script from the published Agent package.'
}
if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Install $ServiceName")) { return }

New-Item -ItemType Directory -Path $InstallRoot, $DataRoot -Force | Out-Null
Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $InstallRoot -Recurse -Force
$targetExe = Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe'
$targetConfig = "$targetExe.config"

$plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(($keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AgentKey)))
try {
    [xml]$configuration = Get-Content -LiteralPath $targetConfig -Raw
    $values = @{
        AgentName = $AgentName
        AgentKey = $plainKey
        PrimaryEndpoint = $PrimaryEndpoint.AbsoluteUri
        SecondaryEndpoint = if ($SecondaryEndpoint) { $SecondaryEndpoint.AbsoluteUri } else { '' }
        DataDirectory = $DataRoot
        WatchedServices = ($WatchedServices | Select-Object -Unique) -join ','
    }
    foreach ($key in $values.Keys) {
        $node = $configuration.configuration.appSettings.add | Where-Object key -eq $key
        if (-not $node) { throw "Agent configuration key is missing: $key" }
        $node.value = $values[$key]
    }
    $configuration.Save($targetConfig)
}
finally {
    $plainKey = $null
    if ($keyPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer) }
}

& sc.exe create $ServiceName "binPath= `"$targetExe`"" 'start= auto' 'obj= NT AUTHORITY\LocalService' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the Agent service.' }
& icacls.exe $InstallRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'LOCAL SERVICE:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the Agent application directory.' }
& icacls.exe $DataRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'LOCAL SERVICE:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the Agent data directory.' }
& sc.exe description $ServiceName 'Read-only outbound monitoring agent' | Out-Null
& sc.exe failure $ServiceName 'reset=86400' 'actions=restart/60000/restart/300000' | Out-Null
Start-Service -Name $ServiceName
Write-Host "Agent installed and started: $ServiceName"
