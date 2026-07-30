#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9 :]{64,95}$')]
    [string[]]$PrivateKeyCertificateSha256,
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatform",
    [string]$ServiceName = 'MonitoringPlatform'
)

$ErrorActionPreference = 'Stop'
function Test-PathUnderRoot {
    param([string]$Path, [string]$Root)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $resolvedPath.StartsWith($resolvedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Grant-CertificatePrivateKeyRead {
    param([string]$CertificateSha256, [string]$Identity)
    $expected = $CertificateSha256.Replace(' ', '').Replace(':', '').ToUpperInvariant()
    $matches = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $expected
    })
    if ($matches.Count -ne 1) { throw "Exactly one LocalMachine\\My certificate with private key must match SHA-256 $expected." }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($matches[0])
    try {
        if ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $rsa.CspKeyContainerInfo.UniqueKeyContainerName
        }
        elseif ($rsa -is [Security.Cryptography.RSACng]) {
            $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsa.Key.UniqueName
        }
        else { throw 'Center certificates must use RSA CAPI or CNG private keys.' }
        if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'Certificate private-key file was not found.' }
        $acl = Get-Acl -LiteralPath $keyPath
        $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Identity, 'Read', 'Allow')))
        Set-Acl -LiteralPath $keyPath -AclObject $acl
    }
    finally { if ($rsa) { $rsa.Dispose() } }
}

$package = [System.IO.Path]::GetFullPath($PackageRoot)
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
if (-not (Test-PathUnderRoot $InstallRoot $env:ProgramFiles) -or -not (Test-PathUnderRoot $DataRoot $env:ProgramData)) {
    throw 'InstallRoot must remain under Program Files and DataRoot must remain under ProgramData.'
}
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
try {
    foreach ($certificateSha256 in ($PrivateKeyCertificateSha256 | Select-Object -Unique)) {
        Grant-CertificatePrivateKeyRead -CertificateSha256 $certificateSha256 -Identity $serviceIdentity
    }
}
catch {
    & sc.exe delete $ServiceName | Out-Null
    throw
}
& icacls.exe $InstallRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the application directory.' }
& icacls.exe $DataRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the data directory.' }
& sc.exe description $ServiceName '轻量化 Windows 机房运维监控中心' | Out-Null
& sc.exe failure $ServiceName 'reset=86400' 'actions=restart/60000/restart/300000' | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Start-Service -Name $ServiceName
Write-Host "Service installed and started: $ServiceName"
