#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)]
    [string]$WitnessConfigPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9 :]{64,95}$')]
    [string]$HttpsCertificateSha256,
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Witness",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatformWitness",
    [string]$ServiceName = 'MonitoringPlatformWitness'
)

$ErrorActionPreference = 'Stop'

function Test-PathUnderRoot {
    param([string]$Path, [string]$Root)
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    return $resolvedPath.StartsWith($resolvedRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

$package = [System.IO.Path]::GetFullPath($PackageRoot)
$config = [System.IO.Path]::GetFullPath($WitnessConfigPath)
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$DataRoot = [System.IO.Path]::GetFullPath($DataRoot)
$programFilesRoot = [System.IO.Path]::GetFullPath($env:ProgramFiles)
$programDataRoot = [System.IO.Path]::GetFullPath($env:ProgramData)
if (-not (Test-PathUnderRoot -Path $InstallRoot -Root $programFilesRoot) -or -not (Test-PathUnderRoot -Path $DataRoot -Root $programDataRoot)) {
    throw 'InstallRoot must remain under Program Files and DataRoot must remain under ProgramData.'
}

$sourceApp = Join-Path $package 'app'
$sourceExe = Join-Path $sourceApp 'MonitoringPlatform.Witness.exe'
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
    throw 'The package does not contain app\MonitoringPlatform.Witness.exe.'
}
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw 'WitnessConfigPath must point to an operator-supplied appsettings.Production.json file.'
}
try {
    $witnessConfig = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
}
catch {
    throw "Witness configuration is not valid JSON: $($_.Exception.Message)"
}
if (-not $witnessConfig.Witness -or [string]::IsNullOrWhiteSpace($witnessConfig.Witness.DataPath)) {
    throw 'Witness configuration must set Witness:DataPath to a local file below DataRoot.'
}
$certificateConfig = $witnessConfig.Kestrel.Endpoints.Https.Certificate
if (-not $certificateConfig -or [string]::IsNullOrWhiteSpace($certificateConfig.Subject) -or
    $certificateConfig.Store -ne 'My' -or $certificateConfig.Location -ne 'LocalMachine' -or $certificateConfig.AllowInvalid -ne $false) {
    throw 'Witness HTTPS certificate must use an exact subject from LocalMachine\My with AllowInvalid=false.'
}
$expectedCertificateSha256 = $HttpsCertificateSha256.Replace(' ', '').Replace(':', '').ToUpperInvariant()
$certificateMatches = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and $_.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow.AddDays(7) -and
    $_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq [string]$certificateConfig.Subject -and
    ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $expectedCertificateSha256
})
if ($certificateMatches.Count -ne 1) { throw 'Exactly one valid HTTPS certificate matching the configured subject and SHA-256 fingerprint is required.' }
$httpsCertificate = $certificateMatches[0]
if (-not ($httpsCertificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.1' })) {
    throw 'Witness HTTPS certificate is missing the Server Authentication EKU.'
}
$configuredDataPath = [System.IO.Path]::GetFullPath([string]$witnessConfig.Witness.DataPath)
if (-not (Test-PathUnderRoot -Path $configuredDataPath -Root $DataRoot)) {
    throw 'Witness:DataPath must remain below DataRoot so the service can be granted only the required write access.'
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service already exists: $ServiceName"
}
if (Test-Path -LiteralPath $InstallRoot) {
    throw "Install directory already exists: $InstallRoot"
}
if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Install $ServiceName")) { return }

New-Item -ItemType Directory -Path $InstallRoot, $DataRoot -Force | Out-Null
Copy-Item -Path (Join-Path $sourceApp '*') -Destination $InstallRoot -Recurse -Force
Copy-Item -LiteralPath $config -Destination (Join-Path $InstallRoot 'appsettings.Production.json') -Force

$serviceIdentity = "NT SERVICE\$ServiceName"
$targetExe = Join-Path $InstallRoot 'MonitoringPlatform.Witness.exe'
& sc.exe create $ServiceName "binPath= `"$targetExe`"" 'start= delayed-auto' "obj= $serviceIdentity" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the Witness Windows service.' }
$rsaPrivateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($httpsCertificate)
try {
    if ($rsaPrivateKey -is [Security.Cryptography.RSACryptoServiceProvider]) {
        $privateKeyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $rsaPrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    }
    elseif ($rsaPrivateKey -is [Security.Cryptography.RSACng]) {
        $privateKeyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsaPrivateKey.Key.UniqueName
    }
    else { throw 'Witness HTTPS certificate must use an RSA CAPI or CNG private key.' }
    if (-not (Test-Path -LiteralPath $privateKeyPath -PathType Leaf)) { throw 'Witness HTTPS certificate private-key file was not found.' }
    $privateKeyAcl = Get-Acl -LiteralPath $privateKeyPath
    $privateKeyAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($serviceIdentity, 'Read', 'Allow')))
    Set-Acl -LiteralPath $privateKeyPath -AclObject $privateKeyAcl
}
catch {
    & sc.exe delete $ServiceName | Out-Null
    throw
}
finally {
    if ($rsaPrivateKey) { $rsaPrivateKey.Dispose() }
}
& icacls.exe $InstallRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the Witness application directory.' }
& icacls.exe $DataRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "$serviceIdentity`:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { & sc.exe delete $ServiceName | Out-Null; throw 'Failed to secure the Witness data directory.' }
& sc.exe description $ServiceName 'Monitoring Platform high-availability lease witness' | Out-Null
& sc.exe failure $ServiceName 'reset=86400' 'actions=restart/60000/restart/300000' | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
Start-Service -Name $ServiceName
Write-Host "Witness service installed and started: $ServiceName"
