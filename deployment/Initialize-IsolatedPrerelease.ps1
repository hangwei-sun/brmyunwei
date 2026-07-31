[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:LOCALAPPDATA\MonitoringPlatform-Prerelease",
    [string]$AdminUsername = 'prerelease-admin',
    [ValidateRange(1024, 65535)]
    [int]$HttpsPort = 8443
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

function Test-CertificateEnhancedKeyUsage {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$RequiredOid)
    $extensions = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($extensions.Count -ne 1) { return $false }
    try {
        $decoded = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
        $decoded.CopyFrom($extensions[0])
        return @($decoded.EnhancedKeyUsages | Where-Object { $_.Value -eq $RequiredOid }).Count -eq 1
    }
    catch { return $false }
}

$packageRoot = $PSScriptRoot
$sourceApp = Join-Path $packageRoot 'app'
$sourceAgent = Join-Path $packageRoot 'agent'
$install = [System.IO.Path]::GetFullPath($InstallRoot)
$currentUserRoot = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA)
if (-not $install.StartsWith($currentUserRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The isolated prerelease must remain under the current user LocalAppData directory.'
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceApp 'MonitoringPlatform.Api.exe') -PathType Leaf)) {
    throw 'Run this script from an extracted release package.'
}
if (Test-Path -LiteralPath $install) {
    throw "Prerelease install path already exists: $install"
}

function Test-HttpsPortAvailable([int]$Port) {
    $excludedOutput = & netsh.exe interface ipv4 show excludedportrange protocol=tcp 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Windows TCP excluded port ranges before initializing HTTPS port $Port."
    }

    foreach ($match in [regex]::Matches(($excludedOutput -join [Environment]::NewLine), '(?m)^\s*(\d+)\s+(\d+)\s*$')) {
        $rangeStart = [int]$match.Groups[1].Value
        $rangeEnd = [int]$match.Groups[2].Value
        if ($Port -ge $rangeStart -and $Port -le $rangeEnd) {
            throw "HTTPS port $Port is reserved by a Windows TCP excluded port range ($rangeStart-$rangeEnd). Choose an approved port with -HttpsPort before initializing."
        }
    }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    try {
        $listener.Start()
    }
    catch {
        throw "HTTPS port $Port cannot be bound on this computer: $($_.Exception.Message) Choose an approved unused port with -HttpsPort before initializing."
    }
    finally {
        $listener.Stop()
    }
}

Test-HttpsPortAvailable -Port $HttpsPort

$appRoot = Join-Path $install 'app'
$dataRoot = Join-Path $install 'data'
$backupRoot = Join-Path $install 'backup'
$keysRoot = Join-Path $install 'keys'
$agentRoot = Join-Path $install 'agent-package'
$rootCertificate = $null
$certificate = $null
$createdInstall = $false
try {
$createdInstall = $true
New-Item -ItemType Directory -Path $appRoot, $dataRoot, $backupRoot, $keysRoot, $agentRoot -Force | Out-Null
Copy-Item -Path (Join-Path $sourceApp '*') -Destination $appRoot -Recurse -Force
Copy-Item -Path (Join-Path $sourceAgent '*') -Destination $agentRoot -Recurse -Force

$machineName = [Environment]::MachineName
$dnsNames = @('localhost', $machineName) | Select-Object -Unique
$certificateCommonName = "MonitoringPlatform-Prerelease-$machineName-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$rootCertificateCommonName = "Monitoring Platform Prerelease Root CA - $machineName"
$rootCertificate = New-SelfSignedCertificate `
    -Subject "CN=$rootCertificateCommonName" `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -FriendlyName 'Monitoring Platform Isolated Prerelease Root CA' -NotAfter (Get-Date).AddDays(365) `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
    -Type Custom -KeyUsage CertSign, CRLSign, DigitalSignature `
    -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0')
$certificate = New-SelfSignedCertificate -Subject "CN=$certificateCommonName" -DnsName $dnsNames -Signer $rootCertificate `
    -CertStoreLocation 'Cert:\CurrentUser\My' -Type Custom -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
    -FriendlyName 'Monitoring Platform Isolated Prerelease' -NotAfter (Get-Date).AddDays(90) `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable
$rootCertificateSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($rootCertificate.RawData))).Replace('-', '')
if (-not $rootCertificate.HasPrivateKey -or -not $certificate.HasPrivateKey -or
    $certificate.Issuer -ne $rootCertificate.Subject -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(7) -or
    -not (Test-CertificateEnhancedKeyUsage $certificate '1.3.6.1.5.5.7.3.1')) {
    throw 'Generated prerelease TLS certificate failed private-key, issuer, lifetime, or Server Authentication EKU validation.'
}
$rootConstraints = $rootCertificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
$rootKeyUsage = $rootCertificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
if (-not $rootConstraints -or -not $rootConstraints.CertificateAuthority -or -not $rootKeyUsage -or
    ($rootKeyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -eq 0) {
    throw 'Generated prerelease root certificate is not a certificate-signing authority.'
}
$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
try {
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    [void]$chain.ChainPolicy.ExtraStore.Add($rootCertificate)
    $chainValid = $chain.Build($certificate)
    $chainRoot = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $chainRootSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($chainRoot.RawData))).Replace('-', '')
    if (-not $chainValid -or $chainRootSha256 -ne $rootCertificateSha256) {
        throw 'Generated prerelease TLS certificate does not chain to the generated root certificate.'
    }
}
finally {
    $chain.Dispose()
}
$rootPublicCertificate = Join-Path $install 'prerelease-root-ca.cer'
$publicCertificate = Join-Path $install 'prerelease-server.cer'
Export-Certificate -Cert $rootCertificate -FilePath $rootPublicCertificate -Force | Out-Null
Export-Certificate -Cert $certificate -FilePath $publicCertificate -Force | Out-Null

$configuration = [ordered]@{
    AllowedHosts = "localhost;$machineName"
    ConnectionStrings = @{ Monitoring = "Data Source=$dataRoot\monitoring.db;Cache=Shared" }
    Authentication = @{ DataProtectionKeysPath = $keysRoot; BootstrapAdmin = @{ Enabled = $false; Username = ''; Password = '' } }
    AgentEnrollment = @{ Enabled = $true; AllowLegacyAgentKeys = $false; IssuerCertificateSubject = $rootCertificateCommonName; IssuerCertificateSha256 = $rootCertificateSha256; IssuerStoreName = 'My'; IssuerStoreLocation = 'CurrentUser'; TokenMinutes = 10; CertificateDays = 90; RotationGraceMinutes = 15 }
    # The prerelease root is intentionally imported through a visible, operator-approved flow.
    # The exact randomized subject still pins certificate selection before that trust is granted.
    Kestrel = @{ Endpoints = @{ Https = @{ Url = "https://0.0.0.0:$HttpsPort"; Certificate = @{ Subject = $certificateCommonName; Store = 'My'; Location = 'CurrentUser'; AllowInvalid = $true } } } }
    TencentCloudSms = @{ Enabled = $false; RolloutMode = 'disabled'; TestPhoneNumbers = @(); Region = 'ap-guangzhou'; SdkAppId = ''; SignName = ''; TemplateId = '' }
    NotificationContacts = @{ Groups = @{} }
    NotificationWorker = @{ Enabled = $true; ScanSeconds = 5; MaxAttempts = 10 }
    ProbeWorker = @{ Enabled = $true; MaxConcurrency = 8; LoopDelaySeconds = 1; MaxBackoffSeconds = 900; JitterMilliseconds = 500 }
    AgentHealth = @{ Enabled = $true; ScanSeconds = 15; OfflineSeconds = 180 }
    DataMaintenance = @{ Enabled = $true; MetricDays = 30; ResolvedIncidentDays = 365; AuditDays = 730; RunHourLocal = 2; BackupDirectory = $backupRoot; BackupKeepDays = 30 }
}
$configuration | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $appRoot 'appsettings.Production.json') -Encoding utf8

function New-RandomPart([string]$Characters, [int]$Length) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 4
        -join (1..$Length | ForEach-Object {
            $rng.GetBytes($bytes)
            $Characters[[BitConverter]::ToUInt32($bytes, 0) % $Characters.Length]
        })
    }
    finally { $rng.Dispose() }
}
$password = (New-RandomPart 'ABCDEFGHJKLMNPQRSTUVWXYZ' 5) + (New-RandomPart 'abcdefghijkmnopqrstuvwxyz' 7) + `
    (New-RandomPart '23456789' 5) + (New-RandomPart '!@$%*_-+' 5)
$secretBytes = [Text.Encoding]::UTF8.GetBytes($password)
$protectedBytes = [Security.Cryptography.ProtectedData]::Protect($secretBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes((Join-Path $install 'bootstrap-admin.dpapi'), $protectedBytes)

[ordered]@{ adminUsername = $AdminUsername; certificateSubject = $certificateCommonName; certificateThumbprint = $certificate.Thumbprint; rootCertificateThumbprint = $rootCertificate.Thumbprint; httpsPort = $HttpsPort; machineName = $machineName; initializedAt = [DateTimeOffset]::Now.ToString('O') } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $install 'initialized.json') -Encoding utf8
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $install /inheritance:r /grant:r "$identity`:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to secure the isolated prerelease directory.' }

Write-Host "Initialized isolated prerelease: $install"
Write-Host "HTTPS URL: https://localhost:$HttpsPort"
Write-Host "Root CA certificate for approved test servers: $rootPublicCertificate"
}
catch {
    if ($certificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
    if ($rootCertificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($rootCertificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
    if ($createdInstall -and (Test-Path -LiteralPath $install)) {
        Remove-Item -LiteralPath $install -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}
