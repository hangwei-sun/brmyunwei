#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9 :]{64,95}$')]
    [string[]]$PrivateKeyCertificateSha256,
    [ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')]
    [string]$DataProtectionCertificateThumbprint,
    [string]$BootstrapUsername,
    [string]$BootstrapPasswordProtectedFile,
    [string]$WitnessTokenProtectedFile,
    [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform",
    [string]$DataRoot = "$env:ProgramData\MonitoringPlatform",
    [string]$ServiceName = 'MonitoringPlatform'
)

$ErrorActionPreference = 'Stop'

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

function Test-PathUnderRoot {
    param([string]$Path, [string]$Root)
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $resolvedPath.StartsWith($resolvedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-NormalizedSha256 {
    param([string]$Value)
    return $Value.Replace(' ', '').Replace(':', '').ToUpperInvariant()
}

function Get-CertificateSha256 {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Certificate.RawData))).Replace('-', '')
}

function Get-PinnedCertificate {
    param([string]$CertificateSha256)
    $expected = ConvertTo-NormalizedSha256 $CertificateSha256
    $matches = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $expected
    })
    if ($matches.Count -ne 1) { throw "Exactly one LocalMachine\My certificate with private key must match SHA-256 $expected." }
    return $matches[0]
}

function Read-CurrentUserProtectedSecret {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $resolved = [IO.Path]::GetFullPath($Path)
    $localAppData = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($localAppData, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Name must be an existing file below the current user LocalAppData directory."
    }
    try {
        $bytes = [IO.File]::ReadAllBytes($resolved)
        $value = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
        if ([string]::IsNullOrWhiteSpace($value)) { throw "$Name is empty." }
        return $value
    }
    finally {
        Remove-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue
    }
}

function Grant-CertificatePrivateKeyRead {
    param([string]$CertificateSha256, [string]$Identity)
    $certificate = Get-PinnedCertificate $CertificateSha256
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
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
if (-not (Test-Path -LiteralPath $sourceApp -PathType Container)) {
    $appArchive = Join-Path $package 'app.zip'
    if (Test-Path -LiteralPath $appArchive -PathType Leaf) {
        Expand-Archive -LiteralPath $appArchive -DestinationPath $sourceApp -Force
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceApp 'MonitoringPlatform.Api.exe') -PathType Leaf)) {
    throw 'The package does not contain app\MonitoringPlatform.Api.exe.'
}
if (-not (Test-Path -LiteralPath $sourceConfig -PathType Leaf)) {
    throw 'Create appsettings.Production.json from the supplied template before installation.'
}
try {
    $centerConfig = Get-Content -LiteralPath $sourceConfig -Raw | ConvertFrom-Json
}
catch {
    throw "Center configuration is not valid JSON: $($_.Exception.Message)"
}
$certificateConfig = $centerConfig.Kestrel.Endpoints.Https.Certificate
if (-not $certificateConfig -or [string]::IsNullOrWhiteSpace($certificateConfig.Subject) -or
    $certificateConfig.Store -ne 'My' -or $certificateConfig.Location -ne 'LocalMachine' -or $certificateConfig.AllowInvalid -ne $false) {
    throw 'Center HTTPS certificate must use an exact subject from LocalMachine\My with AllowInvalid=false.'
}
$dataProtectionCertificate = $null
if (-not [string]::IsNullOrWhiteSpace($centerConfig.Authentication.DataProtectionCertificateThumbprint)) {
    $configuredDataProtectionThumbprint = ([string]$centerConfig.Authentication.DataProtectionCertificateThumbprint).Replace(' ', '').ToUpperInvariant()
    if ($configuredDataProtectionThumbprint -notmatch '^[A-F0-9]{40}$') { throw 'Data Protection certificate thumbprint must contain exactly 40 hexadecimal characters.' }
    if ([string]::IsNullOrWhiteSpace($DataProtectionCertificateThumbprint) -or $configuredDataProtectionThumbprint -ne $DataProtectionCertificateThumbprint.Replace(' ', '').ToUpperInvariant()) {
        throw 'DataProtectionCertificateThumbprint must match the certificate referenced by configuration.'
    }
    $dataProtectionMatches = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $configuredDataProtectionThumbprint })
    if ($dataProtectionMatches.Count -ne 1) { throw 'Exactly one LocalMachine\\My Data Protection certificate with a private key is required.' }
    $dataProtectionCertificate = $dataProtectionMatches[0]
}
elseif ($DataProtectionCertificateThumbprint) { throw 'DataProtectionCertificateThumbprint was supplied but is not referenced by configuration.' }
$providedPins = @($PrivateKeyCertificateSha256 | ForEach-Object { ConvertTo-NormalizedSha256 $_ } | Select-Object -Unique)
$pinnedCertificates = @($providedPins | ForEach-Object { Get-PinnedCertificate $_ })
$httpsStore = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
try {
    $httpsStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $kestrelMatches = @($httpsStore.Certificates.Find(
        [Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectName,
        [string]$certificateConfig.Subject, $true) | Where-Object { $_.HasPrivateKey })
}
finally {
    $httpsStore.Close()
}
if ($kestrelMatches.Count -ne 1) {
    throw 'Kestrel certificate lookup must resolve to exactly one valid LocalMachine\My certificate with a private key.'
}
$httpsCertificate = $kestrelMatches[0]
$httpsPin = Get-CertificateSha256 $httpsCertificate
if ($httpsPin -notin $providedPins -or
    -not (Test-CertificateEnhancedKeyUsage $httpsCertificate '1.3.6.1.5.5.7.3.1')) {
    throw 'The Kestrel-selected HTTPS certificate must match a supplied SHA-256 pin and include the Server Authentication EKU.'
}
$requiredPins = @($httpsPin)
if ($centerConfig.AgentEnrollment.Enabled) {
    if ([string]::IsNullOrWhiteSpace($centerConfig.AgentEnrollment.IssuerCertificateSubject) -or
        $centerConfig.AgentEnrollment.IssuerStoreName -ne 'My' -or $centerConfig.AgentEnrollment.IssuerStoreLocation -ne 'LocalMachine') {
        throw 'Enabled Agent enrollment must use an exact issuer subject from LocalMachine\My.'
    }
    $issuerPin = ConvertTo-NormalizedSha256 ([string]$centerConfig.AgentEnrollment.IssuerCertificateSha256)
    if (-not [regex]::IsMatch($issuerPin, '^[A-F0-9]{64}$')) {
        throw 'Agent enrollment issuer SHA-256 must contain exactly 64 hexadecimal characters.'
    }
    $issuerCertificates = @($pinnedCertificates | Where-Object {
        (Get-CertificateSha256 $_) -eq $issuerPin -and
        $_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq [string]$centerConfig.AgentEnrollment.IssuerCertificateSubject
    })
    $issuerConstraints = if ($issuerCertificates.Count -eq 1) {
        $issuerCertificates[0].Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    }
    $issuerKeyUsage = if ($issuerCertificates.Count -eq 1) {
        $issuerCertificates[0].Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
    }
    if ($issuerCertificates.Count -ne 1 -or $issuerCertificates[0].NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $issuerCertificates[0].NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(7) -or
        -not $issuerConstraints -or -not $issuerConstraints.CertificateAuthority -or -not $issuerKeyUsage -or
        ($issuerKeyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -eq 0) {
        throw 'The enabled Agent enrollment issuer must match its configured subject and SHA-256 pin and be a valid certificate-signing CA.'
    }
    $requiredPins += $issuerPin
}
$requiredPins = @($requiredPins | Select-Object -Unique)
if (@($providedPins | Where-Object { $_ -notin $requiredPins }).Count -ne 0 -or
    @($requiredPins | Where-Object { $_ -notin $providedPins }).Count -ne 0) {
    throw 'PrivateKeyCertificateSha256 must contain only the HTTPS and enabled Agent enrollment issuer certificate pins referenced by configuration.'
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service $ServiceName already exists. Use the documented upgrade procedure."
}
if (($BootstrapUsername -and -not $BootstrapPasswordProtectedFile) -or (-not $BootstrapUsername -and $BootstrapPasswordProtectedFile)) {
    throw 'BootstrapUsername and BootstrapPasswordProtectedFile must be supplied together.'
}
$bootstrapPassword = Read-CurrentUserProtectedSecret -Path $BootstrapPasswordProtectedFile -Name 'BootstrapPasswordProtectedFile'
$witnessToken = Read-CurrentUserProtectedSecret -Path $WitnessTokenProtectedFile -Name 'WitnessTokenProtectedFile'
if ($bootstrapPassword -and ($BootstrapUsername.Trim().Length -lt 3 -or $BootstrapUsername.Trim().Length -gt 64 -or $bootstrapPassword.Length -lt 12)) { throw 'Bootstrap administrator details are invalid.' }
if ($witnessToken -and ($witnessToken.Length -lt 32 -or $witnessToken.Length -gt 256)) { throw 'Witness token must be between 32 and 256 characters.' }

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
    if ($dataProtectionCertificate) {
        Grant-CertificatePrivateKeyRead -CertificateSha256 (Get-CertificateSha256 $dataProtectionCertificate) -Identity $serviceIdentity
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
if ($bootstrapPassword -or $witnessToken) {
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $environment = @()
    if ($bootstrapPassword) {
        $environment += 'Authentication__BootstrapAdmin__Enabled=true'
        $environment += "Authentication__BootstrapAdmin__Username=$($BootstrapUsername.Trim())"
        $environment += "Authentication__BootstrapAdmin__Password=$bootstrapPassword"
    }
    if ($witnessToken) { $environment += "HighAvailability__WitnessBearerToken=$witnessToken" }
    Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value $environment
}
Start-Service -Name $ServiceName
if ($bootstrapPassword) {
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $remaining = @((Get-ItemProperty -LiteralPath $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment | Where-Object { $_ -notlike 'Authentication__BootstrapAdmin__*' })
    Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value $remaining
}
$bootstrapPassword = $null
$witnessToken = $null
Write-Host "Service installed and started: $ServiceName"
