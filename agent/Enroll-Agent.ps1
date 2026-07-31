#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$AgentName,
  [Parameter(Mandatory = $true)][uri]$EnrollmentEndpoint,
  [Parameter(Mandatory = $true)][uri]$IngestEndpoint,
  [Security.SecureString]$OneTimeEnrollmentToken,
  [string]$TokenProtectedFile,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ApprovedSignerThumbprint,
  [uri]$SecondaryIngestEndpoint,
  [string]$WatchedServices = '',
  [string]$DataRoot = "$env:ProgramData\MonitoringPlatform\Agent",
  [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Agent",
  [string]$ServiceName = 'MonitoringPlatformAgent'
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

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$approvedSigner = $ApprovedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
$selfSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($selfSignature.Status -notin @('Valid', 'UnknownError', 'NotTrusted') -or -not $selfSignature.SignerCertificate -or $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $approvedSigner) {
  throw 'Enrollment script signature is missing, invalid, or not from the approved signer.'
}
if ($EnrollmentEndpoint.Scheme -ne 'https' -or $IngestEndpoint.Scheme -ne 'https') { throw 'Enrollment and ingest endpoints must use HTTPS.' }
$configPath = Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe.config'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw 'Install the signed Agent package before enrollment.' }
if ($TokenProtectedFile) {
  if ($OneTimeEnrollmentToken) { throw 'Specify either OneTimeEnrollmentToken or TokenProtectedFile, not both.' }
  $resolvedTokenFile = [IO.Path]::GetFullPath($TokenProtectedFile)
  $localAppData = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $resolvedTokenFile.StartsWith($localAppData, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $resolvedTokenFile -PathType Leaf)) {
    throw 'TokenProtectedFile must be an existing file below the current user LocalAppData directory.'
  }
  try {
    $protectedToken = [IO.File]::ReadAllBytes($resolvedTokenFile)
    $plainToken = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($protectedToken, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
    $OneTimeEnrollmentToken = ConvertTo-SecureString -String $plainToken -AsPlainText -Force
  }
  finally {
    $plainToken = $null
    Remove-Item -LiteralPath $resolvedTokenFile -Force -ErrorAction SilentlyContinue
  }
}
if (-not $OneTimeEnrollmentToken) { throw 'OneTimeEnrollmentToken or TokenProtectedFile is required.' }
if ($SecondaryIngestEndpoint -and $SecondaryIngestEndpoint.Scheme -ne 'https') { throw 'SecondaryIngestEndpoint must use HTTPS.' }
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$programDataRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $DataRoot.StartsWith($programDataRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'DataRoot must remain below ProgramData.' }
if (-not $PSCmdlet.ShouldProcess($AgentName, 'Create client key, submit enrollment CSR, and activate mTLS')) { return }

$requestDirectory = Join-Path $env:ProgramData "MonitoringPlatform\Enrollment\$AgentName"
New-Item -ItemType Directory -Path $requestDirectory -Force | Out-Null
$infPath = Join-Path $requestDirectory 'agent.inf'
$csrPath = Join-Path $requestDirectory 'agent.req'
$certificatePath = Join-Path $requestDirectory 'agent.cer'
@"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$AgentName"
MachineKeySet = TRUE
Exportable = FALSE
KeyLength = 2048
KeyAlgorithm = RSA
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
KeyUsage = 0xA0
[Extensions]
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.2"
"@ | Set-Content -LiteralPath $infPath -Encoding Ascii

& certreq.exe -new $infPath $csrPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrPath)) { throw 'certreq failed to create the client certificate request.' }

$tokenPointer = [IntPtr]::Zero
try {
  $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($OneTimeEnrollmentToken)
  $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
  if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 32) { throw 'OneTimeEnrollmentToken is missing or too short.' }
  $request = @{ hostName = $AgentName; csrPem = (Get-Content -LiteralPath $csrPath -Raw) } | ConvertTo-Json -Compress
  # Contract: POST {hostName, csrPem} with X-Enrollment-Token. Response includes certificateDerBase64 and certificateSha256.
  $response = Invoke-RestMethod -Method Post -Uri $EnrollmentEndpoint -ContentType 'application/json' -Headers @{ 'X-Enrollment-Token' = $token } -Body $request
}
finally {
  $token = $null
  if ($tokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
}

if (-not $response.certificateDerBase64 -or -not $response.certificateSha256) { throw 'Enrollment response did not contain a certificateDerBase64/certificateSha256 pair.' }
$certificateBytes = [Convert]::FromBase64String([string]$response.certificateDerBase64)
$expectedSha256 = ([string]$response.certificateSha256).Replace(' ', '').Replace(':', '').ToUpperInvariant()
$actualSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($certificateBytes))).Replace('-', '')
if ($expectedSha256 -ne $actualSha256) { throw 'Enrollment certificate hash did not match the server response.' }
[IO.File]::WriteAllBytes($certificatePath, $certificateBytes)
& certreq.exe -accept $certificatePath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'certreq failed to install the issued client certificate.' }

$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
  $_.HasPrivateKey -and (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $actualSha256)
} | Select-Object -First 1
if (-not $certificate) { throw 'The issued certificate was not found with an accessible private key.' }
if (-not (Test-CertificateEnhancedKeyUsage $certificate '1.3.6.1.5.5.7.3.2')) { throw 'The issued certificate is missing the Client Authentication EKU.' }
if (-not ($certificate.PrivateKey -is [Security.Cryptography.RSACryptoServiceProvider])) { throw 'Enrollment requires the Microsoft RSA SChannel CSP private key provider.' }
$keyName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName
if (-not (Test-Path -LiteralPath $keyPath)) { throw 'Could not locate the CSP private key file for LOCAL SERVICE access.' }
$acl = Get-Acl -LiteralPath $keyPath
$localServiceSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-19')
$acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($localServiceSid, 'Read', 'Allow')))
Set-Acl -LiteralPath $keyPath -AclObject $acl

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$wasRunning = $service -and $service.Status -eq 'Running'
$previousStartType = if ($service) { $service.StartType } else { $null }
$configBackup = "$configPath.pre-enrollment-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $configPath -Destination $configBackup -Force
try {
  New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null
  & icacls.exe $DataRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Failed to secure the Agent data directory.' }
  [xml]$configuration = Get-Content -LiteralPath $configPath -Raw
  $updates = @{ AgentName = $AgentName; AgentKey = ''; PrimaryEndpoint = $IngestEndpoint.AbsoluteUri; SecondaryEndpoint = if ($SecondaryIngestEndpoint) { $SecondaryIngestEndpoint.AbsoluteUri } else { '' }; WatchedServices = $WatchedServices.Trim(); DataDirectory = $DataRoot; RequireClientCertificate = 'true'; ClientCertificateStoreLocation = 'LocalMachine'; ClientCertificateStoreName = 'My'; ClientCertificateThumbprint = $actualSha256 }
  foreach ($key in $updates.Keys) {
    $node = $configuration.configuration.appSettings.add | Where-Object key -eq $key
    if (-not $node) { throw "Agent configuration key is missing: $key" }
    $node.value = $updates[$key]
  }
  $configuration.Save($configPath)
  if ($service) {
    Set-Service -Name $ServiceName -StartupType Automatic
    if ($wasRunning) { Restart-Service -Name $ServiceName -Force }
    else { Start-Service -Name $ServiceName }
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Agent did not return to Running state after certificate activation.' }
  }
}
catch {
  Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
  if ($service) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Set-Service -Name $ServiceName -StartupType $previousStartType
    if ($wasRunning) { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue }
  }
  throw
}
Remove-Item -LiteralPath $csrPath, $certificatePath -Force -ErrorAction SilentlyContinue
Write-Host "Enrollment completed. Client certificate SHA-256: $actualSha256. Configuration rollback: $configBackup"
