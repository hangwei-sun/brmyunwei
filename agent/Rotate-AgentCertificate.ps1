#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 :]{64,95}$')][string]$NewCertificateSha256,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ApprovedSignerThumbprint,
  [int]$MinimumRemainingDays = 14,
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

$approvedSigner = $ApprovedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
$selfSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($selfSignature.Status -ne 'Valid' -or -not $selfSignature.SignerCertificate -or $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $approvedSigner) {
  throw 'Rotation script signature is missing, invalid, or not from the approved signer.'
}
$thumbprint = $NewCertificateSha256.Replace(' ', '').Replace(':', '').ToUpperInvariant()
if ($thumbprint.Length -ne 64) { throw 'NewCertificateSha256 must be a SHA-256 certificate hash.' }
$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
  $_.HasPrivateKey -and (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $thumbprint)
} | Select-Object -First 1
if (-not $certificate) { throw 'New client certificate was not found with an accessible private key.' }
if ($certificate.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow.AddDays($MinimumRemainingDays)) { throw 'New client certificate expires too soon.' }
if (-not ($certificate.PrivateKey -is [Security.Cryptography.RSACryptoServiceProvider])) { throw 'Rotation requires a CSP private key so LOCAL SERVICE access can be enforced.' }
$keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
if (-not (Test-Path -LiteralPath $keyPath)) { throw 'Could not locate the new certificate private key.' }
$acl = Get-Acl -LiteralPath $keyPath
$acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('LOCAL SERVICE', 'Read', 'Allow')))
Set-Acl -LiteralPath $keyPath -AclObject $acl

$configPath = Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe.config'
if (-not (Test-Path -LiteralPath $configPath)) { throw 'Agent configuration was not found.' }
[xml]$currentConfiguration = Get-Content -LiteralPath $configPath -Raw
$agentName = ($currentConfiguration.configuration.appSettings.add | Where-Object key -eq 'AgentName').value
if ([string]::IsNullOrWhiteSpace($agentName) -or $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne $agentName) {
  throw 'New client certificate subject does not match the configured AgentName.'
}
if (-not (Test-CertificateEnhancedKeyUsage $certificate '1.3.6.1.5.5.7.3.2')) {
  throw 'New certificate is missing the Client Authentication EKU.'
}
$backupPath = "$configPath.pre-rotation-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $configPath -Destination $backupPath -Force
if (-not $PSCmdlet.ShouldProcess($ServiceName, "Activate certificate $thumbprint")) { return }
try {
  [xml]$configuration = Get-Content -LiteralPath $configPath -Raw
  foreach ($key in @('RequireClientCertificate', 'ClientCertificateThumbprint')) {
    $node = $configuration.configuration.appSettings.add | Where-Object key -eq $key
    if (-not $node) { throw "Agent configuration key is missing: $key" }
    $node.value = if ($key -eq 'RequireClientCertificate') { 'true' } else { $thumbprint }
  }
  $configuration.Save($configPath)
  Restart-Service -Name $ServiceName -Force
  if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Agent did not return to Running state.' }
}
catch {
  Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
  Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  throw
}
Write-Host "Certificate rotation completed. Backup retained at $backupPath"
