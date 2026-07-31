[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$Subject = 'Monitoring Platform Local Agent Signer',
  [ValidateRange(1, 10)][int]$ValidYears = 5,
  [string]$OutputDirectory = (Join-Path $PSScriptRoot 'local-signer')
)

$ErrorActionPreference = 'Stop'
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
  throw "Local signer output already exists: $output"
}
if (-not $PSCmdlet.ShouldProcess($output, 'Create non-exportable local Agent code-signing certificate')) { return }

$certificate = $null
try {
  New-Item -ItemType Directory -Path $output -Force | Out-Null
  $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$Subject" `
    -CertStoreLocation 'Cert:\CurrentUser\My' -FriendlyName 'Monitoring Platform Local Agent Signer' `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears($ValidYears)
  if (-not $certificate.HasPrivateKey) { throw 'Generated code-signing certificate has no private key.' }

  $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
  if ($eku.Count -ne 1) { throw 'Generated certificate is missing Enhanced Key Usage.' }
  $decoded = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
  $decoded.CopyFrom($eku[0])
  if (-not ($decoded.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' })) {
    throw 'Generated certificate is missing the Code Signing EKU.'
  }

  $publicPath = Join-Path $output 'MonitoringPlatform.LocalAgentSigner.cer'
  Export-Certificate -Cert $certificate -FilePath $publicPath -Force | Out-Null
  foreach ($store in @('TrustedPeople', 'TrustedPublisher')) {
    Import-Certificate -FilePath $publicPath -CertStoreLocation "Cert:\CurrentUser\$store" | Out-Null
  }
  $certificateSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData))).Replace('-', '')
  [ordered]@{
    subject = $certificate.Subject
    thumbprintSha1 = $certificate.Thumbprint.ToUpperInvariant()
    certificateSha256 = $certificateSha256
    notAfter = $certificate.NotAfter.ToUniversalTime().ToString('O')
    buildTrustStores = @('TrustedPeople', 'TrustedPublisher')
    targetTrustStores = @('Root', 'TrustedPublisher')
  } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $output 'signer.json') -Encoding utf8
  Set-Content -LiteralPath (Join-Path $output 'SIGNER-SHA1.txt') -Value $certificate.Thumbprint.ToUpperInvariant() -Encoding ascii
  [pscustomobject]@{
    ThumbprintSha1 = $certificate.Thumbprint.ToUpperInvariant()
    CertificateSha256 = $certificateSha256
    CertificatePath = $publicPath
    NotAfter = $certificate.NotAfter
  }
}
catch {
  if ($certificate) {
    foreach ($store in @('My', 'TrustedPeople', 'TrustedPublisher')) {
      Remove-Item -LiteralPath "Cert:\CurrentUser\$store\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
  }
  if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue }
  throw
}
