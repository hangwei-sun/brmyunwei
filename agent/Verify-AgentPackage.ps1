#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$FilePath,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ExpectedSignerThumbprint,
  [switch]$AllowUntrustedRoot
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw "File does not exist: $FilePath" }
$signature = Get-AuthenticodeSignature -LiteralPath $FilePath
$expected = $ExpectedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expected) {
  throw 'Code-signing certificate thumbprint does not match the approved signer.'
}
if ($signature.Status -ne 'Valid') {
  $untrustedRootOnly = $AllowUntrustedRoot -and $signature.Status -in @('UnknownError', 'NotTrusted')
  if (-not $untrustedRootOnly) { throw "Code-signing verification failed: $($signature.Status) $($signature.StatusMessage)" }
  if ($signature.SignerCertificate.Subject -ne $signature.SignerCertificate.Issuer) {
    throw 'AllowUntrustedRoot is restricted to the self-signed local validation signer.'
  }
  $now = [DateTime]::UtcNow
  if ($signature.SignerCertificate.NotBefore.ToUniversalTime() -gt $now -or
      $signature.SignerCertificate.NotAfter.ToUniversalTime() -le $now) {
    throw 'Pinned signer is outside its validity period.'
  }
  $basicConstraints = @($signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
  if ($basicConstraints.Count -gt 1) { throw 'Pinned signer has duplicate Basic Constraints extensions.' }
  if ($basicConstraints.Count -eq 1) {
    $decodedConstraints = New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension
    $decodedConstraints.CopyFrom($basicConstraints[0])
    if ($decodedConstraints.CertificateAuthority) { throw 'Pinned signer must be an end-entity certificate, not a CA.' }
  }
  $usageExtension = @($signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
  if ($usageExtension.Count -ne 1) { throw 'Pinned signer is missing Enhanced Key Usage.' }
  $decodedUsage = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
  $decodedUsage.CopyFrom($usageExtension[0])
  if (-not ($decodedUsage.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' })) {
    throw 'Pinned signer is missing the Code Signing EKU.'
  }
  $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
  $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
  [void]$chain.Build($signature.SignerCertificate)
  $chainErrors = @($chain.ChainStatus | Where-Object { $_.Status -ne [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot })
  if ($chainErrors.Count -gt 0) {
    throw "Pinned signer has certificate-chain errors beyond UntrustedRoot: $($chainErrors.Status -join ', ')"
  }
  Write-Warning "Cryptographic signature and pinned signer matched, but the build account does not trust the local root: $($signature.StatusMessage)"
}
Write-Host "Signature verified: $($signature.SignerCertificate.Subject)"
