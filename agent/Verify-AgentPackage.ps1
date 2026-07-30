[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$FilePath,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ExpectedSignerThumbprint
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw "File does not exist: $FilePath" }
$signature = Get-AuthenticodeSignature -LiteralPath $FilePath
$expected = $ExpectedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
if ($signature.Status -ne 'Valid') { throw "Code-signing verification failed: $($signature.Status) $($signature.StatusMessage)" }
if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expected) {
  throw 'Code-signing certificate thumbprint does not match the approved signer.'
}
Write-Host "Signature verified: $($signature.SignerCertificate.Subject)"
