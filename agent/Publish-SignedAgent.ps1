[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$CodeSigningCertificateThumbprint,
  [uri]$TimestampServer,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ProductVersion,
  [string]$PublishedInputDirectory = $PSScriptRoot,
  [string]$OutputDirectory = (Join-Path $PSScriptRoot 'package'),
  [string]$SignToolPath,
  [string]$WixPath
)

$ErrorActionPreference = 'Stop'
if ($TimestampServer -and $TimestampServer.Scheme -ne 'http' -and $TimestampServer.Scheme -ne 'https') {
  throw 'TimestampServer must be HTTP or HTTPS.'
}
$thumbprint = $CodeSigningCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
if (-not $certificate) { throw 'A code-signing certificate with private key was not found in CurrentUser\\My.' }
$codeSigningExtension = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($codeSigningExtension.Count -ne 1) { throw 'Signing certificate is missing Enhanced Key Usage.' }
$decodedUsage = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
$decodedUsage.CopyFrom($codeSigningExtension[0])
if (-not ($decodedUsage.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' })) {
  throw 'Signing certificate is missing the Code Signing EKU.'
}
if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(30)) {
  throw 'Signing certificate expires in 30 days or less.'
}
foreach ($store in @('TrustedPeople', 'TrustedPublisher')) {
  if (-not (Test-Path -LiteralPath "Cert:\CurrentUser\$store\$thumbprint")) {
    throw "Signing certificate must be trusted in CurrentUser\\$store before publication."
  }
}

$signtool = $SignToolPath
if (-not $signtool) { $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
if (-not $signtool) {
  $kitRoot = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\bin'
  $signtool = Get-ChildItem -Path (Join-Path $kitRoot '*\x64\signtool.exe') -File -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK signing tools; signing is required.' }
$wix = $WixPath
if (-not $wix) { $wix = (Get-Command wix.exe -ErrorAction SilentlyContinue).Source }
if (-not $wix) { throw 'wix.exe was not found. Install WiX Toolset v4; a signed MSI is required.' }
if (-not (Test-Path -LiteralPath $signtool -PathType Leaf)) { throw "signtool.exe does not exist: $signtool" }
if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) { throw "wix.exe does not exist: $wix" }
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
  throw "OutputDirectory must be empty to prevent stale or unhashed package files: $OutputDirectory"
}

function Invoke-SignTool {
  param([string]$FilePath)
  $arguments = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $thumbprint)
  if ($TimestampServer) { $arguments += @('/tr', $TimestampServer.AbsoluteUri, '/td', 'SHA256') }
  $arguments += $FilePath
  & $signtool @arguments
  if ($LASTEXITCODE -ne 0) { throw "signtool signing failed: $FilePath" }
}

if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Build and sign Agent package')) { return }
$publishDirectory = Join-Path ([IO.Path]::GetTempPath()) ('monitoring-agent-publish-' + [Guid]::NewGuid().ToString('N'))
$setupPublishDirectory = Join-Path ([IO.Path]::GetTempPath()) ('monitoring-agent-setup-publish-' + [Guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory -Path $publishDirectory -Force | Out-Null
  $publishedExe = Join-Path $PublishedInputDirectory 'MonitoringPlatform.Agent.exe'
  $publishedConfig = "$publishedExe.config"
  if ((Test-Path -LiteralPath $publishedExe -PathType Leaf) -and (Test-Path -LiteralPath $publishedConfig -PathType Leaf)) {
    Copy-Item -LiteralPath $publishedExe, $publishedConfig -Destination $publishDirectory -Force
    $publishedPdb = Join-Path $PublishedInputDirectory 'MonitoringPlatform.Agent.pdb'
    if (Test-Path -LiteralPath $publishedPdb -PathType Leaf) { Copy-Item -LiteralPath $publishedPdb -Destination $publishDirectory -Force }
  }
  else {
    $project = Join-Path $PSScriptRoot 'MonitoringPlatform.Agent.csproj'
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) { throw 'PublishedInputDirectory must contain the published Agent EXE/config when the source project is unavailable.' }
    & dotnet publish $project -c Release -p:Version=$ProductVersion -o $publishDirectory
    if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }
  }
  New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
  Copy-Item -Path (Join-Path $publishDirectory '*') -Destination $OutputDirectory -Recurse -Force
  & dotnet publish (Join-Path $PSScriptRoot 'Setup\MonitoringPlatform.Agent.Setup.csproj') -c Release -p:Version=$ProductVersion -o $setupPublishDirectory
  if ($LASTEXITCODE -ne 0) { throw 'Agent configuration application publish failed.' }
  Copy-Item -Path (Join-Path $setupPublishDirectory '*') -Destination $OutputDirectory -Recurse -Force
  foreach ($script in @('Install-Agent.ps1', 'Enroll-Agent.ps1', 'Rotate-AgentCertificate.ps1', 'Upgrade-Agent.ps1', 'Uninstall-Agent.ps1', 'Verify-AgentPackage.ps1', 'Measure-AgentResource.ps1', 'Test-AgentScripts.ps1', 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $OutputDirectory -Force
  }
  $publicCertificatePath = Join-Path $OutputDirectory 'MonitoringPlatform.LocalAgentSigner.cer'
  Export-Certificate -Cert $certificate -FilePath $publicCertificatePath -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $OutputDirectory 'SIGNER-SHA1.txt') -Value $thumbprint -Encoding ascii
  $targetExe = Join-Path $OutputDirectory 'MonitoringPlatform.Agent.exe'
  Invoke-SignTool $targetExe
  Invoke-SignTool (Join-Path $OutputDirectory 'MonitoringPlatform.Agent.Setup.exe')
  Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ps1' -File | ForEach-Object {
    $parameters = @{ LiteralPath = $_.FullName; Certificate = $certificate; HashAlgorithm = 'SHA256' }
    if ($TimestampServer) { $parameters.TimestampServer = $TimestampServer.AbsoluteUri }
    $signature = Set-AuthenticodeSignature @parameters
    if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $thumbprint -or
        $signature.Status -notin @('Valid', 'UnknownError', 'NotTrusted')) {
      throw "PowerShell signing failed: $($_.Name): $($signature.StatusMessage)"
    }
  }
  $verify = Join-Path $OutputDirectory 'Verify-AgentPackage.ps1'
  & $verify -FilePath $targetExe -ExpectedSignerThumbprint $thumbprint -AllowUntrustedRoot
  Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ps1' -File | ForEach-Object {
    & $verify -FilePath $_.FullName -ExpectedSignerThumbprint $thumbprint -AllowUntrustedRoot
  }

  $certificateSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData))).Replace('-', '')
  [ordered]@{
    product = 'MonitoringPlatform.Agent'
    version = $ProductVersion
    signerSubject = $certificate.Subject
    signerThumbprintSha1 = $thumbprint
    signerCertificateSha256 = $certificateSha256
    signerNotAfter = $certificate.NotAfter.ToUniversalTime().ToString('O')
    timestamped = [bool]$TimestampServer
    trustStores = @('Root', 'TrustedPublisher')
    scope = 'internal-lan-validation'
  } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'package.json') -Encoding utf8

  $msiPath = Join-Path $OutputDirectory "MonitoringPlatform.Agent-$ProductVersion-x64.msi"
  & $wix build (Join-Path $PSScriptRoot 'AgentInstaller.wxs') -arch x64 -d "SourceDir=$OutputDirectory" -d "ProductVersion=$ProductVersion" -o $msiPath
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $msiPath)) { throw 'WiX MSI build failed.' }
  Invoke-SignTool $msiPath
  & $verify -FilePath $msiPath -ExpectedSignerThumbprint $thumbprint -AllowUntrustedRoot

  Get-ChildItem -LiteralPath $OutputDirectory -File | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
  } | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS') -Encoding Ascii
}
finally {
  if (Test-Path -LiteralPath $publishDirectory) { Remove-Item -LiteralPath $publishDirectory -Recurse -Force }
  if (Test-Path -LiteralPath $setupPublishDirectory) { Remove-Item -LiteralPath $setupPublishDirectory -Recurse -Force }
}
Write-Host "Signed EXE, PowerShell delivery scripts, and MSI created at $OutputDirectory"
if (-not $TimestampServer) { Write-Host 'No timestamp was used; signatures remain valid only while the local signer certificate is valid.' }
