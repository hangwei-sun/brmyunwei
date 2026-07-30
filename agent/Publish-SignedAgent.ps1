[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$CodeSigningCertificateThumbprint,
  [Parameter(Mandatory = $true)][uri]$TimestampServer,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ProductVersion,
  [string]$PublishedInputDirectory = $PSScriptRoot,
  [string]$OutputDirectory = (Join-Path $PSScriptRoot 'package')
)

$ErrorActionPreference = 'Stop'
if ($TimestampServer.Scheme -ne 'http' -and $TimestampServer.Scheme -ne 'https') { throw 'TimestampServer must be HTTP or HTTPS.' }
$thumbprint = $CodeSigningCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
if (-not $certificate) { throw 'A code-signing certificate with private key was not found in CurrentUser\\My.' }
$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK signing tools; signing is required.' }
$wix = (Get-Command wix.exe -ErrorAction SilentlyContinue).Source
if (-not $wix) { throw 'wix.exe was not found. Install WiX Toolset v4; a signed MSI is required.' }
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
  throw "OutputDirectory must be empty to prevent stale or unhashed package files: $OutputDirectory"
}

if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Build and sign Agent package')) { return }
$publishDirectory = Join-Path ([IO.Path]::GetTempPath()) ('monitoring-agent-publish-' + [Guid]::NewGuid().ToString('N'))
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
  foreach ($script in @('Install-Agent.ps1', 'Enroll-Agent.ps1', 'Rotate-AgentCertificate.ps1', 'Upgrade-Agent.ps1', 'Uninstall-Agent.ps1', 'Verify-AgentPackage.ps1', 'Measure-AgentResource.ps1', 'Test-AgentScripts.ps1', 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $OutputDirectory -Force
  }
  $targetExe = Join-Path $OutputDirectory 'MonitoringPlatform.Agent.exe'
  & $signtool sign /fd SHA256 /sha1 $thumbprint /tr $TimestampServer.AbsoluteUri /td SHA256 $targetExe
  if ($LASTEXITCODE -ne 0) { throw 'signtool signing failed.' }
  Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ps1' -File | ForEach-Object {
    $signature = Set-AuthenticodeSignature -LiteralPath $_.FullName -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
    if ($signature.Status -ne 'Valid') { throw "PowerShell signing failed: $($_.Name): $($signature.StatusMessage)" }
  }
  $verify = Join-Path $OutputDirectory 'Verify-AgentPackage.ps1'
  & $verify -FilePath $targetExe -ExpectedSignerThumbprint $thumbprint
  Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ps1' -File | ForEach-Object { & $verify -FilePath $_.FullName -ExpectedSignerThumbprint $thumbprint }

  $msiPath = Join-Path $OutputDirectory "MonitoringPlatform.Agent-$ProductVersion-x64.msi"
  & $wix build (Join-Path $PSScriptRoot 'AgentInstaller.wxs') -arch x64 -d "SourceDir=$OutputDirectory" -d "ProductVersion=$ProductVersion" -o $msiPath
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $msiPath)) { throw 'WiX MSI build failed.' }
  & $signtool sign /fd SHA256 /sha1 $thumbprint /tr $TimestampServer.AbsoluteUri /td SHA256 $msiPath
  if ($LASTEXITCODE -ne 0) { throw 'MSI signing failed.' }
  & $verify -FilePath $msiPath -ExpectedSignerThumbprint $thumbprint

  Get-ChildItem -LiteralPath $OutputDirectory -File | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
  } | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS') -Encoding Ascii
}
finally {
  if (Test-Path -LiteralPath $publishDirectory) { Remove-Item -LiteralPath $publishDirectory -Recurse -Force }
}
Write-Host "Signed EXE, PowerShell delivery scripts, and MSI created at $OutputDirectory"
