[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ProductVersion = '0.3.0',
  [string]$SignerDirectory = (Join-Path $PSScriptRoot 'local-signer'),
  [string]$OutputDirectory = (Join-Path $PSScriptRoot 'local-package'),
  [string]$ToolDirectory = (Join-Path $PSScriptRoot '.tools\wix'),
  [string]$WixVersion = '4.0.6'
)

$ErrorActionPreference = 'Stop'
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$zipPath = "$output.zip"
$zipHashPath = "$zipPath.sha256"
$outputExisted = Test-Path -LiteralPath $output
if ($outputExisted -and (Get-ChildItem -LiteralPath $output -Force | Select-Object -First 1)) {
  throw "OutputDirectory must be empty to prevent mixing package generations: $output"
}
foreach ($reservedPath in @($zipPath, $zipHashPath)) {
  if (Test-Path -LiteralPath $reservedPath) { throw "Signed package output already exists: $reservedPath" }
}

$signerMetadata = Join-Path ([IO.Path]::GetFullPath($SignerDirectory)) 'signer.json'
if (-not (Test-Path -LiteralPath $signerMetadata -PathType Leaf)) {
  if (-not $PSCmdlet.ShouldProcess($SignerDirectory, 'Create local code-signing identity')) { return }
  & (Join-Path $PSScriptRoot 'New-LocalCodeSigningCertificate.ps1') -OutputDirectory $SignerDirectory | Out-Null
}
$signer = Get-Content -LiteralPath $signerMetadata -Raw | ConvertFrom-Json
$thumbprint = ([string]$signer.thumbprintSha1).Replace(' ', '').ToUpperInvariant()
if ($thumbprint -notmatch '^[A-F0-9]{40}$') { throw 'Local signer metadata contains an invalid SHA-1 thumbprint.' }

$wix = Join-Path ([IO.Path]::GetFullPath($ToolDirectory)) 'wix.exe'
if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) {
  New-Item -ItemType Directory -Path $ToolDirectory -Force | Out-Null
  & dotnet tool install wix --tool-path $ToolDirectory --version $WixVersion
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $wix -PathType Leaf)) {
    throw 'Pinned WiX Toolset installation failed.'
  }
}

if (-not $PSCmdlet.ShouldProcess($output, 'Create locally signed Agent package and ZIP archive')) { return }
$publish = Join-Path $PSScriptRoot 'Publish-SignedAgent.ps1'
try {
  & $publish -CodeSigningCertificateThumbprint $thumbprint -ProductVersion $ProductVersion `
    -OutputDirectory $output -WixPath $wix -Confirm:$false
  if ($LASTEXITCODE -ne 0) { throw 'Local signed Agent publication failed.' }

  $msi = Get-ChildItem -LiteralPath $output -Filter '*.msi' -File | Select-Object -First 1
  if (-not $msi) { throw 'Signed Agent publication did not produce an MSI.' }
  Compress-Archive -Path (Join-Path $output '*') -DestinationPath $zipPath -CompressionLevel Optimal
  $zipSha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
  "$zipSha256  $([IO.Path]::GetFileName($zipPath))" | Set-Content -LiteralPath $zipHashPath -Encoding ascii
}
catch {
  foreach ($createdPath in @($zipHashPath, $zipPath)) {
    if (Test-Path -LiteralPath $createdPath) { Remove-Item -LiteralPath $createdPath -Force -ErrorAction SilentlyContinue }
  }
  if (Test-Path -LiteralPath $output) {
    if ($outputExisted) {
      Get-ChildItem -LiteralPath $output -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
      Remove-Item -LiteralPath $output -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  throw
}
[pscustomobject]@{
  PackageDirectory = $output
  PackageZip = $zipPath
  PackageZipSha256 = $zipSha256
  MsiPath = $msi.FullName
  ApprovedSignerThumbprint = $thumbprint
  SignerCertificate = (Join-Path $output 'MonitoringPlatform.LocalAgentSigner.cer')
}
