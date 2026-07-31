#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$PackageRoot,
  [Parameter(Mandatory = $true)][string]$ApprovedSignerThumbprint,
  [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Agent",
  [string]$DataRoot = "$env:ProgramData\MonitoringPlatform\Agent",
  [string]$ServiceName = 'MonitoringPlatformAgent'
)

$ErrorActionPreference = 'Stop'
$approvedSigner = $ApprovedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
$selfSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($selfSignature.Status -ne 'Valid' -or -not $selfSignature.SignerCertificate -or $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $approvedSigner) {
  throw 'Upgrade script signature is missing, invalid, or not from the approved signer.'
}
$packageRoot = (Resolve-Path -LiteralPath $PackageRoot).Path
$sourceExe = Join-Path $packageRoot 'MonitoringPlatform.Agent.exe'
$verifyScript = Join-Path $packageRoot 'Verify-AgentPackage.ps1'
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf) -or -not (Test-Path -LiteralPath $verifyScript -PathType Leaf)) {
  throw 'PackageRoot must contain MonitoringPlatform.Agent.exe and Verify-AgentPackage.ps1.'
}
foreach ($signedFile in @($verifyScript, $sourceExe)) {
  $signature = Get-AuthenticodeSignature -LiteralPath $signedFile
  if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $approvedSigner) {
    throw "Package signature is missing, invalid, or not from the approved signer: $signedFile"
  }
}
& $verifyScript -FilePath $sourceExe -ExpectedSignerThumbprint $ApprovedSignerThumbprint
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw "Service does not exist: $ServiceName" }

$rollbackRoot = Join-Path $DataRoot ("rollback\" + (Get-Date -Format yyyyMMddHHmmss))
if (-not $PSCmdlet.ShouldProcess($InstallRoot, 'Upgrade signed Agent package')) { return }
New-Item -ItemType Directory -Path $rollbackRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe') -Destination $rollbackRoot -Force
Copy-Item -LiteralPath (Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe.config') -Destination $rollbackRoot -Force

try {
  Stop-Service -Name $ServiceName -Force
  Copy-Item -LiteralPath $sourceExe -Destination (Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe') -Force
  foreach ($file in @('MonitoringPlatform.Agent.pdb')) {
    $source = Join-Path $packageRoot $file
    if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination (Join-Path $InstallRoot $file) -Force }
  }
  Start-Service -Name $ServiceName
  Start-Sleep -Seconds 5
  if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Upgraded Agent service did not return to Running state.' }
}
catch {
  Copy-Item -LiteralPath (Join-Path $rollbackRoot 'MonitoringPlatform.Agent.exe') -Destination (Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe') -Force
  Copy-Item -LiteralPath (Join-Path $rollbackRoot 'MonitoringPlatform.Agent.exe.config') -Destination (Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe.config') -Force
  Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
  throw
}
Write-Host "Upgrade completed. Rollback files retained at $rollbackRoot"
