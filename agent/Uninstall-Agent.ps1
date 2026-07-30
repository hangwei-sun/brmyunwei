#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Agent",
  [string]$DataRoot = "$env:ProgramData\MonitoringPlatform\Agent",
  [string]$ServiceName = 'MonitoringPlatformAgent',
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ApprovedSignerThumbprint,
  [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$approvedSigner = $ApprovedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
$selfSignature = Get-AuthenticodeSignature -LiteralPath $PSCommandPath
if ($selfSignature.Status -ne 'Valid' -or -not $selfSignature.SignerCertificate -or $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $approvedSigner) {
  throw 'Uninstall script signature is missing, invalid, or not from the approved signer.'
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$allowedInstallRoot = [IO.Path]::GetFullPath($env:ProgramFiles) + [IO.Path]::DirectorySeparatorChar
$allowedDataRoot = [IO.Path]::GetFullPath($env:ProgramData) + [IO.Path]::DirectorySeparatorChar
if (-not $InstallRoot.StartsWith($allowedInstallRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not $DataRoot.StartsWith($allowedDataRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'InstallRoot must remain under Program Files and DataRoot must remain under ProgramData.'
}
if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Stop and remove Agent service')) { return }
$certificateSha256 = $null
$configPath = Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe.config'
if ($RemoveData -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
  try {
    [xml]$configuration = Get-Content -LiteralPath $configPath -Raw
    $certificateSha256 = ($configuration.configuration.appSettings.add | Where-Object key -eq 'ClientCertificateThumbprint').value
  }
  catch { throw "Cannot read the Agent certificate fingerprint before full removal: $($_.Exception.Message)" }
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  & sc.exe delete $ServiceName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Failed to delete Agent service.' }
}
if ($RemoveData -and $certificateSha256) {
  $normalizedCertificateSha256 = $certificateSha256.Replace(' ', '').Replace(':', '').ToUpperInvariant()
  Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData))).Replace('-', '') -eq $normalizedCertificateSha256
  } | Remove-Item -Force
}
if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
if ($RemoveData -and (Test-Path -LiteralPath $DataRoot)) { Remove-Item -LiteralPath $DataRoot -Recurse -Force }
Write-Host ($(if ($RemoveData) { 'Agent, active registered client certificate, and local telemetry were removed. Review expired rotation certificates separately.' } else { 'Agent was removed; local telemetry and client certificate were retained.' }))
