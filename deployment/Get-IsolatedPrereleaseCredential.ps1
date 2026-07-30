[CmdletBinding()]
param([string]$InstallRoot = "$env:LOCALAPPDATA\MonitoringPlatform-Prerelease")

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$metadata = Get-Content -LiteralPath (Join-Path $InstallRoot 'initialized.json') -Raw | ConvertFrom-Json
$secretPath = Join-Path $InstallRoot 'bootstrap-admin.dpapi'
if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) { throw 'Bootstrap credential has already been consumed.' }
$protectedBytes = [IO.File]::ReadAllBytes($secretPath)
$passwordBytes = [Security.Cryptography.ProtectedData]::Unprotect($protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
try {
    $password = [Text.Encoding]::UTF8.GetString($passwordBytes)
    [pscustomobject]@{ Username = $metadata.adminUsername; Password = $password; Url = "https://localhost:$($metadata.httpsPort)" }
}
finally {
    $password = $null
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    Remove-Item -LiteralPath $secretPath -Force
}
