[CmdletBinding()]
param([string]$InstallRoot = "$env:LOCALAPPDATA\MonitoringPlatform-Prerelease")

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$install = [System.IO.Path]::GetFullPath($InstallRoot)
$metadataPath = Join-Path $install 'initialized.json'
$secretPath = Join-Path $install 'bootstrap-admin.dpapi'
$executable = Join-Path $install 'app\MonitoringPlatform.Api.exe'
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf) -or -not (Test-Path -LiteralPath $secretPath -PathType Leaf) -or -not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'The isolated prerelease has not been initialized.'
}

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
$protectedBytes = [IO.File]::ReadAllBytes($secretPath)
$passwordBytes = [Security.Cryptography.ProtectedData]::Unprotect($protectedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$password = [Text.Encoding]::UTF8.GetString($passwordBytes)
try {
    $env:ASPNETCORE_ENVIRONMENT = 'Production'
    $env:Authentication__BootstrapAdmin__Enabled = 'true'
    $env:Authentication__BootstrapAdmin__Username = $metadata.adminUsername
    $env:Authentication__BootstrapAdmin__Password = $password
    Push-Location (Split-Path -Parent $executable)
    try { & $executable }
    finally { Pop-Location }
}
finally {
    $password = $null
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    Remove-Item Env:Authentication__BootstrapAdmin__Password -ErrorAction SilentlyContinue
}
