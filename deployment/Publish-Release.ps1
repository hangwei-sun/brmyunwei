[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'artifacts'
}

$releaseName = "monitoring-platform-$Version-win-x64"
$releaseRoot = Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) $releaseName
$appRoot = Join-Path $releaseRoot 'app'
$archivePath = "$releaseRoot.zip"
if ((Test-Path -LiteralPath $releaseRoot) -or (Test-Path -LiteralPath $archivePath)) {
    throw "Release output already exists: $releaseRoot"
}

New-Item -ItemType Directory -Path $appRoot -Force | Out-Null
Push-Location $repoRoot
try {
    if (git status --porcelain) { throw 'Release builds require a clean Git working tree.' }
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    npm test
    if ($LASTEXITCODE -ne 0) { throw 'npm test failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'npm run build failed.' }
    dotnet test '.\backend\tests\MonitoringPlatform.Api.Tests.csproj' -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
    dotnet run --project '.\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj' -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Agent self-tests failed.' }
    dotnet publish '.\backend\MonitoringPlatform.Api.csproj' -c Release -r win-x64 --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=false -o $appRoot
    if ($LASTEXITCODE -ne 0) { throw 'Backend publish failed.' }
    dotnet publish '.\agent\MonitoringPlatform.Agent.csproj' -c Release -o (Join-Path $releaseRoot 'agent')
    if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed.' }

    New-Item -ItemType Directory -Path (Join-Path $appRoot 'wwwroot') -Force | Out-Null
    Copy-Item -Path '.\dist\*' -Destination (Join-Path $appRoot 'wwwroot') -Recurse -Force
    Copy-Item -LiteralPath '.\deployment\appsettings.Production.template.json' `
        -Destination (Join-Path $releaseRoot 'appsettings.Production.template.json')
    Copy-Item -LiteralPath '.\deployment\Install-Service.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\deployment\Uninstall-Service.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\deployment\Restore-Database.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\deployment\Initialize-IsolatedPrerelease.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\deployment\Start-IsolatedPrerelease.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\deployment\Get-IsolatedPrereleaseCredential.ps1' -Destination $releaseRoot
    Copy-Item -LiteralPath '.\agent\Measure-AgentResource.ps1' -Destination (Join-Path $releaseRoot 'agent')
    Copy-Item -LiteralPath '.\agent\Install-Agent.ps1' -Destination (Join-Path $releaseRoot 'agent')
    Copy-Item -LiteralPath '.\agent\README.md' -Destination (Join-Path $releaseRoot 'agent')

    [ordered]@{
        product = 'MonitoringPlatform'
        version = $Version
        runtime = 'win-x64'
        selfContained = $true
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        commit = (git rev-parse HEAD).Trim()
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releaseRoot 'release.json') -Encoding utf8

    Get-ChildItem -LiteralPath $releaseRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
        $relative = [System.IO.Path]::GetRelativePath($releaseRoot, $_.FullName)
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    } | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS') -Encoding ascii

    Compress-Archive -LiteralPath $releaseRoot -DestinationPath $archivePath -CompressionLevel Optimal
    Write-Host "Release created: $archivePath"
}
finally {
    Pop-Location
}
