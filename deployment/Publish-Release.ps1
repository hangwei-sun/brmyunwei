[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$')]
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
$agentRoot = Join-Path $releaseRoot 'agent'
$witnessRoot = Join-Path $releaseRoot 'witness'
$witnessAppRoot = Join-Path $witnessRoot 'app'
$archivePath = "$releaseRoot.zip"
if ((Test-Path -LiteralPath $releaseRoot) -or (Test-Path -LiteralPath $archivePath)) {
    throw "Release output already exists: $releaseRoot"
}

function Assert-PowerShellSyntax {
    param([string[]]$Paths)

    $errors = @()
    foreach ($path in $Paths) {
        $tokens = $null
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
        $errors += $parseErrors
    }
    if ($errors.Count -gt 0) {
        $errors | Format-List
        throw 'PowerShell syntax verification failed.'
    }
}

function Copy-ReleaseItems {
    param([string]$SourceDirectory, [string[]]$Names, [string]$DestinationDirectory)

    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    foreach ($name in $Names) {
        $source = Join-Path $SourceDirectory $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Release source is missing: $source" }
        Copy-Item -LiteralPath $source -Destination $DestinationDirectory -Force
    }
}

function Assert-NoNuGetVulnerabilities {
    param([string]$Project)

    $output = & dotnet list $Project package --vulnerable --include-transitive --format json
    if ($LASTEXITCODE -ne 0) { throw "NuGet vulnerability scan failed: $Project" }
    $json = $output -join [Environment]::NewLine
    if ($json -match '"vulnerabilities"\s*:') { throw "NuGet vulnerability scan found a vulnerable dependency: $Project" }
}

function Assert-TlsReleasePolicy {
    $isolatedInitializer = Get-Content -LiteralPath '.\deployment\Initialize-IsolatedPrerelease.ps1' -Raw
    if ($isolatedInitializer -notmatch 'Location = ''CurrentUser''; AllowInvalid = \$true') {
        throw 'The isolated prerelease must allow its exact randomized certificate before manual root trust is approved.'
    }

    $production = Get-Content -LiteralPath '.\deployment\appsettings.Production.template.json' -Raw | ConvertFrom-Json
    $witness = Get-Content -LiteralPath '.\witness\appsettings.json' -Raw | ConvertFrom-Json
    if ($production.Kestrel.Endpoints.Https.Certificate.AllowInvalid -ne $false -or
        $witness.Kestrel.Endpoints.Https.Certificate.AllowInvalid -ne $false) {
        throw 'Production center and witness TLS certificates must keep AllowInvalid=false.'
    }
}

Push-Location $repoRoot
try {
    if (git status --porcelain) { throw 'Release builds require a clean Git working tree.' }

    $deploymentScripts = Get-ChildItem -LiteralPath '.\deployment' -Filter '*.ps1' -File | Select-Object -ExpandProperty FullName
    Assert-PowerShellSyntax -Paths $deploymentScripts
    Assert-TlsReleasePolicy
    & '.\agent\Test-AgentScripts.ps1'
    & '.\witness\Test-WitnessScripts.ps1'

    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    npm test
    if ($LASTEXITCODE -ne 0) { throw 'npm test failed.' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'npm run build failed.' }
    npm audit
    if ($LASTEXITCODE -ne 0) { throw 'npm audit found a vulnerable dependency.' }
    dotnet test '.\backend\tests\MonitoringPlatform.Api.Tests.csproj' -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
    dotnet run --project '.\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj' -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Agent self-tests failed.' }
    dotnet test '.\witness\tests\MonitoringPlatform.Witness.Tests.csproj' -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Witness tests failed.' }
    dotnet format '.\backend\MonitoringPlatform.Api.csproj' --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Backend formatting verification failed.' }
    dotnet format '.\agent\MonitoringPlatform.Agent.csproj' --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Agent formatting verification failed.' }
    dotnet format '.\witness\MonitoringPlatform.Witness.csproj' --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Witness formatting verification failed.' }
    Assert-NoNuGetVulnerabilities '.\backend\MonitoringPlatform.Api.csproj'
    Assert-NoNuGetVulnerabilities '.\agent\MonitoringPlatform.Agent.csproj'
    Assert-NoNuGetVulnerabilities '.\witness\MonitoringPlatform.Witness.csproj'

    New-Item -ItemType Directory -Path $appRoot, $agentRoot, $witnessRoot -Force | Out-Null
    dotnet publish '.\backend\MonitoringPlatform.Api.csproj' -c Release -r win-x64 --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=false -o $appRoot
    if ($LASTEXITCODE -ne 0) { throw 'Backend publish failed.' }
    dotnet publish '.\agent\MonitoringPlatform.Agent.csproj' -c Release -p:Version=$Version -o $agentRoot
    if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed.' }
    dotnet publish '.\witness\MonitoringPlatform.Witness.csproj' -c Release -r win-x64 --self-contained true `
        -p:Version=$Version -p:PublishSingleFile=false -o $witnessAppRoot
    if ($LASTEXITCODE -ne 0) { throw 'Witness publish failed.' }

    New-Item -ItemType Directory -Path (Join-Path $appRoot 'wwwroot') -Force | Out-Null
    Copy-Item -Path '.\dist\*' -Destination (Join-Path $appRoot 'wwwroot') -Recurse -Force
    Copy-Item -LiteralPath '.\deployment\appsettings.Production.template.json' `
        -Destination (Join-Path $releaseRoot 'appsettings.Production.template.json')

    Copy-ReleaseItems -SourceDirectory '.\deployment' -DestinationDirectory $releaseRoot -Names @(
        'Install-Service.ps1', 'Uninstall-Service.ps1', 'Restore-Database.ps1',
        'Initialize-IsolatedPrerelease.ps1', 'Start-IsolatedPrerelease.ps1',
        'Get-IsolatedPrereleaseCredential.ps1', 'Invoke-HaPromotion.ps1', 'Set-HaNodePassive.ps1',
        'Invoke-PrereleaseAcceptance.ps1', 'Test-WindowsAgentPrerelease.ps1',
        'HA-受控切换与恢复回放.md'
    )
    Copy-ReleaseItems -SourceDirectory '.\agent' -DestinationDirectory $agentRoot -Names @(
        'Install-Agent.ps1', 'Enroll-Agent.ps1', 'Rotate-AgentCertificate.ps1', 'Upgrade-Agent.ps1',
        'Uninstall-Agent.ps1', 'Verify-AgentPackage.ps1', 'Publish-SignedAgent.ps1',
        'New-LocalCodeSigningCertificate.ps1', 'Build-LocalSignedAgent.ps1',
        'Test-AgentScripts.ps1', 'Measure-AgentResource.ps1', 'README.md', 'AgentInstaller.wxs'
    )
    @'
UNSIGNED RELEASE CANDIDATE - NOT INSTALLABLE

The Agent executable and PowerShell scripts in this release candidate are unsigned.
Do not run Install-Agent.ps1, install an MSI, or run enrollment scripts from this package.
Use these files only for build and test evaluation until a signed release is issued.

Production Agent delivery must use agent\Publish-SignedAgent.ps1 with an approved signer,
signtool.exe, and WiX Toolset v4. Internal validation may use the pinned local-signer workflow;
broader production rollout should replace it with the unit's managed code-signing identity.
'@ | Set-Content -LiteralPath (Join-Path $agentRoot 'UNSIGNED-RC-NOT-INSTALLABLE.txt') -Encoding ascii

    Copy-Item -LiteralPath '.\witness\appsettings.json' -Destination (Join-Path $witnessRoot 'appsettings.Production.template.json')
    Copy-ReleaseItems -SourceDirectory '.\witness' -DestinationDirectory $witnessRoot -Names @(
        'Install-WitnessService.ps1', 'Uninstall-WitnessService.ps1', 'Test-WitnessScripts.ps1', 'README.md'
    )

    [ordered]@{
        product = 'MonitoringPlatform'
        version = $Version
        releaseChannel = 'release-candidate'
        runtime = 'win-x64'
        createdAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        commit = (git rev-parse HEAD).Trim()
        components = [ordered]@{
            backend = [ordered]@{ selfContained = $true; runtime = 'win-x64' }
            witness = [ordered]@{ selfContained = $true; runtime = 'win-x64'; installScript = 'witness\Install-WitnessService.ps1' }
            agent = [ordered]@{ signed = $false; installable = $false; warning = 'agent\UNSIGNED-RC-NOT-INSTALLABLE.txt' }
        }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releaseRoot 'release.json') -Encoding utf8

    Get-ChildItem -LiteralPath $releaseRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($releaseRoot.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    } | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS') -Encoding utf8

    Compress-Archive -LiteralPath $releaseRoot -DestinationPath $archivePath -CompressionLevel Optimal
    Write-Host "Release created: $archivePath"
}
finally {
    Pop-Location
}
