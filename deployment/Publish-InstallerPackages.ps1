[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ProductVersion,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$CodeSigningCertificateThumbprint,
  [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\installers'),
  [string]$WixPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'agent\.tools\wix\wix.exe'),
  [string]$SignToolPath,
  [switch]$RestoreFrontendDependencies
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
$thumbprint = $CodeSigningCertificateThumbprint.Replace(' ', '').ToUpperInvariant()
if ((Test-Path -LiteralPath $output) -and (Get-ChildItem -LiteralPath $output -Force | Select-Object -First 1)) { throw "OutputDirectory must be empty: $output" }
if (-not (Test-Path -LiteralPath $WixPath -PathType Leaf)) { throw "WiX was not found: $WixPath" }
if (-not $SignToolPath) { $SignToolPath = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
if (-not $SignToolPath) {
  $kitRoot = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\bin'
  $SignToolPath = Get-ChildItem -Path (Join-Path $kitRoot '*\x64\signtool.exe') -File -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) { throw 'signtool.exe was not found.' }
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint } | Select-Object -First 1
if (-not $certificate) { throw 'The requested code-signing certificate was not found in CurrentUser\\My.' }

function Invoke-SignFile {
  param([string]$Path)
  & $SignToolPath sign /fd SHA256 /s My /sha1 $thumbprint $Path
  if ($LASTEXITCODE -ne 0) { throw "Failed to sign $Path" }
}

function Copy-SetupPayload {
  param([string]$Destination, [string]$Component)
  New-Item -ItemType Directory -Path $Destination -Force | Out-Null
  $setupOutput = Join-Path $repoRoot 'installer\ControlSetup\bin\Release\net10.0-windows\win-x64\publish'
  Copy-Item -Path (Join-Path $setupOutput '*') -Destination $Destination -Recurse -Force
  if ($Component -eq 'control') {
    Copy-Item -LiteralPath (Join-Path $repoRoot 'deployment\appsettings.Production.template.json'), (Join-Path $repoRoot 'deployment\Install-Service.ps1') -Destination $Destination -Force
  }
  else {
    Copy-Item -LiteralPath (Join-Path $repoRoot 'witness\appsettings.json') -Destination (Join-Path $Destination 'appsettings.Production.template.json') -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'witness\Install-WitnessService.ps1') -Destination $Destination -Force
  }
}

function New-WixPayloadFragment {
  param([string]$SourceDirectory, [string]$GroupId, [string]$OutputPath)
  $files = @(Get-ChildItem -LiteralPath $SourceDirectory -File | Sort-Object Name)
  if ($files.Count -eq 0) { throw "No MSI payload files found: $SourceDirectory" }
  $components = New-Object System.Collections.Generic.List[string]
  $references = New-Object System.Collections.Generic.List[string]
  for ($index = 0; $index -lt $files.Count; $index++) {
    $id = "${GroupId}File$index"
    $relative = $files[$index].Name.Replace('&', '&amp;').Replace('"', '&quot;')
    $components.Add(('      <Component Id="{0}" Guid="*"><File Id="{0}Payload" Source="$(var.SourceDir)\{1}" KeyPath="yes" /></Component>' -f $id, $relative))
    $references.Add(('    <ComponentRef Id="{0}" />' -f $id))
  }
  @(
    '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">',
    '  <Fragment>',
    '    <DirectoryRef Id="INSTALLFOLDER">',
    $components,
    '    </DirectoryRef>',
    ('    <ComponentGroup Id="{0}">' -f $GroupId),
    $references,
    '    </ComponentGroup>',
    '  </Fragment>',
    '</Wix>'
  ) | Set-Content -LiteralPath $OutputPath -Encoding utf8
}

Push-Location $repoRoot
try {
  if (git status --porcelain) { throw 'Installer builds require a clean Git working tree.' }
  if (-not $PSCmdlet.ShouldProcess($output, 'Build signed Control, Witness, and Agent MSI packages')) { return }
  New-Item -ItemType Directory -Path $output -Force | Out-Null
  $frontendBuildRoot = $null
  if ($RestoreFrontendDependencies -or -not (Test-Path -LiteralPath '.\node_modules\.bin\vite.cmd' -PathType Leaf)) {
    $frontendBuildRoot = '.\installer\.frontend-build'
    if (Test-Path -LiteralPath $frontendBuildRoot) { Remove-Item -LiteralPath $frontendBuildRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $frontendBuildRoot -Force | Out-Null
    Copy-Item -LiteralPath '.\package.json', '.\package-lock.json', '.\index.html', '.\vite.config.mjs' -Destination $frontendBuildRoot -Force
    Copy-Item -LiteralPath '.\src' -Destination $frontendBuildRoot -Recurse -Force
    if (Test-Path -LiteralPath '.\public' -PathType Container) { Copy-Item -LiteralPath '.\public' -Destination $frontendBuildRoot -Recurse -Force }
    npm ci --prefix $frontendBuildRoot
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    Push-Location $frontendBuildRoot
    try { npm run build }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    Remove-Item -LiteralPath '.\dist' -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath (Join-Path $frontendBuildRoot 'dist') -Destination '.\dist' -Recurse -Force
  }
  else {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
  }
  dotnet publish '.\backend\MonitoringPlatform.Api.csproj' -c Release -r win-x64 --self-contained true -p:Version=$ProductVersion -o '.\installer\.stage\control\app'
  if ($LASTEXITCODE -ne 0) { throw 'Control application publish failed.' }
  dotnet publish '.\witness\MonitoringPlatform.Witness.csproj' -c Release -r win-x64 --self-contained true -p:Version=$ProductVersion -o '.\installer\.stage\witness\app'
  if ($LASTEXITCODE -ne 0) { throw 'Witness application publish failed.' }
  dotnet publish '.\installer\ControlSetup\MonitoringPlatform.Control.Setup.csproj' -c Release -r win-x64 --self-contained true -p:Version=$ProductVersion -o '.\installer\ControlSetup\bin\Release\net10.0-windows\win-x64\publish'
  if ($LASTEXITCODE -ne 0) { throw 'Setup application publish failed.' }
  New-Item -ItemType Directory -Path '.\installer\.stage\control\app\wwwroot' -Force | Out-Null
  Copy-Item -Path '.\dist\*' -Destination '.\installer\.stage\control\app\wwwroot' -Recurse -Force
  Copy-SetupPayload -Destination '.\installer\.stage\control' -Component control
  Copy-SetupPayload -Destination '.\installer\.stage\witness' -Component witness
  Compress-Archive -Path '.\installer\.stage\control\app\*' -DestinationPath '.\installer\.stage\control\app.zip' -CompressionLevel Optimal
  Remove-Item -LiteralPath '.\installer\.stage\control\app' -Recurse -Force
  Compress-Archive -Path '.\installer\.stage\witness\app\*' -DestinationPath '.\installer\.stage\witness\app.zip' -CompressionLevel Optimal
  Remove-Item -LiteralPath '.\installer\.stage\witness\app' -Recurse -Force
  Get-ChildItem -LiteralPath '.\installer\.stage' -Recurse -File -Filter 'MonitoringPlatform.Control.Setup.exe' | ForEach-Object { Invoke-SignFile $_.FullName }
  Get-ChildItem -LiteralPath '.\installer\.stage' -Recurse -File -Filter '*.ps1' | ForEach-Object { Set-AuthenticodeSignature -LiteralPath $_.FullName -Certificate $certificate -HashAlgorithm SHA256 | Out-Null }
  New-WixPayloadFragment -SourceDirectory '.\installer\.stage\control' -GroupId 'ControlPayload' -OutputPath '.\installer\.stage\ControlPayload.wxs'
  New-WixPayloadFragment -SourceDirectory '.\installer\.stage\witness' -GroupId 'WitnessPayload' -OutputPath '.\installer\.stage\WitnessPayload.wxs'
  & $WixPath build '.\installer\ControlInstaller.wxs' '.\installer\.stage\ControlPayload.wxs' -arch x64 -d 'SourceDir=./installer/.stage/control' -d "ProductVersion=$ProductVersion" -o (Join-Path $output "MonitoringPlatform-Control-$ProductVersion-x64.msi")
  if ($LASTEXITCODE -ne 0) { throw 'Control MSI build failed.' }
  & $WixPath build '.\installer\WitnessInstaller.wxs' '.\installer\.stage\WitnessPayload.wxs' -arch x64 -d 'SourceDir=./installer/.stage/witness' -d "ProductVersion=$ProductVersion" -o (Join-Path $output "MonitoringPlatform-Witness-$ProductVersion-x64.msi")
  if ($LASTEXITCODE -ne 0) { throw 'Witness MSI build failed.' }
  Get-ChildItem -LiteralPath $output -Filter '*.msi' -File | ForEach-Object { Invoke-SignFile $_.FullName }
  & '.\agent\Publish-SignedAgent.ps1' -CodeSigningCertificateThumbprint $thumbprint -ProductVersion $ProductVersion -OutputDirectory (Join-Path $output 'agent') -WixPath $WixPath -SignToolPath $SignToolPath -Confirm:$false
  Copy-Item -LiteralPath (Get-ChildItem -LiteralPath (Join-Path $output 'agent') -Filter '*.msi' | Select-Object -First 1).FullName -Destination $output -Force
  Get-ChildItem -LiteralPath $output -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($output.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
  } | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS') -Encoding ascii
}
finally {
  Remove-Item -LiteralPath '.\installer\.stage' -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath '.\installer\.frontend-build' -Recurse -Force -ErrorAction SilentlyContinue
  Pop-Location
}
