#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [ValidateSet('Check', 'CaptureOfflineCache', 'Rollback')][string]$Mode = 'Check',
  [string]$ServiceName = 'MonitoringPlatformAgent',
  [string]$InstallRoot = "$env:ProgramFiles\MonitoringPlatform\Agent",
  [string]$DataRoot = "$env:ProgramData\MonitoringPlatform\Agent",
  [string]$ApprovedRootCertificateThumbprint,
  [ValidatePattern('^[A-Fa-f0-9 ]{40,59}$')][string]$ApprovedSignerThumbprint,
  [string]$MsiPath,
  [int]$MinimumPendingSamples = 1,
  [switch]$ConfirmRollback,
  [string]$OutputPath = (Join-Path $PWD ("agent-prerelease-check-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'))
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$checks = New-Object System.Collections.Generic.List[object]
function Add-Check([string]$Name, [string]$State, [string]$Detail, $Evidence) {
  $checks.Add([pscustomobject]@{ name = $Name; state = $State; detail = $Detail; evidence = $Evidence })
}
function Save-Report([string]$Result) {
  $report = [pscustomobject]@{
    schemaVersion = 1; generatedAt = (Get-Date).ToUniversalTime().ToString('o'); computerName = $env:COMPUTERNAME
    mode = $Mode; result = $Result; hardStopRequired = ($Result -eq 'failed'); checks = @($checks)
  }
  $directory = Split-Path -Parent $OutputPath; if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
  $report | ConvertTo-Json -Depth 8
}

try {
  $os = Get-CimInstance Win32_OperatingSystem
  $supported = $os.Version -like '6.2*' -or $os.Version -like '6.3*' -or [version]$os.Version -ge [version]'10.0'
  if ($supported) { Add-Check 'operating-system' 'passed' 'Windows version is in the Server 2012/2012 R2 or newer validation range.' @{ caption = $os.Caption; version = $os.Version } }
  else { Add-Check 'operating-system' 'failed' 'Unsupported Windows version for this prerelease validation.' @{ caption = $os.Caption; version = $os.Version } }
  $release = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue).Release
  if ($release -ge 528040) { Add-Check 'dotnet-framework-48' 'passed' '.NET Framework 4.8 or later is installed.' @{ release = $release } }
  else { Add-Check 'dotnet-framework-48' 'failed' '.NET Framework 4.8 is required for the Agent.' @{ release = $release } }

  if ($Mode -eq 'Rollback') {
    if (-not $ConfirmRollback) { throw 'Rollback is destructive. Re-run with -ConfirmRollback after preserving the JSON evidence and obtaining the change approval.' }
    if (-not $ApprovedSignerThumbprint) { throw 'ApprovedSignerThumbprint is required for rollback.' }
    $backupParent = Split-Path -Parent $DataRoot
    $backupRoot = Join-Path $backupParent ('Agent-rollback-evidence-' + (Get-Date -Format 'yyyyMMddHHmmss'))
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    if (Test-Path -LiteralPath $DataRoot) { Copy-Item -LiteralPath $DataRoot -Destination (Join-Path $backupRoot 'AgentData') -Recurse -Force }
    if ($MsiPath) {
      $resolvedMsi = (Resolve-Path -LiteralPath $MsiPath -ErrorAction Stop).Path
      $signature = Get-AuthenticodeSignature -LiteralPath $resolvedMsi
      $expectedSigner = $ApprovedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
      if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
          $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expectedSigner) {
        throw 'Rollback MSI signature is invalid or does not match the approved signer.'
      }
      if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Uninstall MSI-managed Agent while retaining telemetry data')) { return }
      $msiLog = Join-Path $backupRoot 'agent-msi-uninstall.log'
      $arguments = "/x `"$resolvedMsi`" /qn /norestart /l*v `"$msiLog`""
      $result = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
      if ($result.ExitCode -notin 0, 3010) { throw "MSI rollback failed with exit code $($result.ExitCode); inspect $msiLog" }
    }
    else {
      $uninstall = Join-Path $InstallRoot 'Uninstall-Agent.ps1'
      if (-not (Test-Path -LiteralPath $uninstall)) { throw "Uninstall script not found: $uninstall" }
      if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Uninstall script-managed Agent while retaining telemetry data')) { return }
      & $uninstall -InstallRoot $InstallRoot -DataRoot $DataRoot -ServiceName $ServiceName `
        -ApprovedSignerThumbprint $ApprovedSignerThumbprint -Confirm:$false
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Add-Check 'uninstall-rollback' 'failed' 'Agent service still exists after uninstall.' $null }
    elseif (-not (Test-Path -LiteralPath $DataRoot)) { Add-Check 'uninstall-rollback' 'failed' 'Agent data was not retained after uninstall.' $null }
    else { Add-Check 'uninstall-rollback' 'passed' 'Agent service and binaries were removed; local telemetry was retained for recovery.' @{ evidenceBackup = $backupRoot; dataRoot = $DataRoot } }
  }
  else {
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($service -and $service.State -eq 'Running' -and $service.StartName -match 'LocalService') { Add-Check 'agent-service' 'passed' 'Agent is running as LOCAL SERVICE.' @{ processId = $service.ProcessId; startName = $service.StartName } }
    else { Add-Check 'agent-service' 'failed' 'Agent must be installed and running as LOCAL SERVICE.' $service }
    $exe = Join-Path $InstallRoot 'MonitoringPlatform.Agent.exe'
    $config = "$exe.config"
    if ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath $config)) { Add-Check 'agent-installation' 'passed' 'Agent executable and structured configuration are present.' @{ installRoot = $InstallRoot } }
    else { Add-Check 'agent-installation' 'failed' 'Agent executable or configuration is missing.' @{ exe = $exe; config = $config } }
    [xml]$xml = Get-Content -LiteralPath $config -Raw
    $settings = @{}; $xml.configuration.appSettings.add | ForEach-Object { $settings[$_.key] = $_.value }
    $endpoint = [uri]$settings['PrimaryEndpoint']
    if ($endpoint.Scheme -eq 'https') { Add-Check 'https-endpoint' 'passed' 'Primary Agent endpoint uses HTTPS.' @{ endpoint = $endpoint.AbsoluteUri } }
    else { Add-Check 'https-endpoint' 'failed' 'Primary Agent endpoint is not HTTPS.' $null }
    try {
      $tcp = New-Object Net.Sockets.TcpClient($endpoint.Host, $endpoint.Port)
      $stream = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ param($sender, $certificate, $chain, $errors) $errors -eq [Net.Security.SslPolicyErrors]::None }))
      $stream.AuthenticateAsClient($endpoint.Host)
      $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
      $valid = $chain.Build((New-Object Security.Cryptography.X509Certificates.X509Certificate2($stream.RemoteCertificate)))
      $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
      $rootThumbprint = $root.Thumbprint.Replace(' ', '').ToUpperInvariant()
      $expected = if ($ApprovedRootCertificateThumbprint) { $ApprovedRootCertificateThumbprint.Replace(' ', '').ToUpperInvariant() } else { '' }
      $stream.Dispose(); $tcp.Dispose()
      if ($valid -and (-not $expected -or $rootThumbprint -eq $expected)) { Add-Check 'certificate-trust' 'passed' 'TLS chain validates to the approved prerelease root.' @{ rootThumbprint = $rootThumbprint; chainValid = $valid } }
      else { Add-Check 'certificate-trust' 'failed' 'TLS chain is invalid or does not terminate at the approved root.' @{ rootThumbprint = $rootThumbprint; chainValid = $valid } }
    } catch { Add-Check 'certificate-trust' 'failed' $_.Exception.Message $null }
    $pending = Join-Path $DataRoot 'pending'
    if (Test-Path -LiteralPath $pending) { Add-Check 'offline-cache-directory' 'passed' 'Bounded pending-sample directory exists.' @{ path = $pending; count = @((Get-ChildItem -LiteralPath $pending -Filter '*.json')).Count; maxPendingSamples = $settings['MaxPendingSamples'] } }
    else { Add-Check 'offline-cache-directory' 'failed' 'Pending-sample directory does not exist.' @{ path = $pending } }
    if ($Mode -eq 'CaptureOfflineCache') {
      $count = @((Get-ChildItem -LiteralPath $pending -Filter '*.json' -ErrorAction SilentlyContinue)).Count
      if ($count -ge $MinimumPendingSamples) { Add-Check 'offline-cache-capture' 'passed' 'Queued telemetry was found after the operator-performed, time-bounded network isolation.' @{ pendingSamples = $count; minimum = $MinimumPendingSamples } }
      else { Add-Check 'offline-cache-capture' 'failed' 'No queued telemetry found. Do not continue until controlled network isolation and recovery have been proven.' @{ pendingSamples = $count; minimum = $MinimumPendingSamples } }
    } else { Add-Check 'offline-cache-capture' 'not-run' 'This run does not isolate the network. During an approved window, block only Agent egress, wait two sample intervals, restore it, then rerun with -Mode CaptureOfflineCache.' $null }
  }
}
catch { Add-Check 'execution' 'failed' $_.Exception.Message $null }

$failed = @($checks | Where-Object state -eq 'failed')
Save-Report $(if ($failed.Count -eq 0) { 'passed' } else { 'failed' })
if ($failed.Count -gt 0) { exit 2 }
