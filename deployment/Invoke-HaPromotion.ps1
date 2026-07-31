#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$NodeId,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$ClusterId,
  [Parameter(Mandatory = $true)][uri]$WitnessUrl,
  [Parameter(Mandatory = $true)][Security.SecureString]$WitnessBearerToken,
  [Parameter(Mandatory = $true)][string]$StandbyReplicaPath,
  [string]$DatabasePath = "$env:ProgramData\MonitoringPlatform\data\monitoring.db",
  [string]$ConfigurationPath = "$env:ProgramFiles\MonitoringPlatform\app\appsettings.Production.json",
  [string]$ApplicationPath = "$env:ProgramFiles\MonitoringPlatform\app\MonitoringPlatform.Api.exe",
  [string]$ServiceName = 'MonitoringPlatform',
  [Parameter(Mandatory = $true)][uri]$ReadyUrl,
  [ValidateRange(5, 300)][int]$LeaseTtlSeconds = 60,
  [ValidateRange(5, 120)][int]$ReadyTimeoutSeconds = 45,
  [switch]$ConfirmPromotion
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not $ConfirmPromotion) { throw 'ConfirmPromotion is required after verifying that the previous active node is fenced or its lease has expired.' }
if ($WitnessUrl.Scheme -ne 'https' -or $ReadyUrl.Scheme -ne 'https') { throw 'WitnessUrl and ReadyUrl must use HTTPS.' }
$replica = [IO.Path]::GetFullPath($StandbyReplicaPath)
$database = [IO.Path]::GetFullPath($DatabasePath)
$configuration = [IO.Path]::GetFullPath($ConfigurationPath)
$application = [IO.Path]::GetFullPath($ApplicationPath)
foreach ($required in @($replica, $configuration, $application)) { if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required file not found: $required" } }
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw "Service not found: $ServiceName" }

& $application --verify-sqlite $replica
if ($LASTEXITCODE -ne 0) { throw 'Standby replica failed SQLite integrity verification.' }

$tokenPointer = [IntPtr]::Zero
try {
  $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($WitnessBearerToken)
  $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
  $leaseUri = [uri]::new($WitnessUrl, "v1/leases/$([uri]::EscapeDataString($ClusterId))")
  $body = @{ clusterId = $ClusterId; owner = $NodeId; ttlSeconds = $LeaseTtlSeconds; previousEpoch = $null } | ConvertTo-Json -Compress
  $lease = Invoke-RestMethod -Method Put -Uri $leaseUri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
  if ($lease.owner -ne $NodeId -or [long]$lease.epoch -le 0 -or [DateTimeOffset]$lease.expiresAt -le [DateTimeOffset]::UtcNow) { throw 'Witness did not return a valid fencing lease for this node.' }

  if (-not $PSCmdlet.ShouldProcess($database, "Promote replica under witness epoch $($lease.epoch)")) { return }
  $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $rollbackDatabase = "$database.pre-promotion-$timestamp"
  $rollbackConfiguration = "$configuration.pre-promotion-$timestamp"
  Copy-Item -LiteralPath $configuration -Destination $rollbackConfiguration -Force
  $databaseExisted = Test-Path -LiteralPath $database -PathType Leaf
  $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
  $previousEnvironment = (Get-ItemProperty -LiteralPath $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment
  try {
    Stop-Service -Name $ServiceName -Force
    if ($databaseExisted) { Move-Item -LiteralPath $database -Destination $rollbackDatabase }
    foreach ($suffix in @('-wal', '-shm')) { if (Test-Path -LiteralPath "$database$suffix") { Move-Item -LiteralPath "$database$suffix" -Destination "$rollbackDatabase$suffix" } }
    Copy-Item -LiteralPath $replica -Destination $database

    $settings = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
    if (-not $settings.HighAvailability) { $settings | Add-Member -NotePropertyName HighAvailability -NotePropertyValue ([pscustomobject]@{}) }
    foreach ($entry in @{ Enabled = $true; ClusterId = $ClusterId; NodeId = $NodeId; ConfiguredRole = 'active'; WitnessUrl = $WitnessUrl.AbsoluteUri }.GetEnumerator()) {
      if ($settings.HighAvailability.PSObject.Properties.Name -contains $entry.Key) { $settings.HighAvailability.($entry.Key) = $entry.Value }
      else { $settings.HighAvailability | Add-Member -NotePropertyName $entry.Key -NotePropertyValue $entry.Value }
    }
    $temporaryConfig = "$configuration.tmp"
    $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporaryConfig -Encoding UTF8
    Move-Item -LiteralPath $temporaryConfig -Destination $configuration -Force
    $serviceEnvironment = @($previousEnvironment | Where-Object { $_ -notlike 'HighAvailability__WitnessBearerToken=*' }) + "HighAvailability__WitnessBearerToken=$token"
    Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value $serviceEnvironment
    Start-Service -Name $ServiceName
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
    $ready = $false
    while ([DateTimeOffset]::UtcNow -lt $readyDeadline) {
      try {
        $status = Invoke-RestMethod -Uri $ReadyUrl -Method Get -TimeoutSec 5
        if ($status.status -eq 'ready' -and $status.database -eq 'connected' -and $status.role -eq 'active' -and [long]$status.epoch -eq [long]$lease.epoch) {
          $ready = $true
          break
        }
      }
      catch { }
      Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Promoted node did not become ready with witness epoch $($lease.epoch) before timeout." }
  }
  catch {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $rollbackConfiguration -Destination $configuration -Force
    foreach ($currentPath in @($database, "$database-wal", "$database-shm")) {
      if (Test-Path -LiteralPath $currentPath) { Remove-Item -LiteralPath $currentPath -Force }
    }
    foreach ($suffix in @('', '-wal', '-shm')) {
      if (Test-Path -LiteralPath "$rollbackDatabase$suffix") { Copy-Item -LiteralPath "$rollbackDatabase$suffix" -Destination "$database$suffix" -Force }
    }
    if ($null -eq $previousEnvironment) { Remove-ItemProperty -LiteralPath $serviceKey -Name Environment -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value @($previousEnvironment) }
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    throw
  }
  Write-Host "Node promoted under witness epoch $($lease.epoch). Previous database: $rollbackDatabase"
}
finally {
  $token = $null
  if ($tokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
}
