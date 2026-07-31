#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$NodeId,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$ClusterId,
  [Parameter(Mandatory = $true)][uri]$WitnessUrl,
  [Parameter(Mandatory = $true)][uri]$PrimaryReadyUrl,
  [Parameter(Mandatory = $true)][uri]$PromotedReadyUrl,
  [Parameter(Mandatory = $true)][string]$StandbyReplicaPath,
  [string]$DatabasePath = "$env:ProgramData\MonitoringPlatform\data\monitoring.db",
  [string]$ConfigurationPath = "$env:ProgramFiles\MonitoringPlatform\app\appsettings.Production.json",
  [string]$ApplicationPath = "$env:ProgramFiles\MonitoringPlatform\app\MonitoringPlatform.Api.exe",
  [string]$ServiceName = 'MonitoringPlatform',
  [int]$FailureThreshold = 3,
  [int]$CheckSeconds = 5,
  [int]$PromotionCooldownSeconds = 10,
  [ValidateRange(5, 300)][int]$LeaseTtlSeconds = 60
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($WitnessUrl.Scheme -ne 'https' -or $PrimaryReadyUrl.Scheme -ne 'https' -or $PromotedReadyUrl.Scheme -ne 'https') { throw 'WitnessUrl, PrimaryReadyUrl and PromotedReadyUrl must use HTTPS.' }
if ($FailureThreshold -lt 2 -or $FailureThreshold -gt 60) { throw 'FailureThreshold must be between 2 and 60.' }
if ($CheckSeconds -lt 2 -or $CheckSeconds -gt 60) { throw 'CheckSeconds must be between 2 and 60.' }

function Get-ServiceWitnessToken {
  param([string]$Name)
  $environment = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Environment -ErrorAction Stop).Environment
  $entry = @($environment | Where-Object { $_ -like 'HighAvailability__WitnessBearerToken=*' } | Select-Object -First 1)
  if ($entry.Count -ne 1) { throw "Service $Name has no HighAvailability__WitnessBearerToken environment entry." }
  $token = $entry[0].Substring('HighAvailability__WitnessBearerToken='.Length)
  if ($token.Length -lt 32) { throw 'Witness token is invalid.' }
  return $token
}

function Test-PrimaryReady {
  param([uri]$Url)
  try {
    $response = Invoke-RestMethod -Method Get -Uri $Url.AbsoluteUri -TimeoutSec 5
    return $response.status -eq 'ready' -and $response.database -eq 'connected' -and $response.role -eq 'active'
  }
  catch { return $false }
}

$scriptRoot = Split-Path -Parent $PSCommandPath
$promotionScript = Join-Path $scriptRoot 'Invoke-HaPromotion.ps1'
if (-not (Test-Path -LiteralPath $promotionScript -PathType Leaf)) { throw "Promotion script not found: $promotionScript" }

$failures = 0
$lastPromotionAttempt = [DateTimeOffset]::MinValue
while ($true) {
  # A restarted watcher must never promote over a node that already holds the writer lease.
  if (Test-PrimaryReady $PromotedReadyUrl) {
    Write-EventLog -LogName Application -Source 'MonitoringPlatform' -EventId 4103 -EntryType Information -Message "HA failover watcher stopped because $NodeId is already ready for writes."
    break
  }
  if (Test-PrimaryReady $PrimaryReadyUrl) {
    $failures = 0
  }
  else {
    $failures++
    if ($failures -ge $FailureThreshold -and ([DateTimeOffset]::UtcNow - $lastPromotionAttempt).TotalSeconds -ge $PromotionCooldownSeconds) {
      $lastPromotionAttempt = [DateTimeOffset]::UtcNow
      try {
        # The promotion command can only proceed after witness expiry; a network partition does not bypass fencing.
        $token = Get-ServiceWitnessToken $ServiceName
        $secureToken = ConvertTo-SecureString -String $token -AsPlainText -Force
        & $promotionScript -NodeId $NodeId -ClusterId $ClusterId -WitnessUrl $WitnessUrl -WitnessBearerToken $secureToken `
          -StandbyReplicaPath $StandbyReplicaPath -DatabasePath $DatabasePath -ConfigurationPath $ConfigurationPath `
          -ApplicationPath $ApplicationPath -ServiceName $ServiceName -ReadyUrl $PromotedReadyUrl `
          -LeaseTtlSeconds $LeaseTtlSeconds -ConfirmPromotion
        if (-not $?) { throw 'HA promotion script returned a failure status.' }
        Write-EventLog -LogName Application -Source 'MonitoringPlatform' -EventId 4101 -EntryType Information -Message "HA automatic promotion completed for $NodeId under cluster $ClusterId."
        break
      }
      catch {
        Write-EventLog -LogName Application -Source 'MonitoringPlatform' -EventId 4102 -EntryType Warning -Message "HA automatic promotion was fenced or failed: $($_.Exception.Message)"
      }
      finally { $token = $null; $secureToken = $null }
    }
  }
  Start-Sleep -Seconds $CheckSeconds
}
