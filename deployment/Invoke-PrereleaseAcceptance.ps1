[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][uri]$ControlUrl,
  [Parameter(Mandatory = $true)][Security.SecureString]$BearerToken,
  [string]$AgentComputerName = $env:COMPUTERNAME,
  [pscredential]$AgentCredential,
  [int]$MeasurementSeconds = 180,
  [double]$MaxAverageCpuPercent = 0.2,
  [double]$MaxWorkingSetMiB = 25,
  [Nullable[double]]$ObservedNetworkKiBPerMinute,
  [string[]]$BusinessHealthUri = @(),
  [int]$MaxBusinessLatencyMilliseconds = 1000,
  [string[]]$TestPhoneNumber = @(),
  [string[]]$TemplateParameter = @(),
  [switch]$RunSmsTemplateTest,
  [switch]$RequireRetryObservation,
  [int]$DeliveryObservationSeconds = 70,
  [string]$OutputPath = (Join-Path $PWD ("prerelease-acceptance-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'))
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($ControlUrl.Scheme -ne 'https') { throw 'ControlUrl must use HTTPS.' }
if ($MeasurementSeconds -lt 15) { throw 'MeasurementSeconds must be at least 15.' }
if ($DeliveryObservationSeconds -lt 5) { throw 'DeliveryObservationSeconds must be at least 5.' }
if ($MaxBusinessLatencyMilliseconds -lt 1) { throw 'MaxBusinessLatencyMilliseconds must be positive.' }
if ($RunSmsTemplateTest -and $TestPhoneNumber.Count -eq 0) { throw 'TestPhoneNumber is required with RunSmsTemplateTest.' }

$tokenPointer = [IntPtr]::Zero
try {
  $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BearerToken)
  $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
  if ([string]::IsNullOrWhiteSpace($token)) { throw 'BearerToken must not be empty.' }

  $baseUrl = $ControlUrl.AbsoluteUri.TrimEnd('/')
  $headers = @{ Authorization = "Bearer $token" }
  $checks = New-Object System.Collections.Generic.List[object]
  function Add-Check([string]$Name, [string]$State, [string]$Detail, $Evidence) {
    $checks.Add([pscustomobject]@{ name = $Name; state = $State; detail = $Detail; evidence = $Evidence })
  }
  function Invoke-ControlApi([string]$Method, [string]$Path, $Body) {
    $args = @{ Method = $Method; Uri = "$baseUrl$Path"; Headers = $headers; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $args.ContentType = 'application/json'; $args.Body = ($Body | ConvertTo-Json -Depth 8 -Compress) }
    Invoke-RestMethod @args
  }
  function Get-RemoteValidation([string]$ComputerName, [pscredential]$Credential, [int]$Duration, [string]$ServiceName) {
    $script = {
      param($Duration, $ServiceName)
      $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
      if (-not $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) { throw "Service '$ServiceName' is not running." }
      $beforeListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress, LocalPort, OwningProcess)
      $beforeProcess = Get-Process -Id $service.ProcessId -ErrorAction Stop
      $cpuStart = $beforeProcess.CPU
      $started = Get-Date
      Start-Sleep -Seconds $Duration
      $afterService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
      if (-not $afterService -or $afterService.State -ne 'Running' -or $afterService.ProcessId -ne $service.ProcessId) { throw 'Agent service stopped or restarted during resource sampling.' }
      $afterProcess = Get-Process -Id $service.ProcessId -ErrorAction Stop
      $elapsed = ((Get-Date) - $started).TotalSeconds
      $cpu = if ($elapsed -gt 0) { (($afterProcess.CPU - $cpuStart) / $elapsed / [Environment]::ProcessorCount) * 100 } else { 0 }
      $afterListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress, LocalPort, OwningProcess)
      $beforeKeys = @($beforeListeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort):$($_.OwningProcess)" })
      $newListeners = @($afterListeners | Where-Object { $beforeKeys -notcontains "$($_.LocalAddress):$($_.LocalPort):$($_.OwningProcess)" })
      [pscustomobject]@{
        processId = $service.ProcessId
        averageCpuPercent = [math]::Round($cpu, 4)
        workingSetMiB = [math]::Round($afterProcess.WorkingSet64 / 1MB, 3)
        privateMemoryMiB = [math]::Round($afterProcess.PrivateMemorySize64 / 1MB, 3)
        durationSeconds = [math]::Round($elapsed, 1)
        newListeners = @($newListeners)
      }
    }
    if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq '.' -or $ComputerName -eq 'localhost') { return & $script $Duration $ServiceName }
    $params = @{ ComputerName = $ComputerName; ScriptBlock = $script; ArgumentList = @($Duration, $ServiceName); ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    Invoke-Command @params
  }

  try {
    $health = Invoke-RestMethod -Method Get -Uri "$baseUrl/api/health" -ErrorAction Stop
    if ($health.status -eq 'healthy' -and $health.database -eq 'connected') { Add-Check 'control-health' 'passed' 'HTTPS health endpoint is healthy.' $health }
    else { Add-Check 'control-health' 'failed' 'Control endpoint is not healthy.' $health }
  } catch { Add-Check 'control-health' 'failed' $_.Exception.Message $null }

  try {
    $me = Invoke-ControlApi 'Get' '/api/auth/me' $null
    if ($me.role -eq 'Admin') { Add-Check 'administrator-authentication' 'passed' 'Bearer token has administrator scope.' $me }
    else { Add-Check 'administrator-authentication' 'failed' 'Acceptance requires an administrator token.' $me }
  } catch { Add-Check 'administrator-authentication' 'failed' $_.Exception.Message $null }

  try {
    $deliveriesBefore = @(Invoke-ControlApi 'Get' '/api/notification-deliveries' $null)
    $duplicateBefore = @($deliveriesBefore | Group-Object incidentId, policyId | Where-Object Count -gt 1)
    if ($duplicateBefore.Count -eq 0) { Add-Check 'notification-deduplication' 'passed' 'No duplicate incident/policy delivery state exists before observation.' @{ count = $deliveriesBefore.Count } }
    else { Add-Check 'notification-deduplication' 'failed' 'Duplicate notification delivery states detected.' $duplicateBefore }
    Start-Sleep -Seconds $DeliveryObservationSeconds
    $deliveriesAfter = @(Invoke-ControlApi 'Get' '/api/notification-deliveries' $null)
    $duplicateAfter = @($deliveriesAfter | Group-Object incidentId, policyId | Where-Object Count -gt 1)
    if ($duplicateAfter.Count -gt 0) { Add-Check 'notification-deduplication-observation' 'failed' 'Duplicate notification states appeared during observation.' $duplicateAfter }
    else { Add-Check 'notification-deduplication-observation' 'passed' 'No duplicate delivery state appeared during observation.' @{ before = $deliveriesBefore.Count; after = $deliveriesAfter.Count } }
    # A later successful retry clears LastError, so Attempts is the durable retry evidence.
    $retried = @($deliveriesAfter | Where-Object { $_.attempts -gt 1 })
    if ($RequireRetryObservation) {
      if ($retried.Count -gt 0) { Add-Check 'notification-retry' 'passed' 'At least one failed delivery has a recorded retry.' $retried }
      else { Add-Check 'notification-retry' 'failed' 'No retry was observed. Create one controlled failed test delivery before enabling real contacts.' @{ before = $deliveriesBefore.Count; after = $deliveriesAfter.Count } }
    } else { Add-Check 'notification-retry' 'not-run' 'Retry observation is optional in this run. It is required before real contacts are enabled.' @{ observedRetries = $retried.Count } }
  } catch { Add-Check 'notification-delivery-observation' 'failed' $_.Exception.Message $null }

  if ($RunSmsTemplateTest) {
    try {
      $sms = Invoke-ControlApi 'Post' '/api/notifications/test-sms' @{ phoneNumbers = $TestPhoneNumber; templateParameters = $TemplateParameter }
      if ($sms.sent -eq $true) { Add-Check 'sms-template-test' 'passed' 'Tencent Cloud accepted the configured template for test-number delivery.' $sms }
      else { Add-Check 'sms-template-test' 'failed' 'Test SMS request did not report sent=true.' $sms }
    } catch { Add-Check 'sms-template-test' 'failed' $_.Exception.Message $null }
  } else { Add-Check 'sms-template-test' 'not-run' 'No SMS was sent. Use only approved test numbers before real contacts.' $null }

  try {
    $agent = Get-RemoteValidation $AgentComputerName $AgentCredential $MeasurementSeconds 'MonitoringPlatformAgent'
    if ($agent.averageCpuPercent -le $MaxAverageCpuPercent) { Add-Check 'agent-cpu-budget' 'passed' "Average CPU $($agent.averageCpuPercent)% <= $MaxAverageCpuPercent%." $agent }
    else { Add-Check 'agent-cpu-budget' 'failed' "Average CPU $($agent.averageCpuPercent)% exceeds $MaxAverageCpuPercent%. Stop and roll back this batch." $agent }
    if ($agent.workingSetMiB -le $MaxWorkingSetMiB) { Add-Check 'agent-working-set-budget' 'passed' "Working set $($agent.workingSetMiB) MiB <= $MaxWorkingSetMiB MiB." $agent }
    else { Add-Check 'agent-working-set-budget' 'failed' "Working set $($agent.workingSetMiB) MiB exceeds $MaxWorkingSetMiB MiB. Stop and roll back this batch." $agent }
    if (@($agent.newListeners).Count -eq 0) { Add-Check 'unexpected-listener' 'passed' 'Agent created no new TCP listener during sampling.' $agent.newListeners }
    else { Add-Check 'unexpected-listener' 'failed' 'A new TCP listener appeared during Agent sampling. Stop and investigate.' $agent.newListeners }
  } catch { Add-Check 'agent-resource-and-listener' 'failed' $_.Exception.Message $null }

  if ($ObservedNetworkKiBPerMinute.HasValue) {
    if ($ObservedNetworkKiBPerMinute.Value -le 50) { Add-Check 'agent-network-budget' 'passed' "Observed Agent network $($ObservedNetworkKiBPerMinute.Value) KiB/min <= 50 KiB/min." @{ observedKiBPerMinute = $ObservedNetworkKiBPerMinute.Value; source = 'operator-supplied packet/process capture' } }
    else { Add-Check 'agent-network-budget' 'failed' "Observed Agent network $($ObservedNetworkKiBPerMinute.Value) KiB/min exceeds 50 KiB/min. Stop and roll back this batch." @{ observedKiBPerMinute = $ObservedNetworkKiBPerMinute.Value } }
  } else { Add-Check 'agent-network-budget' 'failed' 'No per-process network capture was supplied. Interface counters cannot attribute traffic to the Agent and are not valid evidence.' $null }

  if ($BusinessHealthUri.Count -eq 0) { Add-Check 'business-latency' 'failed' 'No business health URL was supplied. A business-owner approved endpoint is required for rollout acceptance.' $null }
  else {
    foreach ($uri in $BusinessHealthUri) {
      try {
        $watch = [Diagnostics.Stopwatch]::StartNew(); $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec ([math]::Ceiling($MaxBusinessLatencyMilliseconds / 1000.0) + 3) -ErrorAction Stop; $watch.Stop()
        $evidence = @{ uri = $uri; statusCode = [int]$response.StatusCode; latencyMilliseconds = $watch.ElapsedMilliseconds }
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400 -and $watch.ElapsedMilliseconds -le $MaxBusinessLatencyMilliseconds) { Add-Check "business-latency:$uri" 'passed' 'Business endpoint responded within budget.' $evidence }
        else { Add-Check "business-latency:$uri" 'failed' 'Business endpoint status or latency exceeded the approved budget.' $evidence }
      } catch { Add-Check "business-latency:$uri" 'failed' $_.Exception.Message $null }
    }
  }

  $failed = @($checks | Where-Object state -eq 'failed')
  $report = [pscustomobject]@{
    schemaVersion = 1; generatedAt = (Get-Date).ToUniversalTime().ToString('o'); mode = 'single-node-isolated-prerelease';
    controlUrl = $baseUrl; agentComputerName = $AgentComputerName; result = if ($failed.Count -eq 0) { 'passed' } else { 'failed' }
    hardStopRequired = ($failed.Count -gt 0); checks = @($checks)
  }
  $directory = Split-Path -Parent $OutputPath; if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
  $report | ConvertTo-Json -Depth 8
  if ($failed.Count -gt 0) { exit 2 }
}
finally {
  $token = $null
  if ($tokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
}
