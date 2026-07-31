#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][Security.SecureString]$WitnessBearerToken,
  [string]$ServiceName = 'MonitoringPlatform'
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw "Service not found: $ServiceName" }
$pointer = [IntPtr]::Zero
try {
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($WitnessBearerToken)
  $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  if ($token.Length -lt 32 -or $token.Length -gt 256) { throw 'Witness bearer token must be between 32 and 256 characters.' }
  if (-not $PSCmdlet.ShouldProcess($ServiceName, 'store HA witness token in the protected service environment and restart')) { return }
  $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
  $previous = @((Get-ItemProperty -LiteralPath $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment)
  $updated = @($previous | Where-Object { $_ -notlike 'HighAvailability__WitnessBearerToken=*' }) + "HighAvailability__WitnessBearerToken=$token"
  Set-ItemProperty -LiteralPath $serviceKey -Name Environment -Type MultiString -Value $updated
  Restart-Service -Name $ServiceName
}
finally {
  $token = $null
  if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
