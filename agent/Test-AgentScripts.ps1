[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$errors = @()
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File | ForEach-Object {
  $tokens = $null
  $parseErrors = $null
  [void][Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
  $errors += $parseErrors
}
if ($errors.Count -gt 0) { $errors | Format-List; throw 'PowerShell syntax verification failed.' }
Write-Host 'Agent PowerShell syntax verification passed.'
