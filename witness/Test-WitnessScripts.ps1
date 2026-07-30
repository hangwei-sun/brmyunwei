[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$errors = @()
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
    $errors += $parseErrors
}
if ($errors.Count -gt 0) {
    $errors | Format-List
    throw 'Witness PowerShell syntax verification failed.'
}
Write-Host 'Witness PowerShell syntax verification passed.'
