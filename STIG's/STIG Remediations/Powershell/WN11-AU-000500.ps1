<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000500).ps1 
#>

$Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'MaxSize' -Value 0x8000 -PropertyType DWord -Force | Out-Null

# Verify
$Value = (Get-ItemProperty -Path $Path -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
if ($null -eq $Value) {
    "FINDING (V-253337): MaxSize not configured."
} elseif ($Value -ge 32768) {
    "NOT A FINDING (V-253337): MaxSize = $Value KB."
} else {
    "FINDING (V-253337): MaxSize = $Value KB, below 32768."
}
