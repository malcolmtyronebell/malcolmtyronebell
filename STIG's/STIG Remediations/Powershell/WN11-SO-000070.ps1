<#
.SYNOPSIS
    This PowerShell script ensures the machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000070
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-SO-000070/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-SO-000070).ps1 
#>


$Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'InactivityTimeoutSecs' -Value 0x384 -PropertyType DWord -Force | Out-Null

# Verify
$Value = (Get-ItemProperty -Path $Path -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
if ($null -eq $Value) {
    "FINDING (V-253444): InactivityTimeoutSecs not configured."
} elseif ($Value -eq 0) {
    "FINDING (V-253444): InactivityTimeoutSecs = 0 (inactivity limit disabled)."
} elseif ($Value -le 900) {
    "NOT A FINDING (V-253444): InactivityTimeoutSecs = $Value seconds."
} else {
    "FINDING (V-253444): InactivityTimeoutSecs = $Value seconds, must be 900 or less."
} 

